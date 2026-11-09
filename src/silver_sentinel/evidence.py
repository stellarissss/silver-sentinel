"""证据存储与哈希链。

每条证据的 chain_hash = H(上一条 chain_hash | 本条 sha256 | 采集时间)。
删一条、改一条、换顺序，链都会断——这是事后向监管/公安提交材料时的自证基础。
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import time
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import compute_chain_hash, session_scope
from .domain import utcnow
from .models import Evidence

log = logging.getLogger(__name__)

MIME_BY_EXT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".html": "text/html",
    ".txt": "text/plain",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".apk": "application/vnd.android.package-archive",
}


def chain_tip(session: Session) -> str:
    row = session.scalars(select(Evidence).order_by(Evidence.id.desc()).limit(1)).first()
    return row.chain_hash if row else ""


def _same_content(session: Session, asset_id: int, kind: str, digest: str) -> Evidence | None:
    """同一资产的同类证据，内容一模一样就不再插一行。

    取证是周期性的：一个挂了 Cloudflare 的站每轮都落一份
    「Attention Required!」截图，一个小时就能攒出几十条一模一样的记录。
    文件本体靠 sha256 只存一份，但链上每来一次就多一行——线上 2.3 万行里
    有 4100 行是这种重复，占了 18%，查起来全是噪声。
    """
    return session.scalars(
        select(Evidence)
        .where(
            Evidence.asset_id == asset_id,
            Evidence.kind == kind,
            Evidence.sha256 == digest,
            Evidence.deleted_at.is_(None),
        )
        .order_by(Evidence.id.desc())
        .limit(1)
    ).first()


def append(
    session: Session,
    asset_id: int,
    kind: str,
    data: bytes,
    *,
    note: str = "",
    extension: str = ".bin",
    mime: str = "",
    dedupe: bool = True,
) -> Evidence:
    digest = hashlib.sha256(data).hexdigest()
    if dedupe:
        existing = _same_content(session, asset_id, kind, digest)
        if existing is not None:
            return existing

    target = settings.evidence_dir / f"{digest}{extension}"
    if not target.exists():
        target.write_bytes(data)

    prev = chain_tip(session)
    captured = utcnow()  # 必须显式赋值：列默认值在 flush 时才生效，那时已经要算哈希了
    row = Evidence(
        asset_id=asset_id,
        kind=kind,
        sha256=digest,
        prev_hash=prev,
        size=len(data),
        captured_at=captured,
        path=str(target.relative_to(settings.data_dir)) if target.is_relative_to(settings.data_dir) else str(target),
        storage="plain",
        note=note,
        mime=mime or MIME_BY_EXT.get(extension.lower(), ""),
    )
    row.chain_hash = compute_chain_hash(prev, digest, captured.isoformat())
    session.add(row)
    session.flush()
    return row


def append_file(
    session: Session,
    asset_id: int,
    kind: str,
    path: str | Path,
    note: str = "",
    *,
    mime: str = "",
    dedupe: bool = True,
) -> Evidence:
    """按文件写入证据。

    安装包动辄几十 MB，`read_bytes()` 再写一遍会让内存出现双份峰值；
    这里流式算哈希直接落到证据目录，内存只占一个块。
    """
    path = Path(path)
    digest = hashlib.sha256()
    extension = path.suffix or ".bin"
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    hexdigest = digest.hexdigest()
    if dedupe:
        existing = _same_content(session, asset_id, kind, hexdigest)
        if existing is not None:
            return existing

    target = settings.evidence_dir / f"{hexdigest}{extension}"
    if not target.exists():
        shutil.copyfile(path, target)

    prev = chain_tip(session)
    captured = utcnow()
    row = Evidence(
        asset_id=asset_id,
        kind=kind,
        sha256=hexdigest,
        prev_hash=prev,
        size=path.stat().st_size,
        captured_at=captured,
        path=str(target.relative_to(settings.data_dir))
        if target.is_relative_to(settings.data_dir)
        else str(target),
        storage="plain",
        note=note,
        mime=mime or MIME_BY_EXT.get(extension.lower(), ""),
    )
    row.chain_hash = compute_chain_hash(prev, hexdigest, captured.isoformat())
    session.add(row)
    session.flush()
    return row


# ---------------------------------------------------------------- 读回
#
# 证据仓开启 SILVER_VAULT_REMOVE_PLAINTEXT 之后，明文会被删掉，只剩密文。
# 但读取方（预览、下载、打包、重扫）一直直接 `Path(row.path).read_bytes()`，
# 于是全都拿到空字符串——界面显示「证据缺失」、研判只有域名没有正文、
# 分数永远上不去。这是线上「抓了上千条却零高价值线索」的真正原因。
#
# 下面这组函数是全项目唯一的证据读取入口：先读明文，读不到就用 sha256
# 从本地密文还原。任何新代码都不要绕过它们直接读 row.path。

_MISSING_BACKOFF = 300.0
_missing_until: dict[str, float] = {}


def path_of(row: Evidence) -> Path:
    path = Path(row.path or "")
    if not path.is_absolute():
        path = settings.data_dir / path
    return path


def _decrypt(sha256: str) -> bytes:
    """从本地加密仓还原明文。失败返回空串，并短暂缓存失败避免刷日志。"""
    if not sha256:
        return b""
    now = time.monotonic()
    if _missing_until.get(sha256, 0) > now:
        return b""
    try:
        from .vault import get_vault

        data = get_vault().open_local(sha256)
    except Exception as exc:  # noqa: BLE001 密钥缺失/密文损坏都当成「读不到」
        _missing_until[sha256] = now + _MISSING_BACKOFF
        log.debug("密文还原失败 %s: %s", sha256[:12], exc)
        return b""
    if not data:
        _missing_until[sha256] = now + _MISSING_BACKOFF
        return b""
    return data


def read_bytes(row: Evidence) -> bytes:
    """读证据原始字节：明文优先，缺失时用密文还原。

    这里不抛异常——调用方多是接口与流水线，一条证据读不出来不该让整页 500。
    需要区分「没证据」和「解不开」时用 `read_status`。
    """
    path = path_of(row)
    try:
        if path.is_file():
            return path.read_bytes()
    except OSError:
        pass
    return _decrypt(row.sha256)


def read_text(row: Evidence | None, limit: int = 200_000) -> str:
    if row is None:
        return ""
    data = read_bytes(row)
    if not data:
        return ""
    return data[:limit].decode("utf-8", "replace")


def read_status(row: Evidence) -> str:
    """plain | vault | missing。给健康检查与排障用。

    先看 storage 再探文件：开了「上传后删明文」之后，`row.path` 指向的文件
    本来就不该存在，只按路径判断会把 1.7 万条正常证据全报成丢失。
    """
    from .vault import blob_path

    if getattr(row, "storage", "") == "vault" and blob_path(row.sha256).is_file():
        return "vault"
    path = path_of(row)
    try:
        if path.is_file():
            return "plain"
    except OSError:
        pass
    if blob_path(row.sha256).is_file():
        return "vault"
    return "missing"


def materialize(row: Evidence) -> Path | None:
    """把证据落到一个可直接交给 FileResponse 的临时文件。

    明文在就直接返回原路径；只有密文时解密到 `<data>/tmp/`，
    由调用方在响应结束后删除——不要写回 evidence 目录，
    那会让「已脱敏」的证据重新裸奔在磁盘上。
    """
    path = path_of(row)
    if path.is_file():
        return path
    data = _decrypt(row.sha256)
    if not data:
        return None
    tmp_dir = settings.data_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    ext = path.suffix or ".bin"
    target = tmp_dir / f"ev-{row.id}-{row.sha256[:16]}{ext}"
    try:
        target.write_bytes(data)
    except OSError:
        return None
    return target


def cleanup_tmp(older_than_seconds: int = 3600) -> int:
    """清掉解密出来的临时文件与残留的下载包。"""
    tmp_dir = settings.data_dir / "tmp"
    if not tmp_dir.is_dir():
        return 0
    cutoff = time.time() - older_than_seconds
    removed = 0
    for item in tmp_dir.iterdir():
        try:
            if item.is_file() and item.stat().st_mtime < cutoff:
                item.unlink()
                removed += 1
        except OSError:
            continue
    return removed


def latest_text(session: Session, asset_id: int, limit: int = 60_000) -> str:
    """取该资产最新一份页面正文（明文或密文均可）。研判与重评共用。"""
    return read_text(latest_text_row(session, asset_id), limit)


def latest_text_row(session: Session, asset_id: int, kind: str = "page_text") -> Evidence | None:
    return session.scalars(
        select(Evidence)
        .where(
            Evidence.asset_id == asset_id,
            Evidence.kind == kind,
            Evidence.deleted_at.is_(None),
        )
        .order_by(Evidence.id.desc())
        .limit(1)
    ).first()


# ---------------------------------------------------------------- 软删除


def trash_dir() -> Path:
    d = settings.data_dir / "trash"
    d.mkdir(parents=True, exist_ok=True)
    return d


def soft_delete(session: Session, evidence_id: int, *, by: str = "", reason: str = "") -> dict:
    """软删除：文件移到 trash/，数据库留 tombstone。

    链上记录不删除，只标记 deleted_at。这样 verify_chain 仍然连续，
    也能回答「谁在什么时候删了什么、为什么」。
    """
    row = session.get(Evidence, evidence_id)
    if row is None:
        return {"ok": False, "error": "证据不存在"}
    if row.deleted_at is not None:
        return {"ok": False, "error": "已经删除过了"}

    src = Path(row.path)
    if not src.is_absolute():
        src = settings.data_dir / src
    dest = src
    if src.exists():
        dest = trash_dir() / src.name
        try:
            if dest.exists():
                dest = trash_dir() / f"{src.stem}.{int(utcnow().timestamp())}{src.suffix}"
            shutil.move(str(src), str(dest))
        except OSError:
            # 文件移不走也不要让数据库状态和文件脱节：保留原路径，只标记
            dest = src

    row.deleted_at = utcnow()
    row.deleted_by = by or "web"
    row.delete_reason = reason[:300]
    session.flush()
    return {"ok": True, "id": evidence_id, "path": str(dest)}


def restore(session: Session, evidence_id: int) -> dict:
    row = session.get(Evidence, evidence_id)
    if row is None:
        return {"ok": False, "error": "证据不存在"}
    if row.deleted_at is None:
        return {"ok": False, "error": "未删除"}
    name = Path(row.path).name
    moved = False
    for candidate in (trash_dir() / name, *trash_dir().glob(f"{Path(name).stem}.*{Path(name).suffix}")):
        if candidate.exists():
            target = settings.evidence_dir / name
            try:
                shutil.move(str(candidate), str(target))
            except OSError as exc:
                return {"ok": False, "error": f"恢复失败：{exc}"}
            moved = True
            break
    if not moved:
        # 文件已经被 trash --purge 清掉了。这时候把 deleted_at 抹掉只会造出
        # 一条「记录在、文件没了」的假象，不如老实说恢复不了。
        return {"ok": False, "error": "文件已被清理，无法恢复（删除记录仍保留）"}
    row.deleted_at = None
    row.deleted_by = ""
    row.delete_reason = ""
    session.flush()
    return {"ok": True, "id": evidence_id}


def purge_trash(older_than_days: int = 7) -> dict:
    """物理清理回收站。只清文件，不改数据库记录（tombstone 永久保留）。"""
    import time

    cutoff = time.time() - older_than_days * 86400
    removed = 0
    freed = 0
    for item in trash_dir().iterdir():
        if not item.is_file():
            continue
        try:
            if item.stat().st_mtime > cutoff:
                continue
            freed += item.stat().st_size
            item.unlink()
            removed += 1
        except OSError:
            continue
    return {"removed": removed, "freed_bytes": freed}


# ---------------------------------------------------------------- 体检与修复
#
# 背景：开了「上传后删明文」之后，`row.path` 指向的文件被主动删掉，密文在
# `data/vault/blobs/xx/<sha>.ssv`。任何只看 path 的检查都会把正常证据认成丢失。
# 这里把「记录 / 明文 / 密文」三者一次对齐，并给出可执行的修复动作。


def audit(*, with_blobs: bool = True) -> dict:
    """清点证据：明文、密文、真丢失、重复行、孤儿密文。"""
    from .vault import blob_path

    stats = {"total": 0, "plain": 0, "vault": 0, "missing": 0, "deleted": 0}
    by_kind: dict[str, dict[str, int]] = {}
    seen: dict[tuple[int, str, str], int] = {}
    dup_rows = 0
    missing_ids: list[int] = []
    referenced: set[str] = set()

    with session_scope() as session:
        rows = session.execute(
            select(
                Evidence.id, Evidence.asset_id, Evidence.kind, Evidence.sha256,
                Evidence.path, Evidence.storage, Evidence.deleted_at,
            )
        ).all()

    for ev_id, asset_id, kind, sha, path, _storage, deleted_at in rows:
        stats["total"] += 1
        if deleted_at is not None:
            stats["deleted"] += 1
            continue
        referenced.add(sha)
        key = (asset_id, kind, sha)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            dup_rows += 1

        p = Path(path or "")
        if not p.is_absolute():
            p = settings.data_dir / p
        if p.is_file():
            state = "plain"
        elif blob_path(sha).is_file():
            state = "vault"
        else:
            state = "missing"
            if len(missing_ids) < 200:
                missing_ids.append(ev_id)
        stats[state] += 1
        bucket = by_kind.setdefault(kind, {"plain": 0, "vault": 0, "missing": 0})
        bucket[state] += 1

    out = dict(stats)
    out["by_kind"] = by_kind
    out["dup_rows"] = dup_rows
    out["unique_contents"] = len(seen)
    out["missing_ids"] = missing_ids
    if with_blobs:
        root = settings.data_dir / "vault" / "blobs"
        blobs = {p.name[:-4] for p in root.rglob("*.ssv")} if root.is_dir() else set()
        out["blobs"] = len(blobs)
        out["orphan_blobs"] = len(blobs - referenced)
    return out


def repair(*, fix: bool = True, batch: int = 400) -> dict:
    """把 storage 字段与实际存储对齐；真丢失的单列出来。

    只改元数据，不动文件、不删记录——链仍然完整，只是「文件在哪」这件事
    第一次被写清楚了。

    分批提交：常驻服务一直在取证写库，一次性 UPDATE 2.3 万行会把写锁占住
    十几秒，取证队列直接报 database is locked（线上第一次跑就这么失败的）。
    每批独立事务 + 冲突重试，让它能在服务不停的情况下跑完。
    """
    import time as _time

    from .vault import blob_path

    changed = {"to_vault": 0, "to_plain": 0}
    missing: list[dict] = []
    last_id = 0
    total = 0

    while True:
        ready: list[tuple[int, str]] = []
        with session_scope() as session:
            rows = session.execute(
                select(Evidence.id, Evidence.asset_id, Evidence.kind, Evidence.sha256,
                       Evidence.path, Evidence.storage)
                .where(Evidence.id > last_id, Evidence.deleted_at.is_(None))
                .order_by(Evidence.id)
                .limit(batch)
            ).all()
            if not rows:
                break
            last_id = rows[-1][0]
            total += len(rows)
            for ev_id, asset_id, kind, sha, path, storage in rows:
                p = Path(path or "")
                if not p.is_absolute():
                    p = settings.data_dir / p
                if p.is_file():
                    want = "plain"
                elif blob_path(sha).is_file():
                    want = "vault"
                else:
                    want = "missing"
                    if len(missing) < 500:
                        missing.append(
                            {"id": ev_id, "asset_id": asset_id, "kind": kind,
                             "sha256": sha, "path": path}
                        )
                    continue
                if storage != want:
                    ready.append((ev_id, want))

        if fix and ready:
            for attempt in range(5):
                try:
                    with session_scope() as session:
                        for ev_id, want in ready:
                            session.execute(
                                Evidence.__table__.update()
                                .where(Evidence.id == ev_id)
                                .values(storage=want)
                            )
                    break
                except Exception as exc:  # noqa: BLE001 锁冲突重试，别的错误照抛
                    if "locked" not in str(exc).lower() or attempt == 4:
                        raise
                    _time.sleep(0.5 * (attempt + 1))
        for want in (w for _, w in ready):
            changed["to_vault" if want == "vault" else "to_plain"] += 1

    out = {
        "scanned": total,
        "fixed": changed if fix else {},
        "missing": missing,
        "missing_count": len(missing),
    }
    return out


def gc_orphans(*, dry_run: bool = True) -> dict:
    """清掉没有任何证据记录引用的密文。

    孤儿来自「压进密文仓后证据行被硬删」或早期重复上传。留着只是占盘，
    删掉不影响任何可读性——它们的 sha 已经不在任何链上。
    """
    from .vault import blob_path  # noqa: F401  (保持导入一致性)

    root = settings.data_dir / "vault" / "blobs"
    if not root.is_dir():
        return {"removed": 0, "freed_bytes": 0, "dry_run": dry_run}
    with session_scope() as session:
        referenced = {s for (s,) in session.execute(select(Evidence.sha256).distinct())}
    removed = freed = 0
    for path in root.rglob("*.ssv"):
        if path.name[:-4] in referenced:
            continue
        try:
            size = path.stat().st_size
            if not dry_run:
                path.unlink()
            removed += 1
            freed += size
        except OSError:
            continue
    return {"removed": removed, "freed_bytes": freed, "dry_run": dry_run}
