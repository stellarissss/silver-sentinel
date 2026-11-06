"""证据存储与哈希链。

每条证据的 chain_hash = H(上一条 chain_hash | 本条 sha256 | 采集时间)。
删一条、改一条、换顺序，链都会断——这是事后向监管/公安提交材料时的自证基础。
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import compute_chain_hash
from .domain import utcnow
from .models import Evidence

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


def append(
    session: Session,
    asset_id: int,
    kind: str,
    data: bytes,
    *,
    note: str = "",
    extension: str = ".bin",
    mime: str = "",
) -> Evidence:
    digest = hashlib.sha256(data).hexdigest()
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
        note=note,
        mime=mime or MIME_BY_EXT.get(extension.lower(), ""),
    )
    row.chain_hash = compute_chain_hash(prev, hexdigest, captured.isoformat())
    session.add(row)
    session.flush()
    return row


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
