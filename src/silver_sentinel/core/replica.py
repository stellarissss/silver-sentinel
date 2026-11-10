"""异地副本：让证据在服务器被攻破/勒索时仍然存在。

设计原则：
- **增量分片**。事件日志按字节偏移切段上传（part-00000001.jsonl…），
  天然幂等，断网重来不会重复也不会漏。
- **内容寻址**。证据文件以 sha256 命名，同名即同内容，不必比对 mtime。
- **可验证**。同步完回读远端元数据比对长度/摘要，否则「备份成功」只是一句话。
- **不阻塞主流程**。同步失败只记状态，不抛给调用方——监控不能因为备份挂了就停摆。

支持三种后端：
- dir：复制到另一个挂载点（NFS / 另一块盘 / rsync 目标）。最简单也最常用。
- s3：MinIO / AWS S3 / 阿里云 OSS(S3 兼容) / 七牛等。
- webdav：坚果云、Nextcloud 等。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..config import settings
from ..domain import utcnow

log = logging.getLogger(__name__)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _same_device() -> bool:
    """副本目标与数据目录是不是同一块盘。

    同盘「副本」不是备份：机器一坏两份一起没。线上 dir 后端误配到
    /var/lib/silver-sentinel/replica，白复制了 2.7G 密文和 1G DB 快照，
    磁盘直接吃到 95%。宁可跳过并报警，也不要假装备份成功。
    """
    try:
        return os.stat(settings.data_dir).st_dev == os.stat(settings.replica_target).st_dev
    except OSError:
        return False


@dataclass
class ReplicaState:
    event_offset: int = 0
    part_no: int = 0
    last_run: str = ""
    last_ok: bool = False
    last_error: str = ""
    files_synced: int = 0
    bytes_sent: int = 0
    verified: int = 0
    failed: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_offset": self.event_offset,
            "part_no": self.part_no,
            "last_run": self.last_run,
            "last_ok": self.last_ok,
            "last_error": self.last_error,
            "files_synced": self.files_synced,
            "bytes_sent": self.bytes_sent,
            "verified": self.verified,
            "failed": self.failed,
            "history": self.history[-20:],
        }


class Replica:
    def __init__(self) -> None:
        self.backend = settings.replica_backend
        self.target = settings.replica_target
        self.state_path = settings.data_dir / "replica_state.json"
        self.state = self._load_state()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------ 状态
    def _load_state(self) -> ReplicaState:
        if self.state_path.is_file():
            try:
                return ReplicaState(**json.loads(self.state_path.read_text(encoding="utf-8")))
            except (json.JSONDecodeError, TypeError):
                pass
        return ReplicaState()

    def _save_state(self) -> None:
        try:
            self.state_path.write_text(
                json.dumps(self.state.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass

    # ------------------------------------------------------------ 后端
    def _put(self, remote_name: str, data: bytes) -> bool:
        """写入远端。返回是否成功。"""
        if self.backend == "dir":
            dest = Path(self.target) / remote_name
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_suffix(dest.suffix + ".tmp")
            tmp.write_bytes(data)
            tmp.replace(dest)          # 原子替换，避免半截文件
            return True

        if self.backend == "s3":
            import boto3

            client = boto3.client(
                "s3",
                endpoint_url=self.target or None,
                aws_access_key_id=settings.replica_access_key,
                aws_secret_access_key=settings.replica_secret_key,
                region_name="us-east-1",
            )
            client.put_object(Bucket=settings.replica_bucket, Key=remote_name, Body=data)
            return True

        if self.backend == "webdav":
            url = self.target.rstrip("/") + "/" + remote_name
            with httpx.Client(timeout=60, auth=(settings.replica_access_key, settings.replica_secret_key)) as c:
                # WebDAV 新建目录
                parent = url.rsplit("/", 1)[0]
                try:
                    c.request("MKCOL", parent)
                except httpx.HTTPError:
                    pass
                r = c.put(url, content=data)
                return r.status_code in (200, 201, 204)

        raise ValueError(f"未知副本后端：{self.backend}")

    def _verify_remote(self, remote_name: str, expected_size: int) -> bool:
        if not settings.replica_verify:
            return True
        if self.backend == "dir":
            p = Path(self.target) / remote_name
            return p.is_file() and p.stat().st_size == expected_size

        if self.backend == "s3":
            import boto3

            client = boto3.client(
                "s3",
                endpoint_url=self.target or None,
                aws_access_key_id=settings.replica_access_key,
                aws_secret_access_key=settings.replica_secret_key,
                region_name="us-east-1",
            )
            try:
                head = client.head_object(Bucket=settings.replica_bucket, Key=remote_name)
                return int(head["ContentLength"]) == expected_size
            except Exception:  # noqa: BLE001
                return False

        if self.backend == "webdav":
            url = self.target.rstrip("/") + "/" + remote_name
            try:
                with httpx.Client(timeout=30, auth=(settings.replica_access_key, settings.replica_secret_key)) as c:
                    r = c.head(url)
                    return r.status_code == 200 and int(r.headers.get("content-length", -1)) == expected_size
            except httpx.HTTPError:
                return False
        return False

    # ------------------------------------------------------------ 主流程
    def sync_events(self) -> int:
        """把事件日志的新增字节切成新分片上传。返回上传字节数。"""
        if self.backend == "dir" and _same_device():
            log.warning("副本目标与数据目录同盘，跳过事件分片（同盘双份不是备份）")
            return 0
        path = settings.eventlog_path
        if not path.is_file():
            return 0
        size = path.stat().st_size
        if size <= self.state.event_offset:
            return 0

        with path.open("rb") as fh:
            fh.seek(self.state.event_offset)
            chunk = fh.read()

        if not chunk:
            return 0

        self.state.part_no += 1
        name = f"events/part-{self.state.part_no:08d}.jsonl"
        ok = self._put(name, chunk)
        if not ok:
            self.state.part_no -= 1       # 回滚编号，下次重试同一个分片名
            raise RuntimeError(f"事件分片上传失败：{name}")

        if not self._verify_remote(name, len(chunk)):
            raise RuntimeError(f"事件分片校验失败：{name}")

        self.state.event_offset = size
        self.state.verified += 1
        self.state.files_synced += 1
        self.state.bytes_sent += len(chunk)
        return len(chunk)

    def sync_evidence(self, batch: int = 200) -> int:
        """上传尚未同步的证据文件。文件按 sha256 命名，重复上传无副作用。"""
        if self.backend == "dir" and _same_device():
            log.warning("副本目标与数据目录同盘，跳过明文证据复制（同盘双份不是备份）")
            return 0
        ev_dir = settings.evidence_dir
        if not ev_dir.is_dir():
            return 0

        manifest_path = settings.data_dir / "replica_manifest.json"
        synced: set[str] = set()
        if manifest_path.is_file():
            try:
                synced = set(json.loads(manifest_path.read_text(encoding="utf-8")).get("files", []))
            except (json.JSONDecodeError, AttributeError):
                synced = set()

        count = 0
        newly: list[str] = []
        for path in sorted(ev_dir.iterdir(), key=lambda p: p.stat().st_mtime):
            if count >= batch:
                break
            if not path.is_file() or path.name in synced:
                continue
            data = path.read_bytes()
            name = f"evidence/{path.name}"
            if not self._put(name, data):
                self.state.failed += 1
                continue
            if not self._verify_remote(name, len(data)):
                self.state.failed += 1
                continue
            synced.add(path.name)
            newly.append(path.name)
            count += 1
            self.state.files_synced += 1
            self.state.bytes_sent += len(data)
            self.state.verified += 1

        if newly:
            manifest_path.write_text(
                json.dumps({"files": sorted(synced)}, ensure_ascii=False), encoding="utf-8"
            )
        return count

    def sync_vault_blobs(self, batch: int = 400) -> int:
        """把证据仓的密文也复制一份（目标必须在不同盘）。

        开了 SILVER_VAULT_REMOVE_PLAINTEXT 后，evidence/ 目录是空的；
        如果副本只备份明文，机器一坏就只剩远端 vault 一份。密文体积小、
        内容寻址、天然幂等——但同盘复制两份毫无意义，只会吃满磁盘。
        """
        if self.backend == "dir" and _same_device():
            log.warning("副本目标与数据目录同盘，跳过 vault 密文复制（同盘双份不是备份）")
            return 0
        src = settings.data_dir / "vault" / "blobs"
        if not src.is_dir():
            return 0
        manifest_path = settings.data_dir / "replica_vault_manifest.json"
        synced: set[str] = set()
        if manifest_path.is_file():
            try:
                synced = set(json.loads(manifest_path.read_text(encoding="utf-8")).get("files", []))
            except (json.JSONDecodeError, AttributeError):
                synced = set()

        count = 0
        newly: list[str] = []
        for path in sorted(src.rglob("*.ssv"), key=lambda p: p.stat().st_mtime):
            if count >= batch:
                break
            name = f"vault/{path.relative_to(src)}"
            if name in synced:
                continue
            data = path.read_bytes()
            if not self._put(name, data) or not self._verify_remote(name, len(data)):
                self.state.failed += 1
                continue
            synced.add(name)
            newly.append(name)
            count += 1
            self.state.files_synced += 1
            self.state.bytes_sent += len(data)
            self.state.verified += 1

        if newly:
            manifest_path.write_text(json.dumps({"files": sorted(synced)}, ensure_ascii=False), encoding="utf-8")
        return count

    def sync_db(self) -> bool:
        """数据库快照。SQLite 用 backup API 拿到一致性副本，不能直接 copy 正在写的库。"""
        if not settings.db_url.startswith("sqlite"):
            return False
        if self.backend == "dir" and _same_device():
            log.warning("副本目标与数据目录同盘，跳过数据库快照（同盘双份不是备份）")
            return False
        db_path = Path(settings.db_url.replace("sqlite:///", ""))
        if not db_path.is_file():
            return False

        snapshot = settings.data_dir / "sentinel.snapshot.db"
        try:
            import sqlite3

            # 只读源 + 分批复制：4.4G 库一次 backup 会长时间占住源库读快照，
            # 期间其他连接的写入反复撞 SQLITE_BUSY_SNAPSHOT（busy_timeout
            # 对这种情况无效）。分批 + 间隔让写事务有机会插进来。
            src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
            dst = sqlite3.connect(str(snapshot), timeout=30)
            try:
                with dst:
                    src.backup(dst, pages=512, sleep=0.01)
            finally:
                src.close()
                dst.close()
        except Exception as exc:  # noqa: BLE001
            log.warning("数据库快照失败：%s", exc)
            return False

        data = snapshot.read_bytes()
        name = f"db/sentinel-{utcnow().strftime('%Y%m%d-%H%M%S')}.db"
        ok = self._put(name, data) and self._verify_remote(name, len(data))
        try:
            snapshot.unlink()
        except OSError:
            pass
        if ok:
            self.state.files_synced += 1
            self.state.bytes_sent += len(data)
            self._prune_db_snapshots()
        return ok

    def _prune_db_snapshots(self) -> int:
        """只保留最近 N 份数据库快照。

        副本目录是「异地留档」，不是「永久归档」：无限追加会让磁盘在几个
        月内吃满，而磁盘满是取证最先感知到的问题（APK 停下载 → 浏览器缓存
        写不进去 → 取证开始失败）。保留最近 12 份（约 20 小时）足够回滚到
        「今天早上」；更早的历史由事件日志与证据仓承担。
        """
        if self.backend != "dir":
            return 0
        db_dir = Path(self.target) / "db"
        if not db_dir.is_dir():
            return 0
        snaps = sorted(
            (p for p in db_dir.glob("sentinel-*.db") if p.is_file()),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        removed = 0
        for old in snaps[settings.replica_db_keep :]:
            try:
                old.unlink()
                removed += 1
            except OSError as exc:
                log.debug("清理旧快照失败 %s：%s", old, exc)
        if removed:
            log.info("副本快照清理：删除 %s 份旧快照，保留 %s 份", removed, settings.replica_db_keep)
        return removed

    def run_once(self, *, include_db: bool = False) -> dict[str, Any]:
        if not settings.replica_enabled:
            return {"ok": False, "reason": "副本未启用"}
        if not self.target:
            return {"ok": False, "reason": "未配置副本目标"}

        # 同盘 dir 后端整轮跳过。只跳过 vault/DB 不够：事件分片和明文证据
        # 仍会以每小时几百个文件的速度往同盘副本里堆，磁盘照样吃满
        # （线上实测 377 个/小时）。同盘「副本」本来就不是备份，宁可不跑并报警。
        if self.backend == "dir" and _same_device():
            warning = (
                "副本目标与数据目录同盘：已跳过全部同步（事件/证据/vault/DB），"
                "请把 SILVER_REPLICA_TARGET 指向另一块盘，或改用 s3/webdav 后端"
            )
            with self._lock:
                self.state.last_run = utcnow().isoformat()
                self.state.last_ok = True
                self.state.last_error = ""
                self.state.history.append(
                    {"at": self.state.last_run, "ok": True, "skipped": True}
                )
                self._save_state()
            return {
                "ok": True, "backend": self.backend, "skipped": True,
                "same_device_warning": warning, "elapsed": 0.0,
            }

        started = time.monotonic()
        result: dict[str, Any] = {"ok": True, "backend": self.backend}
        with self._lock:
            try:
                result["event_bytes"] = self.sync_events()
                result["evidence_files"] = self.sync_evidence()
                result["vault_blobs"] = self.sync_vault_blobs()
                if include_db:
                    result["db"] = self.sync_db()
                self.state.last_ok = True
                self.state.last_error = ""
            except Exception as exc:  # noqa: BLE001
                self.state.last_ok = False
                self.state.last_error = str(exc)[:300]
                result["ok"] = False
                result["error"] = self.state.last_error
                log.warning("副本同步失败：%s", exc)

            result["elapsed"] = round(time.monotonic() - started, 2)
            self.state.last_run = utcnow().isoformat()
            self.state.history.append({"at": self.state.last_run, **result})
            self._save_state()
        return result

    # ------------------------------------------------------------ 后台循环
    def start(self) -> None:
        if not settings.replica_enabled or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="replica", daemon=True)
        self._thread.start()
        log.info("异地副本已启动：%s -> %s", self.backend, self.target)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        counter = 0
        while not self._stop.wait(max(30, settings.replica_interval)):
            counter += 1
            # 每 20 轮做一次数据库快照（默认约 100 分钟）
            self.run_once(include_db=(counter % 20 == 0))

    # ------------------------------------------------------------ 恢复
    def restore_events(self, dest: Path | None = None) -> dict[str, Any]:
        """把远端分片按序拼回本地事件日志。灾难恢复用。"""
        dest = dest or (settings.data_dir / "events.restored.jsonl")
        if self.backend == "dir":
            src_dir = Path(self.target) / "events"
            if not src_dir.is_dir():
                return {"ok": False, "reason": "远端无 events 目录"}
            parts = sorted(src_dir.glob("part-*.jsonl"))
            with dest.open("wb") as out:
                for p in parts:
                    out.write(p.read_bytes())
            total = dest.stat().st_size
            return {"ok": True, "parts": len(parts), "bytes": total, "path": str(dest)}
        return {"ok": False, "reason": "s3/webdav 恢复请用 rclone/aws-cli 拉取 events/ 前缀后拼接"}

    def status(self) -> dict[str, Any]:
        s = self.state.to_dict()
        s.update(
            {
                "enabled": settings.replica_enabled,
                "backend": self.backend,
                "target_set": bool(self.target),
                "eventlog_size": settings.eventlog_path.stat().st_size if settings.eventlog_path.is_file() else 0,
                "pending_bytes": max(
                    0,
                    (settings.eventlog_path.stat().st_size if settings.eventlog_path.is_file() else 0)
                    - self.state.event_offset,
                ),
            }
        )
        return s


_replica: Replica | None = None
_lock = threading.Lock()


def get_replica() -> Replica:
    global _replica
    if _replica is None:
        with _lock:
            if _replica is None:
                _replica = Replica()
    return _replica
