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
import shutil
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

    def sync_db(self) -> bool:
        """数据库快照。SQLite 用 backup API 拿到一致性副本，不能直接 copy 正在写的库。"""
        if not settings.db_url.startswith("sqlite"):
            return False
        db_path = Path(settings.db_url.replace("sqlite:///", ""))
        if not db_path.is_file():
            return False

        snapshot = settings.data_dir / "sentinel.snapshot.db"
        try:
            import sqlite3

            src = sqlite3.connect(str(db_path))
            dst = sqlite3.connect(str(snapshot))
            with dst:
                src.backup(dst)
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
        return ok

    def run_once(self, *, include_db: bool = False) -> dict[str, Any]:
        if not settings.replica_enabled:
            return {"ok": False, "reason": "副本未启用"}
        if not self.target:
            return {"ok": False, "reason": "未配置副本目标"}

        started = time.monotonic()
        result: dict[str, Any] = {"ok": True, "backend": self.backend}
        with self._lock:
            try:
                result["event_bytes"] = self.sync_events()
                result["evidence_files"] = self.sync_evidence()
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
