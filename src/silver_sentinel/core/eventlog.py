"""只追加事件日志：系统的「黑匣子」。

为什么不能只靠数据库：
1. 数据库行会被 UPDATE。一个域名从 candidate 升到 confirmed，中间发生了什么就没了。
2. 数据库文件可能被破坏或加密勒索。事件日志是顺序写的纯文本，恢复代价最低。
3. 复盘时需要「当时的判断依据」，而不是「现在的字段值」。

格式：每行一个 JSON，字段固定，尾部带 prev_hash 与 hash 形成链。
任何一行被篡改或删除，verify() 都能定位到断点。

一致性：group commit。写入先进内存缓冲，最多 1 秒或 256 条后统一 fsync。
极端情况下最多丢 1 秒事件——但事件同时也会写数据库，两者互为补偿。
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import settings
from ..domain import utcnow

log = logging.getLogger(__name__)

GENESIS = "0" * 64


def _canonical(payload: Any) -> str:
    """稳定序列化：同一份数据必须产生同一个哈希。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _digest(prev: str, seq: int, ts: str, kind: str, payload_json: str) -> str:
    raw = f"{prev}\n{seq}\n{ts}\n{kind}\n{payload_json}".encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(slots=True)
class Event:
    seq: int
    ts: str
    kind: str
    payload: dict[str, Any]
    prev_hash: str
    hash: str

    def to_line(self) -> str:
        return json.dumps(
            {
                "seq": self.seq,
                "ts": self.ts,
                "kind": self.kind,
                "payload": self.payload,
                "prev_hash": self.prev_hash,
                "hash": self.hash,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )

    @classmethod
    def from_line(cls, line: str) -> "Event | None":
        line = line.strip()
        if not line:
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        try:
            return cls(
                seq=int(obj["seq"]),
                ts=str(obj["ts"]),
                kind=str(obj["kind"]),
                payload=obj.get("payload") or {},
                prev_hash=str(obj.get("prev_hash", "")),
                hash=str(obj.get("hash", "")),
            )
        except (KeyError, TypeError, ValueError):
            return None


class EventLog:
    """线程安全 + 跨进程安全的追加日志。

    跨进程用 flock：允许 API 进程和 worker 进程同时写同一个文件而不互相破坏。
    O_APPEND 保证单次 write 的原子性（行长度远小于 PIPE_BUF）。
    """

    def __init__(self, path: Path | None = None, *, fsync_interval: float = 1.0) -> None:
        self.path = Path(path or settings.eventlog_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._fd: int | None = None
        self._seq = 0
        self._head = GENESIS
        self._dirty = 0
        self._last_sync = time.monotonic()
        self._fsync_interval = fsync_interval
        self._open()

    # ------------------------------------------------------------ 生命周期
    def _open(self) -> None:
        self._fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        tail = self._read_tail()
        if tail:
            self._seq = tail.seq
            self._head = tail.hash
        else:
            self._seq = 0
            self._head = GENESIS

    def close(self) -> None:
        with self._lock:
            self._flush(force=True)
            if self._fd is not None:
                try:
                    os.close(self._fd)
                finally:
                    self._fd = None

    def _read_tail(self) -> Event | None:
        """从文件尾部找最后一条完整记录，避免每次启动全量扫描。"""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return None
        if size == 0:
            return None
        with open(self.path, "rb") as fh:
            # 先尝试尾部 64KB，通常一行不到 4KB
            chunk = min(size, 65536)
            fh.seek(size - chunk)
            data = fh.read()
        for raw in reversed(data.splitlines()):
            event = Event.from_line(raw.decode("utf-8", "ignore"))
            if event:
                return event
        return None

    # ------------------------------------------------------------ 写入
    def append(self, kind: str, payload: dict[str, Any]) -> Event:
        ts = utcnow().isoformat(timespec="microseconds")
        with self._lock:
            seq = self._seq + 1
            body = _canonical(payload)
            prev = self._head
            digest = _digest(prev, seq, ts, kind, body)
            event = Event(seq=seq, ts=ts, kind=kind, payload=payload, prev_hash=prev, hash=digest)
            line = event.to_line() + "\n"

            assert self._fd is not None
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX)
            except OSError:
                pass  # 某些文件系统不支持 flock，退化为仅进程内锁
            try:
                # 别的进程可能已追加，写前重读尾部校准 seq，防止链分叉
                tail = self._read_tail()
                if tail and tail.seq >= seq:
                    seq = tail.seq + 1
                    prev = tail.hash
                    digest = _digest(prev, seq, ts, kind, body)
                    event = Event(seq=seq, ts=ts, kind=kind, payload=payload, prev_hash=prev, hash=digest)
                    line = event.to_line() + "\n"
                os.write(self._fd, line.encode("utf-8"))
            finally:
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                except OSError:
                    pass

            self._seq = seq
            self._head = digest
            self._dirty += 1
            self._maybe_sync()
            return event

    def _maybe_sync(self) -> None:
        if self._dirty >= 256 or (time.monotonic() - self._last_sync) >= self._fsync_interval:
            self._flush()

    def _flush(self, force: bool = False) -> None:
        if self._fd is None:
            return
        if not force and self._dirty == 0:
            return
        try:
            os.fsync(self._fd)
        except OSError:
            pass
        self._dirty = 0
        self._last_sync = time.monotonic()

    # ------------------------------------------------------------ 读取
    def iter_events(self, since_seq: int = 0, limit: int = 0) -> Iterator[Event]:
        if not self.path.is_file():
            return
        with open(self.path, "rb") as fh:
            produced = 0
            for raw in fh:
                event = Event.from_line(raw.decode("utf-8", "ignore"))
                if event is None or event.seq <= since_seq:
                    continue
                yield event
                produced += 1
                if limit and produced >= limit:
                    return

    def tail(self, n: int = 50) -> list[Event]:
        if not self.path.is_file():
            return []
        with open(self.path, "rb") as fh:
            lines = fh.readlines()[-n:]
        out: list[Event] = []
        for raw in lines:
            event = Event.from_line(raw.decode("utf-8", "ignore"))
            if event:
                out.append(event)
        return out

    def head(self) -> tuple[int, str]:
        return self._seq, self._head

    @property
    def size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    # ------------------------------------------------------------ 校验
    def verify(self, deep: bool = True) -> dict:
        """deep=True 全量重算；False 只检查首尾衔接。"""
        if not self.path.is_file():
            return {"ok": True, "checked": 0, "note": "日志不存在，视为空"}

        prev = GENESIS
        expected_seq = 1
        checked = 0
        last_ts = ""
        with open(self.path, "rb") as fh:
            for lineno, raw in enumerate(fh, 1):
                event = Event.from_line(raw.decode("utf-8", "ignore"))
                if event is None:
                    return {"ok": False, "checked": checked, "broken_at_line": lineno, "reason": "无法解析的行"}
                if event.seq != expected_seq:
                    return {
                        "ok": False,
                        "checked": checked,
                        "broken_at_line": lineno,
                        "reason": f"序号断裂：期望 {expected_seq} 实际 {event.seq}",
                    }
                if event.prev_hash != prev:
                    return {
                        "ok": False,
                        "checked": checked,
                        "broken_at_line": lineno,
                        "reason": "前序哈希不匹配（中间有记录被删改）",
                    }
                if deep:
                    body = _canonical(event.payload)
                    if _digest(prev, event.seq, event.ts, event.kind, body) != event.hash:
                        return {
                            "ok": False,
                            "checked": checked,
                            "broken_at_line": lineno,
                            "reason": "内容哈希不匹配（该行被改写）",
                        }
                prev = event.hash
                expected_seq += 1
                last_ts = event.ts
                checked += 1
        return {"ok": True, "checked": checked, "head": prev, "last_ts": last_ts}


# ---------------------------------------------------------------- 单例


_log: EventLog | None = None
_log_lock = threading.Lock()


def get_log() -> EventLog:
    global _log
    if _log is None:
        with _log_lock:
            if _log is None:
                _log = EventLog()
    return _log


def emit(kind: str, **payload: Any) -> Event | None:
    """业务层统一入口。日志写失败绝不能让业务流程失败。"""
    try:
        return get_log().append(kind, payload)
    except Exception as exc:  # noqa: BLE001
        log.warning("事件日志写入失败：%s", exc)
        return None
