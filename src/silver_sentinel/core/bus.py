"""进程内事件总线：把发现、研判、图谱变更实时推给前端。

不做消息队列——单机长期运行没必要引入 Redis。用环形缓冲 + 游标即可：
慢客户端从游标处补发，超出缓冲就告诉它「你落后了，重拉快照」。
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class StreamEvent:
    seq: int
    ts: float
    kind: str
    data: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "kind": self.kind, "data": self.data}


class EventBus:
    def __init__(self, capacity: int = 2000) -> None:
        self._buf: deque[StreamEvent] = deque(maxlen=capacity)
        self._seq = 0
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._subscribers = 0

    def publish(self, kind: str, data: dict[str, Any]) -> StreamEvent:
        with self._cond:
            self._seq += 1
            event = StreamEvent(seq=self._seq, ts=time.time(), kind=kind, data=data)
            self._buf.append(event)
            self._cond.notify_all()
            return event

    def since(self, seq: int, timeout: float = 1.0) -> tuple[list[StreamEvent], bool]:
        """返回 (事件列表, 是否有断档)。timeout 用于长轮询等待新事件。"""
        with self._cond:
            if seq >= self._seq:
                self._cond.wait(timeout)
            oldest = self._buf[0].seq if self._buf else self._seq + 1
            gap = seq + 1 < oldest
            events = [e for e in self._buf if e.seq > seq]
            return events, gap

    def recent(self, limit: int = 50) -> list[StreamEvent]:
        with self._lock:
            return list(self._buf)[-limit:]

    @property
    def cursor(self) -> int:
        return self._seq

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"cursor": self._seq, "buffered": len(self._buf)}


bus = EventBus()
