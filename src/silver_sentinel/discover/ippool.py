"""恶意 IP 池：把「同一台服务器」变成可检索的线索。

为什么 IP 比域名可靠
--------------------
站群的域名是一次性的：被骗的人举报一个，就换一个。但服务器不会天天换——
`np4w53.cn` 与 `hksm38.com.cn` 是同模板、同 IP（204.194.55.233）、同 ASN
（AS140869 Turing Group）的一批货。

所以「新域名解析到了已知涉老 IP」这条信号，比任何文本特征都硬：它不需要
页面打开、不需要话术命中、不需要证书，只要一次 DNS 查询。

代价与边界
----------
- **CDN 会毁掉这个信号**。Cloudflare 上一个 IP 后面有几十万站点，命中即误报。
  所以入池与检索两侧都排除共享设施（`is_shared_infra` + ASN 黑白名单）。
- **云主机整段出租**也会误伤。一个 /24 里既有骗子也有正经小站，所以池按
  单个 IP 记，不做网段扩散——宁可少带出几个，也不要把整个机房判成团伙。
- 池只增不删不是办法：给了观察数与最后命中时间，半年没再命中的自动失活。
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# 这些 ASN / 主机商的反向解析结果几乎一定是共享设施，直接拒绝入池
_SHARED_ASN_HINTS = (
    "cloudflare", "akamai", "fastly", "cloudfront", "google", "amazon",
    "microsoft", "azure", "aliyun", "alibaba", "tencent", "qcloud",
    "huawei", "baidu", "kingsoft", "upyun", "qiniu", "bunny", "stackpath",
    "imperva", "incapsula", "sucuri", "ddos-guard", "gcore",
)

# 一条记录放多久不再命中就失活
STALE_DAYS = 180


@dataclass(slots=True)
class IPEntry:
    ip: str
    assets: list[str] = field(default_factory=list)
    reason: str = ""
    asn: str = ""
    hits: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    last_hit_at: float = 0.0
    last_hit_host: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "assets": self.assets[-12:],
            "reason": self.reason[:200],
            "asn": self.asn,
            "hits": self.hits,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_hit_at": self.last_hit_at,
            "last_hit_host": self.last_hit_host,
        }

    @property
    def age_days(self) -> float:
        return (time.time() - max(self.last_seen, self.first_seen)) / 86400


class BadIPPool:
    """JSON 落盘的 IP 池。写入只发生在发现线程与取证回填，量很小。"""

    def __init__(self, path: Path, *, limit: int = 50000) -> None:
        self.path = path
        self.limit = max(1000, limit)
        self._lock = threading.Lock()
        self._data: dict[str, IPEntry] = {}
        self._dirty = 0
        self._load()

    # ---------------------------------------------------------------- 持久化
    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 池子坏了就从空开始，不能阻塞发现层
            log.warning("IP 池读取失败，从空池开始：%s", self.path)
            return
        for ip, row in (raw.get("ips") or {}).items():
            try:
                self._data[ip] = IPEntry(
                    ip=ip,
                    assets=list(row.get("assets") or []),
                    reason=str(row.get("reason") or ""),
                    asn=str(row.get("asn") or ""),
                    hits=int(row.get("hits") or 0),
                    first_seen=float(row.get("first_seen") or 0),
                    last_seen=float(row.get("last_seen") or 0),
                    last_hit_at=float(row.get("last_hit_at") or 0),
                    last_hit_host=str(row.get("last_hit_host") or ""),
                )
            except Exception:  # noqa: BLE001
                continue
        log.info("IP 池载入 %d 条", len(self._data))

    def _flush_locked(self) -> None:
        """调用方已持有 self._lock 时用这个。_lock 不可重入——内部再取一次会死锁。"""
        payload = {
            "version": 1,
            "saved_at": time.time(),
            "ips": {k: v.as_dict() for k, v in self._data.items()},
        }
        self._dirty = 0
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            log.debug("IP 池落盘失败：%s", exc)

    def _flush(self) -> None:
        with self._lock:
            self._flush_locked()

    # ---------------------------------------------------------------- 写入
    @staticmethod
    def _is_shared(ip: str, asn: str) -> bool:
        if not ip or is_private(ip):
            return True
        low = (asn or "").lower()
        return any(h in low for h in _SHARED_ASN_HINTS)

    def observe(
        self, ip: str, *, asset: str, reason: str = "", asn: str = "", force: bool = False
    ) -> bool:
        """记录「某个已确认/高危资产解析到这个 IP」。

        force=True 时跳过共享设施判断——只给人工确认过的资产用。
        """
        ip = (ip or "").strip()
        if not ip or "." not in ip:
            return False
        if not force and self._is_shared(ip, asn):
            return False
        with self._lock:
            entry = self._data.get(ip)
            now = time.time()
            if entry is None:
                if len(self._data) >= self.limit:
                    self._evict_locked()
                entry = IPEntry(ip=ip, first_seen=now, last_seen=now)
                self._data[ip] = entry
            entry.last_seen = now
            if reason and not entry.reason:
                entry.reason = reason[:200]
            if asn and not entry.asn:
                entry.asn = asn
            if asset and asset not in entry.assets:
                entry.assets = (entry.assets + [asset])[-12:]
            self._dirty += 1
            if self._dirty >= 20:
                self._flush_locked()
        return True

    def _evict_locked(self) -> None:
        """池满时淘汰最久没被命中的。"""
        if not self._data:
            return
        victims = sorted(self._data.values(), key=lambda e: (e.last_hit_at, e.last_seen))[:200]
        for v in victims:
            self._data.pop(v.ip, None)

    def note_hit(self, ip: str, host: str) -> None:
        with self._lock:
            entry = self._data.get(ip)
            if entry is None:
                return
            entry.hits += 1
            entry.last_hit_at = time.time()
            entry.last_hit_host = host[:120]
            entry.last_seen = max(entry.last_seen, time.time())
            self._dirty += 1

    def remove(self, ip: str) -> bool:
        with self._lock:
            ok = self._data.pop(ip, None) is not None
            if ok:
                self._dirty += 1
        if ok:
            self._flush()
        return ok

    # ---------------------------------------------------------------- 读取
    def lookup(self, ip: str) -> IPEntry | None:
        entry = self._data.get((ip or "").strip())
        if entry is None:
            return None
        if entry.age_days > STALE_DAYS and not entry.hits:
            return None
        return entry

    def is_bad(self, ip: str) -> bool:
        return self.lookup(ip) is not None

    def prune(self, *, stale_days: int = STALE_DAYS) -> int:
        cutoff = time.time() - stale_days * 86400
        with self._lock:
            dead = [
                ip for ip, e in self._data.items()
                if max(e.last_seen, e.last_hit_at) < cutoff and e.hits == 0
            ]
            for ip in dead:
                self._data.pop(ip, None)
            if dead:
                self._dirty += 1
        if dead:
            self._flush()
        return len(dead)

    def prune_dirty(self) -> None:
        if self._dirty:
            self._flush()

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            rows = sorted(self._data.values(), key=lambda e: (-e.hits, -e.last_seen))
            return {
                "size": len(self._data),
                "hits": sum(e.hits for e in rows),
                "entries": [e.as_dict() for e in rows[:50]],
            }

    def __len__(self) -> int:
        return len(self._data)


def is_private(ip: str) -> bool:
    """内网/保留地址。这类 IP 不可能是外部诈骗站。"""
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return True
    a, b = int(parts[0]), int(parts[1])
    if a in (0, 10, 127):
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    if a >= 224:
        return True
    return False
