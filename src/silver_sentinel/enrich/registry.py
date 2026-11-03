"""注册信息富化（RDAP）。

为什么用 RDAP 而不是 WHOIS：
- WHOIS 是纯文本、格式各异、被大量限流；RDAP 是结构化 JSON（RFC 7480）。
- rdap.org 提供跨 TLD 的聚合路由，一个入口覆盖绝大多数后缀。
- 不依赖国内网络，也不需要任何 API key。

拿到的最有价值字段是 **registration 时间**：
一个含「国惠」「养老」的域名如果是 20 天前注册的，那基本不用再看了。
反过来，2012 年注册的老域名突然改成这个主题，多半是被黑产买下的老站。

注意：RDAP 对 .cn 常不可达（CNNIC 未开放或网络受限），此时返回 unknown，
绝不当成「未注册」——这个区分在处置材料里会被追问。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import settings

log = logging.getLogger(__name__)

RDAP_ENDPOINTS = [
    "https://rdap.org/domain/{domain}",
    "https://rdap.verisign.com/com/v1/domain/{domain}",
]
UA = "Mozilla/5.0 (compatible; silver-sentinel/1.0)"


@dataclass(slots=True)
class RegistryInfo:
    domain: str
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    updated_at: datetime | None = None
    registrar: str = ""
    status: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    age_days: int | None = None
    ok: bool = False
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "registrar": self.registrar,
            "status": self.status,
            "nameservers": self.nameservers,
            "age_days": self.age_days,
            "ok": self.ok,
            "error": self.error,
        }


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    txt = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y%m%d"):
            try:
                dt = datetime.strptime(txt[: len(fmt) + 2], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return dt.replace(tzinfo=None)


class RegistryCache:
    """磁盘缓存。注册信息几乎不变，缓存 30 天足够。"""

    def __init__(self, path: Path, ttl_days: int = 30) -> None:
        self.path = path
        self.ttl = ttl_days * 86400
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        if path.is_file():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                self._data = {}
        self._dirty = 0

    def get(self, domain: str) -> RegistryInfo | None:
        row = self._data.get(domain)
        if not row or time.time() - row.get("_ts", 0) > self.ttl:
            return None
        info = RegistryInfo(domain=domain)
        info.registered_at = _parse_dt(row.get("registered_at"))
        info.expires_at = _parse_dt(row.get("expires_at"))
        info.updated_at = _parse_dt(row.get("updated_at"))
        info.registrar = row.get("registrar", "")
        info.status = row.get("status") or []
        info.nameservers = row.get("nameservers") or []
        info.age_days = row.get("age_days")
        info.ok = bool(row.get("ok"))
        info.error = row.get("error", "")
        return info

    def put(self, info: RegistryInfo) -> None:
        with self._lock:
            self._data[info.domain] = {**info.as_dict(), "_ts": time.time()}
            self._dirty += 1
            if self._dirty >= 100:
                self._flush()

    def _flush(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.path)
            self._dirty = 0
        except OSError:
            pass

    def flush(self) -> None:
        with self._lock:
            self._flush()


class RDAPClient:
    def __init__(self, cache_path: Path | None = None) -> None:
        self.cache = RegistryCache(cache_path or (settings.data_dir / "rdap_cache.json"))
        self._lock = threading.Lock()
        self._last = 0.0
        self.stats = {"queried": 0, "ok": 0, "failed": 0, "cached": 0}

    def _throttle(self) -> None:
        with self._lock:
            wait = 0.25 - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def lookup(self, domain: str) -> RegistryInfo:
        cached = self.cache.get(domain)
        if cached is not None:
            with self._lock:
                self.stats["cached"] += 1
            return cached

        self._throttle()
        info = RegistryInfo(domain=domain)
        tld = domain.rsplit(".", 1)[-1].lower()
        endpoints = RDAP_ENDPOINTS if tld in {"com", "net"} else RDAP_ENDPOINTS[:1]

        for tpl in endpoints:
            url = tpl.format(domain=domain)
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": UA, "Accept": "application/rdap+json"}
                )
                with urllib.request.urlopen(req, timeout=12) as r:
                    data = json.loads(r.read() or b"{}")
            except urllib.error.HTTPError as exc:
                info.error = f"HTTP {exc.code}"
                if exc.code == 404:
                    break        # 明确不存在，别再试下一个
                continue
            except Exception as exc:  # noqa: BLE001
                info.error = f"{type(exc).__name__}"
                continue

            if not isinstance(data, dict) or "errorCode" in data:
                info.error = "rdap error"
                continue

            for ev in data.get("events") or []:
                action = (ev.get("eventAction") or "").lower()
                when = _parse_dt(ev.get("eventDate"))
                if action == "registration":
                    info.registered_at = when
                elif action == "expiration":
                    info.expires_at = when
                elif action in ("last changed", "last update of rdap database"):
                    if action == "last changed":
                        info.updated_at = when

            for ent in data.get("entities") or []:
                roles = [r.lower() for r in ent.get("roles") or []]
                if "registrar" in roles:
                    vcard = ent.get("vcardArray") or []
                    name = ""
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                                name = str(item[3])
                                break
                    info.registrar = name or str(ent.get("handle") or "")[:80]

            info.status = [str(s) for s in (data.get("status") or [])][:8]
            info.nameservers = [
                str(ns.get("ldhName") or "").lower()
                for ns in (data.get("nameservers") or [])
                if ns.get("ldhName")
            ][:8]

            if info.registered_at:
                delta = datetime.utcnow() - info.registered_at
                info.age_days = max(0, delta.days)
            info.ok = True
            info.error = ""
            break

        with self._lock:
            self.stats["queried"] += 1
            if info.ok:
                self.stats["ok"] += 1
            else:
                self.stats["failed"] += 1
        self.cache.put(info)
        return info

    def lookup_many(self, domains: list[str]) -> dict[str, RegistryInfo]:
        out: dict[str, RegistryInfo] = {}
        for d in dict.fromkeys(domains):
            try:
                out[d] = self.lookup(d)
            except Exception as exc:  # noqa: BLE001
                log.debug("RDAP 查询失败 %s: %s", d, exc)
        self.cache.flush()
        return out


_rdap: RDAPClient | None = None
_lock = threading.Lock()


def get_rdap() -> RDAPClient:
    global _rdap
    if _rdap is None:
        with _lock:
            if _rdap is None:
                _rdap = RDAPClient()
    return _rdap
