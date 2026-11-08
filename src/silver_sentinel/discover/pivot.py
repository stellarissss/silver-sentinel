"""同源扩散：从一个已确认的站，带出一窝。

为什么这层是「广泛」的关键
--------------------------
实测（2026-11-08）：`l4k9j.com.cn` 的一张证书里签了 **30 个域名**——

    a7k2m.com.cn  b3t8n.com.cn  c2r7h.com.cn  ...  z7x4c.com.cn

全部是同一个生成器吐出来的随机串，全部 `.com.cn`，同一天签发。
这 30 个域名在本系统的生产库里**一条记录都没有**——不是判不出来，是从没
看见过。域名里没有词，词库必然打空；CT 流就算扫到，也会当成噪声丢掉。

但只要有任何一条线索碰到其中**一个**（举报、urlscan、同 IP、人工录入），
证书就能把剩下 29 个一起交出来。所以这里的投入产出比是 1:30，而不是 1:1。

三个维度，可靠性递减
--------------------
1. **同证书**（cert_sibling）：一次签发覆盖整个批次。骗子不会给每个域名
   单独买证书——多域名证书更便宜。这条最硬。
2. **同 IP**（same_ip）：同一台 VPS 上放了同批货。会被共享主机稀释，所以
   共享设施（CDN/云厂商）一律排除。
3. **同注册商+同 NS+短期注册**：弱信号，交给图聚类，不在这里做。

限流
----
CertSpotter 免费额度 100 次/小时；urlscan 60 次/分钟。
扩散是「有空才做」的后台任务，宁可慢，不能把额度烧光——发现主路（CT）
还要靠这些源兜底。
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger(__name__)

# CertSpotter 免费额度按小时重置；留 20% 余量给手工排查
CERTSPOTTER_HOURLY = 80
URLSCAN_HOURLY = 240

_UA = "silver-sentinel/1.x (+threat-research)"


@dataclass(slots=True)
class PivotHit:
    domain: str
    source: str          # cert_sibling | same_ip
    origin: str          # 从哪个资产扩散出来的
    detail: str = ""     # 人话说明，落进 discovery_reason

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "source": self.source,
            "origin": self.origin,
            "detail": self.detail[:200],
        }


class _TokenBucket:
    """按小时的简单配额。不做精确令牌桶——丢一两次比打死源划算。"""

    def __init__(self, per_hour: int) -> None:
        self.per_hour = max(1, per_hour)
        self._lock = threading.Lock()
        self._window_start = 0.0
        self._used = 0

    def take(self, n: int = 1) -> bool:
        with self._lock:
            now = time.time()
            if now - self._window_start >= 3600:
                self._window_start = now
                self._used = 0
            if self._used + n > self.per_hour:
                return False
            self._used += n
            return True

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            left = max(0, self.per_hour - self._used)
            return {"per_hour": self.per_hour, "used": self._used, "left": left}


def _clean_names(names: list[str], *, origin: str) -> list[str]:
    """证书里的 name_value 是一坨换行分隔的文本，且常含通配符与重复。"""
    out: list[str] = []
    seen: set[str] = set()
    for raw in names:
        for part in str(raw).replace(",", "\n").split("\n"):
            host = part.strip().lower().lstrip("*.").strip(".")
            if not host or "." not in host or " " in host:
                continue
            if host == origin or host in seen:
                continue
            if host.endswith(".local") or host.endswith(".internal"):
                continue
            seen.add(host)
            out.append(host)
    return out


class CertSpotterSource:
    """证书反查。返回「和这个域名共用过一张证书」的其他域名。

    为什么不用 crt.sh：实测 .cn 域名在 crt.sh 上经常查不到（`l4k9j.com.cn`
    返回 0 条），而 CertSpotter 直接从 CT 日志取，同一次签发能拿到全部 30 个
    SAN。对国内站群来说差别是「全有」和「全无」。
    """

    BASE = "https://api.certspotter.com/v1/issuances"
    NAME = "cert_sibling"

    def __init__(self, *, timeout: float = 20.0, bucket: _TokenBucket | None = None) -> None:
        self.timeout = timeout
        self.bucket = bucket or _TokenBucket(CERTSPOTTER_HOURLY)

    def lookup(self, domain: str, *, days: int = 400) -> list[PivotHit]:
        domain = (domain or "").lower().strip(".")
        if not domain or "." not in domain:
            return []
        if not self.bucket.take():
            log.debug("certspotter 配额用尽，跳过 %s", domain)
            return []
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(
                    self.BASE,
                    params={
                        "domain": domain,
                        "include_subdomains": "true",
                        "expand": "dns_names",
                        "match_wildcards": "true",
                    },
                    headers={"User-Agent": _UA},
                )
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:  # noqa: BLE001 一个源挂了不影响别的维度
            log.debug("certspotter 查询失败 %s：%s", domain, exc)
            return []

        hits: list[PivotHit] = []
        seen: set[str] = set()
        for item in payload if isinstance(payload, list) else []:
            issue = str(item.get("not_before") or "")[:10]
            names = _clean_names(item.get("dns_names") or [], origin=domain)
            # 一个证书带 30 个域名是站群；带 500 个是共享证书/云平台，不能用
            if len(names) > 60:
                continue
            for host in names:
                if host in seen:
                    continue
                seen.add(host)
                hits.append(
                    PivotHit(
                        domain=host,
                        source=self.NAME,
                        origin=domain,
                        detail=f"与 {domain} 共用证书（签发于 {issue or '未知'}，共 {len(names) + 1} 个域名）",
                    )
                )
        return hits


class UrlscanSameIP:
    """urlscan 按 IP 反查：这台服务器上还被扫过哪些页面。

    覆盖面小（只含被 urlscan 扫过的），但零误报——它说的是「这个 IP 上确实
    有这个站」，不是推测。
    """

    BASE = "https://urlscan.io/api/v1/search/"
    NAME = "same_ip"

    def __init__(self, *, timeout: float = 25.0, bucket: _TokenBucket | None = None) -> None:
        self.timeout = timeout
        self.bucket = bucket or _TokenBucket(URLSCAN_HOURLY)

    def lookup(self, ip: str, *, origin: str = "", size: int = 100) -> list[PivotHit]:
        ip = (ip or "").strip()
        if not ip or "." not in ip:
            return []
        if not self.bucket.take():
            return []
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(
                    self.BASE,
                    params={"q": f'page.ip:"{ip}"', "size": min(size, 100)},
                    headers={"User-Agent": _UA},
                )
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            log.debug("urlscan IP 反查失败 %s：%s", ip, exc)
            return []

        hits: list[PivotHit] = []
        seen: set[str] = set()
        for item in payload.get("results") or []:
            page = item.get("page") or {}
            host = (page.get("domain") or "").lower().strip(".")
            if not host or host == origin or host in seen:
                continue
            seen.add(host)
            hits.append(
                PivotHit(
                    domain=host,
                    source=self.NAME,
                    origin=origin or ip,
                    detail=f"与 {origin or ip} 同服务器（{ip}）：{(page.get('title') or '')[:40]}",
                )
            )
        return hits


class PivotEngine:
    """把两个维度串起来，并挡住明显的垃圾。"""

    def __init__(
        self,
        *,
        cert_source: CertSpotterSource | None = None,
        ip_source: UrlscanSameIP | None = None,
    ) -> None:
        self.cert = cert_source or CertSpotterSource()
        self.ip = ip_source or UrlscanSameIP()
        self.stats = {"calls": 0, "hits": 0, "skipped": 0, "errors": 0}

    def expand(
        self, domain: str, *, ips: list[str] | None = None, use_ip: bool = True
    ) -> list[PivotHit]:
        """对一个域名做全维度扩散。返回去重后的候选域名。"""
        from ..normalize import is_pivot_noise

        domain = (domain or "").lower().strip(".")
        if not domain:
            return []
        self.stats["calls"] += 1

        raw: list[PivotHit] = []
        try:
            raw.extend(self.cert.lookup(domain))
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            log.debug("证书扩散失败 %s：%s", domain, exc)

        if use_ip:
            for ip in (ips or [])[:2]:
                try:
                    raw.extend(self.ip.lookup(ip, origin=domain))
                except Exception as exc:  # noqa: BLE001
                    self.stats["errors"] += 1
                    log.debug("IP 扩散失败 %s：%s", ip, exc)

        out: list[PivotHit] = []
        seen: set[str] = set()
        for hit in raw:
            host = hit.domain
            if host == domain or host in seen:
                continue
            if is_pivot_noise(host):
                self.stats["skipped"] += 1
                continue
            seen.add(host)
            out.append(hit)
        self.stats["hits"] += len(out)
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.stats,
            "cert_budget": self.cert.bucket.as_dict(),
            "ip_budget": self.ip.bucket.as_dict(),
        }
