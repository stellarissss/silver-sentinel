"""ICP 备案判定。

为什么单独成模块
----------------
备案状态是「境内经营性网站」与「黑产落地页」的一个强区分信号：
仿冒站几乎不可能通过备案（主体资质、域名实名、人脸核验都过不了）。
但反过来说，**没查到备案 ≠ 未备案**——工信部接口会限流、会维护，
.cn 之外的域名本来就不在库内。所以状态只有三档：

    registered   查到备案（附主体与备案号，可直接写进举报材料）
    unregistered 明确查无此站（接口正常返回空）
    unknown      没查或查不了（接口不可用 / 网络不通 / 超限）

把 unknown 当成 unregistered 是最容易犯的错，会让研判偏严、举报材料失实。

接口兼容
--------
对接 ICP_Query / ICP_Query_lite / ICPQuery-MCP 的 HTTP 模式，统一走
    GET {base}/query/web?search=<domain>
它们返回的 JSON 结构不完全一致，这里做宽松解析，只取我们需要的四个字段。

使用约束
--------
- 令牌桶限速，默认 10 次/分钟。工信部接口对频率极敏感，扫快了直接封 IP。
- 只对指定分级的目标查询（默认 candidate 以上），不无差别扫。
- 结果缓存 30 天，避免重复打。
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from ..config import settings
from ..db import session_scope
from ..models import ICPCache

log = logging.getLogger(__name__)

UA = "Mozilla/5.0 (compatible; silver-sentinel/1.0)"


@dataclass(slots=True)
class ICPResult:
    domain: str
    status: str = "unknown"          # registered | unregistered | unknown
    license: str = ""
    entity: str = ""
    nature: str = ""
    detail: list[dict] = field(default_factory=list)
    error: str = ""
    from_cache: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status,
            "license": self.license,
            "entity": self.entity,
            "nature": self.nature,
            "error": self.error,
            "from_cache": self.from_cache,
        }


# 各家实现可能用的字段名，按优先级排列
_FIELD_ALIASES = {
    "domain": ("domain", "domainName", "webSite", "website", "homepage", "ym"),
    "entity": ("unitName", "unit_name", "companyName", "company", "entityName", "主体名称", "主办单位名称"),
    "license": ("icpCode", "icp_code", "license", "code", "备案号", "mainLicence"),
    "nature": ("nature", "natureName", "unitNature", "性质", "主办单位性质"),
}


def _pick(row: dict, key: str) -> str:
    for alias in _FIELD_ALIASES[key]:
        value = row.get(alias)
        if value:
            return str(value).strip()
    return ""


def _iter_records(payload: Any) -> list[dict]:
    """把各家五花八门的响应摊平成记录列表。"""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if not isinstance(payload, dict):
        return []

    for key in ("data", "result", "results", "list", "records", "rows", "items"):
        node = payload.get(key)
        if isinstance(node, list):
            return [r for r in node if isinstance(r, dict)]
        if isinstance(node, dict):
            for sub in ("list", "records", "rows", "items", "data"):
                inner = node.get(sub)
                if isinstance(inner, list):
                    return [r for r in inner if isinstance(r, dict)]
            return [node]
    return []


class RateLimiter:
    """令牌桶。跨线程共享，保证总速率不超。"""

    def __init__(self, per_minute: int) -> None:
        self.capacity = max(1, per_minute)
        self.tokens = float(self.capacity)
        self.rate = self.capacity / 60.0
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self._last) * self.rate)
                self._last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
                need = (1.0 - self.tokens) / self.rate
            if time.monotonic() + need > deadline:
                return False
            time.sleep(min(need, 1.0))


class ICPClient:
    def __init__(self) -> None:
        self.base = settings.icp_api_base
        self.limiter = RateLimiter(settings.icp_rate_per_minute)
        self.stats = {"queried": 0, "registered": 0, "unregistered": 0, "unknown": 0, "cached": 0, "throttled": 0}
        self._lock = threading.Lock()
        self.available: bool | None = None
        self.last_error = ""

    # ------------------------------------------------------------ 缓存
    @staticmethod
    def _cache_get(domain: str) -> ICPResult | None:
        if settings.icp_cache_days <= 0:
            return None
        try:
            with session_scope() as session:
                row = session.scalar(select(ICPCache).where(ICPCache.domain == domain))
                if not row:
                    return None
                if datetime.utcnow() - row.checked_at > timedelta(days=settings.icp_cache_days):
                    return None
                return ICPResult(
                    domain=domain,
                    status=row.status,
                    license=row.license,
                    entity=row.entity,
                    nature=row.nature,
                    from_cache=True,
                )
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _cache_put(res: ICPResult) -> None:
        # unknown 不缓存：下次可能就能查了
        if res.status == "unknown":
            return
        try:
            with session_scope() as session:
                row = session.scalar(select(ICPCache).where(ICPCache.domain == res.domain))
                if row:
                    row.status = res.status
                    row.license = res.license
                    row.entity = res.entity
                    row.nature = res.nature
                    row.checked_at = datetime.utcnow()
                else:
                    session.add(
                        ICPCache(
                            domain=res.domain,
                            status=res.status,
                            license=res.license,
                            entity=res.entity,
                            nature=res.nature,
                            checked_at=datetime.utcnow(),
                        )
                    )
        except Exception as exc:  # noqa: BLE001
            log.debug("ICP 缓存写入失败：%s", exc)

    # ------------------------------------------------------------ 查询
    def probe_service(self) -> bool:
        """探一下本地服务在不在。避免每个域名都白等一次超时。"""
        if not self.base:
            self.available = False
            self.last_error = "未配置 SILVER_ICP_API"
            return False
        url = f"{self.base}/query/web?search={urllib.parse.quote('baidu.com')}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=min(15.0, settings.icp_timeout)) as r:
                r.read(2048)
            self.available = True
            self.last_error = ""
            return True
        except Exception as exc:  # noqa: BLE001
            self.available = False
            self.last_error = f"{type(exc).__name__}: {str(exc)[:120]}"
            return False

    def lookup(self, domain: str, *, use_cache: bool = True) -> ICPResult:
        if use_cache:
            cached = self._cache_get(domain)
            if cached is not None:
                with self._lock:
                    self.stats["cached"] += 1
                return cached

        # 必须先看「服务地址配了没有」。只看开关会导致：ICP 没配，但每次查询
        # 仍然去令牌桶排队（默认 10 次/分钟 = 每个域等 6 秒），整条富化流水线被拖死。
        if not settings.icp_ready:
            return ICPResult(
                domain=domain,
                status="unknown",
                error="备案查询未配置（SILVER_ICP_API 为空）" if settings.icp_enabled else "备案查询未启用",
            )
        if self.available is False:
            return ICPResult(domain=domain, status="unknown", error=self.last_error or "服务不可用")

        if not self.limiter.acquire(timeout=20.0):
            with self._lock:
                self.stats["throttled"] += 1
            return ICPResult(domain=domain, status="unknown", error="限流等待超时")

        url = f"{self.base}/query/web?search={urllib.parse.quote(domain)}"
        res = ICPResult(domain=domain)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=settings.icp_timeout) as r:
                payload = json.loads(r.read() or b"null")
            records = _iter_records(payload)

            if not records:
                res.status = "unregistered"
            else:
                # 只保留与本域名直接相关的记录，避免「按主体名搜索」带回一堆无关站点
                matched = []
                for row in records:
                    row_domain = _pick(row, "domain").lower()
                    if not row_domain or domain.lower() in row_domain or row_domain in domain.lower():
                        matched.append(row)
                if not matched:
                    res.status = "unregistered"
                else:
                    best = matched[0]
                    res.status = "registered"
                    res.license = _pick(best, "license")
                    res.entity = _pick(best, "entity")
                    res.nature = _pick(best, "nature")
                    res.detail = matched[:5]
            res.error = ""
        except urllib.error.HTTPError as exc:
            res.error = f"HTTP {exc.code}"
            if exc.code in (401, 403, 429):
                self.available = False
                self.last_error = res.error
        except Exception as exc:  # noqa: BLE001
            res.error = f"{type(exc).__name__}: {str(exc)[:100]}"

        with self._lock:
            self.stats["queried"] += 1
            self.stats[res.status] = self.stats.get(res.status, 0) + 1
        if res.status != "unknown":
            self._cache_put(res)
        return res

    def status(self) -> dict[str, Any]:
        return {
            "enabled": settings.icp_enabled,
            "api_base": self.base or "(未配置)",
            "available": self.available,
            "last_error": self.last_error,
            "rate_per_minute": settings.icp_rate_per_minute,
            "cache_days": settings.icp_cache_days,
            "stats": self.stats,
        }


_client: ICPClient | None = None
_lock = threading.Lock()


def get_icp() -> ICPClient:
    global _client
    if _client is None:
        with _lock:
            if _client is None:
                _client = ICPClient()
    return _client
