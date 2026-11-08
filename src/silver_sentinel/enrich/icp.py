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
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from ..config import settings
from ..db import session_scope
from ..models import ICPCache

log = logging.getLogger(__name__)

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


@dataclass(slots=True)
class ICPResult:
    domain: str
    status: str = "unknown"          # registered | unregistered | unknown
    license: str = ""
    entity: str = ""
    nature: str = ""
    # 违法违规名单：listed | clean | unknown
    # 这是工信部自己的黑名单，比「有没有备案」更强——备案了也可能被列管。
    violation: str = "unknown"
    violation_title: str = ""
    black_level: int = -1
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
            "violation": self.violation,
            "violation_title": self.violation_title,
            "black_level": self.black_level,
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

    for key in ("data", "result", "results", "list", "records", "rows", "items", "params"):
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


def _payload_error(payload: Any) -> str:
    """接口层失败与「查无此站」必须分开。

    ICP_Query 正常返回 {code:200, success:true, params:{list:[...]}}；
    风控、验证码打挂、上游维护时会给非 200 的 code 或 success=false。
    这类响应如果按「空列表 = 未备案」处理，会把一次接口故障变成一批
    「未备案」结论，直接污染研判与举报材料。
    """
    if not isinstance(payload, dict):
        return "响应不是 JSON 对象"
    if payload.get("success") is False:
        code = payload.get("code")
        msg = str(payload.get("msg") or "接口返回 success=false")[:120]
        return f"code={code}：{msg}" if code is not None else msg
    code = payload.get("code")
    if code is not None:
        try:
            if int(code) not in (0, 200):
                return f"接口返回 code={code}：{str(payload.get('msg') or '')[:80]}"
        except (TypeError, ValueError):
            return f"接口返回非数字 code={code!r}"
    if "params" not in payload and "data" not in payload and "result" not in payload:
        return "响应缺少 params/data 字段"
    return ""


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
        # 工信部有 IP 级风控：短时间十来次查询就会 403（实测 2026-11-05）。
        # 连续失败到阈值就整体冷却，宁可这批不查，也不要把出口 IP 彻底打黑。
        self._consecutive_failures = 0
        self._blocked_until = 0.0
        self._max_failures = settings.icp_max_failures
        self._cooldown = settings.icp_cooldown_seconds

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
                    violation=getattr(row, "violation", "") or "unknown",
                    violation_title=getattr(row, "violation_title", "") or "",
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
                    row.violation = res.violation
                    row.violation_title = res.violation_title
                    row.checked_at = datetime.utcnow()
                else:
                    session.add(
                        ICPCache(
                            domain=res.domain,
                            status=res.status,
                            license=res.license,
                            entity=res.entity,
                            nature=res.nature,
                            violation=res.violation,
                            violation_title=res.violation_title,
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
        if time.monotonic() < self._blocked_until:
            return ICPResult(
                domain=domain,
                status="unknown",
                error=f"接口风控冷却中，还剩 {int(self._blocked_until - time.monotonic())} 秒",
            )

        if not self.limiter.acquire(timeout=20.0):
            with self._lock:
                self.stats["throttled"] += 1
            return ICPResult(domain=domain, status="unknown", error="限流等待超时")

        url = f"{self.base}/query/web?search={urllib.parse.quote(domain)}"
        res = ICPResult(domain=domain)
        try:
            payload = self._get(url)
            failure = _payload_error(payload)
            if failure:
                # 关键区别：接口说「查完了没有」和接口自己出错，是两件事。
                # 把后者当 unregistered 会让研判凭空变严，举报材料也会失实。
                res.error = failure
                res.status = "unknown"
            else:
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

        if res.status == "unknown" and not res.error:
            res.error = "响应无法判定"

        # 明确的风控信号（创宇盾拦截 / 403）要立刻长时间冷却：
        # 2026-11-05 实测，40/分钟的批次跑十几条就被「当前访问已被创宇盾拦截」。
        if res.error and ("拦截" in res.error or "403" in res.error):
            self._blocked_until = time.monotonic() + max(self._cooldown, 3600.0)
            self.last_error = "出口 IP 已被工信部风控拦截，冷却 1 小时以上"
            log.warning("ICP 出口被封：%s", res.error)

        # 连续 unknown 视为风控：整体冷却，避免把出口 IP 打到永久封禁
        if res.status == "unknown":
            self._consecutive_failures += 1
            if self._consecutive_failures >= self._max_failures:
                self._blocked_until = time.monotonic() + self._cooldown
                self.last_error = f"连续 {self._consecutive_failures} 次失败，冷却 {self._cooldown:.0f} 秒"
                log.warning("ICP 连续失败，进入冷却：%s", res.error)
        else:
            self._consecutive_failures = 0

        if settings.icp_violation_check and res.status != "unknown" and res.error == "":
            if self.limiter.acquire(timeout=10.0):
                viol = self._check_violation(domain)
                res.violation = viol.get("violation", "unknown")
                res.violation_title = viol.get("title", "")
                res.black_level = int(viol.get("level", -1))

        with self._lock:
            self.stats["queried"] += 1
            self.stats[res.status] = self.stats.get(res.status, 0) + 1
            if res.violation == "listed":
                self.stats["violation"] = self.stats.get("violation", 0) + 1
        if res.status != "unknown":
            self._cache_put(res)
        return res

    # ------------------------------------------------------------ 备案号反查
    @staticmethod
    def normalize_license(value: str) -> str:
        return re.sub(r"\s+", "", (value or "")).replace("－", "-")

    def license_owners(self, license: str, *, limit: int = 20) -> list[str]:
        """本地缓存里，这个备案号挂在哪些域名下。

        诈骗站会伪造备案号：实测 `np4w53.cn` 与 `hksm38.com.cn` 两个不同域名
        共用「京ICP备202600001号-1」，而且页面 JS 用 `Math.random()` 现生成。
        查「域名有没有备案」永远只能得到「没有」，和亿万没备案的域名混在一起；
        查「这个号属于谁」才能一击命中伪造。

        只读本地缓存，不联网——取证线程不能被一次 30 秒的验证码识别拖住。
        联网版是 `lookup_license()`，给 CLI 的离线回填用。
        """
        lic = self.normalize_license(license)
        if not lic:
            return []
        try:
            with session_scope() as s:
                rows = s.execute(
                    select(ICPCache.domain)
                    .where(func.replace(ICPCache.license, " ", "") == lic)
                    .limit(limit)
                ).all()
                return [r[0] for r in rows if r[0]]
        except Exception as exc:  # noqa: BLE001 缓存坏了不能影响判定
            log.debug("备案号缓存查询失败：%s", exc)
            return []

    def lookup_license(self, license: str) -> dict[str, Any]:
        """按备案号联网反查归属域名。给 `silver-sentinel icp --license` 用。"""
        lic = self.normalize_license(license)
        out: dict[str, Any] = {"license": lic, "domains": [], "status": "unknown", "error": ""}
        if not lic:
            out["error"] = "备案号为空"
            return out
        if not settings.icp_ready:
            out["error"] = "未配置 SILVER_ICP_API"
            return out
        if not self.limiter.acquire(timeout=20.0):
            out["error"] = "限流等待超时"
            return out
        try:
            payload = self._get(f"{self.base}/query/web?search={urllib.parse.quote(lic)}")
            failure = _payload_error(payload)
            if failure:
                out["error"] = failure
                return out
            domains: list[str] = []
            for row in _iter_records(payload):
                d = _pick(row, "domain").lower()
                if d and d not in domains:
                    domains.append(d)
            for d in domains:
                self._cache_put(
                    ICPResult(domain=d, status="registered", license=lic,
                              entity=_pick(_iter_records(payload)[0], "entity") if domains else "")
                )
            out["domains"] = domains
            out["status"] = "registered" if domains else "unregistered"
        except urllib.error.HTTPError as exc:
            out["error"] = f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001
            out["error"] = f"{type(exc).__name__}: {str(exc)[:100]}"
        return out

    # ------------------------------------------------------------ 违法违规名单
    def _check_violation(self, domain: str) -> dict[str, Any]:
        """工信部「违法违规域名」查询。

        blackListLevel 语义（见 ICP_Query 文档）：2 = 暂无违法违规信息，<2 = 有。
        title 在命中时是处置标题。两者都拿不到就保持 unknown，不猜。
        """
        url = f"{self.base}/query/bweb?search={urllib.parse.quote(domain)}"
        try:
            payload = self._get(url)
            if _payload_error(payload):
                return {}
            params = payload.get("params") if isinstance(payload, dict) else None
            if not isinstance(params, dict):
                return {}
            level = params.get("blackListLevel")
            title = str(params.get("title") or "").strip()
            try:
                level = int(level)
            except (TypeError, ValueError):
                level = -1
            if level < 0:
                return {}
            listed = level < 2 or bool(title)
            return {
                "violation": "listed" if listed else "clean",
                "title": title[:200],
                "level": level,
            }
        except Exception as exc:  # noqa: BLE001
            log.debug("违法违规查询失败 %s：%s", domain, exc)
            return {}

    def _get(self, url: str) -> Any:
        req = urllib.request.Request(
            url, headers={"User-Agent": UA, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=settings.icp_timeout) as r:
            return json.loads(r.read() or b"null")

    def status(self) -> dict[str, Any]:
        return {
            "enabled": settings.icp_enabled,
            "api_base": self.base or "(未配置)",
            "available": self.available,
            "last_error": self.last_error,
            "rate_per_minute": settings.icp_rate_per_minute,
            "cooldown_remaining": max(0, int(self._blocked_until - time.monotonic())),
            "consecutive_failures": self._consecutive_failures,
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
