"""DNS 排列探测：不依赖任何外部情报源的自主发现。

为什么需要它
------------
CT 流能覆盖「随机命名」的域名，但依赖外部服务可用性；而骗子起名有很强的
惯性——「国惠民生」「中科养老」「乡村振兴惠民」这类词根组合占了大头。
我们把这些组合全部枚举出来做 DNS 探测，等于自己造了一个不依赖别人的探针。

代价与控制
----------
- 只查 DNS，不查 HTTP。DNS 查询轻、不进对方日志、不触发 WAF。
- 严格限速（默认 25 QPS），轮询多个公共解析器，避免单点被运营商限流。
- 结果持久化缓存，同一域名 7 天内不重复查。
- 有 NS 或 A 记录才算「存在」，NXDOMAIN 直接丢弃。

这条路径的产出会全部进候选池，不做判定——判定交给评分引擎。
"""

from __future__ import annotations

import logging
import random
import threading
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver

from ..config import settings
from ..discover.keywords import CLUSTERS, get_library

log = logging.getLogger(__name__)

# 高频滥用于诈骗站的 TLD（按公开滥用量统计排序），加上主流 TLD 兜底
TLDS_ABUSED = [".top", ".xyz", ".cn", ".cc", ".vip", ".shop", ".site", ".online", ".club", ".icu", ".buzz", ".cyou"]
TLDS_COMMON = [".com", ".net", ".org", ".info", ".wang", ".xin", ".ltd", ".work", ".live", ".fun"]

# 公共解析器轮换。国内三家 + 国际两家，避免单点限流。
RESOLVERS = ["223.5.5.5", "119.29.29.29", "180.76.76.76", "1.1.1.1", "8.8.8.8"]

# 组合词根时只取这些簇，且每个簇限制数量，防止组合爆炸
_SEED_CLUSTERS = ("authority", "scam_signature", "inducement")
_MAX_SEEDS_PER_CLUSTER = 60

# 自动淘汰：长期命中但从没被判成可疑的词，不再拿去探测。
# 注意只影响「探测与组合」，不影响匹配——历史资产仍要能被重新识别。
_SUPPRESS_CACHE: tuple[float, set[str]] = (0.0, set())
_SUPPRESS_TTL = 3600


def _suppressed_terms() -> set[str]:
    global _SUPPRESS_CACHE
    now = time.time()
    ts, cached = _SUPPRESS_CACHE
    if now - ts < _SUPPRESS_TTL:
        return cached
    out: set[str] = set()
    try:
        from sqlalchemy import select

        from ..db import session_scope
        from ..models import KeywordHit

        with session_scope() as s:
            for row in s.scalars(select(KeywordHit).where(KeywordHit.hits >= 25)):
                if (row.dismissed or 0) / max(1, row.hits) >= 0.8:
                    out.add(row.term)
    except Exception:  # noqa: BLE001
        pass
    _SUPPRESS_CACHE = (now, out)
    return out


@dataclass(slots=True)
class ProbeResult:
    domain: str
    exists: bool
    a_records: list[str]
    ns_records: list[str]
    cname: str
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "exists": self.exists,
            "a": self.a_records,
            "ns": self.ns_records,
            "cname": self.cname,
            "error": self.error,
        }


class DNSCache:
    """极简磁盘缓存：域名 -> (结果, 时间戳)。"""

    def __init__(self, path: Path, ttl_days: int = 7) -> None:
        self.path = path
        self.ttl = ttl_days * 86400
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        self._dirty = 0
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            import json

            self._data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            self._data = {}

    def get(self, domain: str) -> ProbeResult | None:
        row = self._data.get(domain)
        if not row:
            return None
        if time.time() - row.get("ts", 0) > self.ttl:
            return None
        return ProbeResult(
            domain=domain,
            exists=bool(row.get("exists")),
            a_records=row.get("a") or [],
            ns_records=row.get("ns") or [],
            cname=row.get("cname") or "",
            error=row.get("error", ""),
        )

    def put(self, result: ProbeResult) -> None:
        with self._lock:
            self._data[result.domain] = {
                "exists": result.exists,
                "a": result.a_records,
                "ns": result.ns_records,
                "cname": result.cname,
                "error": result.error,
                "ts": time.time(),
            }
            self._dirty += 1
            if self._dirty >= 200:
                self._flush()

    def _flush(self) -> None:
        import json

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

    def reverse(self, ip: str) -> list[str]:
        """本地被动 DNS：缓存里有哪些域名解析到了这个 IP。

        这是「不花钱的同源调查」——我们为了别的目的查过的 DNS，
        反过来就是一张「谁和谁同服务器」的表。比任何外部反查 API 都稳，
        因为它只包含我们亲眼见过的事实。
        """
        ip = (ip or "").strip()
        if not ip:
            return []
        out: list[str] = []
        now = time.time()
        for domain, row in self._data.items():
            if now - row.get("ts", 0) > self.ttl:
                continue
            if ip in (row.get("a") or []):
                out.append(domain)
        return out

    def __len__(self) -> int:
        return len(self._data)


class DNSProbe:
    def __init__(self, cache_path: Path | None = None, *, qps: float = 30.0, workers: int = 16) -> None:
        self.cache = DNSCache(cache_path or (settings.data_dir / "dns_cache.json"))
        self.qps = qps
        self.workers = workers
        self._resolver_pool = self._build_pool()
        self._lock = threading.Lock()
        self._last_query = 0.0
        self.stats = {"queried": 0, "exists": 0, "nxdomain": 0, "error": 0, "cached": 0}
        self.resolver_health: list[dict] = []

    @staticmethod
    def _build_pool() -> list[dns.resolver.Resolver]:
        """健康检查：连不上的解析器直接剔除。

        不做这步的话，random.choice 会时不时选中一个黑洞服务器，
        整个探测吞吐被拖到原来的十分之一——这是实测踩过的坑。
        """
        pool: list[dns.resolver.Resolver] = []
        health: list[dict] = []
        for addr in RESOLVERS:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = [addr]
            r.timeout = 1.2
            r.lifetime = 2.0
            r.retry_servfail = False
            t0 = time.monotonic()
            ok = False
            try:
                r.resolve("www.baidu.com", "A", lifetime=2.0)
                ok = True
            except Exception:  # noqa: BLE001
                ok = False
            latency = round((time.monotonic() - t0) * 1000)
            health.append({"server": addr, "ok": ok, "ms": latency})
            if ok:
                pool.append(r)
        if not pool:
            # 全挂时退回系统默认，至少还能查
            r = dns.resolver.Resolver()
            r.timeout = 2.0
            r.lifetime = 3.0
            pool.append(r)
            health.append({"server": "system", "ok": True, "ms": 0})
        DNSProbe.resolver_health = health
        return pool

    def _throttle(self) -> None:
        """全局令牌间隔。多线程共享，保证总 QPS 不超。"""
        with self._lock:
            now = time.monotonic()
            wait = (1.0 / self.qps) - (now - self._last_query)
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._last_query = now

    def query(self, domain: str) -> ProbeResult:
        cached = self.cache.get(domain)
        if cached is not None:
            with self._lock:
                self.stats["cached"] += 1
            return cached

        self._throttle()
        resolver = random.choice(self._resolver_pool)
        a: list[str] = []
        ns: list[str] = []
        cname = ""
        err = ""

        try:
            ans = resolver.resolve(domain, "A", raise_on_no_answer=False)
            if ans.rrset:
                a = [str(r.address) for r in ans.rrset][:8]
        except dns.resolver.NXDOMAIN:
            result = ProbeResult(domain, False, [], [], "")
            with self._lock:
                self.stats["queried"] += 1
                self.stats["nxdomain"] += 1
            self.cache.put(result)
            return result
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.NoAnswer) as exc:
            err = type(exc).__name__
        except Exception as exc:  # noqa: BLE001
            err = type(exc).__name__

        # 没有 A 记录不代表不存在：查 NS 判断是否已托管
        if not a:
            try:
                ans = resolver.resolve(domain, "NS", raise_on_no_answer=False)
                if ans.rrset:
                    ns = [str(r.target).rstrip(".") for r in ans.rrset][:6]
            except Exception:  # noqa: BLE001
                pass

        if not a:
            try:
                ans = resolver.resolve(domain, "CNAME", raise_on_no_answer=False)
                if ans.rrset:
                    cname = str(list(ans.rrset)[0].target).rstrip(".")
            except Exception:  # noqa: BLE001
                pass

        exists = bool(a or ns or cname)
        result = ProbeResult(domain, exists, a, ns, cname, err)
        self.cache.put(result)
        with self._lock:
            self.stats["queried"] += 1
            if exists:
                self.stats["exists"] += 1
            elif err:
                self.stats["error"] += 1
        return result

    def probe_many(self, domains: Iterable[str]) -> list[ProbeResult]:
        targets = [d for d in dict.fromkeys(domains) if d]
        if not targets:
            return []
        out: list[ProbeResult] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for res in pool.map(self.query, targets):
                if res.exists:
                    out.append(res)
        self.cache.flush()
        return out


# ---------------------------------------------------------------- 词根生成


class SeedGenerator:
    """从词库派生可探测的域名词根。

    - 单词根：拼音形式，如 guohui / zhongke / yanglao
    - 双词组合：取两个高频词拼接，如 guohuiminsheng / zhongkekangyang
    - 机构缩写 + 主题词：gh + yanglao

    每轮返回一段切片，由调用方轮转，避免一次性打爆 DNS。
    """

    def __init__(self) -> None:
        self.seeds: list[tuple[str, str]] = []      # (词根, 来源说明)
        self._build()

    def _build(self) -> None:
        from pypinyin import lazy_pinyin

        lib = get_library()
        seen: set[str] = set()
        suppressed = _suppressed_terms()

        primary: list[tuple[str, str]] = []
        secondary: list[tuple[str, str]] = []

        for cluster in _SEED_CLUSTERS:
            terms = [t for t in lib.terms if t.cluster == cluster and not t.weak_only]
            terms.sort(key=lambda t: -t.weight)
            for term in terms[:_MAX_SEEDS_PER_CLUSTER]:
                py = term.pinyin
                if len(py) < 4 or py in seen:
                    continue
                if term.text in suppressed:
                    # 长期误报的词不再拿去探测：省 DNS 配额，也少一批噪声
                    continue
                seen.add(py)
                primary.append((py, term.text))
                secondary.append((py, term.text))

        # 双词组合：机构词 + 主题词，这是骗子最常见的命名结构
        authority = [p for c, ts in CLUSTERS.items() if c == "authority" for p in ts][:25]
        themes = [p for c, ts in CLUSTERS.items() if c in ("policy_theme", "inducement") for p in ts][:40]
        for a in authority:
            pa = "".join(lazy_pinyin(a))
            if len(pa) < 4:
                continue
            for t in themes[:12]:
                pt = "".join(lazy_pinyin(t))
                if len(pt) < 4:
                    continue
                combo = pa + pt
                if len(combo) > 28 or combo in seen:
                    continue
                seen.add(combo)
                secondary.append((combo, f"{a}+{t}"))

        # 地区 + 主题：骗子极爱用「河北惠民」「河南养老」这种地名背书。
        # 地区拼音单独匹配会误报（hebei 出现在大量正常域名里），但作为
        # 组合词根去 DNS 探测是安全的——探不到就没有成本。
        from .keywords import COMBINE_SUFFIXES, REGIONS

        regions = ["".join(lazy_pinyin(r)) for r in REGIONS][:48]
        theme_terms = [
            p
            for c, ts in CLUSTERS.items()
            if c in ("policy_theme", "elder_care", "project_scam")
            for p in ts
        ][:40]
        for idx, region in enumerate(regions):
            if len(region) < 4:
                continue
            # 每个省只取 6 个主题，轮换起点不同，避免全国都用同一批词
            window = theme_terms[idx % 7: idx % 7 + 6]
            for term in window:
                pt = "".join(lazy_pinyin(term))
                if len(pt) < 4:
                    continue
                combo = region + pt
                if len(combo) > 26 or combo in seen:
                    continue
                seen.add(combo)
                secondary.append((combo, f"{region}+{term}"))

        # 主题 + 通用后缀：「××惠民」「××民生」是最常见的招牌写法
        suffixes = ["".join(lazy_pinyin(s)) for s in COMBINE_SUFFIXES][:20]
        for idx, term in enumerate(theme_terms[:12]):
            pt = "".join(lazy_pinyin(term))
            if len(pt) < 4:
                continue
            for suffix in suffixes[idx % 5: idx % 5 + 5]:
                combo = pt + suffix
                if len(combo) > 26 or combo in seen:
                    continue
                seen.add(combo)
                secondary.append((combo, f"{term}+{suffix}"))

        # 数字变体：guohui2026 / guohui88 / guohuivip。
        # 团伙换域时经常只在后面加个年份或吉祥数字，成本最低。
        for seed, origin in list(primary)[:100]:
            for tail in ("2026", "88", "vip"):
                combo = seed + tail
                if combo in seen:
                    continue
                seen.add(combo)
                secondary.append((combo, f"{origin}（数字变体）"))

        # 去重并保持顺序
        self.seeds = list(dict.fromkeys(primary + secondary))

    def candidates(self, offset: int, count: int, tlds: list[str] | None = None) -> list[tuple[str, str]]:
        """返回 [(域名, 来源词)]，按 offset 轮转。"""
        tlds = tlds or (TLDS_ABUSED + TLDS_COMMON)
        total = len(self.seeds)
        if total == 0:
            return []
        out: list[tuple[str, str]] = []
        for i in range(count):
            seed, origin = self.seeds[(offset + i) % total]
            tld = tlds[(offset + i) // max(1, total // len(tlds) + 1) % len(tlds)]
            out.append((f"{seed}{tld}", origin))
        return out

    def stats(self) -> dict[str, int]:
        return {"seeds": len(self.seeds)}
