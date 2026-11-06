"""发现引擎：把「世界里新出现的东西」变成「候选池里的记录」。

核心原则
--------
**发现不等于判定。** 这里只回答「值不值得看一眼」，不回答「是不是诈骗」。
所以阈值设得很低（默认 0.30），命中即收；判定交给 scoring，分级交给 triage。
这条链路允许「宁可错杀」——错杀的成本只是几 KB 存储。

数据流
------
CT 日志 / certstream / DNS 探测 / 人工导入
        ↓ 规范化 + 白名单
    词库匹配（hint 分）
        ↓ 去重（内存 LRU + 库唯一键）
  DiscoveryEvent（只追加的流水）
        ↓ upsert
   Asset(tier=candidate) —— 进入研判队列
        ↓
   事件总线（前端实时看到）

吞吐设计
--------
批量落库：攒够 100 条或 2 秒写一次，避免每条一个事务。
去重分两级：内存 set 挡住同一批内的重复，数据库唯一键挡住跨批重复。
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select

from ..config import settings
from ..core.bus import bus
from ..core.eventlog import emit
from ..db import session_scope
from ..domain import utcnow
from ..models import TIER_CANDIDATE, TIER_COLD, Asset, DiscoveryEvent, KeywordHit
from ..normalize import collapse_host
from .ct import CertObservation, CertStreamClient, CTLogFollower, CtrlShSearch
from .dnsprobe import DNSProbe, SeedGenerator
from .keywords import get_library

log = logging.getLogger(__name__)

# 低于这个 hint 分的域名进冷存：仍然记录，但不进研判队列。
# 设得低是刻意的——「宁可错杀」，冷存比漏掉便宜。
COLD_THRESHOLD = 0.30


@dataclass
class DiscoverStats:
    seen: int = 0
    matched: int = 0
    queued: int = 0
    duplicated: int = 0
    whitelisted: int = 0
    cold: int = 0
    db_errors: int = 0
    started_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        uptime = max(1.0, time.time() - self.started_at)
        return {
            "seen": self.seen,
            "matched": self.matched,
            "queued": self.queued,
            "duplicated": self.duplicated,
            "whitelisted": self.whitelisted,
            "cold": self.cold,
            "db_errors": self.db_errors,
            "uptime_seconds": round(uptime, 1),
            # 这两个数以前混在一起叫 rate_per_min，显示成 1.7/分，
            # 看起来像「系统几乎没在工作」——其实那是入池速度，不是采集速度。
            "certs_per_min": round(self.seen / uptime * 60, 1),
            "assets_per_min": round(self.queued / uptime * 60, 1),
            "rate_per_min": round(self.seen / uptime * 60, 1),
        }


class Deduper:
    """两级去重：内存 LRU 挡批量内重复，数据库唯一键挡跨批。"""

    def __init__(self, capacity: int = 200_000) -> None:
        self._seen: deque[str] = deque(maxlen=capacity)
        self._set: set[str] = set()
        self._lock = threading.Lock()

    def add(self, key: str) -> bool:
        """首次出现返回 True。"""
        with self._lock:
            if key in self._set:
                return False
            if len(self._seen) == self._seen.maxlen:
                old = self._seen[0]
                self._set.discard(old)
            self._seen.append(key)
            self._set.add(key)
            return True


class DiscoveryEngine:
    def __init__(self) -> None:
        self.lib = get_library()
        self.stats = DiscoverStats()
        self.deduper = Deduper(settings.discover_queue_capacity)
        self.pending: deque[tuple[CertObservation | None, str, str, float, list[str]]] = deque()
        self._pending_lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._followers: list[CTLogFollower] = []
        self._stream: CertStreamClient | None = None
        self._dns: DNSProbe | None = None
        self._seeds: SeedGenerator | None = None
        self._dns_offset = 0
        self._running = False
        self._last_flush = time.time()
        self._ct_sh = CtrlShSearch()
        self._ct_sh_last: dict[str, float] = {}

    # ------------------------------------------------------------ 生命周期
    def start(self) -> None:
        if self._running or not settings.discover_enabled:
            return
        self._running = True
        self._stop.clear()

        if settings.allow_network:
            (settings.data_dir / "ct_state").mkdir(parents=True, exist_ok=True)
            # 日志清单的选择放到后台线程做：探测 20 多条日志要十几秒，
            # 不能把 API 启动卡住（健康检查会被容器判死）。
            self._threads.append(
                threading.Thread(target=self._ct_manager, name="discover-ct-mgr", daemon=True)
            )
            self._threads.append(
                threading.Thread(target=self._dns_loop, name="discover-dns", daemon=True)
            )
            self._threads.append(
                threading.Thread(target=self._flush_loop, name="discover-flush", daemon=True)
            )
            self._seeds = SeedGenerator()
            self._dns = DNSProbe(settings.data_dir / "dns_cache.json")

            if settings.ct_stream_enabled and settings.ct_stream_url:
                self._stream = CertStreamClient(settings.ct_stream_url, self._on_ct_batch)
                self._stream.start()

        for t in self._threads:
            t.start()
        log.info("发现引擎已启动：CT 跟随 %s 条日志 + DNS 探测", settings.ct_poll_logs or "自动选择")

    # ------------------------------------------------------------ 日志清单管理
    def _resolve_logs(self) -> list[str]:
        configured = [u.strip() for u in settings.ct_poll_logs.split(",") if u.strip()]
        if configured:
            return configured
        from .ct import fetch_usable_logs

        return fetch_usable_logs(limit=settings.ct_poll_logs_limit)

    def _spawn_follower(self, url: str) -> None:
        slug = url.rstrip("/").rsplit("/", 1)[-1][:24] or "log"
        if not slug or slug == "log":
            parts = [p for p in url.rstrip("/").split("/") if p]
            slug = (parts[-1] if parts else "log")[:24]
        follower = CTLogFollower(
            url,
            settings.data_dir / "ct_state" / f"{slug}.json",
            batch=max(64, settings.ct_poll_batch),
        )
        self._followers.append(follower)
        # 每条日志一个线程：串行轮询时后几条会被前一条的慢请求拖死，
        # 而日志响应时间波动很大（实测 0.5s～5s）。
        t = threading.Thread(
            target=self._ct_loop, args=(follower,), name=f"discover-ct-{slug}", daemon=True
        )
        t.start()

    def _ct_manager(self) -> None:
        try:
            urls = self._resolve_logs()
        except Exception as exc:  # noqa: BLE001
            log.warning("解析 CT 日志清单失败：%s", exc)
            urls = []
        for url in urls:
            if self._stop.is_set():
                return
            self._spawn_follower(url)
        if not self._followers:
            log.warning("没有可用 CT 日志，发现层只剩 DNS 探测")

        # 每半小时检查一次：日志冻结了就换一条。这是它最容易「静默失效」的地方。
        while not self._stop.wait(1800):
            frozen = [f for f in list(self._followers) if f.frozen and not getattr(f, "retired", False)]
            if not frozen:
                continue
            try:
                candidates = self._resolve_logs()
            except Exception:  # noqa: BLE001
                continue
            used = {f.url.rstrip("/") for f in self._followers}
            for dead in frozen:
                dead.retired = True
                spare = [u for u in candidates if u.rstrip("/") not in used]
                if not spare:
                    log.warning("CT 日志 %s 已冻结，但找不到替换日志", dead.url)
                    continue
                used.add(spare[0].rstrip("/"))
                log.warning("CT 日志 %s 已冻结，改跟 %s", dead.url, spare[0])
                self._spawn_follower(spare[0])

    def stop(self) -> None:
        self._stop.set()
        self._running = False
        if self._stream:
            self._stream.stop()
        self._flush(force=True)

    # ------------------------------------------------------------ CT 轮询
    def _ct_loop(self, follower) -> None:
        while not self._stop.is_set() and not getattr(follower, "retired", False):
            started = time.monotonic()
            try:
                # 连续取多批直到追平或预算用尽。单次只取一批的话，
                # 日志增速（实测 ~2000 条/分钟/日志）一旦超过 batch/interval，
                # 中间的证书就被永久跳过。
                follower.catch_up(
                    self._on_ct_batch,
                    max_batches=80,
                    budget=max(6.0, settings.ct_poll_interval * 0.8),
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("CT 轮询异常 %s：%s", follower.url, exc)
            elapsed = time.monotonic() - started
            self._stop.wait(max(2.0, settings.ct_poll_interval - elapsed))

    def _on_ct_batch(self, observations: list[CertObservation]) -> None:
        for obs in observations:
            self.stats.seen += 1
            host = obs.domain.lower().strip(".")
            if not host or "." not in host:
                continue
            if self.lib.is_whitelisted(host):
                self.stats.whitelisted += 1
                continue
            # 一张证书常带 10~30 个 SAN，同一站点的 www/分中心/后台会各算一个资产：
            # 实测 22 小时里 2,512 个主机只对应 1,251 个注册域，一半是重复。
            # 归并到注册域，主机清单留在 meta.hosts，图里仍然能连到具体主机。
            domain = collapse_host(host) if settings.discover_collapse_subdomains else host
            if not domain:
                continue
            result = self.lib.match_domain(host)
            # 一个词都没命中 = 与我们的关注面无关，直接丢弃（这是唯一会丢的分支）
            if not result.hits and result.score < COLD_THRESHOLD:
                self.stats.cold += 1
                continue
            # 只有「载体词」的域名（app./m./www. 这种前缀命中）价值为零：
            # 一个 "app" 就把全世界的 app.xxx.com 收进来，等于没有筛选。
            # 低于阈值一律算冷存，不入资产表——需要时还能从事件流水回放。
            if result.score < COLD_THRESHOLD:
                self.stats.cold += 1
                continue
            self.stats.matched += 1
            if not self.deduper.add(domain):
                self.stats.duplicated += 1
                continue
            obs_host = host
            with self._pending_lock:
                self.pending.append((obs, "domain", domain, result.score, result.terms, obs_host))

    # ------------------------------------------------------------ DNS 探测
    def _dns_loop(self) -> None:
        # 先等 CT 跑起来，避免启动瞬间抢带宽
        self._stop.wait(20)
        while not self._stop.is_set():
            try:
                if not self._seeds or not self._dns:
                    break
                batch = self._seeds.candidates(self._dns_offset, 300)
                self._dns_offset = (self._dns_offset + 300) % max(1, len(self._seeds.seeds))
                found = self._dns.probe_many(d for d, _ in batch)
                origin_map = dict(batch)
                for res in found:
                    domain = res.domain
                    if self.lib.is_whitelisted(domain):
                        self.stats.whitelisted += 1
                        continue
                    match = self.lib.match_domain(domain)
                    score = max(match.score, 0.45)   # DNS 探测命中的词根本身带信号
                    self.stats.seen += 1
                    self.stats.matched += 1
                    if not self.deduper.add(domain):
                        self.stats.duplicated += 1
                        continue
                    obs = CertObservation(
                        domain=domain,
                        all_domains=[domain],
                        issuer="",
                        not_before="",
                        fingerprint="",
                        log_url="dns_probe",
                        entry_index=0,
                        source="dns_probe",
                    )
                    with self._pending_lock:
                        self.pending.append(
                            (obs, "domain", domain, score,
                             match.terms or [origin_map.get(domain, "")], domain)
                        )
                log.info(
                    "DNS 探测：%d 个候选，%d 个已注册（累计存在 %d）",
                    len(batch), len(found), self._dns.stats["exists"],
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("DNS 探测异常：%s", exc)
            self._stop.wait(45)

    # ------------------------------------------------------------ 落库
    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(2.0)
            self._flush()

    def _flush(self, force: bool = False) -> None:
        with self._pending_lock:
            if not self.pending:
                return
            if not force and len(self.pending) < 60 and (time.time() - self._last_flush) < 5:
                return
            batch = list(self.pending)
            self.pending.clear()
        self._last_flush = time.time()

        rows = batch
        try:
            with session_scope() as session:
                created = self._persist(session, rows)
            self.stats.queued += created
        except Exception as exc:  # noqa: BLE001
            self.stats.db_errors += 1
            log.warning("发现批写入失败（%d 条）：%s", len(rows), exc)
            # 失败不重排队：事件日志里已有流水，人工可回放
            emit("discover.flush_failed", count=len(rows), error=str(exc)[:200])

    def _persist(self, session, rows: list[tuple]) -> int:
        created = 0
        assets: list[dict[str, Any]] = []
        for obs, kind, value, score, terms, host in rows:
            normalized = value
            existing = session.scalar(
                select(Asset.id).where(Asset.kind == kind, Asset.normalized == normalized)
            )
            if existing:
                # 只更新 last_seen 和发现原因，不动评分——评分由研判链路负责
                asset = session.get(Asset, existing)
                if asset is not None:
                    asset.last_seen = utcnow()
                    asset.enrich_count = (asset.enrich_count or 0) + 1
                    meta = dict(asset.meta or {})
                    changed = False
                    if score > meta.get("discover_hint", 0):
                        meta["discover_hint"] = round(score, 3)
                        changed = True
                    hosts = meta.get("hosts") or []
                    if host and host not in hosts and len(hosts) < 30:
                        meta["hosts"] = hosts + [host]
                        changed = True
                    if changed:
                        asset.meta = meta
                    # 证书指纹是同一团伙最强的关联证据，第一次拿到就记住
                    if obs is not None and obs.fingerprint and not asset.fingerprint:
                        asset.fingerprint = obs.fingerprint[:64]
                session.add(
                    DiscoveryEvent(
                        source=obs.source if obs else "manual",
                        kind=kind,
                        value=value,
                        normalized=normalized,
                        matched_terms=terms[:12],
                        score_hint=round(score, 3),
                        asset_id=existing,
                        raw=obs.as_dict() if obs else {},
                    )
                )
                continue

            asset = Asset(
                kind=kind,
                value=value,
                normalized=normalized,
                tier=TIER_CANDIDATE if score >= COLD_THRESHOLD else TIER_COLD,
                discovery_source=obs.source if obs else "manual",
                discovery_reason="、".join(terms[:6]),
                score=0.0,
                verdict="insufficient",
                fingerprint=(obs.fingerprint[:64] if obs is not None else ""),
                meta={"discover_hint": round(score, 3), "hosts": [host] if host else []},
            )
            session.add(asset)
            session.flush()
            session.add(
                DiscoveryEvent(
                    source=obs.source if obs else "manual",
                    kind=kind,
                    value=value,
                    normalized=normalized,
                    matched_terms=terms[:12],
                    score_hint=round(score, 3),
                    asset_id=asset.id,
                    raw=obs.as_dict() if obs else {},
                )
            )
            assets.append(
                {
                    "id": asset.id,
                    "kind": kind,
                    "value": value,
                    "score": round(score, 3),
                    "terms": terms[:6],
                    "source": obs.source if obs else "manual",
                }
            )
            created += 1

            # 词库命中统计：用来淘汰永远误报的词
            for term in terms[:6]:
                if not term:
                    continue
                row = session.get(KeywordHit, term)
                if row:
                    row.hits += 1
                    row.last_hit = utcnow()
                else:
                    session.add(KeywordHit(term=term, hits=1))

        session.commit()

        for item in assets[:40]:
            bus.publish("discovery", item)
        if assets:
            emit("discover.batch", created=len(assets), sample=[a["value"] for a in assets[:5]])
        return created

    # ------------------------------------------------------------ 手动注入
    def inject(self, values: Iterable[str], *, source: str = "manual", note: str = "") -> dict[str, Any]:
        """人工/外部导入。用于举报线索、批量域名清单、已知样本附带的基础设施。"""
        added = 0
        skipped = 0
        with session_scope() as session:
            for raw in values:
                value = str(raw).strip().lower().rstrip(".")
                if not value or "." not in value:
                    skipped += 1
                    continue
                if self.lib.is_whitelisted(value):
                    skipped += 1
                    continue
                if not self.deduper.add(value):
                    skipped += 1
                    continue
                match = self.lib.match_domain(value)
                note_text = note or "人工导入"
                existing = session.scalar(
                    select(Asset.id).where(Asset.kind == "domain", Asset.normalized == value)
                )
                if existing:
                    skipped += 1
                    continue
                asset = Asset(
                    kind="domain", value=value, normalized=value,
                    tier=TIER_CANDIDATE, discovery_source=source,
                    discovery_reason=note_text + ("；命中：" + "、".join(match.terms[:5]) if match.terms else ""),
                    meta={"discover_hint": round(match.score, 3)},
                )
                session.add(asset)
                session.flush()
                session.add(
                    DiscoveryEvent(
                        source=source, kind="domain", value=value, normalized=value,
                        matched_terms=match.terms[:12], score_hint=round(match.score, 3),
                        asset_id=asset.id, raw={"note": note_text},
                    )
                )
                added += 1
            session.commit()
        bus.publish("discovery_injected", {"added": added, "skipped": skipped, "source": source})
        emit("discover.inject", added=added, skipped=skipped, source=source)
        return {"added": added, "skipped": skipped}

    def search_history(self, terms: list[str], limit_per_term: int = 60) -> dict[str, Any]:
        """按词根翻 crt.sh 历史。慢，只在需要补漏时手动触发。"""
        total = 0
        for term in terms[:20]:
            last = self._ct_sh_last.get(term, 0)
            if time.time() - last < 3600:      # 同一词根一小时最多查一次
                continue
            self._ct_sh_last[term] = time.time()
            observations = self._ct_sh.search(term, limit=limit_per_term)
            for obs in observations:
                domain = obs.domain.lower()
                if not domain or self.lib.is_whitelisted(domain):
                    continue
                match = self.lib.match_domain(domain)
                if match.score < COLD_THRESHOLD and not match.hits:
                    continue
                if not self.deduper.add(domain):
                    continue
                with self._pending_lock:
                    self.pending.append((obs, "domain", domain, match.score, match.terms))
                total += 1
            time.sleep(2)
        self._flush(force=True)
        return {"queued": total}

    # ------------------------------------------------------------ 状态
    def status(self) -> dict[str, Any]:
        followers = list(self._followers)
        return {
            "running": self._running,
            "stats": self.stats.as_dict(),
            "keyword_library": self.lib.stats(),
            "followers": [f.status() for f in followers],
            "followers_total_lag": sum(
                (f.status().get("lag") or 0) for f in followers if not getattr(f, "retired", False)
            ),
            "followers_frozen": sum(1 for f in followers if f.frozen),
            "stream": self._stream.status() if self._stream else None,
            "dns": self._dns.stats if self._dns else None,
            "seeds": self._seeds.stats() if self._seeds else None,
            "pending": len(self.pending),
            "crt_sh_error": self._ct_sh.last_error,
        }


_engine: DiscoveryEngine | None = None
_lock = threading.Lock()


def get_engine() -> DiscoveryEngine:
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                _engine = DiscoveryEngine()
    return _engine
