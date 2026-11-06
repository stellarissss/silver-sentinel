"""编排层：把各模块串成一条能长期跑的流水线。

一轮完整的周期
--------------
1. **补研判**：候选池里新进来但还没评分的，逐个走 scan。
2. **补富化**：对已评分但缺注册信息/解析/备案的，补齐。
3. **建图**：把新资产的关系写进图。
4. **找团伙**：社区发现，更新 Campaign。
5. **衰减**：把长期没动静的候选降为冷存。

为什么分步而不是一遍过
----------------------
每一步都可能失败（网络、限流、解析），分步才能「跳过失败的部分继续跑」。
每一步都记 TaskRun，重启后能看出上次死在哪。

并发控制的取舍
--------------
采集是 IO 密集的，但目标站点不喜欢被并发打。默认 8 个 worker，
且每个域名的请求之间天然有间隔（不同域名）。
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import or_, select

from . import triage
from .config import settings
from .core.bus import bus
from .core.eventlog import emit
from .db import session_scope
from .enrich.icp import get_icp
from .enrich.registry import get_rdap
from .graph.build import GraphBuilder
from .graph.community import sync_campaigns
from .intake import scan
from .models import TIER_CANDIDATE, TIER_CONFIRMED, TIER_WATCH, Asset, TaskRun
from .normalize import registrable_domain
from .sandbox.apk import get_apk_sandbox

log = logging.getLogger(__name__)


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""

ACTIVE_TIERS = (TIER_CONFIRMED, TIER_WATCH, TIER_CANDIDATE)


@dataclass
class CycleStats:
    scanned: int = 0
    enriched: int = 0
    graph_edges: int = 0
    campaigns: dict[str, Any] = field(default_factory=dict)
    decayed: int = 0
    errors: int = 0
    captured: int = 0
    capture_failed: int = 0
    capture_backfilled: int = 0
    elapsed: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "scanned": self.scanned,
            "enriched": self.enriched,
            "graph_edges": self.graph_edges,
            "campaigns": self.campaigns,
            "decayed": self.decayed,
            "errors": self.errors,
            "captured": self.captured,
            "capture_failed": self.capture_failed,
            "capture_backfilled": self.capture_backfilled,
            "elapsed": round(self.elapsed, 1),
        }


def _task(kind: str) -> TaskRun:
    row = TaskRun(kind=kind, status="running")
    with session_scope() as s:
        s.add(row)
        s.flush()
        s.refresh(row)
    return row


def _finish_task(task_id: int, status: str, stats: dict | None = None, error: str = "") -> None:
    from .domain import utcnow

    with session_scope() as s:
        row = s.get(TaskRun, task_id)
        if row:
            row.status = status
            row.finished_at = utcnow()
            row.stats = stats or {}
            row.error = error[:1000]


# ---------------------------------------------------------------- 单资产


def enrich_asset(asset_id: int, *, with_sandbox: bool = False) -> dict[str, Any]:
    """补齐一个资产的注册信息 / DNS / 备案 / 运行时行为。"""
    from .discover.dnsprobe import DNSProbe

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "reason": "资产不存在"}
        kind = asset.kind
        normalized = asset.normalized
        meta = dict(asset.meta or {})
        facts = dict(meta.get("facts") or {})

    out: dict[str, Any] = {"asset_id": asset_id, "updated": []}

    if kind in ("domain", "url"):
        host = registrable_domain(normalized if kind == "domain" else (meta.get("host") or normalized))
        if host:
            rdap = get_rdap().lookup(host)
            if rdap.ok:
                facts["registrar"] = rdap.registrar
                facts["domain_age_days"] = rdap.age_days
                facts["nameservers"] = rdap.nameservers
                if rdap.registered_at:
                    facts["registered_at"] = rdap.registered_at.isoformat()
                out["updated"].append("rdap")

            if settings.icp_ready:
                icp = get_icp().lookup(host)
                if icp.status != "unknown":
                    out["updated"].append("icp")

            if settings.allow_network and not facts.get("ips"):
                try:
                    probe = DNSProbe(settings.data_dir / "dns_cache.json")
                    res = probe.query(normalized if kind == "domain" else host)
                    if res.exists:
                        facts["ips"] = res.a_records
                        facts["nameservers"] = res.ns_records or facts.get("nameservers", [])
                        out["updated"].append("dns")
                except Exception as exc:  # noqa: BLE001
                    log.debug("DNS 富化失败：%s", exc)

    elif kind == "apk" and with_sandbox:
        obs = get_apk_sandbox().analyze(normalized, static_facts=facts)
        facts["runtime_behaviors"] = obs.behaviors
        facts["runtime_risk"] = obs.risk
        facts["runtime_engine"] = obs.engine
        if obs.c2_candidates:
            facts["embedded_urls"] = obs.c2_candidates
        out["updated"].append(f"apk:{obs.engine}")

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return out
        meta["facts"] = facts
        asset.meta = meta
        asset.enrich_count = (asset.enrich_count or 0) + 1
        if kind in ("domain", "url") and settings.icp_ready:
            icp_row = get_icp().lookup(registrable_domain(normalized))
            if icp_row.status != "unknown":
                asset.icp_status = icp_row.status
                asset.icp_license = icp_row.license or asset.icp_license
                asset.icp_entity = icp_row.entity or asset.icp_entity
                from .domain import utcnow

                asset.icp_checked_at = utcnow()
            if icp_row.violation in ("listed", "clean"):
                asset.icp_violation = icp_row.violation
                asset.icp_violation_title = icp_row.violation_title
                facts["icp_violation"] = icp_row.violation
                if icp_row.violation_title:
                    facts["icp_violation_title"] = icp_row.violation_title
            out["icp"] = icp_row.as_dict()
        # 富化后重新分级：新证据可能把它从候选提到 watch
        decision = triage.apply(asset, facts=facts)
        out["tier"] = asset.tier
        out["reasons"] = decision.reasons[:4]

    bus.publish("enriched", out)
    return out


def _scan_one(asset_id: int) -> dict[str, Any]:
    from .models import Evidence as _Evidence

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "asset_id": asset_id, "reason": "不存在"}
        kind, value = asset.kind, asset.value
        meta = dict(asset.meta or {})
        # 有页面正文就拿来做语料：只按域名重扫，等于每次都在忽略已经取到的证据
        text = ""
        row = s.scalar(
            select(_Evidence)
            .where(_Evidence.asset_id == asset_id, _Evidence.kind == "page_text",
                   _Evidence.deleted_at.is_(None))
            .order_by(_Evidence.id.desc())
            .limit(1)
        )
        if row is not None:
            path = Path(row.path)
            if not path.is_absolute():
                path = settings.data_dir / path
            try:
                if path.exists():
                    text = path.read_text(encoding="utf-8", errors="replace")[:60_000]
            except OSError:
                text = ""

    try:
        result = scan(
            kind, value, text=text or None, meta=meta,
            run_llm=False, do_cluster=False, trigger="pipeline", quick=True,
        )
        return {"ok": True, "asset_id": asset_id, "score": result.assessment.score,
                "verdict": result.assessment.verdict, "tier": result.asset.get("tier")}
    except Exception as exc:  # noqa: BLE001
        log.debug("研判失败 %s: %s", asset_id, exc)
        return {"ok": False, "asset_id": asset_id, "error": str(exc)[:200]}


# ---------------------------------------------------------------- 批量


def pending_assets(limit: int = 200) -> list[int]:
    """挑出「还没评过分」或「发现后一直没动」的候选。"""
    with session_scope() as s:
        rows = s.execute(
            select(Asset.id)
            .where(
                Asset.tier.in_(ACTIVE_TIERS),
                or_(Asset.scan_count == 0, Asset.score == 0.0),
            )
            .order_by(Asset.first_seen.desc())
            .limit(limit)
        ).all()
    return [r[0] for r in rows]


def stale_assets(limit: int = 100, hours: int = 24) -> list[int]:
    """超过 N 小时没重扫的活跃目标。用于持续监控。"""
    from datetime import timedelta

    from .domain import utcnow

    cutoff = utcnow() - timedelta(hours=hours)
    with session_scope() as s:
        rows = s.execute(
            select(Asset.id)
            .where(Asset.tier.in_(ACTIVE_TIERS), Asset.last_seen < cutoff)
            .order_by(Asset.score.desc(), Asset.last_seen)
            .limit(limit)
        ).all()
    return [r[0] for r in rows]


def run_cycle(*, scan_limit: int | None = None, enrich_limit: int = 40, rebuild_graph: bool = True) -> dict[str, Any]:
    """跑一轮。可被调度器反复调用，也可 CLI 手动触发。"""
    started = time.monotonic()
    stats = CycleStats()
    task = _task("cycle")

    try:
        # 1) 研判新候选
        limit = scan_limit or settings.monitor_batch_size
        ids = pending_assets(limit)
        if ids:
            with ThreadPoolExecutor(max_workers=settings.worker_concurrency) as pool:
                futures = {pool.submit(_scan_one, i): i for i in ids}
                for fut in as_completed(futures):
                    res = fut.result()
                    if res.get("ok"):
                        stats.scanned += 1
                    else:
                        stats.errors += 1
            log.info("研判完成：%d 个", stats.scanned)

        # 2) 富化：优先高分目标
        with session_scope() as s:
            enrich_ids = [
                r[0]
                for r in s.execute(
                    select(Asset.id)
                    .where(Asset.tier.in_(ACTIVE_TIERS), Asset.enrich_count == 0)
                    .order_by(Asset.score.desc())
                    .limit(enrich_limit)
                ).all()
            ]
        # 富化是纯 IO（RDAP / DNS），必须并发。串行时 40 个目标要 80 秒以上，
        # 周期永远追不上 tick，候选队列会越堆越长。
        if enrich_ids:
            with ThreadPoolExecutor(max_workers=max(2, min(8, settings.worker_concurrency))) as pool:
                futures = {pool.submit(enrich_asset, aid): aid for aid in enrich_ids}
                for fut in as_completed(futures):
                    try:
                        fut.result()
                        stats.enriched += 1
                    except Exception as exc:  # noqa: BLE001
                        stats.errors += 1
                        log.debug("富化失败 %s: %s", futures[fut], exc)

        # 3) 取证：先把「有效但没取过证」的补进队列，再跑一小批。
        #    放在建图之前，是因为取证会产出新域名与新证书，建图能用上。
        if settings.capture_enabled:
            try:
                from .capture import backfill as capture_backfill
                from .capture import run_batch as run_capture_batch

                stats.capture_backfilled = capture_backfill(limit=settings.capture_backfill_limit)
                cap = run_capture_batch(limit=settings.capture_batch)
                stats.captured = cap.get("ok", 0)
                stats.capture_failed = max(0, cap.get("ran", 0) - cap.get("ok", 0))
            except Exception as exc:  # noqa: BLE001
                stats.errors += 1
                log.warning("取证批次失败：%s", exc)

        # 4) 建图 + 找团伙
        if rebuild_graph and settings.graph_enabled:
            try:
                builder = GraphBuilder()
                gstats = builder.build_all(limit=6000)
                stats.graph_edges = gstats.get("edges", 0)
                stats.campaigns = sync_campaigns()
            except Exception as exc:  # noqa: BLE001
                stats.errors += 1
                log.warning("建图失败：%s", exc)

        # 5) 衰减
        if stats.scanned > 0:
            stats.decayed = triage.decay().get("moved", 0)

        stats.elapsed = time.monotonic() - started
        _finish_task(task.id, "done", stats.as_dict())
        emit("pipeline.cycle", **stats.as_dict())
        bus.publish("cycle", stats.as_dict())
        return {"ok": True, **stats.as_dict()}
    except Exception as exc:  # noqa: BLE001
        stats.errors += 1
        stats.elapsed = time.monotonic() - started
        _finish_task(task.id, "failed", stats.as_dict(), str(exc))
        log.exception("周期执行失败")
        return {"ok": False, "error": str(exc)[:300], **stats.as_dict()}


# ---------------------------------------------------------------- 网页实测


def probe_web(asset_id: int) -> dict[str, Any]:
    """对 URL/域名资产做一次真实页面执行，把结果固化成证据。

    实现在 capture 模块，这里是手动入口的薄封装——自动链路走队列，
    手动点「立即取证」走同步调用，两条路径共用同一套采集与落盘逻辑。
    """
    from .capture import capture_asset

    return capture_asset(asset_id)


# ---------------------------------------------------------------- 后台调度


class Scheduler:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_cycle: dict[str, Any] = {}
        self.cycle_count = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread is not None or not settings.scheduler_in_process:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="scheduler", daemon=True)
        self._thread.start()
        log.info("调度器已启动，tick=%ds", settings.monitor_tick_seconds)

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        # 启动后先让发现引擎跑一会，避免一上来就抢资源
        self._stop.wait(30)
        while not self._stop.is_set():
            try:
                result = run_cycle()
                with self._lock:
                    self.last_cycle = result
                    self.cycle_count += 1
                log.info(
                    "周期 #%d 完成：研判 %s，富化 %s，边 %s，团伙 %s，耗时 %ss",
                    self.cycle_count, result.get("scanned"), result.get("enriched"),
                    result.get("graph_edges"), (result.get("campaigns") or {}).get("communities"),
                    result.get("elapsed"),
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("周期异常：%s", exc)
            # 每轮间隔：默认跟 tick 走（60s）。发现层每 5 秒落一批库，
            # 5 分钟才研判一次会让新线索排长队，也拖慢「发现→告警」的时延。
            self._stop.wait(max(30, settings.monitor_tick_seconds))

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._thread is not None and self._thread.is_alive(),
                "cycles": self.cycle_count,
                "last": self.last_cycle,
                "tick": settings.monitor_tick_seconds,
            }


_scheduler: Scheduler | None = None


def get_scheduler() -> Scheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = Scheduler()
    return _scheduler
