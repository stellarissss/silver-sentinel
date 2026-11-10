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
from datetime import timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import and_, or_, select

from . import triage
from .config import settings
from .core.bus import bus
from .core.eventlog import emit
from .db import session_scope
from .domain import utcnow
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
    llm_judged: int = 0
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
            "llm_judged": self.llm_judged,
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
    from .evidence import latest_text

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "asset_id": asset_id, "reason": "不存在"}
        kind, value = asset.kind, asset.value
        meta = dict(asset.meta or {})
        # 有页面正文就拿来做语料：只按域名重扫，等于每次都在忽略已经取到的证据。
        # 正文可能只剩密文（证据仓脱敏后），必须走统一读取入口，不能直接 open。
        text = latest_text(s, asset_id)
        has_text = bool(text)

    # 已经有正文的资产走「重评」而不是「重扫」：重扫会再打一遍外部接口，
    # 结论却完全一样；重评只用本地证据，毫秒级，可以把整批历史资产刷一遍。
    if has_text:
        from .scoring.reassess import rescore_by_id

        res = rescore_by_id(asset_id, trigger="pipeline")
        return {
            "ok": bool(res.get("ok")),
            "asset_id": asset_id,
            "score": (res.get("after") or {}).get("score"),
            "verdict": (res.get("after") or {}).get("verdict"),
            "tier": (res.get("after") or {}).get("tier"),
            "rescore": True,
        }

    try:
        result = scan(
            kind, value, text=None, meta=meta,
            run_llm=False, do_cluster=False, trigger="pipeline", quick=True,
        )
        return {"ok": True, "asset_id": asset_id, "score": result.assessment.score,
                "verdict": result.assessment.verdict, "tier": result.asset.get("tier")}
    except Exception as exc:  # noqa: BLE001
        log.debug("研判失败 %s: %s", asset_id, exc)
        return {"ok": False, "asset_id": asset_id, "error": str(exc)[:200]}


# ---------------------------------------------------------------- 批量


def pending_assets(limit: int = 200) -> list[int]:
    """挑出「还没评过分」「有正文但没按正文评过」的候选。

    第二类才是重点：证据仓里的 page_text 早已存在，只是历史版本读不到
    正文（明文被脱敏），于是这些资产的分数一直停在「只有域名」的水平。
    幂等键是正文证据 id——同一条正文不重复重算。
    """
    from sqlalchemy import func

    from .models import Evidence
    from .scoring.engine import DEFAULT_THRESHOLDS, get_ruleset

    thresholds = get_ruleset().thresholds
    with session_scope() as s:
        rows = s.execute(
            select(Asset.id, Asset.score, Asset.scan_count, Asset.meta, Asset.verdict)
            .where(
                or_(
                    Asset.tier.in_(ACTIVE_TIERS),
                    # 历史误报：白名单压分后 verdict 没跟着回退，资产沉进
                    # cold/dismissed 就再也不进重评，永久占着高危池。
                    # 把它们拉回来，周期研判会按新规则自动纠正。
                    and_(Asset.verdict == "high_risk",
                         Asset.score < thresholds.get("high_risk", DEFAULT_THRESHOLDS["high_risk"])),
                    and_(Asset.verdict == "suspicious",
                         Asset.score < thresholds.get("suspicious", DEFAULT_THRESHOLDS["suspicious"])),
                ),
                # 人工终审过的资产不再进入机器研判：结论不该被周期任务反复重算，
                # 也省掉每轮 40 个高分资产的白工与 SQLite 锁竞争。
                or_(Asset.reviewed_by == "", Asset.reviewed_by.is_(None)),
            )
            .order_by(Asset.score.desc(), Asset.first_seen.desc())
            .limit(max(limit * 6, 600))
        ).all()
        latest_text = {
            aid: ev_id
            for aid, ev_id in s.execute(
                select(Evidence.asset_id, func.max(Evidence.id))
                .where(Evidence.kind == "page_text", Evidence.deleted_at.is_(None))
                .group_by(Evidence.asset_id)
            ).all()
        }

    with_text: list[int] = []
    fresh: list[int] = []
    inconsistent: list[int] = []
    for asset_id, score, scan_count, meta, verdict in rows:
        scoring = (meta or {}).get("scoring") or {}
        scored_ev = int(scoring.get("evidence_id") or 0)
        current_ev = latest_text.get(asset_id, 0)
        # 判定比分数应得的更重：优先纠正，别让它继续占着高危队列。
        if (
            (verdict == "high_risk"
             and float(score or 0) < thresholds.get("high_risk", DEFAULT_THRESHOLDS["high_risk"]))
            or (verdict == "suspicious"
                and float(score or 0) < thresholds.get("suspicious", DEFAULT_THRESHOLDS["suspicious"]))
        ):
            inconsistent.append(asset_id)
        elif current_ev and current_ev > scored_ev:
            with_text.append(asset_id)
        elif not scan_count or float(score or 0.0) == 0.0:
            fresh.append(asset_id)
    return (inconsistent + with_text + fresh)[:limit]


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


# 建图的节流时间戳。每轮都全量重建 3000+ 资产的边太贵——
# 实测周期 40~60 秒一轮，社区发现日志里「新建 0，更新 0，跳过 18」重复刷屏，
# 纯属空转。图结构的变化速度远低于取证速度，10 分钟一次足够。
_GRAPH_BUILT_AT: float = 0.0


def _should_rebuild_graph() -> bool:
    import time as _time

    gap = max(1, int(getattr(settings, "graph_rebuild_minutes", 10))) * 60
    if _time.monotonic() - _GRAPH_BUILT_AT < gap:
        return False
    return True


def run_cycle(*, scan_limit: int | None = None, enrich_limit: int = 40, rebuild_graph: bool = True) -> dict[str, Any]:
    """跑一轮。可被调度器反复调用，也可 CLI 手动触发。"""
    global _GRAPH_BUILT_AT
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

        # 3) 取证：有独立取证线程时这里绝不插手——Chromium 只有一个，
        #    主周期再去抢只会让两边都变慢。只有线程没起来（老部署/手工跑）才在这里兜底。
        from .worker import capture_worker_alive

        if settings.capture_enabled and not capture_worker_alive():
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

        # 3.5) LLM 补判：只补「有正文、还没判过」的灰区资产，每轮少量。
        #     放在这里而不是取证线程里，是因为模型调用要几秒到几十秒，
        #     不能让它占住 Chromium 的执行窗口。
        try:
            stats.llm_judged = llm_backlog(limit=settings.llm_batch)
        except Exception as exc:  # noqa: BLE001
            log.debug("LLM 补判失败：%s", exc)

        # 4) 建图 + 找团伙（节流：图结构变化远慢于取证，不必每轮重算）
        if rebuild_graph and settings.graph_enabled and _should_rebuild_graph():
            try:
                builder = GraphBuilder()
                gstats = builder.build_all(limit=6000)
                stats.graph_edges = gstats.get("edges", 0)
                stats.campaigns = sync_campaigns()
                _GRAPH_BUILT_AT = time.monotonic()
            except Exception as exc:  # noqa: BLE001
                stats.errors += 1
                log.warning("建图失败：%s", exc)

        # 5) 衰减
        if stats.scanned > 0:
            stats.decayed = triage.decay().get("moved", 0)

        # 6) 自动盯防对齐分级：降回候选的目标不该继续占监控配额
        try:
            from .capture import prune_watch

            prune_watch()
        except Exception as exc:  # noqa: BLE001
            log.debug("对齐盯防失败：%s", exc)

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


# ---------------------------------------------------------------- LLM 补判


def _llm_payload(asset: Asset, facts: dict[str, Any], text: str, evidence_rows: list) -> dict[str, Any]:
    """证据包。必须带证据编号，否则模型写的 [E:1234] 无法核对。"""
    return {
        "asset": {"kind": asset.kind, "value": asset.value[:300], "tier": asset.tier},
        "facts": {k: v for k, v in facts.items() if v not in (None, "", [], 0)},
        "rule_score": float(asset.score or 0.0),
        "rule_verdict": asset.verdict,
        "evidence": [
            {
                "id": row.id,
                "kind": row.kind,
                "note": (row.note or "")[:160],
                "captured_at": row.captured_at.isoformat() if row.captured_at else "",
                "size": row.size,
            }
            for row in evidence_rows[:20]
        ],
        "text_excerpt": text[:6000],
        "note": "reasoning 中请用 [E:证据编号] 标注引用；只能引用上面 evidence 列表里出现的编号。",
    }


def llm_judge(asset_id: int, *, force: bool = False) -> dict[str, Any]:
    """让模型对一条已取证的资产做研判，并把结论并入分级。

    只在「有正文」时跑：没有正文的模型输入就只剩域名，结论不会比规则更好，
    白白花钱。结论本身不改分数（分数仍由规则给出，可复核），但会作为
    一条独立证据影响分级——这是「模型说像」和「规则说像」的区别。
    """
    from . import runtime_settings
    from .analyzers import llm as llm_analyzer
    from .evidence import latest_text_row, read_text
    from .models import Evidence

    cfg = runtime_settings.llm_config()
    if not cfg["ready"]:
        return {"ok": False, "reason": "LLM 未配置"}

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "reason": "资产不存在"}
        facts = dict((asset.meta or {}).get("facts") or {})
        row = latest_text_row(s, asset_id)
        if row is None:
            return {"ok": False, "reason": "没有页面正文，跳过"}
        text = read_text(row, 60_000)
        if len(text) < 120:
            return {"ok": False, "reason": "正文过短，跳过"}
        evidence_rows = list(
            s.scalars(
                select(Evidence)
                .where(Evidence.asset_id == asset_id, Evidence.deleted_at.is_(None))
                .order_by(Evidence.id.desc())
                .limit(20)
            )
        )
        payload = _llm_payload(asset, facts, text, evidence_rows)
        evidence_ids = {r.id for r in evidence_rows}
        before_tier = asset.tier

    started = time.monotonic()
    result = llm_analyzer.analyze(payload)
    if result is None:
        # 记一次失败尝试，6 小时内不再重试，避免每轮都为同一个超时付一次等待
        from .domain import utcnow

        with session_scope() as s:
            asset = s.get(Asset, asset_id)
            if asset is not None:
                meta = dict(asset.meta or {})
                meta["llm_attempt"] = {"at": utcnow().isoformat(), "ok": False}
                asset.meta = meta
        return {"ok": False, "reason": "模型未返回可用结论"}

    # 引用核对：模型声称引用的编号必须真的存在。幻觉编号单独记账，
    # 既用于评估模型可靠性，也避免把编造的引用写进证据链。
    cited = [int(x) for x in result.get("cited_evidence") or []]
    valid = [c for c in cited if c in evidence_ids]
    result["citations_checked"] = {"cited": cited, "valid": valid, "invalid": [c for c in cited if c not in evidence_ids]}
    result["elapsed"] = round(time.monotonic() - started, 2)
    result["evidence_id"] = row.id

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "reason": "资产在研判期间消失"}
        meta = dict(asset.meta or {})
        meta["llm"] = result
        facts = dict(meta.get("facts") or {})
        facts["llm_classification"] = result["classification"]
        facts["llm_confidence"] = result["confidence"]
        facts["llm_stage"] = result.get("stage", "")
        meta["facts"] = facts
        meta["llm_evidence_id"] = row.id
        asset.meta = meta
        decision = triage.apply(asset, facts=facts)
        after_tier = asset.tier
        s.flush()

    if after_tier != before_tier:
        log.info("LLM 研判推动分级 %s：%s -> %s", asset.value[:40], before_tier, after_tier)
        if after_tier in (TIER_WATCH, TIER_CONFIRMED):
            try:
                from .capture import ensure_watch

                ensure_watch(asset_id, by="llm")
            except Exception as exc:  # noqa: BLE001
                log.debug("LLM 后自动纳管失败：%s", exc)
    return {
        "ok": True,
        "asset_id": asset_id,
        "classification": result["classification"],
        "confidence": result["confidence"],
        "tier": after_tier,
        "tier_before": before_tier,
        "reasons": decision.reasons[:4],
        "elapsed": result["elapsed"],
    }


def llm_backlog(limit: int = 2) -> int:
    """挑出「有正文但还没让模型判过」的灰区资产，逐条补判。"""
    from . import runtime_settings

    cfg = runtime_settings.llm_config()
    if not cfg["ready"] or limit <= 0:
        return 0

    with session_scope() as s:
        rows = s.execute(
            select(Asset.id, Asset.score, Asset.meta)
            .where(
                Asset.tier.in_(ACTIVE_TIERS),
                Asset.score >= cfg["gray_low"] * 0.6,
            )
            .order_by(Asset.score.desc(), Asset.last_seen.desc())
            .limit(limit * 12)
        ).all()

    picked: list[int] = []
    cooldown = (utcnow() - timedelta(hours=6)).isoformat()
    for asset_id, _score, meta in rows:
        meta = meta or {}
        if meta.get("llm") and meta.get("llm_evidence_id"):
            # 已经有结论，且没有再取证过
            continue
        attempt = meta.get("llm_attempt") or {}
        if attempt and not attempt.get("ok") and str(attempt.get("at") or "") > cooldown:
            continue
        picked.append(asset_id)
        if len(picked) >= limit:
            break

    done = 0
    for asset_id in picked:
        try:
            res = llm_judge(asset_id)
            if res.get("ok"):
                done += 1
        except Exception as exc:  # noqa: BLE001
            log.debug("LLM 补判失败 %s: %s", asset_id, exc)
    return done


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

    def ensure_running(self) -> bool:
        """看门狗用：线程意外死掉后重拉。

        `start()` 见到 `_thread` 非空就返回，所以这里必须先把死线程清掉，
        否则「重启」会变成一个静默的空操作——界面上看起来一切正常，
        其实已经几个小时没研判过了。
        """
        if not settings.scheduler_in_process:
            return False
        if self._thread is not None and self._thread.is_alive():
            return True
        if self._thread is not None:
            log.error("调度线程已退出，正在重启")
            self._thread = None
        self.start()
        return True

    def _loop(self) -> None:
        from .worker import beat

        # 启动后先让发现引擎跑一会，避免一上来就抢资源
        self._stop.wait(15)
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                result = run_cycle()
                with self._lock:
                    self.last_cycle = result
                    self.cycle_count += 1
                log.info(
                    "周期 #%d 完成：研判 %s，富化 %s，LLM %s，边 %s，团伙 %s，耗时 %ss",
                    self.cycle_count, result.get("scanned"), result.get("enriched"),
                    result.get("llm_judged"), result.get("graph_edges"),
                    (result.get("campaigns") or {}).get("communities"), result.get("elapsed"),
                )
                beat("cycle", count=self.cycle_count, elapsed=result.get("elapsed"), ok=True)
            except Exception as exc:  # noqa: BLE001
                log.warning("周期异常：%s", exc, exc_info=True)
                beat("cycle", count=self.cycle_count, ok=False, error=str(exc)[:200])
            # 每轮间隔：默认跟 tick 走（60s）。发现层每 5 秒落一批库，
            # 5 分钟才研判一次会让新线索排长队，也拖慢「发现→告警」的时延。
            # 本周期超时就不再等满 tick，否则实际节拍会一路漂移。
            spent = time.monotonic() - started
            self._stop.wait(max(5, settings.monitor_tick_seconds - spent))

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
