"""v1.0 新增接口：发现流、关系图谱、运维面板、实时推送。

与 api.py 分开的原因：老接口保持稳定（有测试覆盖），新能力独立演进。
两者共用同一套 db / 服务单例。

实时推送用 SSE 而不是 WebSocket：
- 单向广播，SSE 足够；
- 浏览器原生支持 EventSource，前端不用引库；
- 穿过反代和 CDN 更省心（就是普通 HTTP 长连接）。
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from starlette.background import BackgroundTask

from . import __version__
from .config import settings
from .core.bus import bus
from .core.eventlog import get_log
from .core.replica import get_replica
from .db import session_scope
from .discover.engine import get_engine
from .domain import utcnow
from .graph.community import CommunityFinder, sync_campaigns
from .graph.schema import NODE_TYPES
from .graph.store import get_graph
from .models import (
    TIER_CANDIDATE,
    TIER_COLD,
    TIER_CONFIRMED,
    TIER_DISMISSED,
    TIER_WATCH,
    Asset,
    Campaign,
    DiscoveryEvent,
    KeywordHit,
    ReportBundle,
    TaskRun,
    WatchTarget,
)
from .pipeline import enrich_asset, get_scheduler, probe_web, run_cycle
from .report import channels as report_channels_mod
from .report import service as report_service
from .sandbox.apk import get_apk_sandbox
from .sandbox.web import get_web_sandbox

router = APIRouter()


# ---------------------------------------------------------------- 输入模型


class InjectIn(BaseModel):
    values: list[str] = Field(default_factory=list)
    source: str = "manual"
    note: str = ""


class TierIn(BaseModel):
    tier: str
    reason: str = ""
    reviewer: str = "operator"


class SearchIn(BaseModel):
    terms: list[str] = Field(default_factory=list)
    limit_per_term: int = 60


# ---------------------------------------------------------------- 发现


@router.get("/api/discover/status")
def discover_status() -> dict[str, Any]:
    return get_engine().status()


@router.get("/api/discover/events")
def discover_events(limit: int = Query(default=80, le=500), source: str = "") -> dict[str, Any]:
    with session_scope() as s:
        stmt = select(DiscoveryEvent).order_by(DiscoveryEvent.id.desc()).limit(limit)
        count_stmt = select(func.count(DiscoveryEvent.id))
        if source:
            stmt = stmt.where(DiscoveryEvent.source == source)
            count_stmt = count_stmt.where(DiscoveryEvent.source == source)
        rows = list(s.scalars(stmt))
        total = s.scalar(count_stmt) or 0
    return {
        "total": total,
        "items": [
            {
                "id": r.id,
                "source": r.source,
                "kind": r.kind,
                "value": r.value,
                "terms": r.matched_terms,
                "hint": r.score_hint,
                "asset_id": r.asset_id,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.post("/api/discover/inject")
def discover_inject(payload: InjectIn) -> dict[str, Any]:
    if not payload.values:
        raise HTTPException(400, "values 不能为空")
    return get_engine().inject(payload.values, source=payload.source, note=payload.note)


@router.post("/api/discover/search")
def discover_search(payload: SearchIn) -> dict[str, Any]:
    if not payload.terms:
        raise HTTPException(400, "terms 不能为空")
    return get_engine().search_history(payload.terms, limit_per_term=payload.limit_per_term)


@router.get("/api/discover/keywords")
def keyword_stats(limit: int = Query(default=40, le=200)) -> dict[str, Any]:
    lib = get_engine().lib
    with session_scope() as s:
        rows = list(s.scalars(select(KeywordHit).order_by(KeywordHit.hits.desc()).limit(limit)))
    return {
        "library": lib.stats(),
        "hits": [
            {"term": r.term, "hits": r.hits, "confirmed": r.confirmed, "dismissed": r.dismissed}
            for r in rows
        ],
    }


# ---------------------------------------------------------------- 图


@router.get("/api/graph/stats")
def graph_stats() -> dict[str, Any]:
    try:
        stats = get_graph().stats()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(503, f"图不可用：{exc}") from exc
    stats["node_types"] = {k: v.label for k, v in NODE_TYPES.items()}
    return stats


def _asset_node_key(asset: Asset) -> str:
    """资产 -> 图节点 key。

    不能直接用 normalized：APK 的 normalized 是上传时的文件名，
    URL 的 normalized 是完整链接，两者都不是图里的节点标识。
    """
    if asset.kind == "apk":
        meta = asset.meta or {}
        pkg = meta.get("package_name") or (meta.get("apk") or {}).get("package_name") or asset.value
        return f"apk:{pkg}"
    return f"{asset.kind}:{asset.normalized}"


@router.get("/api/graph/overview")
def graph_overview(limit: int = Query(default=120, le=400)) -> dict[str, Any]:
    """给前端力导向图用的全局子图：取高分资产及其一跳邻居。"""
    with session_scope() as s:
        rows = list(
            s.scalars(
                select(Asset)
                .where(Asset.tier.in_((TIER_CONFIRMED, TIER_WATCH)))
                .order_by(Asset.score.desc())
                .limit(limit)
            )
        )
        if not rows:
            rows = list(
                s.scalars(select(Asset).order_by(Asset.score.desc()).limit(limit))
            )
        # 高分层（已确认 / 观察）通常只有个位数，只取它们的话全局视图就十来个点，
        # 看着像图谱坏了。用候选层的高分资产补足，图才有「全局」的样子。
        shortfall = limit - len(rows)
        if shortfall > 0:
            rows.extend(
                s.scalars(
                    select(Asset)
                    .where(or_(Asset.tier.is_(None), Asset.tier.notin_((TIER_CONFIRMED, TIER_WATCH))))
                    .order_by(Asset.score.desc())
                    .limit(shortfall)
                )
            )
        keys = [_asset_node_key(a) for a in rows]

    store = get_graph()
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for key in keys[:limit]:
        sub = store.neighbors(key, depth=1, limit_nodes=40)
        for n in sub.nodes:
            nodes.setdefault(n.key, {"id": n.key, "type": n.type, "label": n.label, "props": n.props})
        for e in sub.edges:
            edges.append({"source": e.src, "target": e.dst, "rel": e.rel, "weight": e.weight})

    # 去重边
    seen: set[tuple] = set()
    uniq_edges = []
    for e in edges:
        k = (e["source"], e["target"], e["rel"])
        if k in seen:
            continue
        seen.add(k)
        uniq_edges.append(e)

    return {"nodes": list(nodes.values()), "edges": uniq_edges[:2000]}


@router.get("/api/graph/node")
def graph_node(key: str) -> dict[str, Any]:
    if not key or ":" not in key:
        raise HTTPException(400, "key 形如 domain:example.com")
    sub = get_graph().neighbors(key, depth=2)
    return sub.as_dict()


@router.post("/api/graph/rebuild")
def graph_rebuild(limit: int = Query(default=6000, le=50000), with_campaigns: bool = True) -> dict[str, Any]:
    from .graph.build import GraphBuilder

    started = time.monotonic()
    stats = GraphBuilder().build_all(limit=limit)
    if with_campaigns:
        stats["campaigns"] = sync_campaigns()
    stats["elapsed"] = round(time.monotonic() - started, 1)
    return stats


@router.get("/api/graph/communities")
def graph_communities(min_size: int = Query(default=2, ge=2, le=20)) -> dict[str, Any]:
    finder = CommunityFinder()
    comms = finder.find(min_size=min_size)
    return {
        "count": len(comms),
        "items": [
            {
                "size": c.size,
                "weight": c.weight,
                "anchor": c.anchor,
                "by_type": c.by_type,
                "nodes": c.node_keys[:60],
                "reasons": c.reasons[:6],
            }
            for c in comms[:40]
        ],
    }


@router.get("/api/campaigns/{campaign_id}/graph")
def campaign_graph(campaign_id: int) -> dict[str, Any]:
    with session_scope() as s:
        campaign = s.get(Campaign, campaign_id)
        if campaign is None:
            raise HTTPException(404, "团伙不存在")
        assets = [(a.kind, a.normalized) for a in (campaign.assets or [])]

    store = get_graph()
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for kind, value in assets[:40]:
        key = "apk" if kind == "apk" else kind
        sub = store.neighbors(f"{key}:{value}", depth=1, limit_nodes=60)
        for n in sub.nodes:
            nodes.setdefault(n.key, {"id": n.key, "type": n.type, "label": n.label})
        for e in sub.edges:
            edges.append({"source": e.src, "target": e.dst, "rel": e.rel, "weight": e.weight})
    return {"nodes": list(nodes.values()), "edges": edges[:1500], "assets": len(assets)}


# ---------------------------------------------------------------- 资产操作


@router.post("/api/assets/{asset_id}/enrich")
def asset_enrich(asset_id: int, with_sandbox: bool = False) -> dict[str, Any]:
    return enrich_asset(asset_id, with_sandbox=with_sandbox)


@router.post("/api/assets/{asset_id}/probe")
def asset_probe(asset_id: int) -> dict[str, Any]:
    if not (settings.sandbox_enabled and settings.sandbox_browser_enabled):
        raise HTTPException(400, "网页沙箱未启用")
    return probe_web(asset_id)


@router.post("/api/assets/{asset_id}/tier")
def asset_tier(asset_id: int, payload: TierIn) -> dict[str, Any]:
    valid = {TIER_CONFIRMED, TIER_WATCH, TIER_CANDIDATE, TIER_COLD, TIER_DISMISSED}
    if payload.tier not in valid:
        raise HTTPException(400, f"tier 必须是 {sorted(valid)}")
    from .domain import utcnow

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(404, "资产不存在")
        old = asset.tier
        asset.tier = payload.tier
        asset.reviewed_by = payload.reviewer
        asset.reviewed_at = utcnow()
        if payload.tier == TIER_DISMISSED:
            asset.dismiss_reason = payload.reason or "人工排除"
        else:
            asset.dismiss_reason = ""
        if payload.reason:
            asset.discovery_reason = payload.reason[:500]

        # 词库命中率统计：人工排除是唯一可靠的「这条词是误报」信号。
        # 没有这个回写，词库就永远不知道自己哪条规则在制造噪声。
        if payload.tier in (TIER_DISMISSED, TIER_CONFIRMED):
            from .models import KeywordHit

            terms = (asset.meta or {}).get("facts", {}).get("keyword_terms") or []
            for term in list(terms)[:8]:
                row = s.get(KeywordHit, str(term)[:120])
                if row is None:
                    continue
                if payload.tier == TIER_DISMISSED:
                    row.dismissed = (row.dismissed or 0) + 1
                else:
                    row.confirmed = (row.confirmed or 0) + 1
        # 人工排除 = 停止盯防。自动纳管的盯防目标要跟着等级走，
        # 否则回收站里的东西还会被调度器每小时复访一次，白烧带宽。
        target = s.scalar(
            select(WatchTarget)
            .where(WatchTarget.asset_id == asset_id, WatchTarget.auto.is_(True))
            .limit(1)
        )
        if target is not None:
            if payload.tier == TIER_DISMISSED:
                target.enabled = False
                target.next_run_at = None
            elif not target.enabled:
                target.enabled = True
                target.next_run_at = utcnow()
                target.fail_count = 0

        # session_scope 退出时自己提交，这里只需把它刷出去供下面读回
        s.flush()
        value = asset.value
    bus.publish("tier_changed", {"asset_id": asset_id, "value": value, "from": old, "to": payload.tier})
    return {"ok": True, "asset_id": asset_id, "from": old, "to": payload.tier}


@router.get("/api/assets/{asset_id}/graph")
def asset_graph(asset_id: int) -> dict[str, Any]:
    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(404, "资产不存在")
        kind = "apk" if asset.kind == "apk" else asset.kind
        key = f"{kind}:{asset.normalized}"
    return get_graph().neighbors(key, depth=2).as_dict()


# ---------------------------------------------------------------- 运维


@router.get("/api/ops/status")
def ops_status() -> dict[str, Any]:
    sched = get_scheduler()
    eng = get_engine()
    graph_info: dict[str, Any]
    try:
        graph_info = get_graph().stats()
    except Exception as exc:  # noqa: BLE001
        graph_info = {"error": str(exc)[:200]}

    log = get_log()
    from .db import db_stats
    from .enrich.icp import get_icp

    return {
        "version": __version__,
        "capabilities": settings.capability_report(),
        "icp": get_icp().status(),
        # 运维页只显示相对标识：绝对路径属于基础设施信息，不该出现在界面/截图里
        "data_dir": "data/",
        "discover": {"running": eng.status()["running"], "stats": eng.status()["stats"]},
        "scheduler": sched.status(),
        "graph": graph_info,
        "sandbox": {"web": get_web_sandbox().status(), "apk": get_apk_sandbox().status()},
        "replica": get_replica().status(),
        "eventlog": {"seq": log.head()[0], "bytes": log.size_bytes},
        "db": db_stats(),
        "bus": bus.stats(),
    }


@router.get("/api/ops/tasks")
def ops_tasks(limit: int = Query(default=30, le=200)) -> dict[str, Any]:
    with session_scope() as s:
        rows = list(s.scalars(select(TaskRun).order_by(TaskRun.id.desc()).limit(limit)))
    return {
        "items": [
            {
                "id": r.id,
                "kind": r.kind,
                "status": r.status,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "elapsed": round((r.finished_at - r.started_at).total_seconds(), 1)
                if r.finished_at and r.started_at else None,
                "stats": r.stats,
                "error": r.error[:200],
            }
            for r in rows
        ]
    }


@router.get("/api/ops/events")
def ops_events(limit: int = Query(default=60, le=500)) -> dict[str, Any]:
    log = get_log()
    return {
        "head": log.head(),
        "size": log.size_bytes,
        "items": [
            {"seq": e.seq, "ts": e.ts, "kind": e.kind, "payload": e.payload}
            for e in log.tail(limit)
        ],
    }


@router.get("/api/ops/verify")
def ops_verify(deep: bool = True) -> dict[str, Any]:
    from .db import verify_chain as verify_evidence

    with session_scope() as s:
        chain = verify_evidence(s)
    return {"eventlog": get_log().verify(deep=deep), "evidence_chain": chain}


@router.post("/api/ops/rescore")
def ops_rescore(
    limit: int = 200, asset_id: int | None = None, all_assets: bool = False, retier: bool = False
) -> dict[str, Any]:
    """用已取到的证据重算评分。

    部署新版本后必须跑一次：历史资产是在「读不到正文」的版本下打的分。
    """
    from .scoring.reassess import rescore_by_id, rescore_many

    if asset_id:
        return rescore_by_id(asset_id, trigger="api")
    return rescore_many(limit=limit, only_with_text=not all_assets, retier=retier)


@router.post("/api/assets/{asset_id}/llm")
def asset_llm(asset_id: int) -> dict[str, Any]:
    """单条 LLM 补判（手动触发，不受灰区限制）。"""
    from .pipeline import llm_judge

    return llm_judge(asset_id, force=True)


@router.post("/api/ops/cycle")
def ops_cycle(scan_limit: int | None = None) -> dict[str, Any]:
    return run_cycle(scan_limit=scan_limit)


@router.get("/api/health/self")
def health_self() -> dict[str, Any]:
    """自检：这台机器现在还能不能「持续侦查、持续取证」。

    只返回事实，不做判断以外的修饰——运维需要的是「哪条线停了、积压多深」，
    而不是一个绿色的 ok。
    """
    import shutil

    from . import worker
    from .db import db_stats
    from .models import Evidence
    from .vault import VaultError, get_vault

    beats = worker.heartbeat_snapshot()
    cycles = beats.get("cycle") or {}
    capture = beats.get("capture") or {}
    stats = db_stats()

    with session_scope() as s:
        evidence_total = s.scalar(select(func.count(Evidence.id))) or 0
        evidence_active = s.scalar(
            select(func.count(Evidence.id)).where(Evidence.deleted_at.is_(None))
        ) or 0
        watch = s.scalar(
            select(func.count(Asset.id)).where(Asset.tier.in_((TIER_WATCH, TIER_CONFIRMED)))
        ) or 0
        captured = s.scalar(
            select(func.count(Asset.id)).where(Asset.capture_state == "captured")
        ) or 0
        # 吞吐量：只看总量会被「历史很多」骗过去。真正要回答的是
        # 「最近一小时还在出证据吗」——假绿（指标全绿、done_total 不动）
        # 正是靠这三个窗口暴露的。
        now = utcnow()
        windows = {}
        for label, hours in (("1h", 1), ("6h", 6), ("24h", 24)):
            cutoff = now - timedelta(hours=hours)
            windows[label] = s.scalar(
                select(func.count(Evidence.id)).where(Evidence.captured_at >= cutoff)
            ) or 0
        last_evidence = s.scalar(select(func.max(Evidence.captured_at)))

    usage = shutil.disk_usage(settings.data_dir)
    free_gb = round(usage.free / 1024**3, 2)
    stream = get_engine().status().get("stats", {})

    try:
        vault_info = get_vault().status()
    except VaultError as exc:
        vault_info = {"enabled": settings.vault_enabled, "error": str(exc)}

    problems: list[str] = []
    if not worker.is_alive("capture"):
        problems.append("取证线程未运行")
    if cycles.get("age_s") and cycles["age_s"] > 300:
        problems.append(f"主周期已 {int(cycles['age_s'])} 秒没有心跳")
    if free_gb < 2:
        problems.append(f"磁盘剩余 {free_gb}GB")
    queue = worker.capture_queue_health()
    if queue.get("starved"):
        problems.append(
            f"有 {queue.get('pending_assets', 0)} 个待取证资产，但队列里没有到期任务"
        )
    if (queue.get("oldest_queued_minutes") or 0) > 45:
        problems.append(f"取证队列有任务已等待 {queue['oldest_queued_minutes']} 分钟未执行")
    if (queue.get("worker_heartbeat_age_s") or 0) > 300:
        problems.append(f"取证线程心跳已停 {int(queue['worker_heartbeat_age_s'])} 秒")

    # 看门狗自己也可能停：timer 没跑，服务坏了没人重启。它每 2 分钟留一次
    # 记录，15 分钟没动静就说明检查链本身断了。
    watchdog: dict[str, Any] = {"present": False}
    try:
        wd_path = Path(settings.data_dir) / "watchdog.json"
        if wd_path.is_file():
            wd = json.loads(wd_path.read_text(encoding="utf-8"))
            wd_age = int(time.time() - float(wd.get("ts") or 0))
            watchdog = {
                "present": True,
                "age_s": wd_age,
                "ok": wd.get("ok"),
                "action": wd.get("action"),
            }
            if wd_age > 900:
                problems.append(f"看门狗已 {wd_age // 60} 分钟没有检查（timer 可能停了）")
    except Exception as exc:  # noqa: BLE001
        watchdog = {"present": False, "error": str(exc)[:120]}
    # 假绿：所有心跳都正常，但两小时一条证据没出。要么队列全在冷却，
    # 要么浏览器每页都在超时——两种都需要人看一眼，不能算 ok。
    last_age = round((utcnow() - last_evidence).total_seconds(), 1) if last_evidence else None
    if windows["1h"] == 0 and windows["6h"] > 0:
        if (queue.get("pending_assets") or 0) > 0:
            problems.append("最近 1 小时没有新证据（取证可能在空转）")
        else:
            # 队列真的空了：不是取证坏了，是发现层这段时间没产出新候选。
            # 单独说清楚，避免运维对着正常的空队列去查浏览器。
            problems.append("最近 1 小时无新证据，队列也无积压（发现供给不足）")
    if windows["6h"] == 0 and (queue.get("pending_assets") or 0) > 0:
        problems.append(f"6 小时无新证据，但仍有 {queue.get('pending_assets')} 个待取证资产")

    return {
        "ok": not problems,
        "problems": problems,
        "worker": worker.stats(),
        "heartbeats": beats,
        "cycle": {"count": cycles.get("count", 0), "age_s": cycles.get("age_s"), "ok": cycles.get("ok")},
        "capture": {**queue, "worker": capture},
        "assets": {"total": stats.get("assets", 0), "captured": captured, "watch": watch},
        "watchdog": watchdog,
        "evidence": {
            "total": evidence_total,
            "active": evidence_active,
            "last_1h": windows["1h"],
            "last_6h": windows["6h"],
            "last_24h": windows["24h"],
            "last_age_s": last_age,
        },
        "discover": stream,
        "disk": {"free_gb": free_gb, "used_pct": round(usage.used / usage.total * 100, 1)},
        "vault": vault_info,
    }


@router.post("/api/ops/replica")
def ops_replica(include_db: bool = False) -> dict[str, Any]:
    return get_replica().run_once(include_db=include_db)


@router.post("/api/ops/communities")
def ops_communities(min_size: int = 2) -> dict[str, Any]:
    return sync_campaigns(min_size=min_size)


@router.get("/api/metrics")
def metrics() -> Any:
    """Prometheus 文本格式。不引 prometheus_client，手写两个计数器就够。"""
    if not settings.metrics_enabled:
        raise HTTPException(404, "指标未启用")
    from .db import db_stats

    st = db_stats()
    eng = get_engine().status()
    lines = [
        "# HELP silver_assets_total 资产总数",
        "# TYPE silver_assets_total gauge",
        f"silver_assets_total {st['assets']}",
        "# HELP silver_evidence_total 证据条数",
        "# TYPE silver_evidence_total gauge",
        f"silver_evidence_total {st['evidence']}",
        "# HELP silver_graph_nodes 图节点数",
        "# TYPE silver_graph_nodes gauge",
        f"silver_graph_nodes {st['graph_nodes']}",
        "# HELP silver_graph_edges 图边数",
        "# TYPE silver_graph_edges gauge",
        f"silver_graph_edges {st['graph_edges']}",
        "# HELP silver_discover_seen_total 发现的域名总数",
        "# TYPE silver_discover_seen_total counter",
        f"silver_discover_seen_total {eng['stats']['seen']}",
        "# HELP silver_discover_queued_total 入队候选数",
        "# TYPE silver_discover_queued_total counter",
        f"silver_discover_queued_total {eng['stats']['queued']}",
        "# HELP silver_eventlog_bytes 事件日志字节数",
        "# TYPE silver_eventlog_bytes gauge",
        f"silver_eventlog_bytes {get_log().size_bytes}",
    ]
    return StreamingResponse(iter(["\n".join(lines) + "\n"]), media_type="text/plain; version=0.0.4")


# ---------------------------------------------------------------- SSE


@router.get("/api/stream")
async def stream(request: Request, since: int = 0) -> StreamingResponse:
    """Server-Sent Events。慢客户端会收到 gap 提示，让它重拉快照。"""

    async def gen():
        cursor = since or bus.cursor
        yield f"event: hello\ndata: {json.dumps({'cursor': cursor})}\n\n"
        idle = 0.0
        while True:
            if await request.is_disconnected():
                break
            events, gap = bus.since(cursor, timeout=1.0)
            if gap:
                yield f"event: gap\ndata: {json.dumps({'cursor': cursor, 'now': bus.cursor})}\n\n"
                cursor = bus.cursor
            for e in events:
                cursor = e.seq
                yield f"event: {e.kind}\ndata: {json.dumps(e.data, ensure_ascii=False, default=str)}\n\n"
            if not events:
                idle += 1.0
                if idle >= settings.stream_heartbeat:
                    idle = 0.0
                    yield f": heartbeat {int(time.time())}\n\n"
            else:
                idle = 0.0
            await asyncio.sleep(0.2)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ---------------------------------------------------------------- 半自动举报
#
# 服务端只准备材料，不代提交。提交动作发生在用户自己的浏览器里：
# 扩展按 fill 载荷填字段，人过验证码、点提交，再回来登记回执。

class ReportIn(BaseModel):
    asset_id: int
    channel: str = ""
    harm: str = ""
    reporter: str = ""
    api_base: str = ""
    # 用户可在前端改过的正文；为空则按渠道模板生成
    body: str = ""


class MarkIn(BaseModel):
    status: str
    receipt: str = ""
    note: str = ""


def _report_guard(request: Request) -> None:
    """扩展取数鉴权。

    设了 SILVER_REPORT_EXTENSION_TOKEN 就要求带同一令牌；没设则只放行本机，
    避免把「给浏览器扩展取证据」的接口暴露到公网。
    """
    expect = settings.report_extension_token.strip()
    if expect:
        got = request.headers.get("x-ss-token", "")
        if not secrets.compare_digest(got, expect):
            raise HTTPException(status_code=401, detail="令牌无效")
        return
    host = (request.client.host if request.client else "") or ""
    if host not in {"127.0.0.1", "::1", "localhost", "testclient"}:
        raise HTTPException(status_code=403, detail="未配置令牌时仅允许本机访问")


@router.get("/api/report/channels")
def report_channels(harm: str = "") -> dict[str, Any]:
    return {"items": report_channels_mod.catalog(harm), "harm_types": report_channels_mod.HARM_TYPES}


@router.get("/api/report/preview")
def report_preview(asset_id: int, channel: str = "", harm: str = "") -> dict[str, Any]:
    with session_scope() as session:
        try:
            return report_service.preview(session, asset_id, channel, harm)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/api/report/build")
def report_build(payload: ReportIn, request: Request) -> dict[str, Any]:
    api_base = payload.api_base or str(request.base_url).rstrip("/")
    with session_scope() as session:
        try:
            row = report_service.build(
                session, payload.asset_id, payload.channel,
                harm_override=payload.harm, reporter=payload.reporter, api_base=api_base,
                body_override=payload.body,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return report_service.as_dict(row, full=True)


@router.get("/api/report/bundles")
def report_bundles(asset_id: int | None = None, limit: int = Query(default=30, le=200)) -> dict[str, Any]:
    with session_scope() as session:
        stmt = select(ReportBundle).order_by(ReportBundle.id.desc()).limit(limit)
        if asset_id:
            stmt = stmt.where(ReportBundle.asset_id == asset_id)
        rows = list(session.scalars(stmt))
        return {"items": [report_service.as_dict(r) for r in rows]}


@router.get("/api/report/bundles/{code}")
def report_bundle(code: str, full: bool = False) -> dict[str, Any]:
    with session_scope() as session:
        row = session.scalars(select(ReportBundle).where(ReportBundle.code == code)).first()
        if row is None:
            raise HTTPException(status_code=404, detail="材料不存在")
        return report_service.as_dict(row, full=full)


@router.get("/api/report/bundles/{code}/fill")
def report_fill(code: str, request: Request) -> dict[str, Any]:
    """浏览器扩展取「填什么」。"""
    _report_guard(request)
    with session_scope() as session:
        row = session.scalars(select(ReportBundle).where(ReportBundle.code == code)).first()
        if row is None:
            raise HTTPException(status_code=404, detail="材料不存在")
        payload = dict(row.fill or {})
        payload["body"] = row.body
        payload["token"] = settings.report_extension_token
        return payload


@router.get("/api/report/bundles/{code}/file")
def report_file(code: str, kind: str = "zip"):
    """材料下载。不校验令牌：code 是 12 位随机 hex，不可枚举；
    且浏览器直接点链接下载时无法附加自定义头。"""
    with session_scope() as session:
        row = session.scalars(select(ReportBundle).where(ReportBundle.code == code)).first()
        if row is None:
            raise HTTPException(status_code=404, detail="材料不存在")
        path = report_service.file_of(row, kind)
        name = path.name
    if not path.exists():
        raise HTTPException(status_code=410, detail="文件已清理，请重新生成材料")
    return FileResponse(path, filename=name, media_type="application/octet-stream")


@router.post("/api/report/bundles/{code}/mark")
def report_mark(code: str, payload: MarkIn) -> dict[str, Any]:
    with session_scope() as session:
        try:
            row = report_service.mark(session, code, payload.status, payload.receipt, payload.note)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return report_service.as_dict(row)


# ---------------------------------------------------------------- 风险指数

@router.get("/api/risk")
def risk_index() -> dict[str, Any]:
    """四项加权的风险指数，每项都能展开看构成。"""
    from .risk import compute

    return compute()


# ---------------------------------------------------------------- 取证队列

@router.get("/api/capture/queue")
def capture_queue() -> dict[str, Any]:
    from .capture import queue_summary

    return queue_summary()


@router.post("/api/capture/run")
def capture_run(limit: int = Query(default=2, ge=1, le=10)) -> dict[str, Any]:
    from .capture import backfill, run_batch

    backfill(limit=settings.capture_backfill_limit)
    return run_batch(limit=limit)


@router.post("/api/assets/{asset_id}/capture")
def asset_capture(asset_id: int) -> dict[str, Any]:
    """手动「立即取证」。同步执行，返回这次落了哪些证据。"""
    from .capture import capture_asset, enqueue

    if not (settings.sandbox_enabled and settings.sandbox_browser_enabled):
        raise HTTPException(400, "网页沙箱未启用")
    enqueue(asset_id, reason="manual", priority=5)
    result = capture_asset(asset_id)
    return result


# ---------------------------------------------------------------- 证据

@router.get("/api/evidence/{evidence_id}/download")
def evidence_download(evidence_id: int):
    from fastapi.responses import FileResponse

    from . import evidence as evidence_service
    from .models import Evidence

    with session_scope() as session:
        row = session.get(Evidence, evidence_id)
        if row is None or row.deleted_at is not None:
            raise HTTPException(status_code=404, detail="证据不存在或已删除")
        name = f"{row.kind}-{row.id}{Path(row.path).suffix or '.bin'}"
        mime = row.mime or "application/octet-stream"
        path = evidence_service.materialize(row)
    if path is None:
        raise HTTPException(status_code=410, detail="文件已丢失（明文与密文均不可读）")

    def _cleanup_materialized(p: Path) -> None:
        from .config import settings

        # materialize() 在明文存在时返回的是 evidence/ 里的原文件，绝不能删。
        # 只有解密落到 data/tmp 的临时文件才在响应结束后回收，别让已脱敏
        # 的证据重新裸奔在磁盘上（最多滞留 1 小时等 housekeeping 太久了）。
        try:
            if p.resolve().parent == (settings.data_dir / "tmp").resolve():
                p.unlink(missing_ok=True)
        except OSError:
            pass

    return FileResponse(
        path,
        filename=name,
        media_type=mime,
        background=BackgroundTask(_cleanup_materialized, path),
    )


@router.get("/api/evidence/{evidence_id}/preview")
def evidence_preview(evidence_id: int):
    """内联预览：图片直接显示，文本按纯文本返回。

    明文被证据仓脱敏后，这里必须能透明解密——否则界面上每一格都显示
    「文件已丢失」，取证做多少都等于零。
    """
    from fastapi.responses import PlainTextResponse, Response

    from . import evidence as evidence_service
    from .models import Evidence

    with session_scope() as session:
        row = session.get(Evidence, evidence_id)
        if row is None or row.deleted_at is not None:
            raise HTTPException(status_code=404, detail="证据不存在或已删除")
        mime = row.mime or ""
        data = evidence_service.read_bytes(row)
    if not data:
        raise HTTPException(status_code=410, detail="文件已丢失（明文与密文均不可读）")
    if mime.startswith("image/"):
        return Response(data, media_type=mime)
    if mime.startswith("text/") or mime == "application/json":
        return PlainTextResponse(data[:200_000].decode("utf-8", "replace"))
    raise HTTPException(status_code=415, detail="该类型不支持在线预览，请下载")


@router.delete("/api/evidence/{evidence_id}")
def evidence_delete(evidence_id: int, reason: str = "", request: Request = None) -> dict[str, Any]:
    """软删除。文件进回收站，链上留 tombstone。"""
    from .evidence import soft_delete

    by = "web"
    if request is not None:
        try:
            by = f"web@{request.client.host}" if request.client else "web"
        except Exception:  # noqa: BLE001
            by = "web"
    with session_scope() as session:
        result = soft_delete(session, evidence_id, by=by, reason=reason)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "删除失败"))
    return result


@router.post("/api/evidence/{evidence_id}/restore")
def evidence_restore(evidence_id: int) -> dict[str, Any]:
    from .evidence import restore

    with session_scope() as session:
        result = restore(session, evidence_id)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "恢复失败"))
    return result


@router.get("/api/assets/{asset_id}/evidence.zip")
def asset_evidence_zip(asset_id: int):
    """整套证据打包下载。

    走临时文件 + FileResponse，避免把一个几十 MB 的 zip 整个读进内存再吐出去。
    下载完成后由后台任务删掉临时文件。
    """
    from fastapi.responses import FileResponse

    from .capture import asset_zip_file

    try:
        path = asset_zip_file(asset_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return FileResponse(
        path,
        media_type="application/zip",
        filename=f"evidence-{asset_id}.zip",
        background=BackgroundTask(lambda p: p.unlink(missing_ok=True) if p.exists() else None, path),
    )


@router.get("/api/assets/{asset_id}/evidence")
def asset_evidence(asset_id: int) -> dict[str, Any]:
    from .capture import evidence_matrix

    return evidence_matrix(asset_id)


# ---------------------------------------------------------------- 设置（LLM / 出口）

class LLMIn(BaseModel):
    base_url: str = ""
    api_key: str = ""
    model: str = ""
    enabled: bool = True
    gray_low: float | None = None
    gray_high: float | None = None


class EgressIn(BaseModel):
    mode: str = "auto"
    proxies: str = ""


class CaptureIn(BaseModel):
    apk_max_mb: int | None = None
    apk_daily_mb: int | None = None
    apk_tiers: str | None = None


@router.get("/api/settings")
def settings_read() -> dict[str, Any]:
    from . import runtime_settings

    return runtime_settings.llm_public()


@router.post("/api/settings/llm")
def settings_llm(payload: LLMIn) -> dict[str, Any]:
    from . import runtime_settings

    values: dict[str, str] = {
        runtime_settings.LLM_BASE_URL: payload.base_url.strip(),
        runtime_settings.LLM_MODEL: payload.model.strip(),
        runtime_settings.LLM_ENABLED: "1" if payload.enabled else "0",
    }
    # 留空表示「不改」，避免前端把掩码当新密钥写回去
    if payload.api_key.strip():
        values[runtime_settings.LLM_API_KEY] = payload.api_key.strip()
    if payload.gray_low is not None:
        values[runtime_settings.LLM_GRAY_LOW] = str(payload.gray_low)
    if payload.gray_high is not None:
        values[runtime_settings.LLM_GRAY_HIGH] = str(payload.gray_high)
    runtime_settings.set_many(values, by="web")
    return runtime_settings.llm_public()


@router.post("/api/settings/egress")
def settings_egress(payload: EgressIn) -> dict[str, Any]:
    from . import runtime_settings

    mode = payload.mode if payload.mode in {"auto", "proxy", "direct", "off"} else "auto"
    raw = payload.proxies.strip()
    values: dict[str, str] = {runtime_settings.EGRESS_MODE: mode}
    # 留空表示「保持现有代理」——否则每次改模式都会把凭据清掉；
    # 单个 "-" 是显式清空，前端有个专门的按钮走这条路径。
    if raw == "-":
        values[runtime_settings.EGRESS_PROXIES] = ""
    elif raw:
        values[runtime_settings.EGRESS_PROXIES] = raw
    runtime_settings.set_many(values, by="web")
    return runtime_settings.llm_public()


@router.post("/api/settings/capture")
def settings_capture(payload: CaptureIn) -> dict[str, Any]:
    from . import runtime_settings

    values: dict[str, str] = {}
    if payload.apk_max_mb is not None:
        values[runtime_settings.CAPTURE_APK_MAX_MB] = str(max(1, payload.apk_max_mb))
    if payload.apk_daily_mb is not None:
        values[runtime_settings.CAPTURE_APK_DAILY_MB] = str(max(10, payload.apk_daily_mb))
    if payload.apk_tiers is not None:
        values[runtime_settings.CAPTURE_AUTO_APK_TIERS] = payload.apk_tiers
    if values:
        runtime_settings.set_many(values, by="web")
    return runtime_settings.llm_public()


@router.post("/api/settings/llm/test")
def settings_llm_test(payload: LLMIn) -> dict[str, Any]:
    from .analyzers import llm as llm_analyzer

    return llm_analyzer.test_connection(
        base_url=payload.base_url.strip(), api_key=payload.api_key.strip(), model=payload.model.strip()
    )


# ---------------------------------------------------------------- 漏斗与监控

@router.get("/api/funnel")
def funnel() -> dict[str, Any]:
    """五段漏斗：看见 → 命中 → 去重 → 快筛 → 入池。

    运维页之前只有总数，看不出「卡在哪」。这里把每一段的绝对值和转化率
    都摊开，配合每小时一行，能直接判断是词库太窄还是阈值太高。
    """
    from .models import Evidence as _Evidence

    engine = get_engine()
    stats = engine.status()
    with session_scope() as session:
        from datetime import timedelta

        cutoff = utcnow() - timedelta(hours=24)
        admitted_24h = session.scalar(
            select(func.count(Asset.id)).where(Asset.first_seen >= cutoff)
        ) or 0
        events_24h = session.scalar(
            select(func.count(DiscoveryEvent.id)).where(DiscoveryEvent.created_at >= cutoff)
        ) or 0
        # 覆盖率必须分子分母同口径：只算有效资产里有多少已经看过页面。
        # 之前分子把已排除资产也算进来，出现过 200% 这种自相矛盾的数字。
        captured = session.scalar(
            select(func.count(func.distinct(_Evidence.asset_id)))
            .join(Asset, Asset.id == _Evidence.asset_id)
            .where(
                _Evidence.kind.in_(("page_html", "screenshot")),
                _Evidence.deleted_at.is_(None),
                Asset.tier.in_(("confirmed", "watch", "candidate")),
            )
        ) or 0
        active = session.scalar(
            select(func.count(Asset.id)).where(Asset.tier.in_(("confirmed", "watch", "candidate")))
        ) or 0

    live = stats.get("stats") or stats
    seen = live.get("seen", 0) or 0
    matched = live.get("matched", 0) or 0
    duplicated = live.get("duplicated", 0) or 0
    queued = live.get("queued", 0) or 0
    cold = live.get("cold", 0) or 0

    steps = [
        {"key": "seen", "label": "已解析证书", "value": seen},
        {"key": "matched", "label": "命中词根", "value": matched},
        {"key": "deduped", "label": "去重后", "value": max(0, matched - duplicated)},
        {"key": "screened", "label": "通过快筛", "value": max(0, matched - duplicated - cold)},
        {"key": "admitted", "label": "实际入池", "value": queued},
    ]
    for i, step in enumerate(steps):
        prev = steps[i - 1]["value"] if i else step["value"]
        step["rate"] = round(step["value"] / prev, 3) if prev else 0.0

    return {
        "steps": steps,
        "coverage": {
            "active": active,
            "captured": captured,
            "ratio": round(min(1.0, captured / active), 3) if active else 0.0,
        },
        "admitted_24h": admitted_24h,
        "events_24h": events_24h,
        "engine": stats,
    }


class WatchSyncIn(BaseModel):
    limit: int = 60


@router.post("/api/watch/sync")
def watch_sync(payload: WatchSyncIn = WatchSyncIn()) -> dict[str, Any]:
    """把现有的 watch/confirmed 资产批量纳入监控。"""
    from .capture import ensure_watch, prune_watch

    with session_scope() as session:
        ids = list(
            session.scalars(
                select(Asset.id)
                .where(Asset.tier.in_((TIER_CONFIRMED, TIER_WATCH)))
                .order_by(Asset.score.desc())
                .limit(max(1, min(500, payload.limit)))
            )
        )
    added = sum(1 for aid in ids if ensure_watch(aid))
    removed = prune_watch()
    return {"considered": len(ids), "added": added, "removed": removed}
