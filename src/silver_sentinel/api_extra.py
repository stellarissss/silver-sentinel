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
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from . import __version__
from .config import settings
from .core.bus import bus
from .core.eventlog import get_log
from .core.replica import get_replica
from .db import session_scope
from .discover.engine import get_engine
from .graph.community import CommunityFinder, sync_campaigns
from .graph.schema import NODE_TYPES
from .graph.store import get_graph
from .models import (
    TIER_CANDIDATE,
    TIER_COLD,
    TIER_CONFIRMED,
    TIER_DISMISSED,
    TIER_ORDER,
    TIER_WATCH,
    Asset,
    Campaign,
    DiscoveryEvent,
    GraphEdge,
    GraphNode,
    KeywordHit,
    TaskRun,
)
from .pipeline import enrich_asset, get_scheduler, probe_web, run_cycle
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
        if source:
            stmt = stmt.where(DiscoveryEvent.source == source)
        rows = list(s.scalars(stmt))
        total = s.scalar(select(func.count(DiscoveryEvent.id))) or 0
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
        session.commit()
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

    return {
        "version": __version__,
        "capabilities": settings.capability_report(),
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

    ev = verify_evidence.__wrapped__ if hasattr(verify_evidence, "__wrapped__") else None
    with session_scope() as s:
        chain = verify_evidence(s)
    return {"eventlog": get_log().verify(deep=deep), "evidence_chain": chain}


@router.post("/api/ops/cycle")
def ops_cycle(scan_limit: int | None = None) -> dict[str, Any]:
    return run_cycle(scan_limit=scan_limit)


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
