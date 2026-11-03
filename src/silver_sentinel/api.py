"""FastAPI 应用：控制台与 REST 接口。"""

from __future__ import annotations

import tempfile
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from .analyzers import llm as llm_analyzer
from .config import settings
from .db import init_db, session_scope, verify_chain
from .domain import CATEGORY_LABELS, VERDICT_LABELS, utcnow
from .intake import scan
from .models import Asset, Campaign, Evidence, ReportDraft, ScanRun, SignalRow, WatchTarget
from .respond import CHANNELS, advise, build, export_bundle
from .scoring.engine import load_ruleset

WEB_DIR = Path(__file__).parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    init_db()
    from .monitor import start_background

    import os

    if os.environ.get("SILVER_AUTOSTART_MONITOR", "0").strip() in {"1", "true", "yes"}:
        start_background()
    yield


app = FastAPI(title="银发哨兵", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=WEB_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))


class ScanIn(BaseModel):
    kind: str = Field(default="url", description="url|domain|apk|text|miniapp|account")
    value: str = Field(..., min_length=1)
    text: str | None = None
    meta: dict[str, Any] | None = None
    run_llm: bool = True


class WatchIn(BaseModel):
    kind: str = Field(default="keyword", description="keyword|domain|brand")
    value: str = Field(..., min_length=2)
    interval_minutes: int = 360
    note: str = ""


class ReviewIn(BaseModel):
    verdict: str
    reviewer: str = ""
    note: str = ""


def _asset_row(asset: Asset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "kind": asset.kind,
        "value": asset.value,
        "score": round(asset.score, 1),
        "confidence": round(asset.confidence, 3),
        "verdict": asset.verdict,
        "verdict_label": VERDICT_LABELS.get(asset.verdict, asset.verdict),
        "campaign_id": asset.campaign_id,
        "first_seen": asset.first_seen.isoformat(),
        "last_seen": asset.last_seen.isoformat(),
        "scan_count": asset.scan_count,
        "reviewed_by": asset.reviewed_by,
    }


# ---------------------------------------------------------------- 页面


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request, "version": "0.1.0"})


# ---------------------------------------------------------------- 接口


@app.get("/api/health")
def health() -> dict[str, Any]:
    chain = {"ok": None}
    try:
        with session_scope() as session:
            chain = verify_chain(session)
    except Exception as exc:  # noqa: BLE001
        chain = {"ok": False, "error": str(exc)}

    return {
        "status": "ok",
        "version": "0.1.0",
        "network": settings.allow_network,
        "llm": llm_analyzer.status(),
        "evidence_chain": chain,
        "rules": {"count": len(load_ruleset().rules), "version": load_ruleset().version},
    }


@app.get("/api/stats")
def stats() -> dict[str, Any]:
    with session_scope() as session:
        total = session.scalar(select(func.count(Asset.id))) or 0
        by_verdict = dict(
            session.execute(select(Asset.verdict, func.count(Asset.id)).group_by(Asset.verdict)).all()
        )
        by_category = dict(
            session.execute(select(SignalRow.category, func.count(SignalRow.id)).group_by(SignalRow.category)).all()
        )
        campaigns = session.scalar(select(func.count(Campaign.id))) or 0
        reports = session.scalar(select(func.count(ReportDraft.id))) or 0
        since = utcnow() - timedelta(days=7)
        recent = session.scalar(select(func.count(Asset.id)).where(Asset.first_seen >= since)) or 0
        pending = session.scalar(
            select(func.count(Asset.id)).where(Asset.verdict.in_(["high_risk", "confirmed"]))
        ) or 0

        top = list(
            session.scalars(
                select(Asset).where(Asset.score > 0).order_by(Asset.score.desc()).limit(8)
            )
        )

        return {
            "total_assets": total,
            "by_verdict": {k: v for k, v in by_verdict.items()},
            "verdict_labels": VERDICT_LABELS,
            "by_category": {CATEGORY_LABELS.get(k, k): v for k, v in by_category.items()},
            "campaigns": campaigns,
            "reports": reports,
            "recent_7d": recent,
            "pending_action": pending,
            "top_assets": [_asset_row(a) for a in top],
        }


@app.post("/api/scan")
def api_scan(payload: ScanIn) -> dict[str, Any]:
    if payload.kind == "apk":
        raise HTTPException(status_code=400, detail="APK 请使用 /api/scan/apk 上传文件")
    try:
        result = scan(
            payload.kind,
            payload.value,
            text=payload.text,
            meta=payload.meta,
            run_llm=payload.run_llm,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"研判失败：{exc}") from exc

    out = result.as_dict()
    out["advice"] = advise(result.assessment.verdict)
    out["priority"] = out.get("priority")
    return out


@app.post("/api/scan/apk")
async def api_scan_apk(file: UploadFile, run_llm: bool = Query(default=True)) -> dict[str, Any]:
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="请上传 .apk 文件")

    data = await file.read()
    if len(data) > 150 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="文件超过 150MB")
    if not data.startswith(b"PK"):
        raise HTTPException(status_code=400, detail="不是有效的 APK（ZIP）文件")

    tmp = Path(tempfile.mkstemp(suffix=".apk", dir=str(settings.data_dir / "evidence"))[1])
    try:
        tmp.write_bytes(data)
        result = scan("apk", file.filename, file_path=str(tmp), run_llm=run_llm)
    finally:
        tmp.unlink(missing_ok=True)

    out = result.as_dict()
    out["advice"] = advise(result.assessment.verdict)
    return out


@app.get("/api/assets")
def api_assets(
    verdict: str | None = None,
    q: str | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
) -> dict[str, Any]:
    with session_scope() as session:
        stmt = select(Asset).order_by(Asset.score.desc(), Asset.last_seen.desc())
        if verdict:
            stmt = stmt.where(Asset.verdict == verdict)
        if q:
            stmt = stmt.where(Asset.value.contains(q))
        rows = list(session.scalars(stmt.offset(offset).limit(limit)))

        count_stmt = select(func.count(Asset.id))
        if verdict:
            count_stmt = count_stmt.where(Asset.verdict == verdict)
        if q:
            count_stmt = count_stmt.where(Asset.value.contains(q))
        total = session.scalar(count_stmt) or 0
        return {"items": [_asset_row(a) for a in rows], "total": total}


@app.get("/api/assets/{asset_id}")
def api_asset(asset_id: int) -> dict[str, Any]:
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="资产不存在")

        signals = list(
            session.scalars(
                select(SignalRow).where(SignalRow.asset_id == asset_id).order_by(SignalRow.weight.desc())
            )
        )
        evidence = list(
            session.scalars(select(Evidence).where(Evidence.asset_id == asset_id).order_by(Evidence.id))
        )
        campaign = session.get(Campaign, asset.campaign_id) if asset.campaign_id else None

        return {
            **_asset_row(asset),
            "normalized": asset.normalized,
            "meta": asset.meta,
            "notes": asset.notes,
            "signals": [
                {
                    "rule_id": s.rule_id,
                    "category": s.category,
                    "category_label": CATEGORY_LABELS.get(s.category, s.category),
                    "title": s.title,
                    "weight": s.weight,
                    "confidence": s.confidence,
                    "detail": s.detail,
                    "evidence": s.evidence,
                }
                for s in signals
            ],
            "evidence": [
                {
                    "id": e.id,
                    "kind": e.kind,
                    "sha256": e.sha256,
                    "chain_hash": e.chain_hash,
                    "size": e.size,
                    "note": e.note,
                    "captured_at": e.captured_at.isoformat(),
                }
                for e in evidence
            ],
            "campaign": {"id": campaign.id, "name": campaign.name, "summary": campaign.summary} if campaign else None,
            "advice": advise(asset.verdict),
        }


@app.post("/api/assets/{asset_id}/report")
def api_report(asset_id: int, channel: str = "12321", reporter: str = "") -> dict[str, Any]:
    with session_scope() as session:
        try:
            draft = build(session, asset_id, channel, reporter=reporter)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"id": draft.id, "channel": draft.channel, "body": draft.body, "payload": draft.payload}


@app.post("/api/assets/{asset_id}/bundle")
def api_bundle(asset_id: int) -> dict[str, Any]:
    with session_scope() as session:
        try:
            return export_bundle(session, asset_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/assets/{asset_id}/review")
def api_review(asset_id: int, payload: ReviewIn) -> dict[str, Any]:
    if payload.verdict not in VERDICT_LABELS:
        raise HTTPException(status_code=400, detail="非法判定")
    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            raise HTTPException(status_code=404, detail="资产不存在")
        asset.verdict = payload.verdict
        asset.reviewed_by = payload.reviewer or "local"
        asset.reviewed_at = utcnow()
        if payload.note:
            asset.notes = payload.note
        return {"ok": True, "id": asset.id, "verdict": asset.verdict}


@app.get("/api/campaigns")
def api_campaigns() -> dict[str, Any]:
    with session_scope() as session:
        rows = list(session.scalars(select(Campaign).order_by(Campaign.last_seen.desc()).limit(100)))
        counts = dict(
            session.execute(
                select(Asset.campaign_id, func.count(Asset.id)).group_by(Asset.campaign_id)
            ).all()
        )
        return {
            "items": [
                {
                    "id": c.id,
                    "name": c.name,
                    "status": c.status,
                    "summary": c.summary,
                    "assets": counts.get(c.id, 0),
                    "first_seen": c.first_seen.isoformat(),
                    "last_seen": c.last_seen.isoformat(),
                }
                for c in rows
            ]
        }


@app.get("/api/watch")
def api_watch_list() -> dict[str, Any]:
    with session_scope() as session:
        rows = list(session.scalars(select(WatchTarget).order_by(WatchTarget.id)))
        return {
            "items": [
                {
                    "id": t.id,
                    "kind": t.kind,
                    "value": t.value,
                    "interval_minutes": t.interval_minutes,
                    "enabled": t.enabled,
                    "note": t.note,
                    "last_run_at": t.last_run_at.isoformat() if t.last_run_at else None,
                    "next_run_at": t.next_run_at.isoformat() if t.next_run_at else None,
                }
                for t in rows
            ]
        }


@app.post("/api/watch")
def api_watch_add(payload: WatchIn) -> dict[str, Any]:
    if payload.kind not in {"keyword", "domain", "brand"}:
        raise HTTPException(status_code=400, detail="kind 只能是 keyword/domain/brand")
    with session_scope() as session:
        exists = session.scalar(
            select(WatchTarget).where(WatchTarget.kind == payload.kind, WatchTarget.value == payload.value)
        )
        if exists:
            return {"ok": True, "id": exists.id, "existed": True}
        target = WatchTarget(
            kind=payload.kind,
            value=payload.value.strip(),
            interval_minutes=max(15, payload.interval_minutes),
            note=payload.note,
            next_run_at=utcnow(),
        )
        session.add(target)
        session.flush()
        return {"ok": True, "id": target.id, "existed": False}


@app.delete("/api/watch/{target_id}")
def api_watch_delete(target_id: int) -> dict[str, Any]:
    with session_scope() as session:
        target = session.get(WatchTarget, target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="监控目标不存在")
        session.delete(target)
        return {"ok": True}


@app.post("/api/watch/run")
def api_watch_run() -> dict[str, Any]:
    from .monitor import run_due

    return {"results": run_due()}


@app.get("/api/runs")
def api_runs(limit: int = 30) -> dict[str, Any]:
    with session_scope() as session:
        rows = list(session.scalars(select(ScanRun).order_by(ScanRun.id.desc()).limit(limit)))
        return {
            "items": [
                {
                    "id": r.id,
                    "target_id": r.target_id,
                    "status": r.status,
                    "trigger": r.trigger,
                    "started_at": r.started_at.isoformat(),
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                    "stats": r.stats,
                    "error": r.error,
                }
                for r in rows
            ]
        }


@app.get("/api/channels")
def api_channels() -> dict[str, Any]:
    return {"items": [{"key": k, **v} for k, v in CHANNELS.items()]}


@app.get("/api/rules")
def api_rules() -> dict[str, Any]:
    rs = load_ruleset()
    return {
        "version": rs.version,
        "thresholds": rs.thresholds,
        "count": len(rs.rules),
        "items": [
            {
                "id": r.id,
                "category": r.category,
                "title": r.title,
                "weight": r.weight,
                "confidence": r.confidence,
                "detail": r.detail,
            }
            for r in rs.rules
        ],
    }


@app.get("/api/verify-chain")
def api_verify_chain(asset_id: int | None = None) -> dict[str, Any]:
    with session_scope() as session:
        return verify_chain(session, asset_id)


@app.exception_handler(Exception)
async def unhandled_error(request: Request, exc: Exception) -> JSONResponse:  # noqa: ARG001
    return JSONResponse(status_code=500, content={"detail": f"服务内部错误：{exc}"})


def serve() -> None:
    import uvicorn

    uvicorn.run("silver_sentinel.api:app", host="0.0.0.0", port=8000, reload=False)
