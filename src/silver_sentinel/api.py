"""FastAPI 应用：控制台与 REST 接口。"""

from __future__ import annotations

import tempfile
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from . import __version__, webauth
from .analyzers import llm as llm_analyzer
from .config import settings
from .db import init_db, session_scope, verify_chain
from .domain import CATEGORY_LABELS, VERDICT_LABELS, utcnow
from .intake import scan
from .models import Asset, Campaign, Evidence, ReportDraft, ScanRun, SignalRow, WatchTarget
from .respond import CHANNELS, advise, build, export_bundle
from .scoring.engine import load_ruleset

WEB_DIR = Path(__file__).parent / "web"

import logging

logger = logging.getLogger(__name__)


def _discover_running() -> bool:
    """发现引擎是否在跑。不在跑就如实返回 False——控制台据此显示「未启动」，
    而不是让人误以为基座在监控。"""
    try:
        from .discover.engine import get_engine

        return bool(get_engine().status().get("running"))
    except Exception:  # noqa: BLE001
        return False


def _opsec_summary() -> dict[str, Any]:
    try:
        from . import opsec

        info = opsec.status()
        return {
            "enabled": info["enabled"],
            "proxies": info["proxy_count"],
            "egress": "proxy" if info["proxy_count"] else ("direct-degraded" if settings.opsec_allow_direct else "blocked"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"enabled": False, "error": str(exc)}


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    import os

    init_db()

    # 兼容两种写法：SILVER_AUTOSTART（旧）与 SILVER_AUTOSTART_MONITOR（编排文件里用的）
    flag = os.environ.get("SILVER_AUTOSTART") or os.environ.get("SILVER_AUTOSTART_MONITOR", "1")
    autostart = flag.strip().lower() in {"1", "true", "yes"}
    if autostart:
        # 发现 → 调度 → 副本，三条后台线各自独立；任何一个挂了不影响其余
        try:
            from .discover.engine import get_engine

            get_engine().start()
        except Exception as exc:  # noqa: BLE001
            logger.warning("发现引擎启动失败：%s", exc)
        try:
            from .pipeline import get_scheduler

            get_scheduler().start()
        except Exception as exc:  # noqa: BLE001
            logger.warning("调度器启动失败：%s", exc)
        try:
            from .core.replica import get_replica

            get_replica().start()
        except Exception as exc:  # noqa: BLE001
            logger.warning("副本启动失败：%s", exc)
        try:
            from .vault import get_vault

            get_vault().start()
        except Exception as exc:  # noqa: BLE001
            logger.warning("证据仓同步启动失败：%s", exc)

    if os.environ.get("SILVER_AUTOSTART_MONITOR", "0").strip() in {"1", "true", "yes"}:
        from .monitor import start_background

        start_background()
    yield

    # 优雅收尾：把事件日志刷盘，别丢最后几条
    try:
        from .core.eventlog import get_log

        get_log().close()
    except Exception:  # noqa: BLE001
        pass


# 关掉交互式文档：这是内部系统，没必要对外暴露全部接口形状
app = FastAPI(title="银发哨兵", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(webauth.AuthMiddleware)
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
        "tier": asset.tier,
        "discovery_source": asset.discovery_source,
        "discovery_reason": asset.discovery_reason,
        "icp_status": asset.icp_status,
        "icp_entity": asset.icp_entity,
        "campaign_name": asset.campaign.name if asset.campaign else "",
    }


# ---------------------------------------------------------------- 页面


from .api_extra import router as extra_router  # noqa: E402

app.include_router(extra_router)


@app.get("/api/ping")
def ping() -> dict[str, str]:
    """探活。放在鉴权白名单里，供外部监控用，不带任何内部信息。"""
    return {"status": "ok"}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/") -> HTMLResponse:
    if not webauth.auth_enabled():
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(
        request, "login.html",
        {"version": __version__, "next": next or "/", "err": ""},
    )


def _secure_cookie(request: Request) -> bool:
    proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip()
    return request.url.scheme == "https" or proto == "https"


@app.post("/auth/login")
async def do_login(request: Request):  # noqa: ANN201
    from urllib.parse import parse_qs

    raw = (await request.body()).decode("utf-8", "replace")
    form = parse_qs(raw, keep_blank_values=True)
    given = (form.get("password") or [""])[0]
    nxt = (form.get("next") or ["/"])[0] or "/"
    # 只允许站内跳转，避免变成开放重定向
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/"

    key = webauth.client_key(request.scope)
    if webauth.too_many_failures(key):
        return templates.TemplateResponse(
            request, "login.html",
            {"version": __version__, "next": nxt, "err": "尝试次数过多，请 10 分钟后再试"},
            status_code=429,
        )

    if not webauth.check_password(given):
        webauth.note_failure(key)
        return templates.TemplateResponse(
            request, "login.html",
            {"version": __version__, "next": nxt, "err": "口令不正确"},
            status_code=401,
        )

    webauth.clear_failures(key)
    resp = RedirectResponse(nxt, status_code=303)
    resp.set_cookie(
        webauth.COOKIE_NAME,
        webauth.issue(),
        max_age=webauth.SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=_secure_cookie(request),
        path="/",
    )
    return resp


@app.get("/auth/logout")
def do_logout() -> RedirectResponse:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(webauth.COOKIE_NAME, path="/")
    return resp


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    # Starlette ≥0.29 的新签名：request 在前，模板名在后。
    # 旧写法 ("index.html", {...}) 在新版里会把 dict 当模板名，触发 unhashable。
    return templates.TemplateResponse(request, "index.html", {"version": __version__})


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
        "version": __version__,
        "network": settings.allow_network,
        "llm": llm_analyzer.status(),
        "capabilities": settings.capability_report(),
        "discover_running": _discover_running(),
        "evidence_chain": chain,
        "opsec": _opsec_summary(),
        "rules": {"count": len(load_ruleset().rules), "version": load_ruleset().version},
    }


@app.get("/api/opsec")
def opsec_status() -> dict[str, Any]:
    """出站防护状态：是否隔离、代理数量、脱敏了多少标识。"""
    from . import opsec

    return opsec.status()


def _vault_status() -> dict[str, Any]:
    from .vault import VaultError, get_vault

    if not settings.vault_enabled:
        return {"enabled": False, "reason": "SILVER_VAULT_ENABLED=0"}
    try:
        return get_vault().status()
    except VaultError as exc:
        return {"enabled": True, "error": str(exc)}


@app.get("/api/vault")
def vault_status() -> dict[str, Any]:
    return _vault_status()


@app.post("/api/vault/sync")
def vault_sync() -> dict[str, Any]:
    from .vault import get_vault

    if not settings.vault_enabled:
        raise HTTPException(400, "证据仓未启用")
    return get_vault().sync_once()


@app.post("/api/vault/verify")
def vault_verify() -> dict[str, Any]:
    from .vault import get_vault

    if not settings.vault_enabled:
        raise HTTPException(400, "证据仓未启用")
    return get_vault().verify()


@app.get("/api/icp")
def icp_status() -> dict[str, Any]:
    """备案查询的实时状态：可用性、限速、缓存命中与违规命中数。"""
    from .enrich.icp import get_icp

    info = get_icp().status()
    info["configured"] = settings.icp_ready
    return info


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
    tier: str | None = None,
    kind: str | None = None,
    source: str | None = None,
    limit: int = Query(default=50, le=300),
    offset: int = 0,
) -> dict[str, Any]:
    with session_scope() as session:
        stmt = select(Asset).order_by(Asset.score.desc(), Asset.last_seen.desc())
        count_stmt = select(func.count(Asset.id))
        for condition in (
            (Asset.verdict == verdict) if verdict else None,
            (Asset.value.contains(q)) if q else None,
            (Asset.tier == tier) if tier else None,
            (Asset.kind == kind) if kind else None,
            (Asset.discovery_source == source) if source else None,
        ):
            if condition is not None:
                stmt = stmt.where(condition)
                count_stmt = count_stmt.where(condition)
        rows = list(session.scalars(stmt.offset(offset).limit(limit)))
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
