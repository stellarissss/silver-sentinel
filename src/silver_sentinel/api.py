"""FastAPI 应用：控制台与 REST 接口。"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, selectinload

from . import __version__, webauth
from .analyzers import llm as llm_analyzer
from .config import settings
from .db import init_db, session_scope, verify_chain
from .domain import CATEGORY_LABELS, VERDICT_LABELS, utcnow
from .grouping import OFFLINE_CAPTURE_STATES, OFFLINE_MEMBER_CAP
from .intake import scan
from .models import TIER_LABELS, Asset, Campaign, Evidence, ReportDraft, ScanRun, SignalRow, WatchTarget
from .respond import CHANNELS, advise, build, export_bundle
from .scoring.engine import load_ruleset

WEB_DIR = Path(__file__).parent / "web"

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

    from .logsetup import setup_logging

    setup_logging()
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
        try:
            # 常驻取证线程 + 巡检 + 看门狗。取证必须独立于主周期，
            # 否则建图/富化一慢，取证就断档。
            from .worker import start_background

            start_background()
        except Exception as exc:  # noqa: BLE001
            logger.warning("常驻取证线程启动失败：%s", exc)

    if os.environ.get("SILVER_AUTOSTART_MONITOR", "0").strip() in {"1", "true", "yes"}:
        from .monitor import start_background as start_monitor

        start_monitor()
    yield

    # 优雅收尾：把事件日志刷盘，别丢最后几条
    try:
        from .worker import stop_all

        stop_all()
    except Exception:  # noqa: BLE001
        pass
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
    kind: str = Field(default="keyword", description="keyword|domain|brand|asset")
    value: str = Field(default="", description="目标值；kind=asset 时用 asset_id")
    asset_id: int | None = None
    interval_minutes: int = 360
    note: str = ""


class ReviewIn(BaseModel):
    verdict: str
    reviewer: str = ""
    note: str = ""


def _asset_row(
    asset: Asset, evidence_counts: dict[int, int] | None = None
) -> dict[str, Any]:
    """列表行。

    evidence_counts 由折叠视图一次性聚合好传进来：折叠要扫描全量资产，
    若让每行去加载 evidence 关系，几万条证据会被整体 ORM 化，列表接口
    直接挂死。非折叠视图不传，走 relationship 常规路径。
    """
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
        "tier_label": TIER_LABELS.get(asset.tier, asset.tier),
        "discovery_source": asset.discovery_source,
        "discovery_reason": asset.discovery_reason,
        "icp_status": asset.icp_status,
        "icp_entity": asset.icp_entity,
        "campaign_name": asset.campaign.name if asset.campaign else "",
        "capture_state": asset.capture_state or "pending",
        "capture_error": (asset.capture_error or "")[:200],
        "last_capture_at": asset.last_capture_at.isoformat() if asset.last_capture_at else None,
        "evidence_count": (
            evidence_counts.get(asset.id, 0)
            if evidence_counts is not None
            else len(asset.evidence or [])  # relationship 已在 SQL 层排掉软删
        ),
        # 同源折叠：group_key 是这批资产的共同标识，group_kind 说明凭什么归到一起
        "group_key": asset.group_key or "",
        "group_kind": asset.group_kind or "",
        "group_label": ((asset.meta or {}).get("group_label") or ""),
        # 用途：列表页据此显示「客服/论坛/企业」等标签，解释它为什么不占高危队列
        "purpose": _purpose_row(asset),
        # 诱饵/蜜罐：列表页打标，详情页出卡片。不要藏起来——
        # 「这一页是样子货」本身就是判断它价值的关键信息。
        "decoy": _decoy_row(asset),
        # 涉老骗局类型（只读分类）与主体实体：把「以仿冒政府网站为主」
        # 这个结论拆开看，人工复核能按类型、按收款主体分组。
        "elder_schemes": _elder_schemes(asset),
        "entity_count": _entity_count(asset),
    }


def _elder_schemes(asset: Asset) -> list[str]:
    facts = (asset.meta or {}).get("facts") or {}
    e = facts.get("elder") if isinstance(facts, dict) else None
    if not isinstance(e, dict):
        return []
    return [str(x) for x in (e.get("schemes") or [])][:6]


def _entity_count(asset: Asset) -> int:
    facts = (asset.meta or {}).get("facts") or {}
    ent = facts.get("entities") if isinstance(facts, dict) else None
    if not isinstance(ent, dict):
        return 0
    try:
        return int(ent.get("count") or 0)
    except (TypeError, ValueError):
        return 0


def _group_detail(session: Session, asset: Asset) -> dict[str, Any] | None:
    """详情页的「同源」卡片：这一条属于哪一批，批里有多少涉老。

    暖阳那种站的正确读法就在这里：它自己判不出涉老，但它和 77 个涉老站
    共用同一个收单端点。只看单条，永远看不出这件事。
    """
    key = asset.group_key or ""
    if not key:
        return None
    from .grouping import GROUP_LABELS

    peers = list(
        session.scalars(
            select(Asset).where(Asset.group_key == key).order_by(Asset.score.desc()).limit(40)
        )
    )
    elder_count = 0
    for p in peers:
        facts = (p.meta or {}).get("facts") or {}
        e = facts.get("elder") if isinstance(facts, dict) else None
        if isinstance(e, dict) and e.get("elder"):
            elder_count += 1
    return {
        "key": key,
        "kind": asset.group_kind or "",
        "label": (asset.meta or {}).get("group_label")
        or GROUP_LABELS.get(asset.group_kind or "", "同源"),
        "size": len(peers),
        "elder_count": elder_count,
        "members": [
            {
                "id": p.id,
                "value": str(p.value)[:140],
                "kind": p.kind,
                "score": round(float(p.score or 0), 1),
                "tier": p.tier,
                "verdict": p.verdict,
                "capture_state": p.capture_state,
                "elder": bool(
                    isinstance(((p.meta or {}).get("facts") or {}).get("elder"), dict)
                    and (((p.meta or {}).get("facts") or {}).get("elder") or {}).get("elder")
                ),
            }
            for p in peers
        ],
    }


def _decoy_row(asset: Asset) -> dict[str, Any] | None:
    facts = (asset.meta or {}).get("facts") or {}
    decoy = facts.get("decoy") if isinstance(facts, dict) else None
    if not isinstance(decoy, dict):
        return None
    if not (decoy.get("is_decoy") or decoy.get("honeypot") or decoy.get("blocked_by")):
        return None
    return {
        "is_decoy": bool(decoy.get("is_decoy")),
        "kind": decoy.get("kind") or "",
        "reason": decoy.get("reason") or "",
        "weight": decoy.get("weight") or 0,
        "downstream": list(decoy.get("downstream") or [])[:4],
        "honeypot": bool(decoy.get("honeypot")),
        "honeypot_reasons": list(decoy.get("honeypot_reasons") or [])[:3],
        "blocked_by": decoy.get("blocked_by") or "",
    }


def _purpose_row(asset: Asset) -> dict[str, Any] | None:
    purpose = ((asset.meta or {}).get("facts") or {}).get("purpose")
    if not isinstance(purpose, dict) or not purpose.get("purpose"):
        return None
    return {
        "purpose": purpose.get("purpose"),
        "label": purpose.get("label") or purpose.get("purpose"),
        "confidence": purpose.get("confidence") or 0,
        "source": purpose.get("source") or "",
        "suppressed": bool(purpose.get("suppressed")),
        "reason": purpose.get("suppressed_reason") or "",
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


# 证据链校验要逐条重算哈希，随证据条数线性变慢。控制台每 30 秒拉一次
# /api/health，几万条证据时会把一个核对按钮变成常驻 CPU 占用。缓存 5 分钟：
# 链断了是「已经发生」的事实，晚 5 分钟发现不影响处置。
_CHAIN_CACHE: dict[str, Any] = {"at": 0.0, "result": {"ok": None}}


def _cached_chain_check(session) -> dict[str, Any]:  # noqa: ANN001
    now = time.monotonic()
    if now - float(_CHAIN_CACHE["at"]) < 300:
        return _CHAIN_CACHE["result"]  # type: ignore[return-value]
    result = verify_chain(session)
    _CHAIN_CACHE["at"] = now
    _CHAIN_CACHE["result"] = result
    return result


@app.get("/api/health")
def health() -> dict[str, Any]:
    chain = {"ok": None}
    try:
        with session_scope() as session:
            chain = _cached_chain_check(session)
    except Exception as exc:  # noqa: BLE001
        chain = {"ok": False, "error": str(exc)}
    capture: dict[str, Any] = {}
    try:
        from .capture import queue_summary

        summary = queue_summary()
        capture = {
            "queued": summary["queued"],
            "running": summary["running"],
            "failed": summary["failed"],
            "pending_assets": summary["pending_assets"],
        }
    except Exception as exc:  # noqa: BLE001
        capture = {"error": str(exc)[:120]}

    return {
        "status": "ok",
        "version": __version__,
        "network": settings.allow_network,
        "llm": llm_analyzer.status(),
        "capabilities": settings.capability_report(),
        "discover_running": _discover_running(),
        "evidence_chain": chain,
        "capture": capture,
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
    """概览口径。

    历史教训：总数把 2,150 条已排除的误报算进去，界面显示 2,993，
    而真正能处置的只有 800 多，用户看到的是「数字很大、什么都没发生」。
    这里所有比率一律以**有效资产**为分母，已排除单独列一行并注明原因。
    """
    active_tiers = ("confirmed", "watch", "candidate")
    with session_scope() as session:
        total = session.scalar(select(func.count(Asset.id))) or 0
        active = session.scalar(
            select(func.count(Asset.id)).where(Asset.tier.in_(active_tiers))
        ) or 0
        dismissed = session.scalar(
            select(func.count(Asset.id)).where(Asset.tier == "dismissed")
        ) or 0

        by_verdict = dict(
            session.execute(
                select(Asset.verdict, func.count(Asset.id))
                .where(Asset.tier.in_(active_tiers))
                .group_by(Asset.verdict)
            ).all()
        )
        by_category = dict(
            session.execute(
                select(SignalRow.category, func.count(SignalRow.id))
                .join(Asset, Asset.id == SignalRow.asset_id)
                .where(Asset.tier.in_(active_tiers))
                .group_by(SignalRow.category)
            ).all()
        )
        by_tier = dict(
            session.execute(select(Asset.tier, func.count(Asset.id)).group_by(Asset.tier)).all()
        )

        campaigns = session.scalar(select(func.count(Campaign.id))) or 0
        reports = session.scalar(select(func.count(ReportDraft.id))) or 0

        now = utcnow()
        new_24h = session.scalar(
            select(func.count(Asset.id)).where(
                Asset.tier.in_(active_tiers), Asset.first_seen >= now - timedelta(hours=24)
            )
        ) or 0
        new_7d = session.scalar(
            select(func.count(Asset.id)).where(
                Asset.tier.in_(active_tiers), Asset.first_seen >= now - timedelta(days=7)
            )
        ) or 0

        pending = session.scalar(
            select(func.count(Asset.id)).where(
                Asset.tier.in_(active_tiers), Asset.verdict.in_(["high_risk", "confirmed"])
            )
        ) or 0
        # 待取证：有效、可访问、还没跑过页面
        pending_capture = session.scalar(
            select(func.count(Asset.id)).where(
                Asset.tier.in_(active_tiers),
                Asset.kind.in_(("domain", "url")),
                Asset.capture_state.in_(("pending", "failed")),
            )
        ) or 0
        # 只算有效资产：分母是有效池，分子混进已排除的会让覆盖率超过 100%
        with_evidence = session.scalar(
            select(func.count(func.distinct(Evidence.asset_id)))
            .join(Asset, Asset.id == Evidence.asset_id)
            .where(
                Evidence.kind.in_(("page_html", "screenshot")),
                Evidence.deleted_at.is_(None),
                Asset.tier.in_(active_tiers),
            )
        ) or 0
        watch_count = session.scalar(
            select(func.count(func.distinct(WatchTarget.asset_id))).where(
                WatchTarget.enabled.is_(True), WatchTarget.asset_id.is_not(None)
            )
        ) or 0

        # 最近 7 天被排除的数量，用于「数据变更公告」。之前清理 2,150 条却没有任何提示，
        # 用户只看到有效池突然缩水，以为系统坏了。
        dismissed_recent = session.scalar(
            select(func.count(Asset.id)).where(
                Asset.tier == "dismissed", Asset.last_seen >= now - timedelta(days=7)
            )
        ) or 0

        # 「风险最高线索」要给人看还能处置的目标。已失联 / 取证失败的
        # 高分老站（用户举报过的 95 分站群）会把 8 张卡片全占满，
        # 折叠到线索库末尾，这里只留可访问的高分线索。
        top = list(
            session.scalars(
                select(Asset)
                .where(
                    Asset.tier.in_(active_tiers),
                    Asset.score > 0,
                    or_(
                        Asset.capture_state.is_(None),
                        Asset.capture_state.notin_(tuple(OFFLINE_CAPTURE_STATES)),
                    ),
                )
                .order_by(Asset.score.desc())
                .limit(8)
            )
        )
        offline_active = session.scalar(
            select(func.count(Asset.id)).where(
                Asset.tier.in_(active_tiers),
                Asset.capture_state.in_(tuple(OFFLINE_CAPTURE_STATES)),
            )
        ) or 0

        return {
            "total_assets": total,
            "active_assets": active,
            "dismissed_assets": dismissed,
            "by_verdict": by_verdict,
            "by_tier": by_tier,
            "verdict_labels": VERDICT_LABELS,
            "by_category": {CATEGORY_LABELS.get(k, k): v for k, v in by_category.items()},
            "campaigns": campaigns,
            "reports": reports,
            "recent_7d": new_7d,
            "new_24h": new_24h,
            "new_7d": new_7d,
            "pending_action": pending,
            "pending_capture": pending_capture,
            "evidence_coverage": {
                "with_evidence": with_evidence,
                "active": active,
                "ratio": round(min(1.0, with_evidence / active), 3) if active else 0.0,
            },
            "watch_count": watch_count,
            # 兼容旧前端字段名（recent_7d / pending_action 保持不变）
            "notices": [
                {
                    "level": "info",
                    "text": f"近 7 天有 {dismissed_recent} 条历史线索被判定为误报并排除，"
                            f"不计入有效线索。原因可在「线索库 → 已排除」中逐条查看。",
                }
            ] if dismissed_recent else [],
            "top_assets": [_asset_row(a) for a in top],
            "offline_assets": offline_active,
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

    fd, tmp_name = tempfile.mkstemp(suffix=".apk", dir=str(settings.data_dir / "evidence"))
    os.close(fd)  # 以前只取路径丢掉 fd，每次上传泄漏一个文件描述符
    tmp = Path(tmp_name)
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
    sort: str = "score",
    order: str = "desc",
    limit: int = Query(default=50, ge=1, le=300),
    offset: int = Query(default=0, ge=0),
    collapse: bool = True,
    fold_offline: bool = True,
) -> dict[str, Any]:
    """线索列表。默认只返回有效资产（不含已排除）。

    之前默认返回全部，用户一进线索库就看到 2,993 条里混着 2,150 条早已
    判定为误报的域名，既看不出重点，也解释不了「为什么这么多」。

    collapse=True 时按 group_key 折叠：同一张证书 / 同一个收单端点 /
    同一套模板的资产合成一行，代表行取组内分数最高的那条。
    折叠只影响展示，不改数据——每条资产仍然独立取证、独立定级、独立出证据包。
    """
    with session_scope() as session:
        stmt = select(Asset)
        count_stmt = select(func.count(Asset.id))

        tier = (tier or "active").strip().lower()
        # 筛选条件分两拨：tier 只影响列表，不影响「另外还有多少条」
        conditions: list[Any] = []
        tier_conditions: list[Any] = []
        if tier == "active":
            tier_conditions.append(Asset.tier.in_(("confirmed", "watch", "candidate")))
        elif tier == "all":
            pass
        elif tier == "dismissed":
            tier_conditions.append(Asset.tier == "dismissed")
        elif tier:
            tier_conditions.append(Asset.tier == tier)

        if verdict:
            conditions.append(Asset.verdict == verdict)
        if q:
            conditions.append(Asset.value.contains(q))
        if kind:
            conditions.append(Asset.kind == kind)
        if source:
            conditions.append(Asset.discovery_source == source)

        for condition in conditions + tier_conditions:
            stmt = stmt.where(condition)
            count_stmt = count_stmt.where(condition)

        sort_col = {
            "score": Asset.score,
            "last_seen": Asset.last_seen,
            "first_seen": Asset.first_seen,
            "scan_count": Asset.scan_count,
            "value": Asset.value,
        }.get(sort, Asset.score)
        stmt = stmt.order_by(sort_col.asc() if order == "asc" else sort_col.desc(), Asset.id.desc())
        # evidence_count 的加载方式在下面两个分支里分开处理：
        # 非折叠视图只取 limit 行，selectinload 一次批量取回关系是划算的；
        # 折叠视图要扫描全量行来分组，此时 selectinload 会把几万条证据
        # 整体 ORM 化（线上实测 5.7 万条 → 53s，接口直接挂死），改用聚合计数。

        # 每一档各有多少条。「有效 0 条」必须能立刻解释成「另有 N 条冷存」，
        # 否则用户只会看到一张空表，以为东西丢了。
        counts_stmt = select(Asset.tier, func.count(Asset.id))
        for condition in conditions:
            counts_stmt = counts_stmt.where(condition)
        tier_counts = {t: c for t, c in session.execute(counts_stmt.group_by(Asset.tier))}
        raw_total = session.scalar(count_stmt) or 0

        if not collapse:
            rows = list(
                session.scalars(
                    stmt.options(selectinload(Asset.evidence))
                    .offset(offset)
                    .limit(limit)
                )
            )
            return {
                "items": [_asset_row(a) for a in rows],
                "total": raw_total,
                "raw_total": raw_total,
                "limit": limit,
                "offset": offset,
                "tier": tier,
                "tier_counts": tier_counts,
                "collapsed": False,
                "offline_count": 0,
            }

        # 折叠视图：分组代表行要取「组内分数最高的那条」还要带成员列表，
        # SQL 里得套两层子查询，所以先在内存里分组再分页。
        #
        # 但 total 必须是**全局折叠后**的项数：以前用 scan_cap 截断扫描、
        # 再用 Python 切片套 offset，翻到后半段就返回空页，total 也只是
        # 被截断那批能折出的项数。active 档实测不到 2000 行、all 档 7000+，
        # 一次全取的代价远小于错误的分页。
        # 折叠要按 group_key / 前缀族把全量行分组，但每行只需要一个
        # evidence_count 数字：一次 group by 拿到全部计数，不加载关系。
        # 条件与 Asset.evidence 的 primaryjoin 一致，软删 tombstone 不计入。
        evidence_counts = {
            int(asset_id): int(n)
            for asset_id, n in session.execute(
                select(Evidence.asset_id, func.count(Evidence.id))
                .where(Evidence.deleted_at.is_(None))
                .group_by(Evidence.asset_id)
            ).all()
        }
        # campaign 是行里唯一还会懒加载的关系；预加载一次消掉 N+1。
        rows = list(session.scalars(stmt.options(selectinload(Asset.campaign))))
        items, group_count = _collapse_rows(
            rows,
            fold_offline=fold_offline and collapse,
            evidence_counts=evidence_counts,
        )
        offline_count = sum(
            1 for a in rows
            if (a.capture_state or "") in OFFLINE_CAPTURE_STATES
        ) if (fold_offline and collapse) else 0
        view_total = len(items)
        return {
            "items": items[offset: offset + limit],
            "total": view_total,
            "raw_total": raw_total,
            "offline_count": offline_count,
            "limit": limit,
            "offset": offset,
            "tier": tier,
            "tier_counts": tier_counts,
            "collapsed": True,
            "group_count": group_count,
            "truncated": False,
        }


def _collapse_rows(
    rows: list[Asset],
    *,
    fold_offline: bool = True,
    evidence_counts: dict[int, int] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """把已排序的行按 group_key 折叠，保持原来的顺序。

    组在「组内第一条出现的位置」占位，这样按分数排序时，
    一个高分组不会被低分成员拖到后面去。

    group_key 为空时再兜一层「站群前缀族」：取证失败的资产没有正文/证书，
    但 `mz479.top` / `mz749.top` 这类固定前缀 + 变数字的域名，在发现阶段就
    是同一个生成器长期运营的证据（见 discover/burst.py）。只用于展示、
    不写库，误判了也能用「展开全部」一键绕开。

    失联站点（dead / failed）当前拿不到任何页面内容，按分数排会长期霸占
    首屏——线上 95 分死站群一度占满前 60 行，把新线索全压到后面。这里把
    **整组都失联**的组沉到末尾，但保留它们原来的同源依据（同证书 80 个站
    仍是一组、同前缀族仍是一组），团伙证据不能因为折叠而消失；只有连同源
    依据都没有的失联散站，才合成一个「失联站点」大组。混合组里只要还有
    能取到内容的站，就留在前面——那批人还在运营，不该被藏起来。
    """
    from .discover.burst import family_key
    from .grouping import GROUP_LABELS, group_row

    def is_offline(a: Asset) -> bool:
        return (a.capture_state or "") in OFFLINE_CAPTURE_STATES

    order: list[Any] = []
    buckets: dict[str, list[Asset]] = {}
    meta_of: dict[str, tuple[str, str]] = {}
    loose_offline: list[Asset] = []

    for a in rows:
        key = a.group_key or ""
        if key:
            kind = a.group_kind or ""
            label = (a.meta or {}).get("group_label") or GROUP_LABELS.get(kind, "同源")
        else:
            fam = family_key(a.normalized or a.value or "")
            if not fam:
                # 无同源依据的失联散站：攒起来合成一个大组，别几百行铺在末尾
                if fold_offline and is_offline(a):
                    loose_offline.append(a)
                    continue
                order.append(_asset_row(a, evidence_counts))
                continue
            key = f"family:{fam}"
            kind, label = "family", f"同站群前缀族 {fam}"
        if key not in buckets:
            buckets[key] = []
            order.append(key)
            meta_of[key] = (kind, label)
        buckets[key].append(a)

    front: list[dict[str, Any]] = []
    back: list[dict[str, Any]] = []
    group_count = 0
    for entry in order:
        if not isinstance(entry, str):
            front.append(entry)
            continue
        group_assets = buckets[entry]
        # 整组失联才沉底。混合组里还有活站，留在前面。
        # fold_offline=0 时完全不区分失联，退回原来的纯同源折叠。
        all_offline = (
            fold_offline
            and bool(group_assets)
            and all(is_offline(a) for a in group_assets)
        )
        target = back if all_offline else front
        members = [_asset_row(a, evidence_counts) for a in group_assets]
        # 只有 2 条的组不折叠：省下一行，却多一个徽标和一次点击，净收益是负的。
        # 线上实测：46 组里 30 组是「×2 同证书」（同一张证书覆盖两个子域），
        # 全折起来反而让列表更吵。成员仍然逐条显示，只把关联标出来。
        if len(members) < 3:
            for m in members:
                m["group"] = {
                    "key": entry,
                    "kind": meta_of[entry][0],
                    "label": meta_of[entry][1],
                    "size": len(members),
                    "collapsed": False,
                    "members": [
                        {"id": o.get("id"), "value": o.get("value"), "score": o.get("score"),
                         "tier": o.get("tier")}
                        for o in members if o is not m
                    ],
                    "max_score": max((float(o.get("score") or 0) for o in members), default=0.0),
                    "tiers": sorted({o.get("tier") or "" for o in members}),
                }
                if all_offline:
                    m["group"]["offline"] = True
                target.append(m)
            continue
        kind, label = meta_of[entry]
        head = group_row(key=entry, kind=kind, label=label, members=members)
        if all_offline:
            head["group"]["offline"] = True
        target.append(head)
        group_count += 1

    # 无同源依据的失联散站合成一个大组，成员只带前 OFFLINE_MEMBER_CAP 条；
    # 真实规模用 size 给，诱饵/蜜罐由 group_row 从全量统计后浮到组行上。
    if loose_offline:
        members = [_asset_row(a, evidence_counts) for a in loose_offline]
        if len(members) < 3:
            back.extend(members)
        else:
            head = group_row(
                key="offline:lost",
                kind="offline",
                label=f"失联 / 取证失败站点（{len(members)} 条）",
                members=members,
                member_cap=OFFLINE_MEMBER_CAP,
            )
            head["group"]["offline"] = True
            back.append(head)
            group_count += 1
    return front + back, group_count


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
            session.scalars(
                select(Evidence)
                .where(Evidence.asset_id == asset_id, Evidence.deleted_at.is_(None))
                .order_by(Evidence.id)
            )
        )
        deleted = list(
            session.scalars(
                select(Evidence)
                .where(Evidence.asset_id == asset_id, Evidence.deleted_at.is_not(None))
                .order_by(Evidence.id.desc())
                .limit(20)
            )
        )
        campaign = session.get(Campaign, asset.campaign_id) if asset.campaign_id else None

        from .capture import KIND_LABEL, evidence_matrix

        return {
            **_asset_row(asset),
            "normalized": asset.normalized,
            "meta": asset.meta,
            "notes": asset.notes,
            "group": _group_detail(session, asset),
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
                    "kind_label": KIND_LABEL.get(e.kind, e.kind),
                    "sha256": e.sha256,
                    "chain_hash": e.chain_hash,
                    "size": e.size,
                    "mime": e.mime,
                    "note": e.note,
                    "captured_at": e.captured_at.isoformat(),
                    # application/json 也要能预览：网络请求、证书、表单都是 JSON，
                    # 不能预览就只能下载，看一条证据多两步。
                    "previewable": (e.mime or "").startswith(("image/", "text/", "application/json")),
                }
                for e in evidence
            ],
            "evidence_matrix": evidence_matrix(asset_id),
            "evidence_deleted": [
                {
                    "id": e.id,
                    "kind": KIND_LABEL.get(e.kind, e.kind),
                    "deleted_at": e.deleted_at.isoformat() if e.deleted_at else None,
                    "deleted_by": e.deleted_by,
                    "delete_reason": e.delete_reason,
                }
                for e in deleted
            ],
            "changes": (asset.meta or {}).get("changes", []),
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
    """监控列表。

    之前只返回目标本身，用户看不出「这条是自动纳管的还是我手动加的」「盯了几轮
    有没有变化」。这些正是判断监控有没有用的依据，一并返回。
    """
    with session_scope() as session:
        rows = list(session.scalars(select(WatchTarget).order_by(WatchTarget.id)))
        asset_ids = [t.asset_id for t in rows if t.asset_id]
        assets = {
            a.id: a
            for a in (
                session.scalars(select(Asset).where(Asset.id.in_(asset_ids))).all()
                if asset_ids
                else []
            )
        }
        return {
            "items": [
                {
                    "id": t.id,
                    "kind": t.kind,
                    "value": t.value,
                    "interval_minutes": t.interval_minutes,
                    "enabled": t.enabled,
                    "note": t.note,
                    "asset_id": t.asset_id,
                    "auto": bool(t.auto),
                    "fail_count": t.fail_count or 0,
                    "change_count": t.change_count or 0,
                    "last_change_at": t.last_change_at.isoformat() if t.last_change_at else None,
                    "last_run_at": t.last_run_at.isoformat() if t.last_run_at else None,
                    "next_run_at": t.next_run_at.isoformat() if t.next_run_at else None,
                    "asset_value": assets[t.asset_id].value if t.asset_id in assets else "",
                    "asset_tier": assets[t.asset_id].tier if t.asset_id in assets else "",
                    "asset_score": round(assets[t.asset_id].score, 1) if t.asset_id in assets else 0,
                }
                for t in rows
            ],
            "auto": sum(1 for t in rows if t.auto),
            "total": len(rows),
        }


@app.post("/api/watch")
def api_watch_add(payload: WatchIn) -> dict[str, Any]:
    # 资产级盯防走同一条路径，但目标由 asset 派生，避免前端拼错 value
    if payload.kind == "asset":
        if not payload.asset_id:
            raise HTTPException(status_code=400, detail="kind=asset 时必须提供 asset_id")
        from .capture import ensure_watch

        added = ensure_watch(payload.asset_id, force=True, by="界面")
        return {"ok": True, "added": added, "existed": not added}

    if payload.kind not in {"keyword", "domain", "brand"}:
        raise HTTPException(status_code=400, detail="kind 只能是 keyword/domain/brand/asset")
    value = (payload.value or "").strip()
    if len(value) < 2:
        raise HTTPException(status_code=400, detail="监控目标至少 2 个字符")
    with session_scope() as session:
        exists = session.scalar(
            select(WatchTarget).where(WatchTarget.kind == payload.kind, WatchTarget.value == value)
        )
        if exists:
            return {"ok": True, "id": exists.id, "existed": True}
        target = WatchTarget(
            kind=payload.kind,
            value=value,
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
def api_runs(limit: int = Query(default=30, ge=1, le=200)) -> dict[str, Any]:
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
    """直接调 serve() 也要和 CLI 一样读配置、生成口令。

    以前硬编码 0.0.0.0:8000 且跳过 ensure_password：不走 cli:main 的部署
    会丢掉端口配置；若 SILVER_WEB_PASSWORD 未设，鉴权中间件整站放行，
    涉诈线索和举报材料就在公网裸奔。
    """
    import uvicorn

    host = settings.web_host
    webauth.ensure_password(host)
    uvicorn.run("silver_sentinel.api:app", host=host, port=settings.web_port, reload=False)
