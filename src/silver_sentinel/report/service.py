"""举报编排：选类别 → 选渠道 → 生成正文 → 打证据包 → 出填表载荷。"""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..domain import utcnow
from ..models import Asset, Evidence, ReportBundle, SignalRow
from . import bundle as bundle_mod
from . import fill as fill_mod
from . import narrative as nar
from .channels import CHANNELS, Channel, for_harm, get
from .harmtype import classify


def _code() -> str:
    return "rb" + secrets.token_hex(6)


def _evidence_paths(session: Session, asset_id: int) -> tuple[list[Evidence], dict[str, bytes]]:
    """读回该资产的全部证据内容，键是 sha256。

    必须走 evidence.read_bytes() 这个统一入口：开了「上传后删明文」之后
    row.path 指向的明文文件本来就不存在，密文在 vault/blobs。以前这里直接
    Path.exists()，vault 模式下会返回一个空 mapping——交给监管的 ZIP 里
    一张截图都没有，manifest 却仍逐条列出全部证据。
    """
    from ..evidence import read_bytes

    rows = list(
        session.scalars(
            select(Evidence).where(Evidence.asset_id == asset_id).order_by(Evidence.id)
        )
    )
    blobs: dict[str, bytes] = {}
    for e in rows:
        if e.deleted_at is not None:
            continue
        data = read_bytes(e)
        if data:
            blobs[e.sha256] = data
    return rows, blobs


def _page_text(evidence: list[Evidence], blobs: dict[str, bytes]) -> str:
    """取最近一次页面正文快照，用于摘引原话。读不到就返回空。"""
    for ev in reversed(evidence):
        if getattr(ev, "kind", "") != "page_text":
            continue
        data = blobs.get(str(ev.sha256))
        if data:
            return data[:300_000].decode("utf-8", "replace")
    return ""


def build(
    session: Session,
    asset_id: int,
    channel_id: str = "",
    *,
    harm_override: str = "",
    reporter: str = "",
    api_base: str = "",
    body_override: str = "",
) -> ReportBundle:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError(f"资产不存在：{asset_id}")

    signals = list(
        session.scalars(
            select(SignalRow).where(SignalRow.asset_id == asset_id).order_by(SignalRow.weight.desc())
        )
    )
    evidence, ev_paths = _evidence_paths(session, asset_id)

    harm = classify(asset, signals, override=harm_override)
    if not channel_id:
        channel_id = for_harm(harm.harm)[0].id
    channel: Channel = get(channel_id)

    ctx = nar.Ctx(
        asset=asset,
        signals=signals,
        evidence=evidence,
        harm=harm,
        reporter=reporter or settings.report_reporter,
        now=utcnow(),
        page_text=_page_text(evidence, ev_paths),
    )

    if body_override.strip():
        body_text = body_override.strip()
        limit = channel.body_limit or 0
        if limit and len(body_text) > limit:
            body_text = body_text[:limit]
    elif channel.fill == "mailto":
        subject, body = nar.mail(ctx, channel, _abuse_addr(asset), asset.normalized or asset.value)
        body_text = f"主题：{subject}\n\n{body}"
    elif channel.body_limit and channel.body_limit <= 800:
        body_text = nar.brief(ctx, channel)
    else:
        body_text = nar.detail(ctx, channel)

    code = _code()
    out_dir = settings.report_dir / code
    built = bundle_mod.build(ctx, channel, body_text, code, out_dir, ev_paths)

    api = (api_base or settings.report_api_base or "http://127.0.0.1:18700").rstrip("/")
    payload = fill_mod.build(
        channel, ctx, body_text, api, code,
        names={"zip": built.zip_name, "pdf": built.pdf_name},
    )

    row = ReportBundle(
        code=code,
        asset_id=asset_id,
        channel=channel.id,
        harm_type=harm.harm,
        harm_label=harm.label,
        status="draft",
        body=body_text,
        fill=payload,
        manifest=built.manifest,
        pdf_path=str(Path(built.pdf_name)),
        zip_path=str(Path(built.zip_name)),
        pdf_sha256=hashlib.sha256(built.pdf).hexdigest(),
        zip_sha256=hashlib.sha256(built.zip_bytes).hexdigest(),
        size=len(built.zip_bytes),
        created_at=utcnow(),
    )
    session.add(row)
    session.flush()
    return row


def _abuse_addr(asset: Asset) -> str:
    """从采集事实里找 abuse 地址，找不到就留空让用户填。"""
    facts = (asset.meta or {}).get("facts") or {}
    for key in ("abuse_email", "abuse", "registrar_abuse"):
        v = facts.get(key)
        if isinstance(v, str) and "@" in v:
            return v
    return ""


def bundle_dir(code: str) -> Path:
    return settings.report_dir / code


def file_of(row: ReportBundle, kind: str) -> Path:
    name = row.zip_path if kind == "zip" else row.pdf_path
    return bundle_dir(row.code) / name


def mark(session: Session, code: str, status: str, receipt: str = "", note: str = "") -> ReportBundle:
    row = session.scalars(select(ReportBundle).where(ReportBundle.code == code)).first()
    if row is None:
        raise LookupError(f"材料不存在：{code}")
    if status not in {"draft", "opened", "submitted", "failed"}:
        raise ValueError(f"非法状态：{status}")
    if status == "opened" and row.opened_at is None:
        row.opened_at = utcnow()
    if status == "submitted":
        row.submitted_at = utcnow()
    row.status = status
    if receipt:
        row.receipt = receipt[:200]
    if note:
        row.note = note[:2000]
    session.flush()
    return row


def as_dict(row: ReportBundle, *, full: bool = False) -> dict[str, Any]:
    ch = CHANNELS.get(row.channel)
    out: dict[str, Any] = {
        "code": row.code,
        "asset_id": row.asset_id,
        "channel": row.channel,
        "channel_name": ch.name if ch else row.channel,
        "channel_short": ch.short if ch else row.channel,
        "entry_url": ch.entry_url if ch else "",
        "harm_type": row.harm_type,
        "harm_label": row.harm_label,
        "status": row.status,
        "body": row.body,
        "body_length": len(row.body),
        "size": row.size,
        "pdf_sha256": row.pdf_sha256,
        "zip_sha256": row.zip_sha256,
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "opened_at": row.opened_at.isoformat() if row.opened_at else "",
        "submitted_at": row.submitted_at.isoformat() if row.submitted_at else "",
        "receipt": row.receipt,
        "note": row.note,
        "manual": (row.fill or {}).get("manual", []),
        "files": (row.fill or {}).get("files", {}),
    }
    if full:
        out["fill"] = row.fill
        out["manifest"] = row.manifest
    return out


def preview(session: Session, asset_id: int, channel_id: str = "", harm_override: str = "") -> dict[str, Any]:
    """不落盘，只给前端看「会生成什么」。"""
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError(f"资产不存在：{asset_id}")
    signals = list(
        session.scalars(
            select(SignalRow).where(SignalRow.asset_id == asset_id).order_by(SignalRow.weight.desc())
        )
    )
    evidence, ev_paths = _evidence_paths(session, asset_id)
    harm = classify(asset, signals, override=harm_override)
    channel = get(channel_id) if channel_id else for_harm(harm.harm)[0]

    ctx = nar.Ctx(
        asset=asset, signals=signals, evidence=evidence, harm=harm,
        now=utcnow(), page_text=_page_text(evidence, ev_paths),
    )
    if channel.fill == "mailto":
        subject, body = nar.mail(ctx, channel, _abuse_addr(asset), asset.normalized or asset.value)
        text = f"主题：{subject}\n\n{body}"
    elif channel.body_limit and channel.body_limit <= 800:
        text = nar.brief(ctx, channel)
    else:
        text = nar.detail(ctx, channel)

    return {
        "channel": channel.as_dict(),
        "harm": {
            "type": harm.harm,
            "label": harm.label,
            "big": harm.big,
            "small": harm.small,
            "reason": harm.reason,
            "platform": harm.platform,
        },
        "body": text,
        "body_length": len(text),
        "body_limit": channel.body_limit,
        "evidence_count": len(evidence),
        "screenshots": sum(1 for e in evidence if e.kind == "screenshot"),
        "guide": nar.guide(ctx, channel),
        "routes": [c.as_dict() for c in for_harm(harm.harm)],
    }
