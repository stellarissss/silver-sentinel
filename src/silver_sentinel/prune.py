"""清理取证失败的死站：最小留痕后删除，把取证预算留给发现新团伙。

为什么需要
----------
取证队列里塞满了「端口无法连接 / NXDOMAIN」的域名。它们永远取不到证，
却持续占用重试额度、撑大列表、把真正的新团伙挤到后面。一旦不再需要拿
它们去举报，留一条可追溯的最小记录就够了。

安全口径（默认，宁可少删不可误删）
--------------------------------
- capture_state 为 failed 或 dead
- 且没有任何 evidence / 举报包（取到过东西的站一律保留）
- 且没有团伙归属、没被人工审阅过、不是观察/已确认档
- 且 verdict 不是 high_risk（站可能只是暂时下线，域名本身仍有价值）

删除前做两件事，缺一不可：
1. 完整资产行归档到 data_dir/archive/pruned-<ts>.jsonl（可恢复）
2. 每域名写一条 DiscoveryEvent(source="asset_pruned") 精简留痕

删除时：
- scan_runs / watch_targets 的 asset_id 先解引用（NO ACTION / 无 FK，不解会报错或悬空）
- 其余子表由 DB 的 ON DELETE CASCADE 处理
- discovery_events 历史流水原样保留：它本来就是「这个域名怎么被发现的」记录
- graph_nodes / graph_edges 保留：IP、证书、ASN 是跨资产的基础设施证据，
  删掉反而会破坏团伙发现

默认 dry-run，必须 apply=True 才写。
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import DateTime, exists, or_, select, update
from sqlalchemy.exc import OperationalError

from .config import settings
from .db import init_db, session_scope
from .models import (
    Asset,
    DiscoveryEvent,
    Evidence,
    ReportBundle,
    ScanRun,
    WatchTarget,
)

log = logging.getLogger(__name__)

PRUNE_SOURCE = "asset_pruned"
DEFAULT_REASON = "取证永久失败，已无需举报；保留最小留痕，释放取证预算用于发现新团伙"
BATCH_SIZE = 100
MAX_RETRIES = 3

# 错误文本归到几个大类，便于 dry-run 一眼看清删的是什么。
_ERROR_CLASSES: tuple[tuple[str, str], ...] = (
    ("端口无法连接", "端口无法连接"),
    ("NXDOMAIN", "DNS NXDOMAIN"),
    ("Cloudflare", "WAF 拦截"),
    ("WAF", "WAF 拦截"),
    ("Timeout", "超时"),
    ("内网地址", "内网阻断"),
)


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value or "")


def error_class(text: str) -> str:
    for needle, label in _ERROR_CLASSES:
        if needle in (text or ""):
            return label
    return "(无错误文本)" if not text else "其它"


def select_candidates(
    session: Any,
    *,
    include_observed: bool = False,
    include_high_risk: bool = False,
    limit: int = 0,
) -> list[Asset]:
    """按安全口径挑出可删资产。只查不改。"""
    stmt = select(Asset).where(
        Asset.capture_state.in_(("failed", "dead")),
        ~exists(select(Evidence.id).where(Evidence.asset_id == Asset.id)),
        ~exists(select(ReportBundle.id).where(ReportBundle.asset_id == Asset.id)),
        Asset.campaign_id.is_(None),
        or_(Asset.reviewed_by.is_(None), Asset.reviewed_by == ""),
    )
    if not include_observed:
        stmt = stmt.where(Asset.tier.notin_(("watch", "confirmed")))
    if not include_high_risk:
        stmt = stmt.where(Asset.verdict != "high_risk")
    stmt = stmt.order_by(Asset.id)
    if limit > 0:
        stmt = stmt.limit(limit)
    return list(session.scalars(stmt))


def archive_record(asset: Asset, *, reason: str, pruned_at: str) -> dict[str, Any]:
    """完整资产行快照。遍历表列，未来加列不用改这里。"""
    record: dict[str, Any] = {}
    for col in Asset.__table__.columns:
        value = getattr(asset, col.name)
        record[col.name] = _iso(value) if isinstance(value, datetime) else value
    record["pruned_at"] = pruned_at
    record["reason"] = reason
    return record


def build_tombstone(
    asset: Asset, *, archive_name: str, reason: str, pruned_at: str
) -> DiscoveryEvent:
    """数据库内最小留痕：一个域名一条，够查「它为什么被删」。"""
    return DiscoveryEvent(
        source=PRUNE_SOURCE,
        kind=asset.kind or "domain",
        value=(asset.value or "")[:2000],
        normalized=asset.normalized or "",
        matched_terms=[],
        score_hint=float(asset.score or 0.0),
        asset_id=None,
        parent="prune-assets",
        raw={
            "asset_id": asset.id,
            "capture_state": asset.capture_state,
            "capture_error": (asset.capture_error or "")[:300],
            "tier": asset.tier,
            "verdict": asset.verdict,
            "score": asset.score,
            "first_seen": _iso(asset.first_seen),
            "last_seen": _iso(asset.last_seen),
            "discovery_source": asset.discovery_source,
            "discovery_reason": (asset.discovery_reason or "")[:200],
            "group_key": asset.group_key or "",
            "archive": archive_name,
            "pruned_at": pruned_at,
            "reason": reason,
        },
    )


def _summarize(candidates: list[Asset]) -> dict[str, Any]:
    by_state: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    by_error: dict[str, int] = {}
    for a in candidates:
        by_state[a.capture_state or ""] = by_state.get(a.capture_state or "", 0) + 1
        by_tier[a.tier or ""] = by_tier.get(a.tier or "", 0) + 1
        cls = error_class(a.capture_error or "")
        by_error[cls] = by_error.get(cls, 0) + 1
    return {
        "by_state": dict(sorted(by_state.items(), key=lambda kv: -kv[1])),
        "by_tier": dict(sorted(by_tier.items(), key=lambda kv: -kv[1])),
        "by_error": dict(sorted(by_error.items(), key=lambda kv: -kv[1])),
    }


def prune(
    *,
    apply: bool = False,
    include_observed: bool = False,
    include_high_risk: bool = False,
    limit: int = 0,
    reason: str = DEFAULT_REASON,
    archive_dir: Path | str | None = None,
) -> dict[str, Any]:
    """默认 dry-run。apply=True 才归档、留痕、删除。"""
    init_db()
    with session_scope() as session:
        candidates = select_candidates(
            session,
            include_observed=include_observed,
            include_high_risk=include_high_risk,
            limit=limit,
        )

    result: dict[str, Any] = {
        "dry_run": not apply,
        "criteria": {
            "capture_state": ["failed", "dead"],
            "exclude_with_evidence": True,
            "exclude_with_report_bundle": True,
            "exclude_with_campaign": True,
            "exclude_reviewed": True,
            "exclude_tiers": [] if include_observed else ["watch", "confirmed"],
            "exclude_verdict": [] if include_high_risk else ["high_risk"],
        },
        "candidates": len(candidates),
        **_summarize(candidates),
    }
    if not apply:
        result["samples"] = [a.value for a in candidates[:8]]
        result["hint"] = "这是 dry-run，未写任何数据；确认后加 --apply"
        return result
    if not candidates:
        result.update({"applied": True, "deleted": 0, "archive": "", "tombstones": 0})
        return result

    now = datetime.now(UTC)
    pruned_at = now.isoformat()
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    directory = Path(archive_dir) if archive_dir else settings.data_dir / "archive"
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f"pruned-capture-failed-{stamp}.jsonl"
    with archive.open("w", encoding="utf-8") as handle:
        for a in candidates:
            handle.write(
                json.dumps(
                    archive_record(a, reason=reason, pruned_at=pruned_at),
                    ensure_ascii=False,
                    default=str,
                )
                + "\n"
            )

    deleted = 0
    for start in range(0, len(candidates), BATCH_SIZE):
        batch = candidates[start : start + BATCH_SIZE]
        ids = [a.id for a in batch]
        tombstones = [
            build_tombstone(a, archive_name=archive.name, reason=reason, pruned_at=pruned_at)
            for a in batch
        ]
        for attempt in range(MAX_RETRIES):
            try:
                with session_scope() as session:
                    session.execute(
                        update(ScanRun).where(ScanRun.asset_id.in_(ids)).values(asset_id=None)
                    )
                    session.execute(
                        update(WatchTarget)
                        .where(WatchTarget.asset_id.in_(ids))
                        .values(asset_id=None)
                    )
                    session.add_all(tombstones)
                    rows = list(session.scalars(select(Asset).where(Asset.id.in_(ids))))
                    for row in rows:
                        session.delete(row)
                    session.flush()
                deleted += len(rows)
                break
            except OperationalError as exc:
                if attempt == MAX_RETRIES - 1:
                    raise
                log.warning("清理批次撞锁，第 %d 次重试：%s", attempt + 1, exc)
                time.sleep(1.5 * (attempt + 1))

    result.update(
        {
            "applied": True,
            "deleted": deleted,
            "archive": str(archive),
            "tombstones": len(candidates),
        }
    )
    return result


def restore(archive: Path | str, *, apply: bool = False) -> dict[str, Any]:
    """从归档 JSONL 恢复资产。已存在同 normalized 的跳过，保证幂等。"""
    init_db()
    path = Path(archive)
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    result: dict[str, Any] = {
        "dry_run": not apply,
        "archive": str(path),
        "records": len(records),
        "restored": 0,
        "skipped": 0,
    }
    if not apply:
        return result

    columns = set(Asset.__table__.columns.keys()) - {"id", "pruned_at", "reason"}
    datetime_cols = {
        col.name for col in Asset.__table__.columns if isinstance(col.type, DateTime)
    }
    with session_scope() as session:
        # 唯一约束是 (kind, normalized)，不是 normalized 单列：domain 与 url
        # 可能产生同一个值，只按 normalized 去重会误跳过一条、丢数据。
        existing = {
            (kind, normalized)
            for kind, normalized in session.execute(select(Asset.kind, Asset.normalized))
        }
        for record in records:
            normalized = record.get("normalized") or ""
            dedup_key = (record.get("kind") or "domain", normalized)
            if dedup_key in existing:
                result["skipped"] += 1
                continue
            data = {k: v for k, v in record.items() if k in columns}
            for key in datetime_cols:
                if isinstance(data.get(key), str):
                    try:
                        data[key] = datetime.fromisoformat(data[key])
                    except ValueError:
                        data[key] = None
            session.add(Asset(**data))
            existing.add(dedup_key)
            result["restored"] += 1
    return result
