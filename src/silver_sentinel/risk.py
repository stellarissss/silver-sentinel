"""风险指数：一个能解释、能追溯的总览数字。

为什么不用「平均分」
--------------------
平均分对样本量不敏感：2,000 条冷存资产会把一个刚出现的高危团伙稀释成 12 分，
看起来「风险很低」，而这正是最危险的误读。

这里用四项加权，每一项都能点开看构成：
- 高危占比（40%）：当前有效资产里，多少是高度可疑及以上；
- 高危新增（30%）：近 24 小时新出现的高危，衡量「正在发生」；
- 证据完备（20%）：有多少资产真的看过页面，衡量结论有多可信；
- 监控覆盖（10%）：该盯的是否都在盯，衡量闭环有没有断。

指数只用于「今天要不要多看两眼」，不用于定性。定性永远看具体资产。
"""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, select

from .config import settings
from .db import session_scope
from .domain import utcnow
from .models import TIER_CONFIRMED, TIER_DISMISSED, TIER_WATCH, Asset, Evidence, WatchTarget

ACTIVE = (TIER_CONFIRMED, TIER_WATCH, "candidate")
HIGH = ("high_risk", "confirmed")

WEIGHTS = {"high_ratio": 0.40, "new_high": 0.30, "evidence": 0.20, "watch": 0.10}

LABELS = {
    "high_ratio": "高危占比",
    "new_high": "近 24 小时高危新增",
    "evidence": "证据完备率",
    "watch": "监控覆盖率",
}

# 一天新增高危占有效资产 5% 视为满分。再高就是「全面失控」，指数封顶即可。
NEW_HIGH_FULL = 0.05


def _scalar(session, stmt, default=0):
    value = session.scalar(stmt)
    return value if value is not None else default


def compute() -> dict[str, Any]:
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    with session_scope() as s:
        active = _scalar(
            s, select(func.count(Asset.id)).where(Asset.tier.in_(ACTIVE))
        )
        high = _scalar(
            s,
            select(func.count(Asset.id)).where(
                Asset.tier.in_(ACTIVE), Asset.verdict.in_(HIGH)
            ),
        )
        new_high = _scalar(
            s,
            select(func.count(Asset.id)).where(
                Asset.tier.in_(ACTIVE),
                Asset.verdict.in_(HIGH),
                Asset.first_seen >= day_ago,
            ),
        )
        # 分子分母同口径：只统计有效资产里有多少已经有页面证据
        with_evidence = _scalar(
            s,
            select(func.count(func.distinct(Evidence.asset_id)))
            .join(Asset, Asset.id == Evidence.asset_id)
            .where(
                Evidence.kind.in_(("page_html", "screenshot")),
                Evidence.deleted_at.is_(None),
                Asset.tier.in_(ACTIVE),
            ),
        )
        watch_total = _scalar(
            s,
            select(func.count(Asset.id)).where(Asset.tier.in_((TIER_CONFIRMED, TIER_WATCH))),
        )
        watch_covered = _scalar(
            s,
            select(func.count(func.distinct(WatchTarget.asset_id))).where(
                WatchTarget.enabled.is_(True), WatchTarget.asset_id.is_not(None)
            ),
        )
        dismissed = _scalar(
            s, select(func.count(Asset.id)).where(Asset.tier == TIER_DISMISSED)
        )

    high_ratio = (high / active) if active else 0.0
    new_rate = (new_high / active) if active else 0.0
    # 证据完备率以「有效资产」为分母；超过 100% 说明证据来自已排除资产，按 100 算
    ev_ratio = min(1.0, (with_evidence / active) if active else 0.0)
    watch_ratio = min(1.0, (watch_covered / watch_total) if watch_total else 1.0)

    parts = {
        "high_ratio": round(min(1.0, high_ratio * 2) * 100, 1),   # 50% 高危即满分
        "new_high": round(min(1.0, new_rate / NEW_HIGH_FULL) * 100, 1),
        "evidence": round(ev_ratio * 100, 1),
        "watch": round(watch_ratio * 100, 1),
    }
    index = round(sum(parts[k] * WEIGHTS[k] for k in WEIGHTS), 1)

    return {
        "index": index,
        "level": level_of(index),
        "parts": [
            {
                "key": key,
                "label": LABELS[key],
                "score": parts[key],
                "weight": WEIGHTS[key],
                "raw": {
                    "high_ratio": f"{high}/{active}",
                    "new_high": f"{new_high}/24h",
                    "evidence": f"{with_evidence}/{active}",
                    "watch": f"{watch_covered}/{watch_total}",
                }[key],
                "hint": {
                    "high_ratio": "有效资产中判定为高度可疑及以上的比例",
                    "new_high": "近 24 小时新增高危；越高说明正在扩散",
                    "evidence": "有页面 HTML 或截图的资产比例；越低说明结论越不可靠",
                    "watch": "高危/观察目标中已纳入周期复访的比例",
                }[key],
            }
            for key in WEIGHTS
        ],
        "counts": {
            "active": active,
            "high": high,
            "new_high_24h": new_high,
            "with_evidence": with_evidence,
            "watch_total": watch_total,
            "watch_covered": watch_covered,
            "dismissed": dismissed,
        },
        "trend": trend(days=7),
        "computed_at": now.isoformat(),
    }


def level_of(index: float) -> str:
    if index >= 70:
        return "high"
    if index >= 45:
        return "elevated"
    if index >= 25:
        return "moderate"
    return "low"


LEVEL_LABEL = {"high": "高", "elevated": "偏高", "moderate": "中等", "low": "低"}


def trend(days: int = 7) -> list[dict[str, Any]]:
    """从副本快照里重建每日指数。

    没有快照时返回空数组，前端画一条「暂无历史」而不是编一条平滑曲线。
    """
    root = settings.data_dir / "replica" / "db"
    if not root.is_dir():
        return []
    cutoff = (utcnow() - timedelta(days=days)).strftime("%Y%m%d")
    by_day: dict[str, Path] = {}
    for item in sorted(root.glob("sentinel-*.db")):
        stamp = item.stem.replace("sentinel-", "")[:8]
        if len(stamp) == 8 and stamp.isdigit() and stamp >= cutoff:
            by_day[stamp] = item  # 同一天保留最后一份

    out: list[dict[str, Any]] = []
    for day in sorted(by_day):
        point = _index_from_snapshot(by_day[day])
        if point is not None:
            out.append({"date": f"{day[:4]}-{day[4:6]}-{day[6:]}", **point})
    return out


def _index_from_snapshot(path: Path) -> dict[str, Any] | None:
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)
        try:
            cur = conn.cursor()
            active = cur.execute(
                "select count(*) from assets where tier in ('confirmed','watch','candidate')"
            ).fetchone()[0]
            high = cur.execute(
                "select count(*) from assets where tier in ('confirmed','watch','candidate')"
                " and verdict in ('high_risk','confirmed')"
            ).fetchone()[0]
            with_ev = cur.execute(
                "select count(distinct asset_id) from evidence where kind in ('page_html','screenshot')"
                " and (deleted_at is null)"
            ).fetchone()[0] if _has_column(cur, "evidence", "deleted_at") else cur.execute(
                "select count(distinct asset_id) from evidence where kind in ('page_html','screenshot')"
            ).fetchone()[0]
            watch_total = cur.execute(
                "select count(*) from assets where tier in ('confirmed','watch')"
            ).fetchone()[0]
            covered = cur.execute(
                "select count(distinct asset_id) from watch_targets where enabled=1 and asset_id is not null"
            ).fetchone()[0] if _has_column(cur, "watch_targets", "asset_id") else 0
        finally:
            conn.close()
    except (sqlite3.Error, OSError):
        return None

    if not active:
        return None
    parts = {
        "high_ratio": min(1.0, (high / active) * 2) * 100,
        "new_high": 0.0,  # 快照看不出「近 24h」，趋势里这一项按 0 处理
        "evidence": min(1.0, with_ev / active) * 100,
        "watch": min(1.0, covered / watch_total) * 100 if watch_total else 100.0,
    }
    index = round(sum(parts[k] * WEIGHTS[k] for k in WEIGHTS), 1)
    return {"index": index, "active": active, "high": high}


def _has_column(cur, table: str, column: str) -> bool:
    try:
        return any(row[1] == column for row in cur.execute(f"PRAGMA table_info({table})"))
    except sqlite3.Error:
        return False
