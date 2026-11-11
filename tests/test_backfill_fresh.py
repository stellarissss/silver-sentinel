"""新线索取证饥饿：水位常年只有 1，排序错了就永远轮不到新资产。

线上复现：近 24h 新增 1850 条资产，973 条 pending 没有任何 CaptureTask。
根因不是队列卡死，而是 backfill 的 order_by 把 source_rank 放在
「从未取证」之前——ip_pool / ct_bulk 来源的 0 分老站「24 小时复访」
池有 3000+ 条且每天再生，pivot / ct_poll 来源的新线索排在后面，
每轮 room=1 只补一条，补的全是复访。新资产没正文 → 0 分 →
insufficient → 首页按分数排序永远看不到它们。

这组用例钉死「同一档位内，近 24h 首次发现且从未取证的线索先入队」。
"""

from __future__ import annotations

from datetime import timedelta

from silver_sentinel.db import session_scope
from silver_sentinel.domain import utcnow
from silver_sentinel.models import Asset, CaptureTask


def _asset(s, value, *, score=0.0, tier="candidate", capture_state="pending",
           source="pivot", last_capture_at=None, seen_ago_hours=0):
    a = Asset(
        kind="domain", value=value, normalized=value, score=score,
        tier=tier, capture_state=capture_state,
        discovery_source=source,
        first_seen=utcnow() - timedelta(hours=seen_ago_hours),
        last_seen=utcnow() - timedelta(hours=seen_ago_hours),
        last_capture_at=last_capture_at,
    )
    s.add(a)
    s.flush()
    return a


def test_fresh_pending_beats_high_rank_refresh(fresh_db):
    """room=1 时，补进去的必须是新线索，不是 ip_pool 的 0 分复访老站。"""
    from silver_sentinel.capture import backfill, queue_summary

    now = utcnow()
    with session_scope() as s:
        # 复访老站：来源最硬（ip_pool），24h 前取过证，分数 0
        old = _asset(
            s, "old-ip-pool.cn", score=0.0, capture_state="captured",
            source="ip_pool", last_capture_at=now - timedelta(hours=30),
            seen_ago_hours=72,
        )
        # 新线索：来源排最后（pivot），从未取证，分数也是 0
        fresh = _asset(s, "brand-new-pivot.cn", score=0.0,
                       capture_state="pending", source="pivot", seen_ago_hours=1)
        old_id, fresh_id = old.id, fresh.id
        # 造 5 条 due 任务把 room 压到 1（线上实测的稳定水位）
        for i in range(5):
            a = _asset(s, f"filler{i}.cn", score=0.0, capture_state="pending")
            s.add(CaptureTask(asset_id=a.id, state="queued", next_run_at=now))

    summary = queue_summary()
    assert summary["queued_due"] >= 5

    added = backfill(limit=1)
    assert added == 1

    with session_scope() as s:
        assert s.query(CaptureTask).filter(
            CaptureTask.asset_id == fresh_id, CaptureTask.state == "queued"
        ).count() == 1, "新线索必须先入队"
        assert s.query(CaptureTask).filter(
            CaptureTask.asset_id == old_id, CaptureTask.state == "queued"
        ).count() == 0, "复访老站不该抢走唯一的配额"


def test_fresh_pending_beats_ct_bulk_refresh_with_higher_score(fresh_db):
    """即使复访老站分数更高，也不能压过「从未取证」的新线索。"""
    from silver_sentinel.capture import backfill

    now = utcnow()
    with session_scope() as s:
        old = _asset(
            s, "old-bulk.cn", score=12.0, capture_state="captured",
            source="ct_bulk", last_capture_at=now - timedelta(hours=30),
            seen_ago_hours=60,
        )
        fresh = _asset(s, "fresh-poll.cn", score=0.0,
                       capture_state="pending", source="ct_poll", seen_ago_hours=2)
        old_id, fresh_id = old.id, fresh.id
        for i in range(5):
            a = _asset(s, f"pad{i}.cn")
            s.add(CaptureTask(asset_id=a.id, state="queued", next_run_at=now))

    assert backfill(limit=1) == 1
    with session_scope() as s:
        assert s.query(CaptureTask).filter(CaptureTask.asset_id == fresh_id).count() == 1
        assert s.query(CaptureTask).filter(CaptureTask.asset_id == old_id).count() == 0


def test_watch_refresh_still_outranks_candidate_fresh(fresh_db):
    """分级优先于取证状态这条业务规则不能被改坏：watch 复访仍比 candidate 首访急。"""
    from silver_sentinel.capture import backfill

    now = utcnow()
    with session_scope() as s:
        watch = _asset(
            s, "watch-refresh.cn", score=0.0, tier="watch",
            capture_state="captured", source="ct_poll",
            last_capture_at=now - timedelta(hours=30), seen_ago_hours=60,
        )
        cand = _asset(s, "candidate-fresh.cn", score=0.0, tier="candidate",
                      capture_state="pending", source="pivot", seen_ago_hours=1)
        watch_id, cand_id = watch.id, cand.id
        for i in range(5):
            a = _asset(s, f"pad{i}.cn")
            s.add(CaptureTask(asset_id=a.id, state="queued", next_run_at=now))

    assert backfill(limit=1) == 1
    with session_scope() as s:
        assert s.query(CaptureTask).filter(CaptureTask.asset_id == watch_id).count() == 1
        assert s.query(CaptureTask).filter(CaptureTask.asset_id == cand_id).count() == 0
