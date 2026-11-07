"""取证队列的两条纪律。

这两个用例都是线上踩出来的，不是想当然：
- 进程重启会把 running 的任务留在库里，不回收就永远转圈；
- 回填无脑塞任务会让队列变成一条河（进 12 / 出 2）。
"""

from __future__ import annotations

from datetime import timedelta

from silver_sentinel.capture import backfill, enqueue, queue_summary, run_batch
from silver_sentinel.db import init_db, session_scope
from silver_sentinel.domain import utcnow
from silver_sentinel.models import TIER_CANDIDATE, Asset, CaptureTask


def _asset(value: str, tier: str = TIER_CANDIDATE) -> int:
    with session_scope() as s:
        row = Asset(kind="domain", value=value, normalized=value, tier=tier, capture_state="pending")
        s.add(row)
        s.flush()
        return row.id


def test_backfill_stops_at_queue_watermark(fresh_db):
    init_db()
    for i in range(20):
        _asset(f"q{i}.example.com")

    first = backfill(limit=30)
    assert first > 0
    summary = queue_summary()
    # 水位 = max(4, capture_batch * 3)，默认 batch=2 → 最多 6 条
    assert summary["queued"] <= 6, summary
    assert summary["pending_assets"] >= 14

    # 队列里还有活的时候再补，不该继续堆
    assert backfill(limit=30) == 0


def test_stale_running_task_is_reclaimed(fresh_db, monkeypatch):
    init_db()
    aid = _asset("stale.example.com")
    assert enqueue(aid, reason="manual") is True

    # 模拟「进程在取证途中被重启」：状态停在 running，时间戳是很久以前
    with session_scope() as s:
        task = s.query(CaptureTask).filter_by(asset_id=aid).one()
        task.state = "running"
        task.started_at = utcnow() - timedelta(hours=3)

    # 不回收的话，enqueue 会因为「已有 running 任务」直接跳过
    assert enqueue(aid, reason="manual") is False

    monkeypatch.setattr("silver_sentinel.capture.capture_asset", lambda _aid: {"ok": True})
    run_batch(limit=1)

    with session_scope() as s:
        task = s.query(CaptureTask).filter_by(asset_id=aid).one()
    assert task.state == "done"
