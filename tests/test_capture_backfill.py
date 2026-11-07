"""取证队列的水位与补队规则。

线上症状：部署几小时后浏览器空转，积压的 600 多个待取证资产一动不动，
队列摘要显示「5 条排队、最老 46 分钟」，看起来像卡死，其实是补队逻辑自己
把自己锁死了：

1. 水位按**全部**排队任务算，5 条失败重试（next_run_at 在 5～16 分钟后）
   就把 6 个缓冲位占满，backfill 每轮直接 return 0；
2. 就算水位还有空，取数时也没排除「已经在队列里」的资产，前 N 条永远是
   同样几个老面孔，enqueue 全部跳过，新的还是补不进来；
3. 取证失败 3 次进入 failed 的资产，下轮 backfill 又把它捞回来重试，
   死域名无限循环，长期挤占配额。

下面五个用例把这三条钉住。时间用相对量构造，不依赖真实时钟。
"""

from __future__ import annotations

from datetime import timedelta

import pytest


def _asset(session, value: str, *, score: float = 10.0, tier: str = "candidate", capture_state: str = "pending"):
    from silver_sentinel.models import Asset

    asset = Asset(
        kind="domain",
        value=value,
        normalized=value,
        score=score,
        tier=tier,
        capture_state=capture_state,
    )
    session.add(asset)
    session.flush()
    return asset


def _task(
    session,
    asset_id: int,
    *,
    state: str = "queued",
    attempts: int = 0,
    next_in_min: float = 0.0,
    finished_ago_min: float | None = None,
    created_ago_min: float = 0.0,
):
    from silver_sentinel.domain import utcnow
    from silver_sentinel.models import CaptureTask

    now = utcnow()
    task = CaptureTask(
        asset_id=asset_id,
        state=state,
        attempts=attempts,
        next_run_at=now + timedelta(minutes=next_in_min),
        created_at=now - timedelta(minutes=created_ago_min),
        finished_at=now - timedelta(minutes=finished_ago_min) if finished_ago_min is not None else None,
    )
    session.add(task)
    session.flush()
    return task


@pytest.fixture
def db(fresh_db):
    from silver_sentinel.db import session_scope

    return session_scope


def test_backoff_tasks_do_not_occupy_the_waterline(db):
    """退避中的任务不该把新线索挡在门外。"""
    from silver_sentinel.capture import backfill
    from silver_sentinel.models import Asset, CaptureTask

    with db() as s:
        for i in range(6):
            asset = _asset(s, f"dead{i}.example.com", capture_state="failed")
            _task(s, asset.id, state="queued", attempts=2, next_in_min=10 + i)
        _asset(s, "fresh.example.com", score=30.0)

    added = backfill(limit=8)
    assert added == 1

    with db() as s:
        fresh = s.query(Asset).filter(Asset.normalized == "fresh.example.com").one()
        assert s.query(CaptureTask).filter(CaptureTask.asset_id == fresh.id).count() == 1


def test_assets_already_queued_are_not_reselected(db):
    """补队要能跳过老面孔，否则每轮都白取一遍同样的前 N 条。"""
    from silver_sentinel.capture import backfill
    from silver_sentinel.models import Asset, CaptureTask

    with db() as s:
        # 三条高分资产已经在队列里等执行
        for i in range(3):
            asset = _asset(s, f"hot{i}.example.com", score=90.0 - i)
            _task(s, asset.id, state="queued", next_in_min=0)
        # 一条低分但没排过队的
        _asset(s, "newcomer.example.com", score=5.0)

    added = backfill(limit=8)
    assert added == 1

    with db() as s:
        newcomer = s.query(Asset).filter(Asset.normalized == "newcomer.example.com").one()
        assert s.query(CaptureTask).filter(CaptureTask.asset_id == newcomer.id).count() == 1


def test_dead_asset_enters_cooldown_and_comes_back_later(db):
    """连续三次失败后先冷却，冷却期满仍会再试一次——不是永久放弃。"""
    from silver_sentinel.capture import backfill
    from silver_sentinel.domain import utcnow
    from silver_sentinel.models import Asset, CaptureTask

    with db() as s:
        dead = _asset(s, "gone.example.com", capture_state="failed")
        task = _task(s, dead.id, state="failed", attempts=3, finished_ago_min=5)
        task_id = task.id

    assert backfill(limit=8) == 0, "刚判死的资产不该立刻重排队"

    # 冷却期过后（默认 6 小时）自动再试
    with db() as s:
        task = s.get(CaptureTask, task_id)
        task.finished_at = utcnow() - timedelta(hours=7)

    assert backfill(limit=8) == 1

    with db() as s:
        alive = s.query(Asset).filter(Asset.normalized == "gone.example.com").one()
        assert s.query(CaptureTask).filter(CaptureTask.asset_id == alive.id, CaptureTask.state == "queued").count() == 1


def test_queue_summary_reports_backoff_separately(db):
    """退避任务要单独计数，不能让最老任务年龄虚高到 46 分钟。"""
    from silver_sentinel.capture import queue_summary

    with db() as s:
        for i in range(3):
            asset = _asset(s, f"wait{i}.example.com", capture_state="failed")
            _task(s, asset.id, state="queued", attempts=2, next_in_min=20 + i)

    summary = queue_summary()
    assert summary["queued"] == 3
    assert summary["queued_due"] == 0
    assert summary["queued_scheduled"] == 3
    assert summary["oldest_queued_minutes"] == 0
    assert summary["next_due_in_minutes"] > 0


def test_queue_summary_counts_overdue_task(db):
    """真正到点没跑的任务必须被看见。"""
    from silver_sentinel.capture import queue_summary

    with db() as s:
        asset = _asset(s, "late.example.com")
        _task(s, asset.id, state="queued", next_in_min=-8, created_ago_min=8)

    summary = queue_summary()
    assert summary["queued_due"] == 1
    assert summary["oldest_queued_minutes"] >= 7
