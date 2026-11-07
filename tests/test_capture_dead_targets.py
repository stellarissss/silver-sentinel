"""失败分型与冷却：别拿浏览器时间去反复撞同一堵墙。

线上背景：181 条失败任务里 64 条 ERR_NAME_NOT_RESOLVED、51 条 SSL 握手失败，
它们被「失败 3 次 → 等 6 小时」这条统一规则反复拉起，一天白烧近一小时
浏览器，新线索只能排在后面。这里钉住三件事：

1. 失败按性质分三类，冷却时间不同；
2. 永久失败立即落 failed + dead，不做分钟级重试；
3. 冷却期满仍会再试一次，不永久放弃；
4. 历史失败资产在升级后按错误文本补冷却，不会被一次性全部重排。
"""

from __future__ import annotations

from datetime import timedelta

import pytest


@pytest.fixture
def db(fresh_db):
    from silver_sentinel.db import session_scope

    return session_scope


def _asset(session, value: str, *, capture_state: str = "pending", capture_error: str = ""):
    from silver_sentinel.models import Asset

    asset = Asset(
        kind="domain",
        value=value,
        normalized=value,
        score=10.0,
        tier="candidate",
        capture_state=capture_state,
        capture_error=capture_error,
    )
    session.add(asset)
    session.flush()
    return asset


def test_classify_failure_by_nature():
    from silver_sentinel.capture import (
        FAILURE_BLOCKED,
        FAILURE_DEAD,
        FAILURE_TRANSIENT,
        classify_failure,
    )

    cases = {
        "Error: Page.goto: net::ERR_NAME_NOT_RESOLVED at http://x.com/": FAILURE_DEAD,
        "net::ERR_CONNECTION_REFUSED": FAILURE_DEAD,
        "net::ERR_ADDRESS_UNREACHABLE": FAILURE_DEAD,
        "无可访问地址": FAILURE_DEAD,
        "net::ERR_SSL_PROTOCOL_ERROR": FAILURE_BLOCKED,
        "net::ERR_CERT_AUTHORITY_INVALID": FAILURE_BLOCKED,
        "net::ERR_EMPTY_RESPONSE": FAILURE_BLOCKED,
        "Timeout 30000ms exceeded": FAILURE_TRANSIENT,
        "net::ERR_CONNECTION_RESET": FAILURE_TRANSIENT,
        "": FAILURE_TRANSIENT,
    }
    for error, kind in cases.items():
        assert classify_failure(error) == kind, error


def test_dead_target_is_not_requeued_in_minutes(db, monkeypatch):
    from silver_sentinel import capture
    from silver_sentinel.models import Asset, CaptureTask

    with db() as s:
        asset = _asset(s, "gone.example.com")
        asset_id = asset.id

    capture.enqueue(asset_id)
    monkeypatch.setattr(
        capture,
        "capture_asset",
        lambda _aid: {"ok": False, "error": "net::ERR_NAME_NOT_RESOLVED"},
    )
    out = capture.run_batch(limit=1)
    assert out["ok"] == 0

    with db() as s:
        task = s.query(CaptureTask).filter_by(asset_id=asset_id).one()
        # 不是「10 分钟后再试」，而是直接判失败，等冷却
        assert task.state == "failed"
        assert task.error.startswith("[dead]")
        asset = s.get(Asset, asset_id)
        assert asset.capture_state == "dead"
        assert asset.capture_retry_at is not None
        delay = asset.capture_retry_at - task.finished_at
        assert delay >= timedelta(hours=70)

    # 冷却期内补队不能再把它捞回来
    assert capture.backfill(limit=8) == 0


def test_dead_target_returns_after_cooldown(db):
    from silver_sentinel.capture import backfill
    from silver_sentinel.domain import utcnow
    from silver_sentinel.models import CaptureTask

    with db() as s:
        asset = _asset(s, "back.example.com", capture_state="dead")
        asset.capture_retry_at = utcnow() - timedelta(minutes=1)
        asset_id = asset.id

    assert backfill(limit=8) == 1
    with db() as s:
        assert s.query(CaptureTask).filter_by(asset_id=asset_id, state="queued").count() == 1


def test_transient_failure_keeps_short_backoff(db, monkeypatch):
    from silver_sentinel import capture
    from silver_sentinel.models import Asset, CaptureTask

    with db() as s:
        asset = _asset(s, "flaky.example.com")
        asset_id = asset.id

    capture.enqueue(asset_id)
    monkeypatch.setattr(
        capture,
        "capture_asset",
        lambda _aid: {"ok": False, "error": "Timeout 30000ms exceeded"},
    )
    capture.run_batch(limit=1)

    with db() as s:
        task = s.query(CaptureTask).filter_by(asset_id=asset_id).one()
        assert task.state == "queued", "抖动类失败必须留在队列里重试"
        assert task.next_run_at > utcnow_plus(minutes=5)
        asset = s.get(Asset, asset_id)
        assert asset.capture_state == "failed"
        assert asset.capture_retry_at is not None


def utcnow_plus(*, minutes: int):
    from silver_sentinel.domain import utcnow

    return utcnow() + timedelta(minutes=minutes)


def test_seed_retry_state_classifies_history(db):
    """升级后第一次启动：历史失败资产按错误文本补冷却，不能一次性全重排。"""
    from silver_sentinel.capture import seed_retry_state
    from silver_sentinel.models import Asset

    with db() as s:
        dead = _asset(s, "old-dead.example.com", capture_state="failed",
                      capture_error="net::ERR_NAME_NOT_RESOLVED")
        blocked = _asset(s, "old-blocked.example.com", capture_state="failed",
                         capture_error="net::ERR_SSL_PROTOCOL_ERROR")
        dead_id, blocked_id = dead.id, blocked.id

    assert seed_retry_state() == 2

    with db() as s:
        dead = s.get(Asset, dead_id)
        blocked = s.get(Asset, blocked_id)
        assert dead.capture_state == "dead"
        assert dead.capture_retry_at is not None
        assert blocked.capture_state == "failed"
        assert blocked.capture_retry_at is not None
        assert blocked.capture_retry_at < dead.capture_retry_at
