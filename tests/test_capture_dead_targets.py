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


def _asset(
    session,
    value: str,
    *,
    capture_state: str = "pending",
    capture_error: str = "",
    tier: str = "candidate",
    score: float = 10.0,
):
    from silver_sentinel.models import Asset

    asset = Asset(
        kind="domain",
        value=value,
        normalized=value,
        score=score,
        tier=tier,
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


def test_cold_fill_only_when_queue_is_idle(db, monkeypatch):
    """队列真空时用冷档填谷，但要有节流，且不能挤占真线索。"""
    from silver_sentinel import capture
    from silver_sentinel.config import settings
    from silver_sentinel.models import CaptureTask

    monkeypatch.setattr(settings, "capture_cold_fill_seconds", 180)
    capture._COLD_FILL_AT = 0.0

    with db() as s:
        cold = _asset(s, "cold.example.com", tier="cold")
        cold_id = cold.id

    assert capture.backfill(limit=8) == 1
    with db() as s:
        assert s.query(CaptureTask).filter_by(asset_id=cold_id, state="queued").count() == 1

    # 节流：同一分钟内不会再取第二条
    assert capture.backfill(limit=8) == 0


def test_cold_fill_does_not_preempt_real_leads(db, monkeypatch):
    from silver_sentinel import capture
    from silver_sentinel.config import settings

    monkeypatch.setattr(settings, "capture_cold_fill_seconds", 180)
    capture._COLD_FILL_AT = 0.0

    with db() as s:
        _asset(s, "cold2.example.com", tier="cold")
        _asset(s, "hot.example.com", score=50.0)

    assert capture.backfill(limit=8) == 1, "只有一条真线索进队，不应再补冷档"
    assert capture._COLD_FILL_AT == 0.0


def test_asset_level_retry_wins_over_task_level_guard(db):
    """资产级冷却与任务级「刚判死」不能互相打架。

    线上现场：36 条失败资产按错误文本被判成 transient，`capture_retry_at`
    只推后 10 分钟；但它们的老任务 `attempts=3` 且 5 分钟前才结束，任务级的
    「6 小时内不再试」仍然生效。结果 due=0、队列空转，可重试资产一条也进不来。
    """
    from silver_sentinel.capture import backfill
    from silver_sentinel.domain import utcnow
    from silver_sentinel.models import CaptureTask

    with db() as s:
        asset = _asset(s, "retry.example.com", capture_state="failed")
        asset.capture_retry_at = utcnow() - timedelta(minutes=1)
        asset_id = asset.id
        s.add(
            CaptureTask(
                asset_id=asset_id,
                state="failed",
                attempts=3,
                next_run_at=utcnow(),
                finished_at=utcnow() - timedelta(minutes=5),
            )
        )
        s.flush()

    assert backfill(limit=8) == 1
    with db() as s:
        assert s.query(CaptureTask).filter_by(asset_id=asset_id, state="queued").count() == 1


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


def test_fast_dead_only_trusts_nxdomain(monkeypatch):
    """DNS 预检只把 NXDOMAIN 判死；超时和 NoAnswer 必须放行给浏览器。"""
    import dns.resolver

    from silver_sentinel.capture import _fast_dead
    from silver_sentinel.config import settings

    monkeypatch.setattr(settings, "allow_network", True)

    def nxdomain(*_a, **_k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver, "resolve", nxdomain)
    assert "NXDOMAIN" in _fast_dead("gone.example.com")

    def timeout(*_a, **_k):
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.resolver, "resolve", timeout)
    assert _fast_dead("slow.example.com") == ""

    monkeypatch.setattr(dns.resolver, "resolve", lambda *_a, **_k: object())
    assert _fast_dead("alive.example.com") == ""


def test_tcp_precheck_distinguishes_open_and_closed():
    """端口预检只负责排除必然失败的取证，判定要保守。"""
    import socket

    from silver_sentinel.capture import _tcp_alive

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        assert _tcp_alive("127.0.0.1", port, timeout=1)
    finally:
        srv.close()
    assert not _tcp_alive("127.0.0.1", port, timeout=1)


def test_second_transient_failure_escalates_to_daily_cooldown(db, monkeypatch):
    """两次都超时就不再按分钟重试：第三次基本是目标侧的问题。"""
    from silver_sentinel import capture
    from silver_sentinel.models import Asset, CaptureTask

    with db() as s:
        asset = _asset(s, "slow2.example.com")
        asset_id = asset.id

    capture.enqueue(asset_id)
    monkeypatch.setattr(
        capture, "capture_asset", lambda _aid: {"ok": False, "error": "Timeout 30000ms exceeded"}
    )
    capture.run_batch(limit=1)          # 第 1 次：排队 10 分钟后再试
    with db() as s:
        t = s.query(CaptureTask).filter_by(asset_id=asset_id).one()
        assert t.state == "queued"

    with db() as s:                     # 让它现在到期，跑第 2 次
        t = s.query(CaptureTask).filter_by(asset_id=asset_id).one()
        t.next_run_at = t.next_run_at - timedelta(minutes=11)
    capture.run_batch(limit=1)

    with db() as s:
        t = s.query(CaptureTask).filter_by(asset_id=asset_id).one()
        assert t.state == "failed"
        assert t.error.startswith("[blocked]")
        asset = s.get(Asset, asset_id)
        assert asset.capture_retry_at is not None
