"""v1.16.10 监控与高危识别修复的回归测试。

三条线上确证的问题：
1. 冒充国务院办公厅的 s.qka91.com（中稀同心惠民资金审核）只给 70 分 /
   suspicious，按分数排序挤不进主页 top8，长期「没被识别为高危」。
2. 200 个自动盯防名额里 103 个是 NXDOMAIN 死站，占满配额、空转复访，
   真正在线的可疑站挤不进来。
3. 复访对已判死资产仍反复排队，且监控页「有变更 0 / 有失败 0」像空转。
"""

from __future__ import annotations

import pytest


def _asset(session, value="x.cn", **kw):
    from silver_sentinel.models import Asset

    a = Asset(kind="domain", value=value, normalized=value, **kw)
    session.add(a)
    session.flush()
    return a


# ---------------------------------------------------------------- 修复1：冒充最高国家机关提分


def test_top_authority_impersonation_scored_high_risk():
    """冒充国务院办公厅（level=3）应到高危档，能上主页、优先取证。"""
    from silver_sentinel.scoring.reassess import assess_now

    class _Fake:
        score = 0.0
        verdict = "insufficient"
        confidence = 0.0
        reviewed_by = ""

    a = _Fake()
    a.value = "s.qka91.com"
    a.normalized = "s.qka91.com"
    a.meta = {}
    claim = {
        "verdict": "impersonation",
        "level": 3,
        "agencies": ["国务院办公厅", "国务院"],
        "official_domains": {"国务院办公厅": ["gov.cn"]},
    }
    assessment, _ = assess_now(a, facts={"claim": claim}, text="中稀同心 惠民资金审核 国务院办公厅")
    assert assessment.score >= 90.0
    assert assessment.verdict == "high_risk"
    assert any(s.rule_id == "IMP-002H" for s in assessment.signals)


def test_ordinary_impersonation_no_longer_score_verdict_mismatch():
    """普通冒充：suspicious 也应改判为 high_risk，不再留 70 分挂 suspicious。"""
    from silver_sentinel.scoring.reassess import _apply_claim

    class _Fake:
        score = 70.0
        verdict = "suspicious"
        confidence = 0.8
        notes: list[str] = []

        def __init__(self):
            self.signals = []

    a = _Fake()
    _apply_claim(a, {"claim": {"verdict": "impersonation", "level": 2, "agencies": ["某局"]}}, {})
    assert a.verdict == "high_risk"
    assert a.score >= 70.0


def test_machine_never_assigns_confirmed_even_for_top_authority():
    """提分再高，机器也不得给 confirmed——那条档留给人工终审。"""
    from silver_sentinel.scoring.reassess import assess_now

    class _Fake:
        value = "fake-gov.cn"
        normalized = "fake-gov.cn"
        meta = {}
        reviewed_by = ""

    claim = {"verdict": "impersonation", "level": 3, "agencies": ["国务院"],
             "official_domains": {"国务院": ["gov.cn"]}}
    assessment, _ = assess_now(_Fake(), facts={"claim": claim}, text="")
    assert assessment.verdict != "confirmed"


# ---------------------------------------------------------------- 修复2：死站清出盯防池


@pytest.fixture
def db(fresh_db):
    from silver_sentinel.db import session_scope

    return session_scope


def test_prune_watch_disables_dead_asset(db):
    from silver_sentinel.capture import prune_watch
    from silver_sentinel.models import WatchTarget

    with db() as s:
        dead = _asset(s, "dead.cn", tier="watch", capture_state="dead",
                      capture_error="DNS 解析失败（NXDOMAIN）")
        alive = _asset(s, "alive.cn", tier="watch", capture_state="captured")
        s.add(WatchTarget(kind="asset", value="dead.cn", asset_id=dead.id, auto=True,
                          interval_minutes=360))
        s.add(WatchTarget(kind="asset", value="alive.cn", asset_id=alive.id, auto=True,
                          interval_minutes=360))
    moved = prune_watch()
    assert moved == 1
    with db() as s:
        by_value = {w.value: w for w in s.query(WatchTarget).all()}
        # 死站不删除（保住 scan_runs 外键），只停用
        assert by_value["dead.cn"].enabled is False
        assert "判死" in by_value["dead.cn"].note
        assert by_value["alive.cn"].enabled is True


def test_reconcile_watch_skips_dead_asset(db):
    from silver_sentinel.capture import reconcile_watch
    from silver_sentinel.models import WatchTarget

    with db() as s:
        _asset(s, "dead.cn", tier="confirmed", capture_state="dead")
        _asset(s, "alive.cn", tier="confirmed", capture_state="captured")
    reconcile_watch()
    with db() as s:
        values = [w.value for w in s.query(WatchTarget).all()]
    assert "alive.cn" in values
    assert "dead.cn" not in values


def test_prune_watch_keeps_manual_dead_target(db):
    """人工加的目标即便关联死站也不动——用户意图优先于自动清理。"""
    from silver_sentinel.capture import prune_watch
    from silver_sentinel.models import WatchTarget

    with db() as s:
        dead = _asset(s, "dead.cn", tier="watch", capture_state="dead")
        s.add(WatchTarget(kind="asset", value="dead.cn", asset_id=dead.id, auto=False,
                          interval_minutes=360))
    moved = prune_watch()
    assert moved == 0
    with db() as s:
        t = s.query(WatchTarget).first()
        assert s.query(WatchTarget).count() == 1
        assert t.enabled is True


def test_reconcile_revives_disabled_compliant_target(db):
    """死站复活后，对账应复活其停用目标而不是新增（唯一约束）。"""
    from silver_sentinel.capture import reconcile_watch
    from silver_sentinel.models import WatchTarget

    with db() as s:
        alive = _asset(s, "revived.cn", tier="watch", capture_state="captured", score=80.0)
        s.add(WatchTarget(kind="asset", value="revived.cn", asset_id=alive.id, auto=True,
                          enabled=False, interval_minutes=360, note="[自动停用] 已判死"))
    r = reconcile_watch()
    assert r.get("revived") == 1
    with db() as s:
        targets = s.query(WatchTarget).all()
        assert len(targets) == 1  # 不能新增第二条（uq 唯一约束）
        assert targets[0].enabled is True


# ---------------------------------------------------------------- 修复3：复访遇死站自愈停用


def test_run_asset_target_retires_dead(db, monkeypatch):
    import silver_sentinel.monitor as mon
    from silver_sentinel.models import WatchTarget

    with db() as s:
        dead = _asset(s, "dead.cn", tier="watch", capture_state="dead")
        s.add(WatchTarget(kind="asset", value="dead.cn", asset_id=dead.id, auto=True,
                          interval_minutes=360, next_run_at=None))
    with db() as s:
        tid = s.query(WatchTarget).first().id

    # 不让排队被调用：死站必须在不 enqueue 的情况下被跳过
    called = {"n": 0}

    def _boom(*a, **k):
        called["n"] += 1

    monkeypatch.setattr("silver_sentinel.capture.enqueue", _boom)
    # 取证线程「活着」才会走到 enqueue 分支；这里要证明死站在排队前就被拦下。
    # _run_asset_target 内部是 from .worker import capture_worker_alive，patch 源模块。
    monkeypatch.setattr("silver_sentinel.worker.capture_worker_alive", lambda: True)

    result = mon.run_target(tid)
    assert result["status"] == "skipped"
    assert called["n"] == 0
    with db() as s:
        target = s.get(WatchTarget, tid)
        assert target.enabled is False
        assert "判死" in (target.note or "")
