"""机构级伪装与盯防对账。

线上两条真实数据决定了这里的口径：

- `tuiyijunren.cn`（退役军人网）46.6 分，coverage.impersonation=3，
  正文 4439 字、21 个关键词命中，却卡在 45 分结构旁路之外——因为那条旁路
  要求「冒充 + 说服」同时成立，而它没有说服类特征。冒充三个身份元素本身
  已经足够定性。
- `watch_targets` 表是空的，`scan_runs` 一天 0 条：分级升到 watch 之后，
  纳管调用点漏了一次，资产就只剩低频复访，看起来一切正常。
"""

from __future__ import annotations

import pytest


@pytest.fixture
def db(fresh_db):
    from silver_sentinel.db import session_scope

    return session_scope


def _asset(session, value="x.cn", *, score=46.6, coverage=None, tier="candidate"):
    from silver_sentinel.models import Asset

    asset = Asset(
        kind="domain",
        value=value,
        normalized=value,
        score=score,
        tier=tier,
        verdict="high_risk",
        meta={"facts": {"coverage": coverage or {}}, "triaged": True},
    )
    session.add(asset)
    session.flush()
    return asset


def test_institutional_impersonation_enters_watch(db):
    from silver_sentinel.triage import decide

    with db() as s:
        asset = _asset(s, "tuiyijunren.cn", score=46.6, coverage={"impersonation": 3})
        decision = decide(asset)
    assert decision.tier == "watch"
    assert "冒充" in "；".join(decision.reasons)


def test_single_impersonation_stays_candidate(db):
    from silver_sentinel.triage import decide

    with db() as s:
        asset = _asset(s, "zijinpan.cn", score=45.0, coverage={"impersonation": 1, "financial": 2})
        decision = decide(asset)
    assert decision.tier == "candidate"


def test_impersonation_needs_score_floor(db):
    """只有 3 项冒充、分数却很低时不动——低分说明正文几乎没有诈骗语义。"""
    from silver_sentinel.triage import decide

    with db() as s:
        asset = _asset(s, "low.cn", score=30.0, coverage={"impersonation": 3})
        decision = decide(asset)
    assert decision.tier == "candidate"


def test_reconcile_watch_fills_missing_targets(db):
    from silver_sentinel.capture import reconcile_watch
    from silver_sentinel.models import WatchTarget

    with db() as s:
        _asset(s, "watched.cn", score=61.0, tier="watch")
        _asset(s, "confirmed.cn", score=88.0, tier="confirmed")
        _asset(s, "cand.cn", score=20.0, tier="candidate")

    assert reconcile_watch()["added"] == 2

    with db() as s:
        values = {t.value for t in s.query(WatchTarget).all()}
    assert values == {"watched.cn", "confirmed.cn"}


def test_reconcile_watch_is_idempotent(db):
    from silver_sentinel.capture import reconcile_watch
    from silver_sentinel.models import WatchTarget

    with db() as s:
        _asset(s, "watched.cn", score=61.0, tier="watch")

    assert reconcile_watch()["added"] == 1
    assert reconcile_watch()["added"] == 0
    with db() as s:
        assert s.query(WatchTarget).count() == 1


def test_brief_flags_empty_pipeline(db, capsys):
    from types import SimpleNamespace

    from silver_sentinel.cli import cmd_brief

    rc = cmd_brief(SimpleNamespace(hours=24))
    out = capsys.readouterr().out
    assert rc == 1
    assert "没有任何新资产" in out


def test_brief_reports_healthy_day(db, capsys):
    from datetime import timedelta
    from types import SimpleNamespace

    from silver_sentinel.cli import cmd_brief
    from silver_sentinel.domain import utcnow
    from silver_sentinel.models import CaptureTask, Evidence

    with db() as s:
        asset = _asset(s, "seen.cn", score=55.0, tier="watch")
        asset.first_seen = utcnow()
        s.add(
            CaptureTask(
                asset_id=asset.id,
                state="done",
                reason="backfill",
                priority=10,
                finished_at=utcnow(),
            )
        )
        s.add(
            Evidence(
                asset_id=asset.id,
                kind="html",
                sha256="0" * 64,
                path="/tmp/x",
                captured_at=utcnow() - timedelta(minutes=5),
            )
        )

    rc = cmd_brief(SimpleNamespace(hours=24))
    out = capsys.readouterr().out
    assert rc == 0
    assert "新资产" in out
    assert "取证完成" in out
