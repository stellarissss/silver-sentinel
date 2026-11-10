"""v1.16.6 判定一致性回归。

线上留过一批「20 分却挂 high_risk」的资产：白名单压分后 verdict 没回退，
资产沉进 cold 档又不再进周期重评，误报就永久留在高危池里。
"""

from __future__ import annotations

import argparse
from types import SimpleNamespace

from silver_sentinel.cli import cmd_reconcile_verdicts
from silver_sentinel.db import session_scope, verify_chain
from silver_sentinel.evidence import append
from silver_sentinel.models import Asset, SignalRow
from silver_sentinel.pipeline import pending_assets
from silver_sentinel.scoring.engine import normalize_verdict, verdict_for_score


def _asset(session, value: str, *, score: float, verdict: str, tier: str = "cold") -> Asset:
    row = Asset(
        kind="domain", value=value, normalized=value,
        score=score, verdict=verdict, tier=tier,
    )
    session.add(row)
    session.flush()
    return row


def _signals(session, asset_id: int, n: int = 4) -> None:
    for i in range(n):
        session.add(
            SignalRow(
                asset_id=asset_id,
                rule_id=f"T-{i}",
                category="impersonation",
                title=f"测试信号 {i}",
                weight=20.0,
                confidence=0.7,
            )
        )
    session.flush()


def test_verify_chain_for_single_asset(fresh_db):
    """按资产过滤时不能从空链尾起算，否则必然误报断点。"""
    with session_scope() as s:
        a1 = _asset(s, "a1.example", score=0, verdict="insufficient")
        a2 = _asset(s, "a2.example", score=0, verdict="insufficient")
        append(s, a1.id, "page_text", b"one", extension=".txt")
        append(s, a2.id, "page_text", b"two", extension=".txt")
        append(s, a1.id, "page_text", b"three", extension=".txt")
        append(s, a2.id, "page_text", b"four", extension=".txt")
        whole = verify_chain(s)
        per_asset = verify_chain(s, a2.id)
    assert whole["ok"] is True
    assert per_asset["ok"] is True, per_asset
    assert per_asset["checked"] == 2


def test_verdict_for_score_matches_thresholds():
    t = {"suspicious": 15, "high_risk": 40, "confirmed": 70}
    assert verdict_for_score(20, t, signals=4) == "suspicious"
    assert verdict_for_score(38.8, t, signals=4) == "suspicious"
    assert verdict_for_score(45, t, signals=4) == "high_risk"
    assert verdict_for_score(95, t, signals=4) == "high_risk"
    assert verdict_for_score(95, t, signals=1) == "insufficient"


def test_normalize_verdict_downgrades_but_keeps_manual_review():
    def mk(verdict: str, score: float) -> SimpleNamespace:
        return SimpleNamespace(
            score=score, verdict=verdict, signals=[1, 2, 3, 4], notes=[]
        )

    a = mk("high_risk", 20)
    normalize_verdict(a, {"suspicious": 15, "high_risk": 40}, min_signals=2)
    assert a.verdict == "suspicious"
    assert any("回退" in n for n in a.notes)

    b = mk("high_risk", 20)
    normalize_verdict(b, {"suspicious": 15, "high_risk": 40}, reviewed=True, min_signals=2)
    assert b.verdict == "high_risk"  # 人工终审不动

    c = mk("confirmed", 20)
    normalize_verdict(c, {"suspicious": 15, "high_risk": 40}, min_signals=2)
    assert c.verdict == "confirmed"

    d = mk("high_risk", 95)
    normalize_verdict(d, {"suspicious": 15, "high_risk": 40}, min_signals=2)
    assert d.verdict == "high_risk"  # 伪造标识码提级仍成立

    e = SimpleNamespace(score=95, verdict="high_risk", signals=[1], notes=[])
    normalize_verdict(e, {"suspicious": 15, "high_risk": 40}, min_signals=2)
    assert e.verdict == "high_risk"  # 硬证据只有一条信号也不能降级


def test_reconcile_verdicts_dry_run_then_apply(fresh_db):
    with session_scope() as s:
        a = _asset(s, "over.example", score=20, verdict="high_risk")
        _signals(s, a.id)
        aid = a.id

    dry = argparse.Namespace(apply=False, limit=0)
    cmd_reconcile_verdicts(dry)
    with session_scope() as s:
        assert s.get(Asset, aid).verdict == "high_risk"  # dry-run 不写库

    cmd_reconcile_verdicts(argparse.Namespace(apply=True, limit=0))
    with session_scope() as s:
        row = s.get(Asset, aid)
        assert row.verdict == "suspicious"
        assert row.meta["verdict_reconciled"]["from"] == "high_risk"


def test_reconcile_keeps_hard_evidence_high_score_assets(fresh_db):
    """95 分的仿冒财政部站群不能被「信号数不足」误降。"""
    with session_scope() as s:
        a = _asset(s, "fake-gov.example", score=95, verdict="high_risk")
        _signals(s, a.id, n=1)
        aid = a.id
    cmd_reconcile_verdicts(argparse.Namespace(apply=True, limit=0))
    with session_scope() as s:
        assert s.get(Asset, aid).verdict == "high_risk"


def test_pending_assets_pulls_in_inconsistent_cold_assets(fresh_db):
    """冷存档的误报必须被周期研判拉回来，否则永久留在高危池。"""
    with session_scope() as s:
        a = _asset(s, "cold-high.example", score=20, verdict="high_risk", tier="cold")
        aid = a.id
    assert aid in pending_assets(limit=50)
