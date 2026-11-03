"""评分引擎：可解释性、单调性、弃权与不夸大。"""

from __future__ import annotations

import pytest

from silver_sentinel.domain import Signal
from silver_sentinel.scoring.engine import aggregate, assess, evaluate, load_ruleset

THRESHOLDS = {"suspicious": 15, "high_risk": 40, "confirmed": 70}


def sig(rule_id="X", weight=20, confidence=0.8, category="persuasion") -> Signal:
    return Signal(rule_id=rule_id, category=category, title=rule_id, weight=weight, confidence=confidence)


def test_ruleset_loads_and_is_unique():
    rs = load_ruleset()
    assert len(rs.rules) >= 30
    ids = [r.id for r in rs.rules]
    assert len(ids) == len(set(ids))
    assert rs.thresholds["high_risk"] == 35


def test_single_signal_abstains():
    score, conf, verdict, *_ = aggregate([sig()], THRESHOLDS, min_signals=2)
    assert verdict == "insufficient"


def test_score_is_monotonic_in_signal_count():
    one = aggregate([sig(weight=20)], THRESHOLDS, min_signals=1)[0]
    two = aggregate([sig(weight=20), sig(rule_id="Y", weight=20)], THRESHOLDS, min_signals=1)[0]
    three = aggregate([sig(weight=20), sig("Y", 20), sig("Z", 20)], THRESHOLDS, min_signals=1)[0]
    assert one < two < three


def test_noisy_or_never_exceeds_100():
    many = [sig(f"R{i}", 30, 1.0) for i in range(30)]
    score = aggregate(many, THRESHOLDS, min_signals=1)[0]
    assert score <= 100.0


def test_cross_category_bonus_applied():
    same_cat = [sig("A", 20, 0.8, "persuasion"), sig("B", 20, 0.8, "persuasion")]
    cross_cat = [sig("A", 20, 0.8, "persuasion"), sig("B", 20, 0.8, "financial")]
    multi = [sig("A", 20, 0.8, "persuasion"), sig("B", 20, 0.8, "financial"),
             sig("C", 20, 0.8, "technical"), sig("D", 20, 0.8, "distribution")]
    assert aggregate(multi, THRESHOLDS, min_signals=1)[0] > aggregate(cross_cat, THRESHOLDS, min_signals=1)[0]
    assert aggregate(cross_cat, THRESHOLDS, min_signals=1)[0] == pytest.approx(
        aggregate(same_cat, THRESHOLDS, min_signals=1)[0], abs=0.01
    )


def test_confirmed_requires_official_or_review():
    strong = [sig(f"R{i}", 30, 0.95) for i in range(6)]
    score, conf, verdict, *_ = aggregate(strong, THRESHOLDS, min_signals=1)
    assert score >= 70
    assert verdict == "high_risk"  # 机器不得自行授予「确认」

    _, _, verdict_official, *_ = aggregate(strong, THRESHOLDS, official=True, min_signals=1)
    assert verdict_official == "confirmed"


def test_condition_evaluator_supports_nesting():
    ctx = {
        "facts": {"a": 3, "b": True, "c": ["x", "y"], "d": None},
        "text": "免费领鸡蛋 国家补贴",
        "indicators": {"phones": ["13812345678"]},
    }
    assert evaluate({"fact": "a", "op": "gte", "value": 3}, ctx)
    assert evaluate({"fact": "b", "op": "eq", "value": True}, ctx)
    assert evaluate({"fact": "c", "op": "contains", "value": "x"}, ctx)
    assert evaluate({"text_any": ["领鸡蛋"]}, ctx)
    assert not evaluate({"text_any": ["专家义诊"]}, ctx)
    assert evaluate({"all": [{"text_any": ["领鸡蛋"]}, {"fact": "a", "op": "gt", "value": 1}]}, ctx)
    assert evaluate({"any": [{"text_any": ["不存在"]}, {"fact": "b", "op": "truthy"}]}, ctx)
    assert evaluate({"not": {"text_any": ["不存在"]}}, ctx)
    assert not evaluate({"fact": "missing_key", "op": "eq", "value": False}, ctx)
    assert not evaluate({"fact": "d", "op": "eq", "value": False}, ctx)  # None 不等于 False


def test_assess_typical_egg_scam_reaches_high_risk():
    text = (
        "免费领鸡蛋，健康讲座到场即送米面油。国家惠民补贴发放，实名注册领 2 万元养老补贴。"
        "应用商店搜不到，点击继续安装，忽略风险提示。邀请好友拿直推奖励，发展下线晋升团队长。"
        "充值请使用 USDT-TRC20，转账到个人账户。专家义诊，特效药包治百病。"
    )
    result = assess({"distribution_channel": "sideload"}, text=text)
    assert result.score >= 40
    assert result.verdict == "high_risk"
    assert len(result.coverage) >= 3
    assert any(s.rule_id == "PER-001" for s in result.signals)
    assert any(s.rule_id == "FIN-002" for s in result.signals)


def test_assess_benign_text_stays_low():
    result = assess({"icp_registered": True}, text="今天天气不错，社区组织老年人体检，免费测量血压。")
    assert result.verdict in {"insufficient", "low"}
    assert result.score < 15


def test_every_signal_carries_human_readable_reason():
    result = assess(
        {"distribution_channel": "sideload"},
        text="免费领鸡蛋 国家补贴 立即下载 继续安装",
    )
    for signal in result.signals:
        assert signal.title
        assert signal.weight > 0
        assert 0 < signal.confidence <= 1
