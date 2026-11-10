"""判定阈值的单一真相源。

线上出过一次口径事故：`rules/builtin.yaml` 写 `high_risk: 35`，代码兜底却写 40。
规则加载成功时按 35 判，一旦 YAML 缺字段回退到 40，同一批资产结论会突变；
`priority_of()` 还按 40 分档，35~39 分的 high_risk 被排到 P3。
这里把「代码默认 == YAML」钉死，并验证所有兜底确实来自同一个常量。
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import yaml

from silver_sentinel.scoring import engine
from silver_sentinel.scoring.engine import (
    DEFAULT_THRESHOLDS,
    RuleSet,
    load_ruleset,
    priority_of,
    verdict_for_score,
)

BUILTIN = Path(engine.__file__).resolve().parent.parent / "rules" / "builtin.yaml"


def _yaml_thresholds() -> dict[str, float]:
    raw = yaml.safe_load(BUILTIN.read_text(encoding="utf-8")) or {}
    return {k: float(v) for k, v in (raw.get("thresholds") or {}).items()}


def test_default_thresholds_match_builtin_yaml():
    assert DEFAULT_THRESHOLDS == _yaml_thresholds()


def test_ruleset_default_factory_matches_constant_and_is_not_shared():
    a, b = RuleSet(), RuleSet()
    assert a.thresholds == DEFAULT_THRESHOLDS
    assert b.thresholds == DEFAULT_THRESHOLDS
    # 每个实例必须拿到自己的副本，否则一处改写会污染全局规则
    a.thresholds["high_risk"] = 99.0
    assert b.thresholds["high_risk"] == DEFAULT_THRESHOLDS["high_risk"]
    assert DEFAULT_THRESHOLDS["high_risk"] != 99.0


def test_load_ruleset_matches_yaml():
    assert load_ruleset().thresholds == _yaml_thresholds()


def test_partial_yaml_falls_back_to_defaults(tmp_path, monkeypatch):
    """只写 high_risk 的 YAML：其余档位必须用同一常量补齐，而不是整体回退。"""
    (tmp_path / "builtin.yaml").write_text(
        "version: 1\nthresholds:\n  high_risk: 50\n", encoding="utf-8"
    )
    monkeypatch.setattr(engine, "RULES_DIR", tmp_path)
    monkeypatch.delenv("SILVER_RULES_PATH", raising=False)
    rs = load_ruleset()
    assert rs.thresholds["high_risk"] == 50.0
    assert rs.thresholds["suspicious"] == DEFAULT_THRESHOLDS["suspicious"]
    assert rs.thresholds["confirmed"] == DEFAULT_THRESHOLDS["confirmed"]


def test_missing_threshold_key_uses_single_default(monkeypatch):
    """空 thresholds 时兜底值必须来自 DEFAULT_THRESHOLDS，不是硬编码 40。"""
    monkeypatch.setitem(DEFAULT_THRESHOLDS, "high_risk", 55.0)
    monkeypatch.setitem(DEFAULT_THRESHOLDS, "suspicious", 20.0)
    assert verdict_for_score(18.0, {}) == "low"
    assert verdict_for_score(50.0, {}) == "suspicious"
    assert verdict_for_score(60.0, {}) == "high_risk"


def test_priority_of_boundaries_follow_thresholds(monkeypatch):
    def at(score: float, verdict: str = "suspicious") -> SimpleNamespace:
        return SimpleNamespace(score=score, verdict=verdict)

    # 36~39 分的 high_risk 按 35 门槛合法，必须排在 P2 而不是 P3
    assert priority_of(at(35.0, "high_risk")) == "P2"
    assert priority_of(at(34.9)) == "P3"
    assert priority_of(at(70.0)) == "P1"
    assert priority_of(at(14.9)) == "P4"
    assert priority_of(at(0.0, "confirmed")) == "P0"

    # 改常量，分档跟着变——证明没有第二套硬编码分界
    monkeypatch.setitem(DEFAULT_THRESHOLDS, "high_risk", 55.0)
    assert priority_of(at(40.0)) == "P3"
    assert priority_of(at(56.0)) == "P2"


def test_no_hardcoded_threshold_fallbacks_in_source():
    """跨模块（engine / cli / pipeline）不得再把数字写回 .get 兜底。"""
    src = Path(engine.__file__).resolve().parent.parent
    pattern = re.compile(r'thresholds\.get\("(?:suspicious|high_risk|confirmed)",\s*\d')
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if pattern.search(line):
                offenders.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not offenders, "阈值兜底必须引用 DEFAULT_THRESHOLDS：" + "; ".join(offenders)
