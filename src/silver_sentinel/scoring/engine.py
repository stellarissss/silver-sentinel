"""规则引擎与风险聚合。

三个刻意的设计决定：

1. **noisy-OR 聚合而非加权求和。** 求和会让「十条弱特征」轻易超过「一条铁证」；
   noisy-OR 下每条信号贡献递减，符合证据的实际证明力。
2. **置信度与风险分分离。** 风险分回答「有多像」，置信度回答「证据够不够」。
   只有 1 条信号时，即使权重很高也不该给出确定结论。
3. **确认等级不由分数授予。** 最高档 `confirmed` 只来自人工复核或官方通报，
   机器最多判到 `high_risk`。这是对误伤成本的尊重。
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..domain import Assessment, Category, Signal
from ..normalize import normalize_text

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


@dataclass(slots=True)
class Rule:
    id: str
    category: str
    title: str
    weight: float
    confidence: float
    when: dict[str, Any]
    detail: str = ""
    cite: str = ""


@dataclass(slots=True)
class RuleSet:
    version: int = 1
    rules: list[Rule] = field(default_factory=list)
    brands: list[str] = field(default_factory=list)
    asset_unfreeze_terms: list[str] = field(default_factory=list)
    official_terms: list[str] = field(default_factory=list)
    therapeutic_terms: list[str] = field(default_factory=list)
    thresholds: dict[str, float] = field(
        default_factory=lambda: {"suspicious": 15, "high_risk": 40, "confirmed": 70}
    )
    sources: list[str] = field(default_factory=list)

    @property
    def by_id(self) -> dict[str, Rule]:
        return {r.id: r for r in self.rules}


def _parse_brands(raw: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for group in raw.get("brands", {}).values():
        out.extend(str(x) for x in group)
    return out


def load_ruleset(extra_path: str | Path | None = None) -> RuleSet:
    """加载内置规则，可按 id 覆盖/追加外部规则文件。"""
    builtin = RULES_DIR / "builtin.yaml"
    raw = yaml.safe_load(builtin.read_text(encoding="utf-8")) or {}

    rs = RuleSet(
        version=int(raw.get("version", 1)),
        brands=_parse_brands(raw),
        asset_unfreeze_terms=list(raw.get("asset_unfreeze_terms", [])),
        official_terms=list(raw.get("official_terms", [])),
        therapeutic_terms=list(raw.get("therapeutic_terms", [])),
        thresholds={k: float(v) for k, v in (raw.get("thresholds") or {}).items()}
        or {"suspicious": 15, "high_risk": 40, "confirmed": 70},
        sources=[str(builtin)],
    )

    def ingest(document: dict[str, Any]) -> None:
        for item in document.get("rules", []) or []:
            try:
                rule = Rule(
                    id=str(item["id"]),
                    category=str(item["category"]),
                    title=str(item["title"]),
                    weight=float(item["weight"]),
                    confidence=float(item.get("confidence", 0.7)),
                    when=item.get("when") or {},
                    detail=str(item.get("detail", "")),
                    cite=str(item.get("cite", "")),
                )
            except (KeyError, TypeError, ValueError):
                continue
            rs.rules = [r for r in rs.rules if r.id != rule.id] + [rule]

    ingest(raw)

    path = extra_path or os.environ.get("SILVER_RULES_PATH")
    if path and Path(path).is_file():
        ingest(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
        rs.sources.append(str(path))

    return rs


# ---------------------------------------------------------------- 条件求值


_OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gt": lambda a, b: _num(a) is not None and _num(b) is not None and _num(a) > _num(b),
    "gte": lambda a, b: _num(a) is not None and _num(b) is not None and _num(a) >= _num(b),
    "lt": lambda a, b: _num(a) is not None and _num(b) is not None and _num(a) < _num(b),
    "lte": lambda a, b: _num(a) is not None and _num(b) is not None and _num(a) <= _num(b),
    "in": lambda a, b: a in (b or []),
    "contains": lambda a, b: b in (a or []),
    "nonempty": lambda a, _b: bool(a),
    "truthy": lambda a, _b: bool(a),
}


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except (TypeError, ValueError):
        return None


def _text_hit(text: str, needle: str) -> bool:
    return normalize_text(needle).lower() in text


def evaluate(cond: dict[str, Any], ctx: dict[str, Any], hits: list[str] | None = None) -> bool:
    """对声明式条件求值。支持 all / any / not 嵌套。

    hits 用于收集「具体命中了哪些词/正则」，这是把结论变成可核查证据的关键：
    用户看到的不是「系统认为可疑」，而是「系统在这里读到了这句话」。
    """
    if not cond:
        return False

    if "all" in cond:
        results = [evaluate(c, ctx, hits) for c in cond["all"]]
        return all(results)
    if "any" in cond:
        results = [evaluate(c, ctx, hits) for c in cond["any"]]
        return any(results)
    if "not" in cond:
        return not evaluate(cond["not"], ctx, None)  # 否定分支不采集命中词

    text = ctx.get("text", "") or ""
    facts = ctx.get("facts", {}) or {}
    indicators = ctx.get("indicators", {}) or {}

    if "text_any" in cond:
        raw = cond["text_any"]
        needles = [str(n) for n in (raw if isinstance(raw, list) else [raw])]
        matched = [n for n in needles if _text_hit(text, n)]
        if hits is not None and matched:
            hits.extend(matched[:4])
        return bool(matched)
    if "text_all" in cond:
        raw = cond["text_all"]
        needles = [str(n) for n in (raw if isinstance(raw, list) else [raw])]
        matched = [n for n in needles if _text_hit(text, n)]
        if hits is not None and matched:
            hits.extend(matched[:4])
        return len(matched) == len(needles)
    if "text_regex" in cond:
        try:
            match = re.search(str(cond["text_regex"]), text, re.IGNORECASE)
        except re.error:
            return False
        if match and hits is not None:
            hits.append(match.group(0)[:24])
        return match is not None
    if "indicator" in cond:
        key = str(cond["indicator"])
        values = indicators.get(key, []) or []
        wanted = cond.get("value")
        if "op" in cond and cond["op"] in _OPS:
            return _OPS[str(cond["op"])](values, wanted)
        return bool(values)

    fact = cond.get("fact")
    if fact is None:
        return False
    op = str(cond.get("op", "truthy"))
    fn = _OPS.get(op)
    if fn is None:
        return False
    return bool(fn(facts.get(fact), cond.get("value")))


# ---------------------------------------------------------------- 聚合


def aggregate(
    signals: list[Signal],
    thresholds: dict[str, float],
    *,
    official: bool = False,
    reviewed: bool = False,
    min_signals: int = 2,
) -> tuple[float, float, str, dict[str, int], int, list[str]]:
    """返回 (风险分, 置信度, 判定, 维度覆盖, 独立来源数, 备注)。"""
    notes: list[str] = []
    coverage: dict[str, int] = {}

    if not signals:
        return 0.0, 0.0, "insufficient", coverage, 0, ["未命中任何规则，无法判定"]

    survival = 1.0
    for sig in signals:
        strength = max(0.0, min(1.0, sig.weight / 100.0)) * max(0.0, min(1.0, sig.confidence))
        survival *= 1.0 - strength
        coverage[sig.category] = coverage.get(sig.category, 0) + 1

    score = (1.0 - survival) * 100.0

    # 跨维度加成：同时命中分发、冒充、资金、话术，比同一维度堆十条更有指向性
    n_cats = len(coverage)
    if n_cats >= 4:
        score = min(100.0, score * 1.08)
        notes.append(f"覆盖 {n_cats} 个独立维度，跨维度一致性显著提高判定可信度")

    reliability = 1.0
    for sig in signals:
        reliability *= 1.0 - max(0.0, min(1.0, sig.confidence))
    coverage_factor = min(1.0, 0.6 + 0.1 * n_cats)
    confidence = round((1.0 - reliability) * coverage_factor, 3)

    sources = len({s.source for s in signals})

    # 官方通报/人工复核是最高级别证据，一条就足以定性，不受最小信号数约束
    if official or reviewed:
        score = max(score, 72.0)
        notes.append("存在官方通报或人工复核结论，判定为确认涉诈")
        return round(score, 1), confidence, "confirmed", coverage, sources, notes

    if len(signals) < min_signals:
        notes.append(f"仅命中 {len(signals)} 条信号，低于最小判定门槛，按弃权处理")
        return round(score, 1), confidence, "insufficient", coverage, sources, notes

    if score < thresholds.get("suspicious", 15):
        return round(score, 1), confidence, "low", coverage, sources, notes

    if score < thresholds.get("high_risk", 40):
        return round(score, 1), confidence, "suspicious", coverage, sources, notes

    if score >= thresholds.get("confirmed", 70):
        notes.append("分数已达到确认档，但缺少官方通报或人工复核，按保守原则降级为高度可疑")

    return round(score, 1), confidence, "high_risk", coverage, sources, notes


def assess(
    facts: dict[str, Any],
    text: str = "",
    indicators: dict[str, list[str]] | None = None,
    ruleset: RuleSet | None = None,
    *,
    official: bool = False,
    reviewed: bool = False,
    min_signals: int = 2,
) -> Assessment:
    rs = ruleset or load_ruleset()
    ctx = {
        "facts": facts,
        "text": normalize_text(text).lower(),
        "indicators": indicators or {},
    }

    matched_signals: list[Signal] = []
    for rule in rs.rules:
        try:
            matched_terms: list[str] = []
            if evaluate(rule.when, ctx, matched_terms):
                detail = rule.detail
                unique_terms = list(dict.fromkeys(t for t in matched_terms if t))[:5]
                if unique_terms:
                    detail = f"命中「{'、'.join(unique_terms)}」。" + detail
                else:
                    # 事实类规则没有原文可引，就把判定值摊开给用户看
                    fact_name = (rule.when or {}).get("fact")
                    fact_value = facts.get(fact_name) if fact_name else None
                    if fact_value not in (None, "", [], False) and not isinstance(fact_value, bool):
                        detail = f"判定值：{str(fact_value)[:80]}。" + detail
                matched_signals.append(
                    Signal(
                        rule_id=rule.id,
                        category=rule.category,
                        title=rule.title,
                        weight=rule.weight,
                        confidence=rule.confidence,
                        detail=detail[:200],
                        source="rule",
                        evidence=rule.cite,
                    )
                )
        except Exception:  # 单条规则异常不应中断整次研判
            continue

    score, confidence, verdict, coverage, sources, notes = aggregate(
        matched_signals,
        rs.thresholds,
        official=official,
        reviewed=reviewed,
        min_signals=min_signals,
    )

    return Assessment(
        score=score,
        confidence=confidence,
        verdict=verdict,
        signals=matched_signals,
        facts=facts,
        coverage=coverage,
        independent_sources=sources,
        notes=notes,
    )


def priority_of(assessment: Assessment) -> str:
    if assessment.verdict == "confirmed":
        return "P0"
    if assessment.score >= 70:
        return "P1"
    if assessment.score >= 40:
        return "P2"
    if assessment.score >= 15:
        return "P3"
    return "P4"


CATEGORY_ORDER = [c.value for c in Category]
