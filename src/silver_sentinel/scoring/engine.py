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
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..domain import Assessment, Category, Signal
from ..normalize import normalize_text

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

# 阈值唯一来源。必须与 rules/builtin.yaml 的 thresholds 一致——以前代码
# 兜底写 40、YAML 写 35，同一套规则两个默认值：加载成功时按 35 判，
# 一旦 YAML 缺字段回退到 40，同一批资产结论会突变。测试会钉死两者相等。
DEFAULT_THRESHOLDS: dict[str, float] = {
    "suspicious": 15.0,
    "high_risk": 35.0,
    "confirmed": 70.0,
}


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
        default_factory=lambda: dict(DEFAULT_THRESHOLDS)
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

    # YAML 缺字段时按单一常量补齐，而不是整体回退到另一套默认值：
    # 以前「只缺一档」也会用 40 顶替 35，同一批资产结论会突变。
    parsed_thresholds = {
        k: float(v) for k, v in (raw.get("thresholds") or {}).items()
        if k in DEFAULT_THRESHOLDS
    }
    rs = RuleSet(
        version=int(raw.get("version", 1)),
        brands=_parse_brands(raw),
        asset_unfreeze_terms=list(raw.get("asset_unfreeze_terms", [])),
        official_terms=list(raw.get("official_terms", [])),
        therapeutic_terms=list(raw.get("therapeutic_terms", [])),
        thresholds={**DEFAULT_THRESHOLDS, **parsed_thresholds},
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

    # 内容规则单独一份文件：它们看的是页面正文，与结构规则的生命周期不同
    # （话术变得快，结构特征变得慢），分开放才好各自迭代。
    content = RULES_DIR / "content.yaml"
    if content.is_file():
        ingest(yaml.safe_load(content.read_text(encoding="utf-8")) or {})
        rs.sources.append(str(content))

    path = extra_path or os.environ.get("SILVER_RULES_PATH")
    if path and Path(path).is_file():
        ingest(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
        rs.sources.append(str(path))

    return rs


_RULESET_CACHE: dict[str, Any] = {"key": None, "value": None}
_RULESET_LOCK = threading.Lock()


def _ruleset_key() -> tuple:
    """规则文件的 (路径, mtime, 大小)。改过规则立即生效，没改就走缓存。"""
    items = []
    for path in (RULES_DIR / "builtin.yaml", RULES_DIR / "content.yaml"):
        try:
            st = path.stat()
            items.append((str(path), st.st_mtime_ns, st.st_size))
        except OSError:
            items.append((str(path), 0, 0))
    extra = os.environ.get("SILVER_RULES_PATH", "")
    if extra and Path(extra).is_file():
        try:
            st = Path(extra).stat()
            items.append((extra, st.st_mtime_ns, st.st_size))
        except OSError:
            pass
    return tuple(items)


def get_ruleset() -> RuleSet:
    """带缓存的规则集。研判是热路径，每轮解析两份 YAML 纯属浪费。"""
    key = _ruleset_key()
    with _RULESET_LOCK:
        if _RULESET_CACHE["key"] == key and _RULESET_CACHE["value"] is not None:
            return _RULESET_CACHE["value"]
    rs = load_ruleset()
    with _RULESET_LOCK:
        _RULESET_CACHE["key"] = key
        _RULESET_CACHE["value"] = rs
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

    if score < thresholds.get("suspicious", DEFAULT_THRESHOLDS["suspicious"]):
        return round(score, 1), confidence, "low", coverage, sources, notes

    if score < thresholds.get("high_risk", DEFAULT_THRESHOLDS["high_risk"]):
        return round(score, 1), confidence, "suspicious", coverage, sources, notes

    if score >= thresholds.get("confirmed", DEFAULT_THRESHOLDS["confirmed"]):
        notes.append("分数已达到确认档，但缺少官方通报或人工复核，按保守原则降级为高度可疑")

    return round(score, 1), confidence, "high_risk", coverage, sources, notes


VERDICT_RANK = {
    "insufficient": 0,
    "low": 1,
    "suspicious": 2,
    "high_risk": 3,
    "confirmed": 4,
    "benign": -1,
}


def verdict_for_score(
    score: float,
    thresholds: dict[str, float],
    *,
    signals: int = 2,
    min_signals: int = 2,
) -> str:
    """只按分数与信号数反推机器判定，与 aggregate() 的分支保持一致。"""
    if signals < min_signals:
        return "insufficient"
    if score < thresholds.get("suspicious", DEFAULT_THRESHOLDS["suspicious"]):
        return "low"
    if score < thresholds.get("high_risk", DEFAULT_THRESHOLDS["high_risk"]):
        return "suspicious"
    return "high_risk"


def normalize_verdict(
    assessment: Any,
    thresholds: dict[str, float],
    *,
    reviewed: bool = False,
    min_signals: int = 2,
) -> None:
    """分数被压低后，判定必须同步回退。

    线上出现过 `score=20 / verdict=high_risk` 的资产：白名单把分数压到 20，
    `_apply_claim()` 早先却无条件给了 high_risk，而资产随后沉进 cold 档、
    再也不进周期重评，于是这条误报永久留在高危池里。这里做最后一道归一：
    人工终审（reviewed/confirmed）不受影响，机器判定不能比分数应得的更重。
    """
    if reviewed or assessment.verdict == "confirmed":
        return
    # 硬证据提级（伪造政府标识码、官方通报）不依赖「至少 N 条信号」：
    # 分数已经到高危门槛，就不要拿 min_signals 把它降回 insufficient。
    # 少了这一句，上一轮确认的仿冒财政部站群（95 分）会被批量打回。
    if float(assessment.score or 0) >= thresholds.get(
        "high_risk", DEFAULT_THRESHOLDS["high_risk"]
    ):
        return
    expected = verdict_for_score(
        float(assessment.score or 0),
        thresholds,
        signals=len(getattr(assessment, "signals", []) or []),
        min_signals=min_signals,
    )
    if VERDICT_RANK.get(assessment.verdict, 0) > VERDICT_RANK.get(expected, 0):
        previous = assessment.verdict
        assessment.verdict = expected
        assessment.notes.append(
            f"分数 {float(assessment.score or 0):.1f} 未达 {previous} 门槛，判定回退为 {expected}"
        )


# ---------------------------------------------------------------- 领域识别
#
# 线上有一类稳定的误报：体育直播、影视站群。它们的域名常常长成
# `fj-weixin-qq.cc`、`jrs-weixin-qq.cc` 这种「地名+品牌词」的批量注册形态，
# 页面正文里又会顺带出现「巴马」「温泉」「分红」之类的地名/运营词。
# 词库与内容规则在字面上全中，但这条线索和涉老诈骗毫无关系。
#
# 这里做一个窄而明确的判断：正文里体育/影视词密集、且完全没有涉老诈骗的
# 定性词时，视为「主题无关」，只保留结构特征（备案、域名年龄、TLD）。
# 之所以要求「完全没有」，是因为骗局页面也常拿体育直播做幌子（赌博引流），
# 一旦出现「民族资产解冻/养老/返利」等词，就不再走这条豁免。

ELDER_SIGNATURE_TERMS = (
    "民族资产解冻", "资产解冻", "养老", "老龄", "返利", "补贴", "免费领", "领鸡蛋",
    "保健品", "讲座", "会销", "拉人头", "报单", "股权认购", "数字人民币", "云数贸",
    "消费养老", "以房养老", "理疗", "艾灸", "收藏品", "纪念币",
)
OFF_TOPIC_VERTICALS: dict[str, tuple[str, ...]] = {
    "sports": (
        "足球", "篮球", "NBA", "CBA", "英超", "西甲", "德甲", "意甲", "法甲",
        "中超", "世界杯", "比分", "赛事", "直播", "录像", "集锦", "WNBA", "NCAA",
    ),
    "media": ("电影", "电视剧", "动漫", "全集", "在线观看", "高清", "迅雷", "磁力"),
    # 成人内容站：常见形态是「仿品牌域名 + 引导下载 APK」，
    # dou-yin.org 这类站会同时命中品牌仿冒、拉新奖励、未备案三组特征，
    # 打分能到 57 分进自动盯防——但它是涉黄团伙，不是涉老诈骗。
    # 只保留结构特征（备案、域名年龄、TLD），内容信号全部不采信。
    "adult": (
        "成人视频", "成人片", "成人内容", "午夜影院", "午夜观影", "午夜短视频",
        "福利姬", "裸舞", "裸聊", "无码", "三级片", "伦理片", "情色", "色情",
        "麻豆", "糖心", "哔咔", "撸管", "约炮", "人妻", "偷拍",
    ),
    # 加速器/翻墙工具站：一类被抢注域名承载的灰产聚合站。它们会同时命中
    # 未备案、引导下载 APK、域名拼音撞上机构名（gongxiaoshe88 → 供销社），
    # 但服务对象不是老人，也不使用涉老话术。豁免内容信号，只留结构特征。
    "accelerator": (
        "加速器", "vpn", "翻墙", "科学上网", "外网", "机场节点",
        "免费节点", "ssr", "v2ray", "clash", "梯子", "翻墙软件",
    ),
    # 跨境赌博站群：品牌词 + 连续数字后缀批量注册（didi3663/didi8398/… 实测
    # 一次进来 20 个同模板域名），正文是「彩金、有效投注、存提款、备用网址」。
    # 它们会命中「退款客服」「支付宝背书」「未备案」，40 分上下，既到不了
    # watch 又长期占着候选池前排。属违法但与涉老诈骗不同主题，豁免内容信号，
    # 只留结构特征——真要关联到涉老案件时，靠域名/证书/收款地址建图。
    "gambling": (
        "棋牌", "娱乐城", "彩金", "投注", "存提款", "提现", "百家乐",
        "视讯", "电子游艺", "开元棋牌", "备用网址", "娱乐平台", "博彩",
        "真人荷官", "老虎机", "六合彩", "时时彩", "信用盘",
    ),
    # 域名停放/待售页：正文是 SEO 填充文 + 「本域名出售 / 联系邮箱 / 微信」。
    # 这类页会命中品牌词、CT-006（联系邮箱 + 微信）、品牌拼接，40 分上下，
    # 是候选池里最常见的噪声。判据是可判定的页面类型，命中一条即可。
    "parked": (
        "this domain name is for sale", "this domain is for sale", "buy this domain",
        "本域名出售", "域名出售", "域名转让", "域名停放", "parked domain",
        "inquire about this domain", "域名询价",
    ),
}

# 各类垂直站判定所需的命中词数。默认 4。
OFF_TOPIC_MIN_HITS: dict[str, int] = {"accelerator": 2, "parked": 1}


def detect_off_topic(text: str) -> str:
    """判断页面主体是不是「和涉老诈骗无关的垂直站」。返回领域名或空串。"""
    sample = (text or "")[:20000]
    if not sample:
        return ""
    if any(term in sample for term in ELDER_SIGNATURE_TERMS):
        return ""
    # 英文词条（vpn / parked domain / for sale）大小写不敏感
    haystack = sample.lower()
    for vertical, terms in OFF_TOPIC_VERTICALS.items():
        # 词表规模差异很大：体育有几十个专有名词，加速器只有十来个且
        # 「加速器 + 外网」这种组合已足够定性，没必要凑够 4 个。
        need = OFF_TOPIC_MIN_HITS.get(vertical, 4)
        if sum(1 for term in terms if term.lower() in haystack) >= need:
            return vertical
    return ""


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

    # 主题无关的页面不看内容，只看结构。理由见上方注释。
    if text:
        vertical = detect_off_topic(text)
        if vertical:
            if isinstance(facts, dict):
                facts["off_topic"] = vertical
            text = ""

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
    """优先级分档必须与判定阈值同源。

    以前这里硬编码 70/40/15，而 high_risk 门槛是 YAML 里的 35——
    35~39 分的 high_risk 会被标成 P3，人工审阅顺序被悄悄颠倒。
    """
    if assessment.verdict == "confirmed":
        return "P0"
    if assessment.score >= DEFAULT_THRESHOLDS["confirmed"]:
        return "P1"
    if assessment.score >= DEFAULT_THRESHOLDS["high_risk"]:
        return "P2"
    if assessment.score >= DEFAULT_THRESHOLDS["suspicious"]:
        return "P3"
    return "P4"


CATEGORY_ORDER = [c.value for c in Category]
