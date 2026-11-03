"""领域枚举与值对象。

这里刻意把「判定等级」和「置信度」分开：
一个资产可以风险分很高，但证据只来自单一来源，此时不应给出「确认诈骗」。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    """统一使用「无时区的 UTC」。

    SQLite 的 DateTime 不保留 tzinfo，若写入 aware、读出 naive，
    证据链的 isoformat 校验会永远失败。全链路统一为 naive UTC 最省事，
    展示层负责补 'Z' 再交给浏览器本地化。
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AssetKind(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    APK = "apk"
    MINIAPP = "miniapp"      # 微信/支付宝小程序
    ACCOUNT = "account"      # 公众号、企业微信、个人号
    TEXT = "text"            # 话术、聊天记录、宣传文案
    UNKNOWN = "unknown"


class Verdict(str, Enum):
    INSUFFICIENT = "insufficient"   # 证据不足，弃权
    LOW = "low"
    SUSPICIOUS = "suspicious"
    HIGH_RISK = "high_risk"
    CONFIRMED = "confirmed"         # 需人工复核或官方通报
    BENIGN = "benign"               # 人工排除


class Category(str, Enum):
    DISTRIBUTION = "distribution"   # 怎么送到老人手机上的
    IMPERSONATION = "impersonation"  # 冒充谁
    FINANCIAL = "financial"         # 怎么收钱
    PERSUASION = "persuasion"       # 怎么说话
    TECHNICAL = "technical"         # 代码里干了什么
    REPUTATION = "reputation"       # 外部信誉


CATEGORY_LABELS: dict[str, str] = {
    "distribution": "分发渠道",
    "impersonation": "身份冒充",
    "financial": "资金模式",
    "persuasion": "诱导话术",
    "technical": "技术特征",
    "reputation": "外部信誉",
}

VERDICT_LABELS: dict[str, str] = {
    "insufficient": "证据不足",
    "low": "低风险",
    "suspicious": "可疑",
    "high_risk": "高度可疑",
    "confirmed": "确认涉诈",
    "benign": "已排除",
}


@dataclass(slots=True)
class Signal:
    """一条可解释的判定依据。权重是「若该信号成立，其单独指向涉诈的强度」。"""

    rule_id: str
    category: str
    title: str
    weight: float
    confidence: float
    detail: str = ""
    source: str = "rule"
    evidence: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "weight": round(self.weight, 2),
            "confidence": round(self.confidence, 3),
            "detail": self.detail,
            "source": self.source,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class Assessment:
    """一次研判的完整结论。"""

    score: float
    confidence: float
    verdict: str
    signals: list[Signal] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    coverage: dict[str, int] = field(default_factory=dict)
    independent_sources: int = 0
    notes: list[str] = field(default_factory=list)
    llm: dict[str, Any] | None = None

    @property
    def top_signals(self) -> list[Signal]:
        return sorted(self.signals, key=lambda s: s.weight * s.confidence, reverse=True)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 1),
            "confidence": round(self.confidence, 3),
            "verdict": self.verdict,
            "signals": [s.as_dict() for s in self.top_signals],
            "facts": self.facts,
            "coverage": self.coverage,
            "independent_sources": self.independent_sources,
            "notes": self.notes,
            "llm": self.llm,
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, indent=2)


def stable_key(*parts: str) -> str:
    """跨运行稳定的短键，用于幂等写入。"""
    raw = "\x1f".join(p or "" for p in parts).encode("utf-8", "ignore")
    return hashlib.sha256(raw).hexdigest()[:24]
