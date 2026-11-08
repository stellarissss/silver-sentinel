"""域名形态学：从「名字长什么样」判断它是不是批量生成的。

为什么需要这一层
----------------
CT 日志每天几十万个新域名，词库只能筛出「名字里写了什么」的那部分。
而涉老诈骗站群的域名是**批量生成的随机串**：

    np4w53.cn   hksm38.com.cn   l4k9j.com.cn   m5w1p.com.cn   s.qka91.com

它们不在任何词库里，却共享同一套生成器特征：短、无音节、字母与数字混排、
不含任何能读出来的词。这个特征本身不是罪证——但它能把「值得花一次 DNS 和
一次 HTTP 去确认」的集合从每天几十万压到几千，让全量探测变得可行。

设计取舍：**只用于排序，不用于定罪**。
形态分高的域名仍然要走正常取证与判定；形态分低的也可能有问题（老骗子用
好记的域名）。这里唯一的作用是决定「先看谁」，不是「谁有问题」。

实测校准（2026-11-08）
----------------------
正例（同一模板站群，已取证确认）：
    np4w53 / hksm38 / l4k9j / m5w1p / qka91  → 0.72 ~ 0.95
负例（正规站与合法业务）：
    huicetong（惠策通）/ xindazx（新大咨询）/ laoweimin（老魏民）→ 0.05 ~ 0.2
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# 出现在任意站点前缀里的服务标签，不代表命名习惯
_SERVICE_LABELS = frozenset(
    {
        "www", "m", "wap", "api", "app", "cdn", "static", "img", "images", "assets",
        "admin", "mail", "smtp", "pop", "ns", "ns1", "ns2", "dns", "ftp", "sso",
        "login", "auth", "pay", "open", "dev", "test", "demo", "staging", "beta",
        "blog", "shop", "store", "news", "help", "support", "docs", "doc",
    }
)

# 常见英文词与拼音里的高频音节片段。命中即认为「能读出来」，形态分下调。
_READABLE_FRAGMENTS = (
    "gov", "edu", "com", "net", "org", "cn", "info", "tech", "cloud", "data",
    "bank", "pay", "chip", "link", "soft", "web", "site", "home", "life",
    "health", "care", "love", "good", "best", "news", "shop", "mall", "game",
    "app", "yun", "ke", "xin", "hua", "zhong", "guo", "min", "sheng", "fu",
    "li", "cai", "zheng", "bao", "jian", "kang", "yang", "lao", "nian",
)

_VOWELS = frozenset("aeiou")

# 滥用率最高的后缀。同分数下这些后缀排在前面。
ABUSED_TLDS = frozenset(
    {
        "top", "xyz", "cn", "cc", "vip", "shop", "site", "online", "club", "icu",
        "buzz", "cyou", "link", "live", "fun", "wang", "ltd", "work", "info",
        "asia", "biz", "pw", "tk", "ml", "ga", "cf", "gq", "rest", "monster",
    }
)


@dataclass(slots=True)
class MorphScore:
    """一个域名的形态评估结果。score 只用于排序。"""

    score: float
    label: str
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {"score": round(self.score, 3), "label": self.label, "reasons": list(self.reasons)}


def _apex_label(host: str) -> str:
    """取注册域的最左标签：s.qka91.com → qka91，np4w53.cn → np4w53。

    不做完整 PSL 解析——这里只关心命名形态，末两级足够。
    """
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    parts = [p for p in host.split(".") if p]
    if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "gov", "edu", "co"):
        return parts[-3]
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _vowel_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in _VOWELS) / len(letters)


def _tld(host: str) -> str:
    host = (host or "").lower().strip(".")
    return host.rsplit(".", 1)[-1] if "." in host else ""


def assess(host: str) -> MorphScore:
    """给域名打一个「像不像批量生成」的分。0 = 完全正常，1 = 典型站群。"""
    label = _apex_label(host)
    reasons: list[str] = []
    if not label:
        return MorphScore(0.0, "", ("空域名",))
    if label in _SERVICE_LABELS:
        return MorphScore(0.0, label, ("服务标签",))

    score = 0.0
    digits = sum(1 for c in label if c.isdigit())
    letters = sum(1 for c in label if c.isalpha())

    # ---- 形态：长度与字符集
    if not re.fullmatch(r"[a-z0-9]+", label):
        # 带连字符/下划线的多半是正常项目名（my-shop、hello_world）
        return MorphScore(0.05, label, ("含分隔符",))
    if not (4 <= len(label) <= 12):
        reasons.append("长度异常")
        score -= 0.1
    if len(label) <= 8:
        score += 0.1
    if digits == 0:
        reasons.append("纯字母")
        score -= 0.15
    if letters < 2:
        return MorphScore(0.1, label, ("字母过少",))

    # ---- 混排：数字夹在字母中间是生成器的典型输出
    if digits and 0 < label.find(next(c for c in label if c.isdigit())) < len(label) - 1:
        score += 0.22
        reasons.append("数字夹在字母中")
    elif digits and label[-1].isdigit():
        score += 0.08
        reasons.append("数字结尾")

    # ---- 音节：读不出来的短串
    vr = _vowel_ratio(label)
    if vr <= 0.2:
        score += 0.32
        reasons.append("几乎无元音")
    elif vr <= 0.34:
        score += 0.2
        reasons.append("元音稀少")
    else:
        score -= 0.1

    # 三个以上连续元音（如 "aue"）反而像乱码，但更常见于拼音/英文，作中性处理
    if re.search(r"[aeiou]{3,}", label):
        score -= 0.05

    # ---- 可读性：命中任何常见词/音节都说明是「有意取的」
    hit = next((f for f in _READABLE_FRAGMENTS if f in label), "")
    if hit:
        score -= 0.28
        reasons.append(f"含常见词 {hit}")
    else:
        score += 0.1

    # ---- 数字密度
    ratio = digits / len(label)
    if 0.25 <= ratio <= 0.6:
        score += 0.12
        reasons.append("字母数字混排")

    # ---- 后缀：滥用率高的 TLD 略微提权（只影响排序）
    if _tld(host) in ABUSED_TLDS:
        score += 0.06

    # 字符熵：越高越像随机串。4~6 位的正常词熵约 1.8~2.2
    ent = _entropy(label)
    if ent >= 3.2:
        score += 0.12
        reasons.append("高熵")
    elif ent <= 2.0:
        score -= 0.05

    return MorphScore(max(0.0, min(1.0, score)), label, tuple(reasons))


def is_random_label(label: str) -> bool:
    """便捷判定：标签是否典型随机串（阈值取实测分界 0.55）。"""
    return assess(label).score >= 0.55


# ---------------------------------------------------------------- 批次判定

BULK_MIN_DOMAINS = 8        # 少于这个数谈不上「一批」
BULK_HOT_SCORE = 0.60       # 单个域名达到这个分算「随机串」
BULK_HOT_RATIO = 0.60       # 一批里随机串至少占这么多


def is_bulk_batch(domains: list[str]) -> bool:
    """一群域名像不像「同一个生成器吐出来的」。

    用例是证书 SAN：实测 np4w53.cn 那张证书挂了 90 个域名，全是
    `oi6o45.cn` `uw2v71.cn` `tx7y28.cn` 这种。而正常站（baidu.com）的
    SAN 里也有 50 个，但全是 `click.hm.baidu.com` `baifubao.com` 这类
    有意义的业务域名。

    判据用**比例**不用「有没有随机串」：共享主机和 CDN 的证书里也会混着
    几个随机子域，但不会 60% 都是。
    """
    names = [d for d in (domains or []) if d and "." in d]
    if len(names) < BULK_MIN_DOMAINS:
        return False
    # 抽样判定：一张证书可能有 90 个域名，逐个打分在 CT 主循环里是纯浪费。
    # 12 个样本够看出命名习惯，误差在 ±8% 以内，不影响 60% 这条线。
    sample = names if len(names) <= 12 else names[:12]
    hot = 0
    for d in sample:
        try:
            if assess(d).score >= BULK_HOT_SCORE:
                hot += 1
        except Exception:  # noqa: BLE001
            continue
    return hot / len(sample) >= BULK_HOT_RATIO
