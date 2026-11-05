"""把资产翻译成各渠道的「类别选项」。

12377 的类别树来自其官方 /js/harmtype.js（见 data/harmtype.json），
大类是三位数字，小类是 32 位 hex。选错类别会被直接判无效，所以这里不做模糊猜测：
拿不准就落到该大类下语义最宽的小类，并在 reason 里写明依据。
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

_DATA = Path(__file__).with_name("data") / "harmtype.json"


@lru_cache(maxsize=1)
def _tree() -> dict[str, Any]:
    return json.loads(_DATA.read_text(encoding="utf-8"))


def _small_id(big: str, keyword: str) -> tuple[str, str]:
    """按名字片段找小类，返回 (id, name)。找不到返回 ("", "")。"""
    for row in _tree()["small"]:
        if row["big"] == big and keyword in row["name"]:
            return row["id"], row["name"]
    return "", ""


def small_options(big: str) -> list[dict[str, str]]:
    return [{"id": r["id"], "name": r["name"]} for r in _tree()["small"] if r["big"] == big]


BIG_NAMES: dict[str, str] = {r["id"]: r["name"] for r in _tree()["big"]}

# 涉老线索的专属专区（专项任务 010）
_ELDER_ZONE = _small_id("010", "养老诈骗")

_ELDER_HINTS = ("养老", "老年", "老人", "退休", "补贴", "免费领", "免费送", "保健品", "惠民", "以房养老")
_IMPERSONATION_HINTS = ("仿冒", "冒充", "假冒", "国家机关", "政府", "公章", "红头文件", "部委", "民政局", "社保局")
_SOE_HINTS = ("国企", "央企", "国有", "事业单位", "电力", "石油", "铁路")
_BANK_HINTS = ("银行", "支付", "网银", "信用卡")
_GAMBLING_HINTS = ("赌", "博彩", "彩票", "棋牌", "投注", "六合彩")
_PORN_HINTS = ("色情", "淫秽", "裸聊", "招嫖", "成人视频")
_RUMOR_HINTS = ("谣言", "辟谣", "伪科普", "虚假信息", "不实")

# 境外站点常用英文词根，按主机名 token 整段匹配，避免 alphabet 命中 bet
_GAMBLING_TOKENS = {"bet", "bets", "betting", "casino", "slot", "slots", "poker", "sbobet", "jili", "pgsoft"}
_PORN_TOKENS = {"porn", "xxx", "sex", "sexy", "nude", "adult", "av"}


@dataclass(frozen=True)
class Harm:
    harm: str
    label: str
    big: str
    small: str
    small_name: str
    platform: str          # 12377 的 report_platform：WEBSITE / APP / ACCOUNT
    type_12321: str        # 12321 的 type：0 色情 1 钓鱼诈骗 2 隐私 3 政治 4 其他
    reason: str


def _blob(asset: Any, signals: Iterable[Any]) -> str:
    parts = [getattr(asset, "value", ""), getattr(asset, "normalized", ""), getattr(asset, "notes", "")]
    for s in signals:
        parts.append(getattr(s, "title", ""))
        parts.append(getattr(s, "detail", ""))
    meta = getattr(asset, "meta", None) or {}
    if isinstance(meta, dict):
        for key in ("title", "page_title", "llm", "keywords", "hosts"):
            v = meta.get(key)
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, dict):
                parts.extend(str(x) for x in v.values() if isinstance(x, str))
            elif isinstance(v, list):
                parts.extend(str(x) for x in v if isinstance(x, str))
    return " ".join(parts)


def _hit(blob: str, hints: tuple[str, ...]) -> bool:
    return any(h in blob for h in hints)


def _token_hit(*hosts: str, words: set[str]) -> bool:
    """主机名按 . - _ 切词后整段比对，避免子串误报。"""
    import re as _re

    for host in hosts:
        for token in _re.split(r"[.\-_\d]+", (host or "").lower()):
            if token and token in words:
                return True
    return False


def classify(asset: Any, signals: Iterable[Any] = (), override: str = "") -> Harm:
    signals = list(signals)
    blob = _blob(asset, signals)
    kind = getattr(asset, "kind", "domain")

    host = str(getattr(asset, "normalized", "") or getattr(asset, "value", "") or "")
    elder = _hit(blob, _ELDER_HINTS)
    impersonation = _hit(blob, _IMPERSONATION_HINTS)
    gambling = _hit(blob, _GAMBLING_HINTS) or _token_hit(host, words=_GAMBLING_TOKENS)
    porn = _hit(blob, _PORN_HINTS) or _token_hit(host, words=_PORN_TOKENS)
    rumor = _hit(blob, _RUMOR_HINTS)

    if override:
        harm = override
    elif kind in {"apk", "app"}:
        harm = "app"
    elif kind in {"account", "wechat", "qq"}:
        harm = "account"
    elif gambling:
        harm = "gambling"
    elif porn:
        harm = "porn"
    elif rumor and not impersonation:
        harm = "rumor"
    elif impersonation:
        harm = "impersonation"
    elif elder:
        harm = "fraud"
    else:
        harm = "fraud"

    platform = "APP" if harm == "app" else ("ACCOUNT" if harm == "account" else "WEBSITE")
    type_12321 = "1"
    if harm == "porn":
        type_12321 = "0"
    elif harm == "rumor":
        type_12321 = "4"
    elif harm == "gambling":
        type_12321 = "1"

    big, small, sname, reason = "003", "", "", ""

    if harm == "gambling":
        big = "006"
        small, sname = _small_id("006", "网络博彩")
        reason = "命中赌博类词根，归入「网络博彩」"
    elif harm == "porn":
        big = "004"
        small, sname = _small_id("004", "含有色情内容")
        reason = "命中色情类词根，归入「含有色情内容的信息」"
    elif harm == "rumor":
        big = "008"
        small, sname = _small_id("008", "伪科普")
        if not small:
            small, sname = _small_id("008", "公共政策")
        reason = "内容为可核查的虚假陈述，归入谣言类"
    elif elder:
        big = "010"
        small, sname = _ELDER_ZONE
        reason = "线索含养老／补贴／免费领等涉老特征，走「涉养老诈骗有害信息举报专区」"
    elif harm == "impersonation":
        big = "003"
        if _hit(blob, _BANK_HINTS):
            small, sname = _small_id("003", "仿冒银行")
            reason = "涉及支付／银行页面，归入「仿冒银行网站进行支付交易诈骗」"
        elif _hit(blob, _SOE_HINTS):
            small, sname = _small_id("003", "国有企事业单位")
            reason = "仿冒对象为国企／事业单位"
        else:
            small, sname = _small_id("003", "仿冒国家机关")
            reason = "仿冒对象为国家机关"
    elif harm == "app":
        big = "010" if elder else "003"
        if big == "010":
            small, sname = _ELDER_ZONE
            reason = "涉诈 App 且带涉老特征，走涉养老诈骗专区"
        else:
            small, sname = _small_id("003", "仿冒国家机关")
            reason = "涉诈 App，暂按仿冒类提交"
    elif harm == "account":
        big = "003"
        small, sname = _small_id("003", "仿冒国家机关")
        reason = "涉诈社交账号，暂按仿冒类提交"
    else:
        big = "010" if elder else "003"
        if big == "010":
            small, sname = _ELDER_ZONE
            reason = "涉老诈骗引流，走涉养老诈骗专区"
        else:
            small, sname = _small_id("003", "仿冒国家机关")
            reason = "未命中更具体的小类，按仿冒类提交"

    if not small:  # 兜底：绝不提交空类别
        opts = small_options(big)
        if opts:
            small, sname = opts[0]["id"], opts[0]["name"]
            reason += "（原类别未匹配到，回退到该大类首项）"

    return Harm(
        harm=harm,
        label=BIG_NAMES.get(big, big) + (" / " + sname if sname else ""),
        big=big,
        small=small,
        small_name=sname,
        platform=platform,
        type_12321=type_12321,
        reason=reason,
    )
