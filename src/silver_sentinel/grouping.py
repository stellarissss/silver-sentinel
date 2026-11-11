"""同源折叠：把「同一批东西」收成一行。

为什么需要
----------
一张 LiteSSL 证书带 91 个随机域名，十个前端站共用一个 `submit.php`，
八十一条页面标题逐字相同。把 91 行摊在列表里，人工复核看到的是
九十次重复劳动，而真正要判断的「这批站是不是一伙的」反而被淹没。

折叠不是「合并同类项」这么简单，它得回答一个问题：
**凭什么说它们是一伙的**。所以每一组都带一个依据，从强到弱：

    campaign  已确认的团伙（人工或情报源给的）
    cert      同一张证书签发。骗子换域名不换证书——一次签发覆盖全部域名，
              这是最硬的技术关联，因为证书是 CA 签的，不是页面写的。
    backend   同一收单端点。换域名不会换收单服务器，钱最终流向同一处。
    template  同一套页面模板。标题归一化后逐字相同、正文骨架一致。

**不用「同 IP」**：共享主机上住着几百个互不相干的站，按 IP 聚合会把
正常企业站和诈骗站折成一组，是纯粹的噪声。

折叠只影响**展示**，不改数据：每条资产仍然独立取证、独立定级、独立出证据包。
分组是给人看的视图，不是合并同类项。
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# 标题归一化：去掉年份、数字、标点、空白。
# 实测 81 条「2026年个人财政补贴申领」只差年份，归一化后完全一致。
_YEAR = re.compile(r"(?:19|20)\d{2}\s*年?")
_PUNCT = re.compile(r"[\s\-_·•|｜/\\,，。.、:：;；!！?？\"'“”‘’()（）\[\]【】<>《》]+")
_DIGITS = re.compile(r"\d+")

# 这些标题没有辨识度，不能用来分组——按标题折叠会把半个互联网收成一组。
_GENERIC_TITLE = re.compile(
    r"^(?:首页|主页|欢迎|登录|注册|错误|提示|通知|公告|"
    r"index|home|welcome|login|signin|sign_in|error|not\s*found|"
    r"loading|please\s*wait|just\s*a\s*moment|maintenance|"
    r"coming\s*soon|under\s*construction|checking|verify|"
    r"403|404|500|502|503|"
    r"安全检测|安全验证|请稍候|加载中|系统提示)$",
    re.IGNORECASE,
)

# 分组键前缀 → 人话
GROUP_LABELS = {
    "campaign": "同团伙",
    "cert": "同证书",
    "backend": "同收单端点",
    "template": "同模板",
    "family": "同站群前缀族",
    "offline": "失联站点",
}

GROUP_ORDER = {"campaign": 4, "cert": 3, "backend": 2, "template": 1, "family": 0, "offline": 0}

# 站点失联 / 取证失败：当前拿不到任何页面内容，再怎么排序也挤不出新证据。
# 这类资产按分数排会长期霸占首屏（线上 95 分站群全部 dead，首页前 60 行
# 全是它们）。折叠只影响展示，不改判定、不删数据，展开可见、可一键关掉。
OFFLINE_CAPTURE_STATES = frozenset({"dead", "failed"})

# 单个折叠组最多带多少成员进响应。失联组线上有 1400+ 条，全塞进 JSON
# 既拖慢列表也把前端展开卡死；真实总数用 size 给，成员分页另走详情。
OFFLINE_MEMBER_CAP = 40


def normalize_title(title: str) -> str:
    t = (title or "").strip()
    if not t:
        return ""
    t = _YEAR.sub("", t)
    t = _PUNCT.sub("", t)
    t = _DIGITS.sub("", t)
    return t.strip().lower()


def _short_hash(s: str, n: int = 12) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()[:n]


def cert_fingerprint(cert: dict[str, Any]) -> str:
    """证书指纹：序列号 + 签发者 + 主体。

    不用 DER 哈希，因为取证链路上拿到的已经是解析后的字段。
    这三个字段相同 ⇒ 同一张证书（CA 的序列号在同一签发者下唯一）。
    """
    if not isinstance(cert, dict):
        return ""
    serial = str(cert.get("serial") or "").strip()
    issuer = str(cert.get("issuer") or "").strip()
    subject = str(cert.get("subject") or "").strip()
    if not (serial and issuer):
        return ""
    return _short_hash(f"{issuer}|{subject}|{serial}", 16)


def compute(
    *,
    kind: str,
    value: str = "",
    meta: dict[str, Any] | None = None,
    facts: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    """算一组键。返回 (group_key, group_kind, label)。

    没有足够依据时返回 ("", "", "")——**宁可不成组，也不要错组**。
    """
    meta = meta or {}
    facts = facts or {}

    # 1. 已知团伙
    cid = meta.get("campaign_id")
    if cid:
        return f"campaign:{cid}", "campaign", f"团伙 #{cid}"

    # 2. 同一张证书
    cert = facts.get("cert") or {}
    fp = cert_fingerprint(cert) if isinstance(cert, dict) else ""
    if fp:
        n = int(cert.get("dns_count") or len(cert.get("dns_names") or []) or 0)
        label = f"同证书（{n} 域名）" if n > 1 else "同证书"
        return f"cert:{fp}", "cert", label

    # 3. 同一收单端点
    backends = facts.get("backend_hosts") or []
    if isinstance(backends, list) and backends:
        host = str(backends[0] or "").strip().lower()
        if host:
            return f"backend:{host}", "backend", f"同收单端点 {host}"

    # 4. 同一套模板（只对网页类资产有意义）
    if kind not in ("url", "domain"):
        return "", "", ""
    web = meta.get("web_observation") or {}
    title = str(web.get("title") or "")
    norm = normalize_title(title)
    # 短标题（<4 字）没有区分度；通用标题（首页/登录/404）会把无关站收成一组
    if len(norm) < 4 or _GENERIC_TITLE.match(norm):
        return "", "", ""

    # 正文骨架再兜一层：标题相同但一个是 12 字空壳、一个是 3000 字长文，
    # 不可能是同一套模板（前者是诱饵，后者是内容页）。
    text_len = int((facts.get("features") or {}).get("text_len") or 0)
    bucket = "s" if text_len and text_len < 400 else "l"
    return f"template:{_short_hash(norm)}:{bucket}", "template", f"同模板「{title[:28]}」"


def group_row(
    *,
    key: str,
    kind: str,
    label: str,
    members: list[dict[str, Any]],
    member_cap: int | None = None,
) -> dict[str, Any]:
    """把一组成员压成列表页的一行。

    代表行取「分数最高、档位最高」的那一条：它是这批里最该被看的样本。
    代表行本身的字段照常返回，前端不用为分组行写第二套渲染。

    member_cap 只截「展开时可见的成员」，不动 size / max_score / 诱饵统计——
    失联组线上有 1400+ 条，全量塞进 JSON 会把列表请求拖到几 MB，但真实
    规模和组内的诱饵标记一条都不能丢。
    """
    rank = {"confirmed": 4, "watch": 3, "candidate": 2, "cold": 1, "dismissed": 0}
    ordered = sorted(
        members,
        key=lambda m: (rank.get(m.get("tier") or "", 0), float(m.get("score") or 0)),
        reverse=True,
    )
    head = dict(ordered[0])
    # 组里有没有诱饵/蜜罐必须浮到组行上。
    # 否则「26537.net 是诱饵」这件事会被折叠吞掉——代表行是收单端点，
    # 而真正需要人工看一眼的那条藏在展开后的第三行。
    decoys = [m for m in ordered if m.get("decoy")]
    shown = ordered if member_cap is None else ordered[:member_cap]
    head["group"] = {
        "key": key,
        "kind": kind,
        "label": label,
        "size": len(members),
        "collapsed": True,
        "decoy_count": len(decoys),
        "decoy_kind": ((decoys[0].get("decoy") or {}).get("kind") or "") if decoys else "",
        # 成员只带列表页需要的字段，别把整条 asset 塞进响应里
        "members": [
            {
                "id": m.get("id"),
                "value": str(m.get("value") or "")[:120],
                "kind": m.get("kind") or "",
                "score": m.get("score"),
                "tier": m.get("tier"),
                "verdict": m.get("verdict"),
                "capture_state": m.get("capture_state"),
                "evidence_count": m.get("evidence_count") or 0,
                "decoy_kind": (m.get("decoy") or {}).get("kind") or "",
            }
            for m in shown
        ],
        "members_truncated": len(shown) < len(members),
        "max_score": max((float(m.get("score") or 0) for m in members), default=0.0),
        "tiers": sorted({m.get("tier") or "" for m in members}),
    }
    return head
