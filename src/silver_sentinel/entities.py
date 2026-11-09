"""主体实体：把页面里的「钱交给谁、联系谁」抽成可关联的节点。

为什么单独建一层
----------------
图谱原来只有 domain / ip / cert / asn / entity(ICP) 这些**基础设施**节点，
联系方式节点形同虚设（线上 wechat 只有 3 个）。根因有两处：

1. `graph/build.py` 的 `build_all` 传给 `_attach_indicators` 的是
   `Evidence.note`，而 note 只有一句「页面正文 https://...」——真正的正文
   从来没被读进来，指标自然抽不到。
2. `normalize.extract_indicators` 能抽 QQ/微信/手机/银行卡，但没有
   「收款户名 / 开户行 / 公司主体」这类中文主体，也没有去重归一。

主体是比 IP 更硬的关联证据：同一个微信号 / 同一张收款卡 / 同一个公司名
出现在几十个域名上，几乎必然是同一伙人。IP 会换、证书会重签，收款账户
不会天天换。

设计取舍
--------
- 纯文本进、结构化出，不发网络请求、不碰数据库：取证流水线每站跑一次，
  也可以对历史证据离线回填。
- **复用** `normalize.extract_indicators`，只补它没覆盖的中文主体字段。
- 值做归一（去空格/全角、微信号小写），但**不脱敏**：这是内部研判库，
  举报材料需要原值；对外展示的脱敏由 API 层负责。
"""

from __future__ import annotations

import re
from typing import Any

from .normalize import extract_indicators, normalize_text

# 收款主体：常见于「转账验资」「缴纳解冻费」页面的落地页
_PAYEE_RE = re.compile(
    r"(?:收款(?:人|方|户名|账户)|户名|账户名|开户(?:人|名)|收款单位)\s*[:：]?\s*"
    r"([\u4e00-\u9fff·]{2,20}|[A-Za-z][A-Za-z .]{2,30})"
)
_BANK_RE = re.compile(
    r"([\u4e00-\u9fff]{2,12}(?:银行|支行|分行|信用社|农商行))"
)
_COMPANY_RE = re.compile(
    r"([\u4e00-\u9fff]{2,20}(?:有限公司|股份公司|集团|合作社|服务中心|管理中心|基金会))"
)

# 明显的占位/示例值，不进主体库
_NOISE = frozenset(
    {"张三", "李四", "王某", "某某", "示例", "测试", "姓名", "收款人", "中国人民银行",
     "工商银行", "建设银行", "农业银行", "中国银行", "招商银行"}
)

ENTITY_FIELDS = (
    "phones", "landlines", "qq", "wechat", "bank_cards", "wallets",
    "payees", "banks", "companies",
)

# 图谱节点类型与 rel，集中在这里，避免 build.py 里散落重复
NODE_TYPES = {
    "phones": ("phone", "USES_PHONE"),
    "landlines": ("landline", "USES_PHONE"),
    "qq": ("qq", "USES_CONTACT"),
    "wechat": ("wechat", "USES_CONTACT"),
    "bank_cards": ("bank_card", "USES_PAYMENT"),
    "wallets": ("wallet", "USES_PAYMENT"),
    "payees": ("payee", "USES_PAYMENT"),
    "banks": ("bank", "USES_PAYMENT"),
    "companies": ("entity", "CLAIMS_ENTITY"),
}


def _clean(value: str) -> str:
    return re.sub(r"\s+", "", (value or "").strip().strip(":,，。;；"))


def _dedup(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in values:
        v = _clean(raw)
        if not v or v in _NOISE or len(v) > 64:
            continue
        key = v.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(v)
    return out


def from_text(text: str) -> dict[str, list[str]]:
    """从一段正文抽主体实体。输入可以是页面文本、APK strings、话术样本。"""
    body = normalize_text(text or "")
    if not body:
        return {}

    ind = extract_indicators(body)
    out: dict[str, list[str]] = {
        "phones": _dedup(ind.get("phones", [])),
        "landlines": _dedup(ind.get("landlines", [])),
        "qq": _dedup(ind.get("qq", [])),
        "wechat": _dedup(ind.get("wechat", [])),
        "bank_cards": _dedup(ind.get("bank_cards", [])),
        "wallets": _dedup(ind.get("wallets", [])),
        "payees": _dedup(_PAYEE_RE.findall(body)),
        "banks": _dedup(_BANK_RE.findall(body)),
        "companies": _dedup(_COMPANY_RE.findall(body)),
    }
    # 微信号大小写不敏感，统一小写便于跨站归并
    out["wechat"] = [v.lower() for v in out["wechat"]]
    return {k: v for k, v in out.items() if v}


def read_evidence_text(rows: list[Any], *, per_row_limit: int = 60_000,
                       max_chars: int = 200_000) -> str:
    """把证据行（可能明文或 vault 密文）还原成正文。

    这是修 `build_all` 那个 bug 的关键：以前只把 `Evidence.note` 当正文，
    而 note 是「页面正文 https://...」——一个指标都抽不出来。
    `evidence.read_text` 会自己判断 plain / vault，读不出来就跳过。
    """
    from .evidence import read_text

    parts: list[str] = []
    used = 0
    for row in rows:
        if used >= max_chars:
            break
        text = read_text(row, per_row_limit)
        if text:
            parts.append(text)
            used += len(text)
    return "\n".join(parts)


def from_evidence_rows(rows: list[Any], *, per_row_limit: int = 60_000,
                       max_chars: int = 200_000) -> dict[str, list[str]]:
    """从证据正文抽实体（read_evidence_text 的结构化封装）。"""
    return from_text(read_evidence_text(rows, per_row_limit=per_row_limit, max_chars=max_chars))


def as_dict(entities: dict[str, list[str]] | None) -> dict[str, Any]:
    """给 meta/facts 落库用：只保留非空字段，并给出总数便于列表页排序。"""
    data = {k: list(v) for k, v in (entities or {}).items() if v}
    data["count"] = sum(len(v) for k, v in data.items() if k != "count")
    return data
