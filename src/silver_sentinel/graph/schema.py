"""图的词汇表：节点类型、关系类型、权重。

把「谁和谁有关系」变成可计算的边，是这套系统从「工具库」变成「情报系统」的分界。
一个域名单独看只是可疑；一个域名 + 一张证书 + 一个钱包 + 三个包名 + 一个备案主体
连起来，才是「一伙人」。

权重的含义：这条边在「同源」判断里贡献多少。不是置信度，是可累加的证据量。
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NodeType:
    name: str
    label: str
    icon: str


NODE_TYPES: dict[str, NodeType] = {
    "domain": NodeType("domain", "域名", "globe"),
    "url": NodeType("url", "链接", "link"),
    "ip": NodeType("ip", "IP", "server"),
    "asn": NodeType("asn", "ASN", "network"),
    "cert": NodeType("cert", "证书", "shield"),
    "apk": NodeType("apk", "应用", "package"),
    "wallet": NodeType("wallet", "钱包地址", "wallet"),
    "phone": NodeType("phone", "手机号", "phone"),
    "landline": NodeType("landline", "固话", "phone"),
    "qq": NodeType("qq", "QQ", "message"),
    "wechat": NodeType("wechat", "微信", "message"),
    "email": NodeType("email", "邮箱", "mail"),
    "bank_card": NodeType("bank_card", "银行卡", "card"),
    "entity": NodeType("entity", "备案主体", "building"),
    "registrar": NodeType("registrar", "注册商", "store"),
    "template": NodeType("template", "页面模板", "layout"),
    "brand": NodeType("brand", "被冒用品牌", "tag"),
    "campaign": NodeType("campaign", "团伙", "users"),
    "actor": NodeType("actor", "主体", "user"),
    "keyword": NodeType("keyword", "关键词", "search"),
}

# 关系：(源类型, 关系名, 目标类型, 权重, 说明)
# 权重设计依据：越难伪造、越难更换的证据权重越高。
# 证书私钥只有一份——共用证书几乎等于同一运营者。
RELATION_WEIGHTS: dict[str, tuple[float, str]] = {
    "RESOLVES_TO": (0.35, "解析到"),
    "HAS_CERT": (0.30, "持有证书"),
    "SIGNED_WITH": (0.55, "签名证书"),        # APK 与证书
    "SHARES_CERT": (0.90, "共用证书"),         # 最硬的同源证据
    "EMBEDS": (0.45, "内嵌"),
    "MENTIONS": (0.40, "提及"),
    "USES_WALLET": (0.85, "使用收款地址"),
    "USES_PHONE": (0.60, "使用联系方式"),
    "REGISTERED_BY": (0.50, "注册于"),
    "HOSTED_ON": (0.25, "托管于"),
    "ICP_ENTITY": (0.70, "备案主体"),
    "IMPERSONATES": (0.35, "冒用"),
    "SAME_TEMPLATE": (0.65, "同模板"),
    "PART_OF": (1.00, "属于"),
    "DERIVED_FROM": (0.50, "衍生自"),
    "OPERATED_BY": (1.00, "由…运营"),
}

EDGE_TYPES = list(RELATION_WEIGHTS)


def node_key(node_type: str, value: str) -> str:
    return f"{node_type}:{value.strip().lower()[:200]}"


def parse_key(key: str) -> tuple[str, str]:
    node_type, _, value = key.partition(":")
    return node_type, value


def edge_weight(rel: str) -> float:
    return RELATION_WEIGHTS.get(rel, (0.3, ""))[0]


# 参与「同源」聚类的边：只认这些，避免「都解析到同一个 CDN」把全世界连成一团
CLUSTER_RELATIONS = {
    "SHARES_CERT",
    "SIGNED_WITH",
    "USES_WALLET",
    "USES_PHONE",
    "ICP_ENTITY",
    "SAME_TEMPLATE",
    "EMBEDS",
    "RESOLVES_TO",   # 仅 url -> domain 方向参与，见 store.cluster_edges 的过滤
}

# 结构性关系：不是「同源证据」，而是「本来就是一体的」。
# 例如 url 解析到 domain，URL 资产天然属于该域名，不该被当成独立个体。
STRUCTURAL_RELATIONS = {"RESOLVES_TO"}

# 这些边只做展示与扩线，不参与聚类（噪声太大）
DISPLAY_ONLY_RELATIONS = {"RESOLVES_TO", "HOSTED_ON", "HAS_CERT", "MENTIONS", "IMPERSONATES"}
