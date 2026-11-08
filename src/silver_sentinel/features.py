"""用途特征抽取：把「一个网站是干什么用的」变成可计算的数字。

为什么要有这一层
----------------
词库建模的是「涉老行业的词汇」，不是「欺诈行为」。实测 25 个正规垂类站里
8 个得分 ≥0.97，比已知诈骗样本还高——因为正规从业者天天写「养老/补贴/民政」。
继续在词表里加词只会让排序更差。

真正稳定的判别信息不在「用了什么词」，而在**这个站的结构性用途**：
客服 SaaS 有工单/坐席/会话 SDK，论坛有版块/楼层/回复，电商有购物车/SKU，
企业站有产品中心/解决方案。这些是「一个站长期是什么」的沉淀，骗子做不出来
——他做的是单页落地页、报名表单、APK 分发。

所以本模块只做一件事：**不看风险，只看用途**。风险仍由词库 + 冒充判定负责。
这样「词库保广（召回不退）／用途保细（把客服站论坛挡在门外）」才能同时成立。

设计约束
--------
1. 纯函数、无网络、无数据库：可以从已落库的证据重算，也可以给训练脚本批量跑。
2. 特征名与顺序固定（`FEATURE_NAMES`），模型文件自带版本号，避免换特征后
   旧模型静默错位。
3. 抽不出来就给 0，绝不抛异常——取证链路上任何一次异常都会让整站白跑。
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

FEATURE_VERSION = 1

# ---------------------------------------------------------------------------
# 用途词典：判「用途」，不判「可疑」。
# 这些词在诈骗站上也会出现（落地页同样写「立即领取」），所以它们只进用途
# 分类器，不进风险评分。两套词库刻意分开，避免又一次「加词→误报↑」。
# ---------------------------------------------------------------------------

USE_LEXICON: dict[str, tuple[str, ...]] = {
    "cs": (
        "在线客服", "客服系统", "客服中心", "工单", "坐席", "会话", "访客",
        "智能客服", "客服机器人", "呼叫中心", "客户服务", "服务台", "帮助中心",
        "在线咨询", "留言咨询", "售后", "服务工单", "知识库", "满意度",
    ),
    "forum": (
        "论坛", "版块", "板块", "帖子", "楼主", "回帖", "发帖", "置顶", "精华",
        "主题帖", "威望", "讨论区", "灌水", "楼层", "版主", "抢沙发", "楼中楼",
    ),
    "ecommerce": (
        "购物车", "立即购买", "加入购物车", "商品详情", "库存", "运费", "订单",
        "下单", "优惠券", "促销", "店铺", "卖家", "买家", "包邮", "规格", "SKU",
        "批发", "采购", "询盘", "起订量", "样品",
    ),
    "corporate": (
        "关于我们", "解决方案", "产品中心", "联系我们", "企业文化", "公司简介",
        "发展历程", "招贤纳士", "人才招聘", "合作伙伴", "资质证书", "服务网络",
        "案例展示", "新闻动态",
    ),
    "news": (
        "责任编辑", "来源：", "记者", "通讯员", "本报", "新华社", "报道", "专访",
        "评论", "要闻", "时政", "财经", "体育", "娱乐", "图片新闻", "视频新闻",
        "版权所有", "未经授权",
    ),
    "portal": (
        "频道", "专题", "资讯", "推荐阅读", "热门", "排行榜", "首页", "栏目",
        "政策解读", "行业动态", "专家", "智库", "数据库", "研究报告", "白皮书",
    ),
    "landing": (
        "立即领取", "立即申请", "立即报名", "马上领取", "限时", "名额", "仅限",
        "扫码", "加微信", "点击领取", "免费领取", "一键申请", "在线申报",
        "填写信息", "提交申请", "审核", "补贴", "发放", "领取",
    ),
    "appdist": (
        "下载安装", "安卓版", "苹果版", "APK", "安装包", "扫码下载", "客户端下载",
        "立即下载", "APP下载", "手机版下载", "安装教程", "允许安装",
    ),
}

# 用途词典键 → 特征名。两边命名习惯不同（ecommerce/ecom），显式映射避免
# 「某个键忘改导致 KeyError」——这个坑在第一次自测时就踩了。
_USE_FIELDS: dict[str, str] = {
    "cs": "use_cs",
    "forum": "use_forum",
    "ecommerce": "use_ecom",
    "corporate": "use_corp",
    "news": "use_news",
    "portal": "use_portal",
    "landing": "use_landing",
    "appdist": "use_appdist",
}

# 客服 SaaS 的域名特征：页面引用了这些 SDK，基本可以断定这是个客服系统/客服站。
CS_SDK_HOSTS = (
    "53kf.com", "meiqia.com", "sobot.com", "zhichi.com", "udesk.cn", "easemob.com",
    "hihoocn.com", "live800.com", "7moor.com", "kf5.com", "cctvchat.com",
    "zendesk.com", "intercom.io", "tawk.to", "crisp.chat", "livechatinc.com",
)
ANALYTICS_HOSTS = (
    "google-analytics.com", "googletagmanager.com", "hm.baidu.com", "cnzz.com",
    "51.la", "umeng.com", "matomo", "clarity.ms", "hotjar.com",
)
PAYMENT_HOSTS = (
    "alipay.com", "weixin.qq.com", "tenpay.com", "unionpay.com", "paypal.com",
)
CDN_HOSTS = (
    "cdn.", "cloudflare", "aliyun", "qiniu", "bcebos", "myqcloud", "jsdelivr",
    "unpkg.com", "bootcdn", "staticfile",
)
# 高滥用后缀：不是「一定坏」，只是先验概率高，交给自己学。
RISKY_TLDS = frozenset(
    {"top", "xyz", "cyou", "icu", "cc", "buzz", "monster", "sbs", "cfd", "lol",
     "click", "link", "shop", "vip", "work", "live", "fun", "online", "site", "space"}
)
FREE_ISSUERS = ("let's encrypt", "zerossl", "r3", "r10", "e1", "buypass", "sectigo")

# 固定顺序：模型按位置取值，顺序变了必须升 FEATURE_VERSION。
FEATURE_NAMES: tuple[str, ...] = (
    # 文本形态
    "text_len", "log_text_len", "cjk_ratio", "digit_ratio", "punct_ratio",
    "unique_char_ratio", "para_count", "avg_para_len", "max_para_len", "repeat_line_ratio",
    # 词库（只作为「行业相关度」，不作为可疑度）
    "kw_hits", "kw_clusters", "kw_strong_clusters", "kw_density",
    "kw_policy", "kw_authority", "kw_elder", "kw_scam",
    # 用途词
    "use_cs", "use_forum", "use_ecom", "use_corp", "use_news", "use_portal",
    "use_landing", "use_appdist", "cta_count", "cta_density",
    # 结构
    "html_len_kb", "form_count", "input_count", "password_inputs", "tel_inputs",
    "id_inputs", "button_count", "link_count", "nav_count", "iframe_count",
    "img_count", "canvas_count", "script_count", "inline_script_kb",
    "has_breadcrumb", "has_search",
    # 网络
    "third_party_hosts", "cs_sdk_hosts", "analytics_hosts", "payment_hosts",
    "cdn_hosts", "post_targets", "external_script_hosts", "blocked_requests",
    # 基础设施
    "domain_len", "domain_digits", "domain_hyphens", "is_ip_host", "risky_tld",
    "tls_free_issuer", "tls_days_valid", "has_tls",
    # 自称 / 页面形态
    "claim_level", "claim_agencies", "has_site_id", "has_icp",
    "impersonation_flag", "low_text_page", "apk_links", "qrcode_links",
)

_CJK = re.compile(r"[\u4e00-\u9fff]")
_DIGIT = re.compile(r"\d")
_PUNCT = re.compile(r"[，。！？；：、,.!?;:\"'（）()\[\]【】《》<>—\-…·]")
_CTA = re.compile(
    r"立即[^\s，。]{0,6}|马上[^\s，。]{0,6}|一键[^\s，。]{0,6}|点击[^\s，。]{0,6}"
    r"|免费[^\s，。]{0,6}|现在[^\s，。]{0,6}(?:领取|申请|报名|下载)|扫码[^\s，。]{0,4}"
)
_PHONE_INPUT = re.compile(r"1[3-9]\d{9}|手机号|手机号码|联系电话|电话")
_ID_INPUT = re.compile(r"身份证|证件号|证件号码|银行卡|卡号|社保号")
_IP_HOST = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass(slots=True)
class FeatureBundle:
    """特征向量 + 给人看的证据片段（解释用，不进模型）。"""

    values: dict[str, float] = field(default_factory=dict)
    hints: list[str] = field(default_factory=list)

    def vector(self) -> list[float]:
        return [float(self.values.get(name, 0.0)) for name in FEATURE_NAMES]

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": FEATURE_VERSION,
            "values": {k: round(float(v), 4) for k, v in self.values.items()},
            "hints": self.hints[:12],
        }


def _ratio(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole > 0 else 0.0


def _text_stats(text: str) -> dict[str, float]:
    n = len(text)
    if n == 0:
        return {
            "text_len": 0.0, "log_text_len": 0.0, "cjk_ratio": 0.0, "digit_ratio": 0.0,
            "punct_ratio": 0.0, "unique_char_ratio": 0.0, "para_count": 0.0,
            "avg_para_len": 0.0, "max_para_len": 0.0, "repeat_line_ratio": 0.0,
        }
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    paras = [ln for ln in lines if len(ln) >= 12] or lines
    lengths = [len(ln) for ln in paras] or [0]
    # 重复行占比：模板页（导航/页脚/推荐位）重复度高，正文页低。
    uniq = len(set(lines))
    return {
        "text_len": float(n),
        "log_text_len": round(math.log1p(n), 4),
        "cjk_ratio": _ratio(len(_CJK.findall(text)), n),
        "digit_ratio": _ratio(len(_DIGIT.findall(text)), n),
        "punct_ratio": _ratio(len(_PUNCT.findall(text)), n),
        "unique_char_ratio": _ratio(len(set(text)), n),
        "para_count": float(len(paras)),
        "avg_para_len": round(sum(lengths) / len(lengths), 2),
        "max_para_len": float(max(lengths)),
        "repeat_line_ratio": _ratio(len(lines) - uniq, len(lines)) if lines else 0.0,
    }


def _count_terms(text: str, terms: tuple[str, ...]) -> int:
    """命中多少个「不同」词，而不是出现次数。

    按次数统计会让长页面天然占优——客服站首页两万字，「回复」出现 40 次，
    论坛分会飙到天花板。用途是「有没有这套词」，不是「说了多少遍」。
    """
    return sum(1 for t in terms if t in text)


def _domains_in(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in urls:
        try:
            host = (urlsplit(u).hostname or "").lower()
        except ValueError:
            continue
        if host:
            out.append(host)
    return out


def _host_in(host: str, patterns: tuple[str, ...]) -> bool:
    return any(p in host for p in patterns)


def extract(
    *,
    url: str = "",
    html: str = "",
    text: str = "",
    facts: dict[str, Any] | None = None,
    requests: list[dict[str, Any]] | None = None,
    forms: list[dict[str, Any]] | None = None,
    tls: dict[str, Any] | None = None,
    apk_links: list[str] | None = None,
) -> FeatureBundle:
    """抽一次特征。任何异常都退化成 0，不向上抛。"""
    facts = facts or {}
    bundle = FeatureBundle()
    vals = bundle.values
    vals.update(_text_stats(text or ""))

    # ---- 词库：只当「行业相关度」，不当可疑度
    try:
        from .discover.keywords import get_library

        m = get_library().match_any("", (text or "")[:20000])
        by_cluster: dict[str, int] = {}
        for hit in m.hits:
            by_cluster[hit.cluster] = by_cluster.get(hit.cluster, 0) + 1
        strong = {"scam_signature", "authority", "brand", "impersonation"}
        vals["kw_hits"] = float(len(m.hits))
        vals["kw_clusters"] = float(len(by_cluster))
        vals["kw_strong_clusters"] = float(len(strong & set(by_cluster)))
        vals["kw_density"] = round(len(m.hits) * 1000 / max(len(text or ""), 1), 4)
        vals["kw_policy"] = float(by_cluster.get("policy_theme", 0))
        vals["kw_authority"] = float(by_cluster.get("authority", 0))
        vals["kw_elder"] = float(by_cluster.get("elder_care", 0))
        vals["kw_scam"] = float(by_cluster.get("scam_signature", 0))
    except Exception:  # noqa: BLE001 词库坏了不能影响取证
        for k in ("kw_hits", "kw_clusters", "kw_strong_clusters", "kw_density",
                  "kw_policy", "kw_authority", "kw_elder", "kw_scam"):
            vals.setdefault(k, 0.0)

    # ---- 用途词典
    body = text or ""
    for key, field_name in _USE_FIELDS.items():
        vals[field_name] = float(_count_terms(body, USE_LEXICON.get(key, ())))
    cta = len(_CTA.findall(body))
    vals["cta_count"] = float(cta)
    vals["cta_density"] = round(cta * 1000 / max(len(body), 1), 4)

    # ---- 结构：优先用已解析的 forms，其次从 HTML 统计
    forms = forms or []
    vals["form_count"] = float(len(forms))
    inputs = 0
    password_inputs = 0
    tel_inputs = 0
    id_inputs = 0
    for f in forms:
        if not isinstance(f, dict):
            continue
        fields = f.get("inputs") or f.get("fields") or []
        if not isinstance(fields, list):
            continue
        for item in fields:
            inputs += 1
            desc = json.dumps(item, ensure_ascii=False) if not isinstance(item, str) else item
            low = desc.lower()
            if "password" in low:
                password_inputs += 1
            if _PHONE_INPUT.search(desc):
                tel_inputs += 1
            if _ID_INPUT.search(desc):
                id_inputs += 1
    vals["input_count"] = float(inputs)
    vals["password_inputs"] = float(password_inputs)
    vals["tel_inputs"] = float(tel_inputs)
    vals["id_inputs"] = float(id_inputs)

    html = html or ""
    vals["html_len_kb"] = round(len(html) / 1024, 2)
    inline = sum(len(seg) for seg in re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I))
    vals["inline_script_kb"] = round(inline / 1024, 2)
    lower_html = html.lower()
    vals["button_count"] = float(len(re.findall(r"<button\b", lower_html)))
    vals["link_count"] = float(len(re.findall(r"<a\b", lower_html)))
    vals["nav_count"] = float(len(re.findall(r"<nav\b", lower_html)))
    vals["iframe_count"] = float(len(re.findall(r"<iframe\b", lower_html)))
    vals["img_count"] = float(len(re.findall(r"<img\b", lower_html)))
    vals["canvas_count"] = float(len(re.findall(r"<canvas\b", lower_html)))
    vals["script_count"] = float(len(re.findall(r"<script\b", lower_html)))
    vals["has_breadcrumb"] = 1.0 if re.search(r"面包屑|breadcrumb|当前位置[：:]", html + body, re.I) else 0.0
    vals["has_search"] = 1.0 if re.search(r"type=[\"']?search|<form[^>]+search|搜索", lower_html) else 0.0

    # ---- 网络
    reqs = requests or []
    hosts = _domains_in([str(r.get("url") or "") for r in reqs if isinstance(r, dict)])
    third_party = {h for h in hosts if _host_of(url) and not h.endswith(_host_of(url))}
    vals["third_party_hosts"] = float(len(third_party))
    # 按唯一主机计数：一个页面会往同一个客服域名发几十条请求，
    # 按请求条数算会把「1 个 SDK」放大成「122 个 SDK」，特征直接失真。
    vals["cs_sdk_hosts"] = float(len({h for h in hosts if _host_in(h, CS_SDK_HOSTS)}))
    vals["analytics_hosts"] = float(len({h for h in hosts if _host_in(h, ANALYTICS_HOSTS)}))
    vals["payment_hosts"] = float(len({h for h in hosts if _host_in(h, PAYMENT_HOSTS)}))
    vals["cdn_hosts"] = float(len({h for h in hosts if _host_in(h, CDN_HOSTS)}))
    vals["post_targets"] = float(
        sum(1 for r in reqs if isinstance(r, dict) and str(r.get("method", "GET")).upper() not in ("GET", "HEAD", "OPTIONS"))
    )
    vals["external_script_hosts"] = float(len({h for h in hosts if h.endswith(".js") or "/js/" in h}))
    vals["blocked_requests"] = float(facts.get("blocked_requests") or 0)

    # ---- 基础设施
    host = _host_of(url)
    vals["domain_len"] = float(len(host))
    vals["domain_digits"] = float(len(_DIGIT.findall(host)))
    vals["domain_hyphens"] = float(host.count("-") + host.count("."))
    vals["is_ip_host"] = 1.0 if _IP_HOST.match(host) else 0.0
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    vals["risky_tld"] = 1.0 if tld in RISKY_TLDS else 0.0
    tls = tls or {}
    issuer = str(tls.get("issuer") or "").lower()
    vals["tls_free_issuer"] = 1.0 if issuer and any(x in issuer for x in FREE_ISSUERS) else 0.0
    vals["tls_days_valid"] = _tls_days(tls)
    vals["has_tls"] = 1.0 if (tls or str(url).startswith("https")) else 0.0

    # ---- 自称 / 页面形态
    claim = facts.get("claim") or {}
    if not isinstance(claim, dict):
        claim = {}
    try:
        vals["claim_level"] = float(claim.get("level") or 0)
    except (TypeError, ValueError):
        vals["claim_level"] = 0.0
    vals["claim_agencies"] = float(len(claim.get("agencies") or []))
    vals["has_site_id"] = 1.0 if claim.get("site_id") else 0.0
    vals["has_icp"] = 1.0 if claim.get("icp") else 0.0
    vals["impersonation_flag"] = 1.0 if str(claim.get("verdict") or "").startswith(("fake", "impersonation")) else 0.0
    vals["low_text_page"] = 1.0 if len(body) < 300 else 0.0
    vals["apk_links"] = float(len(apk_links or facts.get("apk_links") or []))
    vals["qrcode_links"] = float(len(facts.get("qrcode_links") or []))

    # ---- 解释线索（给人看，不进模型）
    hints: list[str] = []
    if vals["cs_sdk_hosts"]:
        hints.append(f"引用 {int(vals['cs_sdk_hosts'])} 个客服 SDK")
    if vals["use_forum"] >= 6:
        hints.append("论坛版式（版块/楼层/回复）")
    if vals["use_ecom"] >= 5:
        hints.append("电商版式（购物车/商品/订单）")
    if vals["use_corp"] >= 5:
        hints.append("企业站版式（关于我们/解决方案）")
    if vals["nav_count"] >= 1 or vals["link_count"] >= 40:
        hints.append("多级导航")
    if vals["cta_count"] and len(body) and vals["cta_density"] > 2:
        hints.append("强 CTA（每千字多次行动号召）")
    if vals["low_text_page"]:
        hints.append("纯图/短落地页")
    bundle.hints = hints
    return bundle


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _tls_days(tls: dict[str, Any]) -> float:
    """证书剩余有效期（天）。抽不出来给 0，由模型自行处理。"""
    from datetime import UTC, datetime

    raw = tls.get("not_after") or tls.get("valid_to") or ""
    if not raw:
        return 0.0
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return round((dt - datetime.now(UTC)).total_seconds() / 86400, 2)
    except Exception:  # noqa: BLE001
        return 0.0


def vector_from_facts(facts: dict[str, Any]) -> list[float]:
    """从落库的 facts 还原特征向量（重评/训练用，不重新抓站）。"""
    feats = facts.get("features") or {}
    values = feats.get("values") if isinstance(feats, dict) else None
    if not isinstance(values, dict):
        return [0.0] * len(FEATURE_NAMES)
    return [float(values.get(name, 0.0) or 0.0) for name in FEATURE_NAMES]
