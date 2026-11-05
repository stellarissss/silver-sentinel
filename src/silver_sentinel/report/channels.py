"""举报渠道注册表。

每条记录对应一次真实探测（2026-11-05），字段含义：

``fill``
    ``auto``   扩展把全部文本字段填好，人只需过验证码并点提交
    ``semi``   通用标签匹配填充，页面改版后可能漂移
    ``mailto`` 生成 abuse 邮件，一键唤起邮件客户端
    ``guide``  只提供入口与填报要点，需人工填写

``captcha``
    ``image`` 图形验证码（可留空，人填）／``slider`` 行为验证（人拖）／
    ``turnstile`` Cloudflare 托管校验／``none``

``attachment``
    ``multi`` 支持多附件上传，``single`` 单个，``none`` 不支持
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Channel:
    id: str
    name: str
    short: str
    operator: str
    entry_url: str
    kind: str                       # regulator | infra | platform | hotline
    fill: str                       # auto | semi | mailto | guide
    captcha: str
    attachment: str
    login_required: bool
    body_limit: int                 # 正文硬上限（字符），0 表示未知
    max_urls: int                   # 单次可提交的网址条数，0 表示不限/未知
    supports: tuple[str, ...]       # 适用的 harm 类型
    priority: int                   # 越小越优先
    requirements: tuple[str, ...] = ()
    notes: str = ""
    # 扩展注入所需：content script 匹配的 host
    match_hosts: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "short": self.short,
            "operator": self.operator,
            "entry_url": self.entry_url,
            "kind": self.kind,
            "fill": self.fill,
            "captcha": self.captcha,
            "attachment": self.attachment,
            "login_required": self.login_required,
            "body_limit": self.body_limit,
            "max_urls": self.max_urls,
            "supports": list(self.supports),
            "priority": self.priority,
            "requirements": list(self.requirements),
            "notes": self.notes,
            "match_hosts": list(self.match_hosts),
        }


# harm 类型（系统内部口径）
HARM_TYPES: dict[str, str] = {
    "impersonation": "仿冒官方机构／国企",
    "phishing": "钓鱼与支付诈骗",
    "fraud": "诈骗引流",
    "gambling": "网络赌博",
    "porn": "淫秽色情",
    "rumor": "谣言与伪科普",
    "app": "涉诈应用",
    "account": "涉诈社交账号",
    "trademark": "商标／著作权侵权",
}

_ALL = tuple(HARM_TYPES)

CHANNELS: dict[str, Channel] = {
    "12377": Channel(
        id="12377",
        name="中央网信办（国家网信办）违法和不良信息举报中心",
        short="12377 网信举报",
        operator="中央网络安全和信息化委员会办公室",
        # 统一表单页；大类由 cookie bigHarmType 决定，扩展会先写 cookie 再刷新
        entry_url="https://www.12377.cn/jbxzxq/jbxx/zcjb/zcjb.html",
        kind="regulator",
        fill="auto",
        captcha="image",
        attachment="multi",
        login_required=True,
        body_limit=500,
        max_urls=20,
        supports=_ALL,
        priority=1,
        requirements=(
            "需先注册并登录 12377 账号（实名）",
            "图形验证码由人工填写",
            "正文上限 500 字，超长会被前端截断",
        ),
        notes="专项任务里有「涉养老诈骗有害信息举报专区」，涉老线索优先走该小类。",
        match_hosts=("www.12377.cn", "new.12377.cn"),
    ),
    "12321": Channel(
        id="12321",
        name="12321 网络不良与垃圾信息举报受理中心",
        short="12321 不良网站",
        operator="工业和信息化部（中国互联网协会承办）",
        entry_url="https://www.12321.cn/web",
        kind="regulator",
        fill="auto",
        captcha="slider",
        attachment="none",
        login_required=False,
        body_limit=2200,
        max_urls=1,
        supports=("phishing", "fraud", "gambling", "porn", "app", "impersonation"),
        priority=2,
        requirements=(
            "免登录，但提交时弹数美滑块验证，需人工拖动",
            "网页版不支持附件，证据靠正文描述与后续补充",
        ),
        notes="不良类型选「钓鱼及诈骗」；涉及 App 的走同一页面切到「不良手机应用」。",
        match_hosts=("www.12321.cn", "12321.cn"),
    ),
    "qq_urlsec": Channel(
        id="qq_urlsec",
        name="腾讯安全·网址安全中心（可疑网站举报）",
        short="腾讯网址举报",
        operator="腾讯科技",
        entry_url="https://urlsec.qq.com/report.html",
        kind="platform",
        fill="auto",
        captcha="slider",
        attachment="single",
        login_required=False,
        body_limit=0,
        max_urls=1,
        supports=("phishing", "fraud", "gambling", "porn", "impersonation"),
        priority=3,
        requirements=("可留邮箱接收处置结果", "提交时弹腾讯防水墙验证，需人工完成"),
        notes="响应快，2 天内分析；拦截后微信/QQ 内分享链接会直接提示风险。",
        match_hosts=("urlsec.qq.com",),
    ),
    "cyberpolice": Channel(
        id="cyberpolice",
        name="公安部网络违法犯罪信息举报网站",
        short="公安网举报",
        operator="公安部网络安全保卫局",
        entry_url="https://cyberpolice.mps.gov.cn/#/Integrated/index",
        kind="regulator",
        fill="guide",
        captcha="image",
        attachment="multi",
        login_required=True,
        body_limit=0,
        max_urls=0,
        supports=("fraud", "gambling", "porn", "impersonation"),
        priority=4,
        requirements=(
            "需实名注册并登录，部分情形要求人脸核验",
            "表单在登录后才可见，本系统不做自动填充",
        ),
        notes="适合已造成实际损失的案件线索；单纯网址举报走 12377 更快。",
        match_hosts=("cyberpolice.mps.gov.cn",),
    ),
    "cf_abuse": Channel(
        id="cf_abuse",
        name="Cloudflare 滥用举报",
        short="CF 滥用",
        operator="Cloudflare, Inc.",
        entry_url="https://abuse.cloudflare.com/",
        kind="infra",
        fill="semi",
        captcha="turnstile",
        attachment="none",
        login_required=False,
        body_limit=0,
        max_urls=5,
        supports=_ALL,
        priority=5,
        requirements=("需要站点确实解析到 Cloudflare", "Turnstile 由人过"),
        notes="只对 CF 承载的站点有效；能拿到源站时优先举报源站机房。",
        match_hosts=("abuse.cloudflare.com",),
    ),
    "registrar_abuse": Channel(
        id="registrar_abuse",
        name="域名注册商 / 托管商滥用邮箱",
        short="注册商 abuse",
        operator="域名注册商（以 WHOIS 为准）",
        entry_url="",
        kind="infra",
        fill="mailto",
        captcha="none",
        attachment="multi",
        login_required=False,
        body_limit=4000,
        max_urls=10,
        supports=_ALL,
        priority=6,
        requirements=("需有 WHOIS 中的 abuse 联系地址", "用英文书写，附证据包"),
        notes="下架域名最直接的一步；对 .cn 域名同时抄送 CNNIC 投诉邮箱。",
        match_hosts=(),
    ),
    "piyao": Channel(
        id="piyao",
        name="中国互联网联合辟谣平台",
        short="联合辟谣",
        operator="中央网信办违法和不良信息举报中心",
        entry_url="https://www.piyao.org.cn/",
        kind="regulator",
        fill="guide",
        captcha="none",
        attachment="none",
        login_required=False,
        body_limit=0,
        max_urls=0,
        supports=("rumor",),
        priority=7,
        requirements=("仅受理谣言线索，诈骗网址不受理",),
        notes="冒充政策、伪造补贴文件的「伪政策」内容适合走这里。",
        match_hosts=("www.piyao.org.cn",),
    ),
    "12315": Channel(
        id="12315",
        name="全国 12315 平台（市场监管）",
        short="12315",
        operator="国家市场监督管理总局",
        entry_url="https://www.12315.cn/",
        kind="regulator",
        fill="guide",
        captcha="slider",
        attachment="multi",
        login_required=True,
        body_limit=0,
        max_urls=0,
        supports=("fraud", "trademark"),
        priority=8,
        requirements=("需实名注册", "需明确被举报经营者主体"),
        notes="针对有实体经营者的虚假宣传、价格欺诈；纯境外网站通常不受理。",
        match_hosts=("www.12315.cn",),
    ),
    "96110": Channel(
        id="96110",
        name="反诈专线 96110 / 报警 110",
        short="96110",
        operator="公安部",
        entry_url="tel:96110",
        kind="hotline",
        fill="guide",
        captcha="none",
        attachment="none",
        login_required=False,
        body_limit=0,
        max_urls=0,
        supports=("fraud",),
        priority=0,
        requirements=("仅用于正在发生或已发生转账的情形",),
        notes="已经转账的，先打这个再走任何线上举报。",
        match_hosts=(),
    ),
}

# 按 harm 类型给出的推荐顺序（id 列表）
ROUTES: dict[str, tuple[str, ...]] = {
    "impersonation": ("12377", "12321", "qq_urlsec", "registrar_abuse", "cyberpolice"),
    "phishing": ("12377", "12321", "qq_urlsec", "registrar_abuse", "cf_abuse", "cyberpolice"),
    "fraud": ("96110", "12377", "12321", "qq_urlsec", "cyberpolice", "registrar_abuse"),
    "gambling": ("12377", "12321", "qq_urlsec", "registrar_abuse", "cyberpolice"),
    "porn": ("12377", "12321", "qq_urlsec", "registrar_abuse"),
    "rumor": ("12377", "piyao"),
    "app": ("12377", "12321", "qq_urlsec"),
    "account": ("12377", "12321"),
    "trademark": ("12377", "12315"),
}


def get(channel_id: str) -> Channel:
    return CHANNELS.get(channel_id) or CHANNELS["12377"]


def for_harm(harm: str) -> list[Channel]:
    """按推荐顺序返回适用渠道。"""
    order = ROUTES.get(harm) or ROUTES["phishing"]
    seen: set[str] = set()
    out: list[Channel] = []
    for cid in order:
        if cid in seen or cid not in CHANNELS:
            continue
        seen.add(cid)
        out.append(CHANNELS[cid])
    return out


def catalog(harm: str = "") -> list[dict[str, Any]]:
    """渠道目录。带 harm 时标注是否推荐、排序靠前。"""
    recommended = {c.id for c in for_harm(harm)} if harm in ROUTES else set()
    rows = []
    for ch in CHANNELS.values():
        d = ch.as_dict()
        d["recommended"] = ch.id in recommended
        d["harm_label"] = HARM_TYPES.get(harm, "")
        rows.append(d)
    rows.sort(key=lambda r: (not r["recommended"], r["priority"]))
    return rows
