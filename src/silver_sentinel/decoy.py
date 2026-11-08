"""诱饵与蜜罐：把「对方不想让人看见的东西」变成证据。

为什么单独一层
--------------
暖阳那一批站教了一件事：**首页不等于内容**。

    26537.net 首页是「安全检测中心，请稍候」，正文里一个涉老词都没有。
    按词表判，它是干净的；按行为判，它是几十个涉老站的入口。
    之前把它留在 candidate 里躺着，理由是「判不出涉老」——判断没错，
    但结论错了：它不是「没有价值」，它是**分发渠道**。

所以这里换一个问法：这一页是不是**故意做给人（和扫描器）看的样子货**？

五种形态
--------
    interstitial   CDN/WAF 的验证页。不是对方的东西，是我们的网络被拦。
                   唯一正确的处理是**重试**，绝不能拿它当证据判低分。
    security_check 「环境检测/安全核验/正在检测」的假页面。真身在下一跳。
    blank_shell    空壳：正文极短，只有一个按钮/表单，没有任何业务内容。
    expired        收尾页：「活动已结束/名额已满/已过期」。说明这站**运作过**。
    honeypot       蜜罐：隐藏陷阱字段、navigator.webdriver 检测、反调试死循环。

判错的代价
----------
把 WAF 页当诱饵 → 一批正常站被记成「故意伪装」，污染证据；
把诱饵当正常页 → 判定引擎看到的是空壳，直接漏判（暖阳就是这个坑）。

所以两条硬规矩：

1. **先排除基础设施**。命中 Cloudflare / 阿里云 / 百度云加速 / 腾讯云 WAF
   指纹的，一律 interstitial，不进证据链。
2. **诱饵必须「短」且「空」**。正文 3000 字的补贴公告里出现「安全检测」
   四个字，那是政策原文，不是诱饵。长度是这里最重要的一个判据。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- 基础设施指纹
#
# 这些是「我们的请求被中间设备拦了」，不是目标站的内容。
# 把它们当证据是最容易犯的错：一批正常站会因为机房 IP 被 WAF 挑战，
# 全部记成「伪装页」，然后判定引擎按空壳给低分，人工复核时一脸茫然。

_WAF_FINGERPRINTS = (
    # Cloudflare
    ("cf-chl", "Cloudflare 挑战"),
    ("__cf_chl_", "Cloudflare 挑战"),
    ("challenge-platform", "Cloudflare 挑战"),
    ("cf-browser-verification", "Cloudflare 挑战"),
    ("just a moment", "Cloudflare 挑战"),
    ("attention required", "Cloudflare 挑战"),
    ("ray id", "Cloudflare 拦截"),
    # 阿里云
    ("aliyun_waf", "阿里云 WAF"),
    ("acw_sc__v2", "阿里云 WAF"),
    ("errors.aliyun.com", "阿里云 WAF"),
    ("yundun", "阿里云盾"),
    # 百度云加速
    ("yunjiasu", "百度云加速"),
    ("yunjiasu-cdn", "百度云加速"),
    # 腾讯云
    ("tencent-cloud-waf", "腾讯云 WAF"),
    ("waf.tencentcloud", "腾讯云 WAF"),
    # 通用
    ("enable javascript and cookies to continue", "通用 JS 挑战"),
    ("checking your browser", "通用浏览器校验"),
    ("ddos protection by", "DDoS 防护页"),
    ("incapsula", "Imperva"),
    ("sucuri", "Sucuri"),
)

# ---------------------------------------------------------------- 形态词表

# 「安全检测/核验」类假页面。注意都必须配「正文短」才算——
# 政策公告里写「系统将进行安全检测」是正常句子。
_SECURITY_CHECK = re.compile(
    r"安全检测|环境检测|风险检测|安全核验|正在核验|安全中心|检测中|"
    r"正在检测|系统检测|设备检测|浏览器检测|环境异常|请稍候|请稍等|"
    r"正在加载|加载中|正在跳转|即将跳转|请勿关闭"
)

_BLANK_MARKERS = re.compile(
    r"网站建设中|正在建设|敬请期待|即将上线|维护中|系统升级|"
    r"暂停服务|已停止访问|域名已过期|页面不存在|404|not\s*found",
    re.IGNORECASE,
)

_EXPIRED = re.compile(
    r"活动已结束|活动结束|名额已满|名额已抢完|已过期|已截止|"
    r"领取结束|申报结束|通道关闭|已停止发放|来晚了"
)

# 反自动化：对方明确在检测「你是不是脚本」。
# 这是蜜罐最硬的证据——正常业务页面不需要判断访问者是不是无头浏览器。
_ANTI_AUTOMATION = re.compile(
    r"navigator\.webdriver|HeadlessChrome|headless|"
    r"puppeteer|playwright|selenium|phantomjs|"
    r"\$cdc_[a-zA-Z0-9_]{6,}|__nightmare|_selenium|"
    r"window\.callPhantom|domAutomation|"
    r"detect(?:ed)?\s+(?:automation|bot|headless)|"
    r"疑似(?:机器|脚本|爬虫)|检测到(?:自动化|爬虫|脚本)|"
    r"请关闭(?:开发者工具|调试工具)|debugger"
)

# 隐藏陷阱字段：用正常业务绝不会用的字段名，配 display:none。
_TRAP_FIELD = re.compile(
    r"confirm_email|email_confirm|email2|address2|website_url|homepage|"
    r"company_website|fax|nickname_confirm|honeypot|leave_?this_?empty|"
    r"do_?not_?fill|bot_?field",
    re.IGNORECASE,
)

_HIDDEN_INPUT = re.compile(
    r"<(?:input|textarea)[^>]*(?:"
    r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|"
    r'tabindex\s*=\s*["\']?-1|aria-hidden\s*=\s*["\']?true'
    r")[^>]*>",
    re.IGNORECASE,
)

# 跳转壳：整个页面只有一个 location 赋值 / meta refresh。
_REDIRECT_JS = re.compile(
    r"location\.(?:href|replace|assign)\s*[=(]|"
    r"window\.location\s*=|"
    r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh",
    re.IGNORECASE,
)

# 下载入口：诱饵页的价值全在这里——它把人往包里带。
# 必须限定在 href/src 里。整页搜 "download" 会把 GA 脚本、
# 隐私政策里的「下载 App」文案全算成去向，线上实测因此误判过三例。
_DOWNLOAD_HINT = re.compile(
    r"""(?:href|src|action)\s*=\s*["'][^"']*(?:\.apk|/download|/down/|/dl/|/app/|/go/|anzhuo|android)""",
    re.IGNORECASE,
)

# 短正文的门槛。实测：真诱饵页正文 12–180 字，
# 真公告页 800–4000 字。400 是个很宽的分界，不会误伤。
_SHORT_TEXT = 400
_VERY_SHORT_TEXT = 120
_SHELL_HTML = 3000


# 分析/统计域名：它们出现在每个页面的请求里，但**不是**「去向」。
# 线上实测：把 XHR 目标当去向时，三个 virsms 站被判成核验诱饵，
# 而它们唯一的「去向」是 google-analytics.com/g/collect。
_ANALYTICS = re.compile(
    r"google-analytics\.com|googletagmanager\.com|doubleclick\.net|"
    r"hm\.baidu\.com|cnzz\.com|umeng\.com|clarity\.ms|hotjar\.|sentry\.io|"
    r"connect\.facebook\.net|facebook\.com/tr|analytics\.tiktok\.com|"
    r"beacon\.|/collect\?|/g/collect|/pixel",
    re.IGNORECASE,
)


def _is_analytics(url: str) -> bool:
    return bool(_ANALYTICS.search(url or ""))


@dataclass
class DecoySignal:
    """一页是不是样子货，以及它指向哪里。"""

    is_decoy: bool = False
    kind: str = ""            # security_check / blank_shell / expired / redirect_shell
    confidence: float = 0.0
    # 证据：写成人话，直接进详情页和举报材料
    evidence: list[str] = field(default_factory=list)
    # 真身去向：下一跳 URL、后端接收地址、下载入口
    downstream: list[str] = field(default_factory=list)
    # 基础设施拦截：不是目标站的内容，必须重试
    blocked_by: str = ""
    # 蜜罐：对方在检测自动化。这是「专业化」的证据，不是排除理由
    honeypot: bool = False
    honeypot_reasons: list[str] = field(default_factory=list)
    # 给分级用的强度：0 无意义，1 弱（空壳），2 中（收尾页），3 强（核验诱饵/蜜罐）
    weight: int = 0
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "is_decoy": self.is_decoy,
            "kind": self.kind,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence[:8],
            "downstream": self.downstream[:6],
            "blocked_by": self.blocked_by,
            "honeypot": self.honeypot,
            "honeypot_reasons": self.honeypot_reasons[:6],
            "weight": self.weight,
            "reason": self.reason,
        }

    def is_interstitial(self) -> bool:
        return bool(self.blocked_by)


def _text_len(text: str) -> int:
    """正文字数：去掉空白后的长度。

    不去重、不去停用词——这里只关心「这页有没有实质内容」，
    100 字的导航栏和 100 字的公告在这一点上没有区别。
    """
    return len(re.sub(r"\s+", "", text or ""))


def _waf(html: str, title: str) -> str:
    blob = f"{title}\n{html[:8000]}".lower()
    for needle, label in _WAF_FINGERPRINTS:
        if needle in blob:
            return label
    return ""


def _trap_fields(html: str) -> list[str]:
    """找出隐藏的陷阱输入框。

    只看「隐藏」还不够——很多正常表单用 hidden 存 csrf token。
    两个条件同时成立才算：隐藏 **且** 字段名是 honeypot 惯用名。
    """
    found: list[str] = []
    for m in _HIDDEN_INPUT.finditer(html or ""):
        snippet = m.group(0)
        name = re.search(r"name\s*=\s*[\"']([^\"']{1,40})[\"']", snippet)
        if not name:
            continue
        if _TRAP_FIELD.search(name.group(1)):
            found.append(name.group(1))
    return sorted(set(found))


def assess(
    *,
    html: str = "",
    text: str = "",
    title: str = "",
    status: int = 0,
    final_url: str = "",
    request_host: str = "",
    html_len: int = 0,
    forms: list[dict[str, Any]] | None = None,
    second_hop: dict[str, Any] | None = None,
    apk_links: list[str] | None = None,
    download_entries: list[str] | None = None,
    post_targets: list[str] | None = None,
    honeypot_report: dict[str, Any] | None = None,
) -> DecoySignal:
    """判一页是不是诱饵 / 蜜罐 / 被 WAF 拦了。

    纯函数：不发请求、不读数据库，方便在 rescore 里对历史资产重算。
    """
    html = html or ""
    text = text or ""
    title = title or ""
    n = _text_len(text)
    html_len = html_len or len(html)
    hop = second_hop or {}
    sig = DecoySignal()

    # ---- 0. 基础设施拦截：优先级最高，命中就立刻返回。
    #
    # 这一步必须在所有判断之前。WAF 挑战页的标题就是「安全检测」，
    # 不先识别出来，每一批被挡的站都会变成「诱饵」。
    if status in (403, 429, 503) or n < _VERY_SHORT_TEXT:
        label = _waf(html, title)
        if label:
            sig.blocked_by = label
            sig.confidence = 0.9
            sig.reason = f"被 {label} 拦截，页面不是目标站的内容"
            sig.evidence.append(f"命中 {label} 指纹，HTTP {status}")
            return sig

    # ---- 1. 蜜罐：对方在检测自动化。
    #
    # 和「诱饵」不同，蜜罐不一定是假页面——它可能是个真业务页，
    # 只是专门为爬虫准备了陷阱。所以单独标，不占用 decoy.kind。
    hp = honeypot_report or {}
    if hp.get("suspected"):
        sig.honeypot = True
        sig.honeypot_reasons.extend(list(hp.get("reasons") or [])[:3])

    traps = _trap_fields(html)
    if traps:
        sig.honeypot = True
        sig.honeypot_reasons.append("表单含隐藏陷阱字段：" + "、".join(traps[:3]))

    # 反自动化只认「短页面」或「明确的检测语句」。
    # 正规站在隐私政策里写一句 "we do not use navigator.webdriver" 也会命中，
    # 但那种页面上万字，不会走进这个分支。
    anti = _ANTI_AUTOMATION.search(html)
    if anti and (n < 3000 or re.search(r"检测到|请关闭|detected", anti.group(0), re.IGNORECASE)):
        sig.honeypot = True
        token = anti.group(0).strip()[:40]
        sig.honeypot_reasons.append(f"页面含反自动化检测：{token}")
        # 无限 debugger 是最典型的「反调试死循环」
        if re.search(r"setInterval\s*\(.{0,120}?debugger|while\s*\(\s*(?:1|true)\s*\)\s*\{[^}]*debugger", html, re.DOTALL):
            sig.honeypot_reasons.append("反调试死循环（setInterval + debugger）")

    if sig.honeypot and not sig.weight:
        sig.weight = 3
        sig.reason = "检测到反自动化措施：" + "；".join(sig.honeypot_reasons[:2])

    # ---- 2. 跳转壳：HTML 极小，只有一个跳转。
    hop_url = str(hop.get("url") or "")
    if hop_url and not _is_analytics(hop_url):
        sig.downstream.append(hop_url)
    # apk_links 与 download_entries 会重叠（`.apk` 结尾的链接两边都算），
    # 不去重就会出现「10 个下载入口」而实际只有 5 个。
    for u in list(apk_links or [])[:5] + list(download_entries or [])[:5]:
        if u and not _is_analytics(u) and u not in sig.downstream:
            sig.downstream.append(u)
    # 表单 POST 的去向也算「有去向」。
    #
    # 这一步是为「按钮没点中」兜底：暖阳那类的表单地址写在 JS 里，
    # `_follow_cta` 认不出「点我」这种文案就没跳过去，但 XHR 已经打到了
    # `api.php`。运行时请求是现成的证据，不用再抓一次页面。
    for u in list(post_targets or [])[:3]:
        if not u:
            continue
        if request_host and request_host in u:
            continue  # 同站提交不算「把人送走」
        if _is_analytics(u):
            continue  # 埋点不是去向
        if u not in sig.downstream:
            sig.downstream.append(u)

    if html_len < _SHELL_HTML and n < _VERY_SHORT_TEXT and _REDIRECT_JS.search(html):
        # 两种写法都要接住：`location.href='...'` 和
        # `<meta http-equiv="refresh" content="0;url=...">`。
        # 后者是 meta 里嵌在 content 中的 `url=`，两边没有引号包着。
        target = re.search(
            r"(?:location\.(?:href|replace|assign)\s*[=(]\s*|url\s*=\s*)"
            r"[\"']?([^\"';\s]{4,300})",
            html,
            re.IGNORECASE,
        )
        if target and target.group(1) not in sig.downstream:
            sig.downstream.append(target.group(1))
        if target and request_host and request_host not in target.group(1):
            sig.is_decoy = True
            sig.kind = "redirect_shell"
            sig.confidence = 0.72
            sig.weight = 2
            sig.evidence.append(f"页面仅 {html_len} 字节，正文 {n} 字，只有一个跳转")
            sig.reason = "整页是一个跳转壳，真实内容在另一域名"
            return sig

    # ---- 3. 核验诱饵：假「安全检测」页。
    #
    # 三个条件缺一不可：短正文 + 核验词 + 有去向。
    # 只有「安全检测」四个字没有去向的，可能真是维护公告。
    has_exit = bool(sig.downstream) or bool(forms) or bool(_DOWNLOAD_HINT.search(html))
    if n <= _SHORT_TEXT and _SECURITY_CHECK.search(f"{title}\n{text}"):
        if not has_exit:
            # 没有去向的「请稍候」既可能是诱饵也可能是坏页面。
            # 给弱信号，不判 decoy——宁可在详情页留一句，也不要污染主判据。
            sig.evidence.append(f"正文仅 {n} 字，含核验类措辞，但未发现去向")
            sig.reason = "疑似空转页，无去向"
            return sig
        sig.is_decoy = True
        sig.kind = "security_check"
        # 有下载入口的核验页几乎可以确定是分发诱饵
        sig.confidence = 0.82 if _DOWNLOAD_HINT.search(html) else 0.68
        sig.weight = 3
        sig.evidence.append(f"正文仅 {n} 字，标题/正文为核验类措辞：「{title[:40] or '无标题'}」")
        if sig.downstream:
            sig.evidence.append(f"有 {len(sig.downstream)} 个去向（下一跳/下载）")
        sig.reason = "核验诱饵页，真实内容在下一跳"
        return sig

    # ---- 3b. 下载壳：没有内容，只有包。
    #
    # 暖邻 26537.net 的实际形态：正文 127 字，5 个 `/go/downloadN` 跳板，
    # 没有表单、没有核验词、没有「建设中」。它不伪装成任何东西，
    # 它就是一张「点这里下载」的皮——而这正是分发链路的入口。
    #
    # 判据必须同时满足「短」「有包」「无表单」：
    # 正规软件官网也有下载按钮，但会写功能介绍、客服、备案，正文不会只有 127 字。
    apk_entries = list(apk_links or []) + list(download_entries or [])
    apk_entries = [u for u in apk_entries if u and not _is_analytics(u)]
    if n <= 200 and apk_entries and not forms:
        sig.is_decoy = True
        sig.kind = "download_shell"
        sig.confidence = 0.7
        sig.weight = 3
        sig.evidence.append(f"正文仅 {n} 字，直接给出 {len(apk_entries)} 个下载入口")
        if sig.downstream:
            sig.evidence.append(f"入口指向 {sig.downstream[0][:80]}")
        sig.reason = "下载壳：页面没有内容，只有安装包入口"
        return sig

    # ---- 4. 收尾页：活动结束/名额已满。
    #
    # 这类页面的价值不在正文，而在**它承认自己干过这件事**。
    # 「补贴申领已结束」本身就是证据：没有申领，哪来的结束。
    if n <= _SHORT_TEXT and _EXPIRED.search(text):
        sig.is_decoy = True
        sig.kind = "expired"
        sig.confidence = 0.6
        sig.weight = 2
        m = _EXPIRED.search(text)
        sig.evidence.append(f"正文仅 {n} 字，直接写「{m.group(0)}」")
        sig.reason = "收尾页：承认活动存在但已关闭，是「曾运作」的证据"
        return sig

    # ---- 5. 空壳：极短正文 + 没有业务内容。
    if n <= _VERY_SHORT_TEXT and _BLANK_MARKERS.search(f"{title}\n{text}"):
        sig.is_decoy = True
        sig.kind = "blank_shell"
        sig.confidence = 0.55
        sig.weight = 1
        sig.evidence.append(f"正文仅 {n} 字，标题/正文为建设中或维护类措辞")
        sig.reason = "空壳页，无实质内容"
        return sig

    if not sig.is_decoy and not sig.honeypot:
        sig.reason = "未发现诱饵或蜜罐特征"
    return sig


# ---------------------------------------------------------------- 与判定链的衔接


def action_evidence(sig: DecoySignal | dict[str, Any]) -> str:
    """把诱饵转成 elder 的「转化动作」证据。

    这是「不漏判」的关键一步：诱饵页本身没有涉老词，
    但它把人**送到**了有涉老词的下一跳。这条证据补的就是那个断点。
    """
    if isinstance(sig, dict):
        if not sig.get("is_decoy"):
            return ""
        kind = str(sig.get("kind") or "")
        downstream = list(sig.get("downstream") or [])
    else:
        if not sig.is_decoy:
            return ""
        kind = sig.kind
        downstream = sig.downstream

    parts = {
        "security_check": "页面伪装成安全核验，引导进入下一跳",
        "redirect_shell": "整页跳转到另一域名",
        "expired": "页面写「活动已结束」，承认此前存在该活动",
        "blank_shell": "空壳页，无实质内容",
        "download_shell": "下载壳页，只给安装包入口",
    }
    base = parts.get(kind, "诱饵页")
    if downstream:
        base += "（去向 " + str(downstream[0])[:80] + "）"
    return base


def triage_note(sig: DecoySignal | dict[str, Any], *, elder: bool) -> tuple[str, str]:
    """给分级一个建议：(建议档位, 理由)。

    空字符串表示「不干预，按常规评分走」。

    原则：
    - WAF 拦截页 → 不参与分级，等重试；
    - 诱饵 + 已判涉老 → 不额外升档（已经够了），但理由记清楚；
    - 诱饵 + 未判涉老 + 有去向 → 至少 candidate，且写明「分发节点」。
      暖阳 26537.net 就是这一类：它自己不是诈骗页，它把老人送到诈骗页。
    - 纯空壳无去向 → 不干预，让评分自然把它压到冷存。
    """
    if isinstance(sig, dict):
        blocked_by = str(sig.get("blocked_by") or "")
        honeypot = bool(sig.get("honeypot"))
        hp_reasons = [str(x) for x in (sig.get("honeypot_reasons") or [])]
        is_decoy = bool(sig.get("is_decoy"))
        weight = int(sig.get("weight") or 0)
        downstream = list(sig.get("downstream") or [])
        reason = str(sig.get("reason") or "")
    else:
        blocked_by = sig.blocked_by
        honeypot = sig.honeypot
        hp_reasons = sig.honeypot_reasons
        is_decoy = sig.is_decoy
        weight = sig.weight
        downstream = sig.downstream
        reason = sig.reason

    if blocked_by:
        return "", f"被 {blocked_by} 拦截，本次不参与分级"
    if honeypot:
        return "", "含反自动化措施：" + "；".join(hp_reasons[:2])
    if not is_decoy:
        return "", ""
    if elder:
        return "", f"{reason}（已按涉老定档）"
    if weight >= 2 and downstream:
        return "candidate", f"诱饵/分发节点：{reason}，去向 {len(downstream)} 个"
    if weight >= 2:
        return "candidate", f"诱饵页：{reason}"
    return "", f"空壳页：{reason}"