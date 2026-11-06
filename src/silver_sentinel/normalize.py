"""实体规范化与指标提取。

这一段是全部判定的地基：同一批骗子会把同一个链接挂上十几个跳转参数反复发，
如果不做规范化，线索库会被重复项淹没。
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

# 常见二级公共后缀，用于取「可注册域名」
# 两级公共后缀：不做归并会出大事故（x.co.za 和 y.co.za 会被当成同一个站）。
# 这里取「常见 + 中国相关」的集合；冷门后缀宁可少归并，也不要把不同主体并成一个。
TWO_LEVEL_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk",
    "com.tw", "org.tw", "net.tw", "edu.tw", "gov.tw",
    "com.mo", "edu.mo", "gov.mo",
    "com.sg", "edu.sg", "gov.sg",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "co.za", "org.za", "gov.za", "net.za",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "govt.nz",
    "co.kr", "or.kr", "go.kr", "ne.kr",
    "com.my", "gov.my", "edu.my",
    "co.id", "or.id", "go.id", "ac.id",
    "co.th", "or.th", "go.th", "ac.th",
    "com.vn", "gov.vn", "edu.vn",
    "com.ph", "gov.ph", "edu.ph",
    "com.pk", "gov.pk", "edu.pk",
    "com.sa", "gov.sa", "edu.sa",
    "com.tr", "gov.tr", "edu.tr",
    "com.ar", "gov.ar", "edu.ar",
    "com.mx", "gob.mx", "edu.mx",
    "com.co", "gov.co", "edu.co",
    "com.pe", "gob.pe", "edu.pe",
    "com.ua", "gov.ua", "edu.ua",
    "com.pl", "gov.pl", "edu.pl",
    "com.ru", "gov.ru", "edu.ru",
    "com.es", "gob.es", "edu.es",
    "co.il", "gov.il", "ac.il",
    "com.eg", "gov.eg", "edu.eg",
    "com.ng", "gov.ng", "edu.ng",
    "co.ke", "go.ke", "ac.ke",
}

# 可以安全按「末两级」取注册域的后缀；不在表里的国别后缀宁可不归并
_SIMPLE_TLDS = {
    "cn", "com", "net", "org", "top", "xyz", "cc", "info", "app", "dev", "cloud",
    "site", "online", "shop", "vip", "club", "live", "work", "ink", "fun", "icu",
    "buzz", "cyou", "ltd", "store", "tech", "space", "website", "host", "press",
    "link", "pro", "biz", "me", "tv", "io", "co", "ai", "so", "ws", "mobi",
    "asia", "art", "design", "today", "life", "world", "group", "email", "digital",
    "pub", "run", "sh", "one", "page", "news", "blog", "fit", "best",
}

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "spm", "scm", "from", "from_source", "share_token", "share_id", "sharer",
    "_wv", "scene", "clicktime", "enterid", "wfr", "share_medium", "share_plat",
    "share_session_id", "share_tag", "timestamp", "unique_k", "buvid", "mid",
    "is_story_h5", "share_from", "bbid", "ts", "vd_source",
}

SHORTENERS = {
    "bit.ly", "t.cn", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "dwz.cn", "url.cn", "suo.im", "sourl.cn", "mrw.so", "6url.cn", "dwz.date",
    "rebrand.ly", "cutt.ly", "shorturl.at", "s.id", "rb.gy", "tiny.cc",
}

FREE_HOSTING_SUFFIXES = (
    ".github.io", ".vercel.app", ".netlify.app", ".pages.dev", ".web.app",
    ".firebaseapp.com", ".000webhostapp.com", ".glitch.me", ".surge.sh",
    ".herokuapp.com", ".repl.co", ".ngrok.io", ".trycloudflare.com",
)

# 共享基础设施后缀：云厂商、对象存储、PaaS、建站平台。
# 这些域下的子域由平台批量签发**通配符证书**，所以「共用证书」「同 IP」
# 在这里没有任何归因价值——把它们算成团伙，等于把同一朵云上的所有客户判成一伙。
# 发现层照常记录（宁可错杀），但图上不建证书/解析边，避免污染归因。
SHARED_INFRA_SUFFIXES = (
    ".amazonaws.com", ".cloudfront.net", ".elb.amazonaws.com",
    ".azurewebsites.net", ".azureedge.net", ".blob.core.windows.net", ".cloudapp.azure.com",
    ".snowflake.com", ".snowflake.app", ".snowflakecomputing.com",
    # 设备/平台的「每账号一个随机子域」：名字里带 mz/gk 纯属巧合
    ".viam.cloud", ".myvolumio.org", ".ccaiplatform.com", ".aws.dev",
    ".googleusercontent.com", ".appspot.com", ".run.app", ".web.app",
    ".aliyuncs.com", ".oss-cn-hangzhou.aliyuncs.com", ".myqcloud.com", ".cos.ap-shanghai.myqcloud.com",
    ".qiniucdn.com", ".bcebos.com", ".jdcloud.com", ".ctyunxs.cn",
    ".digitaloceanspaces.com", ".r2.dev", ".workers.dev", ".deno.dev", ".fly.dev",
    ".onrender.com", ".railway.app", ".render.com", ".now.sh",
    ".notion.site", ".framer.app", ".webflow.io", ".wixsite.com", ".godaddysites.com",
    ".myshopify.com", ".gitlab.io", ".bitbucket.io", ".sourceforge.io",
    ".pages.dev", ".netlify.app", ".vercel.app", ".azurestaticapps.net", ".github.io",
)

# 页面里出现率极高、和团伙归因无关的第三方域名。
# 落地页几乎都会挂统计脚本、字体 CDN、客服组件；把它们当「新发现的域名」
# 回灌进发现队列，只会把队列塞满 jsdelivr 和 google-analytics。
PIVOT_NOISE_ROOTS = {
    "google-analytics.com", "googletagmanager.com", "google.com", "gstatic.com",
    "googleapis.com", "doubleclick.net", "googlesyndication.com", "youtube.com",
    "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com",
    "cdnjs.com", "bootcdn.net", "staticfile.org", "cdn.bootcss.com",
    "baidu.com", "bdstatic.com", "cnzz.com", "umeng.com", "gtimg.cn",
    "qq.com", "weixin.qq.com", "wechat.com", "tencent.com", "alipay.com",
    "aliyun.com", "aliyuncs.com", "w3.org", "schema.org", "jquery.com",
    "bootstrapcdn.com", "fontawesome.com", "sentry.io", "hotjar.com",
    "facebook.com", "twitter.com", "tiktok.com", "instagram.com",
    "microsoft.com", "windows.net", "apple.com", "amazon.com",
}


def is_pivot_noise(domain: str) -> bool:
    """这个域名值不值得回灌进发现队列。

    判据只有一条：它是不是「几乎所有站点都会挂」的公共基础设施。
    是就丢掉——回灌的目的是找同伙，不是找 CDN。
    """
    d = (domain or "").lower().strip(".")
    if not d or "." not in d:
        return True
    if re.fullmatch(r"[\d.]+", d):
        return True
    for root in PIVOT_NOISE_ROOTS:
        if d == root or d.endswith("." + root):
            return True
    for suffix in SHARED_INFRA_SUFFIXES:
        bare = suffix.lstrip(".")
        if d == bare or d.endswith(suffix):
            return True
    return False


# 未备案/低成本注册常见 TLD，用作弱信号，不作单独判定
CHEAP_TLDS = {"top", "xyz", "icu", "buzz", "cyou", "shop", "vip", "club", "online", "site", "live", "cc", "tk", "ml", "ga", "cf", "gq"}

OFFICIAL_TLD_HINTS = {".gov.cn", ".gov", ".mil"}

_CJK = re.compile(r"[\u4e00-\u9fff]")
_DOMAIN_RE = re.compile(
    r"(?<![\w@.-])((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24})(?![\w-])"
)
_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'，。；、）】」》]+", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?86[- ]?)?(1[3-9]\d{9})(?!\d)")
_LANDLINE_RE = re.compile(r"(?<!\d)(0\d{2,3}[- ]?\d{7,8})(?!\d)")
_QQ_RE = re.compile(r"(?:QQ|qq|扣扣)(?:群|号|群号)?\s*[:：]?\s*(\d{5,11})")
_WECHAT_RE = re.compile(r"(?:微信|V信|vx|VX|weixin|WeChat)\s*[:：]?\s*([a-zA-Z][-_a-zA-Z0-9]{5,19})")
_PACKAGE_RE = re.compile(r"\b([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,4})\b")
_ETH_RE = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")
_TRON_RE = re.compile(r"\b(T[1-9A-HJ-NP-Za-km-z]{33})\b")
_BTC_RE = re.compile(r"\b(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_CARD_RE = re.compile(r"(?<!\d)(\d{16,19})(?!\d)")

# 疑似跳转/落地页常见路径词
LANDING_HINTS = ("download", "app", "down", "install", "apk", "reg", "invite", "h5", "promo", "activity", "share")


def strip_invisible(text: str) -> str:
    """清除零宽字符与全角空格——骗子常用它们绕过关键词过滤。"""
    return re.sub(r"[\u200b-\u200f\u202a-\u202e\ufeff\u00a0\u3000]", " ", text)


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKC", strip_invisible(text or ""))
    return re.sub(r"\s+", " ", text).strip()


def split_host_port(netloc: str) -> tuple[str, int | None]:
    netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):
        host, _, rest = netloc.partition("]")
        host = host.lstrip("[")
        port = rest.lstrip(":") if rest.startswith(":") else ""
    elif ":" in netloc:
        host, _, port = netloc.rpartition(":")
    else:
        host, port = netloc, ""
    try:
        port_num = int(port) if port else None
    except ValueError:
        port_num = None
    return host.lower().rstrip("."), port_num


def normalize_url(raw: str) -> tuple[str, str]:
    """返回 (规范化 URL, host)。非法输入原样返回并给出空 host。"""
    raw = normalize_text(raw)
    if not raw:
        return "", ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw.lstrip("/")

    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw, ""

    host, port = split_host_port(parts.netloc)
    if not host:
        return raw, ""

    scheme = "https" if parts.scheme.lower() in {"https", "wss"} else "http"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host

    path = re.sub(r"/{2,}", "/", unquote(parts.path or "/"))
    if len(path) > 1:
        path = path.rstrip("/")

    query_pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k.lower() not in TRACKING_PARAMS]
    query = urlencode(sorted(query_pairs))

    return urlunsplit((scheme, netloc, path, query, "")), host


def normalize_domain(raw: str) -> str:
    raw = normalize_text(raw).lower()
    raw = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", raw)
    raw = raw.split("/")[0].split("?")[0]
    host, _ = split_host_port(raw)
    return host


def registrable_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    if not host or re.fullmatch(r"[\d.]+", host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


# 免费二级域平台：骗子正是用「平台域 + 自己起的名字」来落地，
# 归并到平台域等于把线索扔了，所以这类只保留完整主机名。
NO_COLLAPSE_SUFFIXES = (
    ".duckdns.org", ".dpdns.org", ".ddns.net", ".no-ip.org", ".hopto.org",
    ".zapto.org", ".serveo.net", ".ngrok.io", ".ngrok-free.app",
    ".trycloudflare.com", ".localtunnel.me", ".us.kg", ".eu.org",
    ".blogspot.com", ".wordpress.com", ".wixsite.com", ".framer.app",
)


def collapse_host(host: str) -> str:
    """把主机归并到注册域；后缀不可识别时原样返回，避免把不同主体并成一个。

    这是「宁可少归并」的取舍：并错了会把两个无关团伙焊在一起，
    比多留几条资产严重得多。
    """
    if _suffix_hit(host, NO_COLLAPSE_SUFFIXES):
        return host
    apex = registrable_domain(host)
    labels = apex.split(".")
    if len(labels) == 2 and labels[1] not in _SIMPLE_TLDS:
        return host
    return apex


def tld_of(host: str) -> str:
    host = host or ""
    return "." + host.rsplit(".", 1)[-1] if "." in host else ""


def is_shortener(host: str) -> bool:
    return registrable_domain(normalize_domain(host)) in SHORTENERS


def _suffix_hit(host: str, suffixes: tuple[str, ...]) -> bool:
    """后缀命中判断。同时认「更深的子域」和「域名本身就是平台域」两种情况：
    normalize_domain 可能把 demo.vercel.app 归一成 vercel.app，
    只写 endswith('.vercel.app') 会漏掉后者。"""
    for suf in suffixes:
        bare = suf.lstrip(".")
        if host == bare or host.endswith(suf):
            return True
    return False


def is_free_hosting(host: str) -> bool:
    return _suffix_hit(normalize_domain(host), FREE_HOSTING_SUFFIXES)


def is_shared_infra(host: str) -> bool:
    """是否位于共享基础设施（云 / 对象存储 / 建站平台）之下。

    这类域名的证书与 IP 由平台统一分配，不能作为「同一团伙」的证据。
    """
    return _suffix_hit(normalize_domain(host), SHARED_INFRA_SUFFIXES)


def is_official_domain(host: str) -> bool:
    return any(host.endswith(s) for s in OFFICIAL_TLD_HINTS)


def luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 16 <= len(digits) <= 19:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def extract_indicators(text: str) -> dict[str, list[str]]:
    """从自由文本中抽取可核查指标。去重且保持出现顺序。"""
    text = normalize_text(text)

    def uniq(items: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out

    urls: list[str] = []
    for match in _URL_RE.findall(text):
        cleaned = match.rstrip(".,;:!?)]}>\"'")
        normalized, _ = normalize_url(cleaned)
        if normalized:
            urls.append(normalized)

    domains = [normalize_domain(d) for d in _DOMAIN_RE.findall(text)]
    domains = [d for d in uniq(domains) if not d.endswith(".apk") and not d.endswith(".jpg")]

    cards = [m for m in _CARD_RE.findall(text) if luhn_ok(m)]
    # 包名与域名形状相同，靠「首段是否为常见 TLD」区分：
    # com.guohui.minsheng 这种反域名写法是 Android 包名惯例，不会作为域名注册。
    packages = [
        p
        for p in uniq(_PACKAGE_RE.findall(text))
        if p.count(".") >= 2
        and p.startswith(("com.", "cn.", "org.", "net.", "io.", "me.", "top."))
        and not p.endswith((".com", ".cn", ".net", ".html", ".apk", ".jpg", ".png"))
    ]

    return {
        "urls": uniq(urls),
        "domains": uniq(domains),
        "phones": uniq(_PHONE_RE.findall(text)),
        "landlines": uniq(_LANDLINE_RE.findall(text)),
        "qq": uniq(_QQ_RE.findall(text)),
        "wechat": uniq(_WECHAT_RE.findall(text)),
        "wallets": uniq(_ETH_RE.findall(text) + _TRON_RE.findall(text) + _BTC_RE.findall(text)),
        "bank_cards": uniq(cards),
        "apk_packages": uniq(packages),
    }


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) or len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_SUFFIX_NOISE = ("-official", "official", "-cn", "cn-", "-app", "app-", "-vip", "vip-", "1", "8", "88", "666")


def brand_lookalike(host: str, brands: set[str]) -> tuple[str, str] | None:
    """判断域名是否在模仿给定品牌，返回 (命中的品牌, 说明)。"""
    label = registrable_domain(host).split(".")[0]
    for brand in brands:
        if label == brand:
            continue  # 完全一致不算「仿冒」，可能是真官方，交由其他信号判断
        if label.startswith(brand) or label.endswith(brand):
            extra = label.replace(brand, "").strip("-")
            # 品牌词 + 短后缀（含拼音、数字、cn/zg 等）几乎不会出现在官方域名上
            if extra and (extra.isdigit() or len(extra) <= 10):
                return brand, f"域名 {label} 在品牌词「{brand}」上附加「{extra}」"
        if len(brand) >= 5 and 0 < levenshtein(label, brand) <= 2:
            return brand, f"域名 {label} 与品牌「{brand}」编辑距离 {levenshtein(label, brand)}"
        for noise in _SUFFIX_NOISE:
            if label == f"{brand}{noise}" or label == f"{noise}{brand}":
                return brand, f"域名 {label} 采用「{brand}+{noise}」拼接"
    return None


def sha256_bytes(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def shingle_hash(text: str, size: int = 5) -> str:
    """页面/话术模板指纹：分词后取 n-gram 哈希，用于跨域名归并同一套模板。"""
    import hashlib

    tokens = re.findall(r"[\u4e00-\u9fff]|[a-zA-Z]+|\d+", normalize_text(text).lower())
    if len(tokens) < size:
        return hashlib.sha256(" ".join(tokens).encode()).hexdigest()[:16]
    grams = {" ".join(tokens[i : i + size]) for i in range(len(tokens) - size + 1)}
    digest = sorted(hashlib.md5(g.encode()).hexdigest() for g in grams)[:256]
    return hashlib.sha256("".join(digest).encode()).hexdigest()[:16]


def has_cjk(text: str) -> bool:
    return bool(_CJK.search(text or ""))
