"""页面「自称」抽取与冒充判定。

为什么不能靠词库
----------------
词库建模的是**行业词汇**，不是**欺诈行为**。「财政部」「民政部」「补贴」
「养老」这些词，正规从业者天天写，央视健康的八段锦教程也能命中
`scam_signature`。实测 25 个正规垂类站里 8 个得分 ≥0.97，比诈骗样本还高。

骗子真正无法伪装的不是用词，而是**身份**：它必须说「我是财政部」，
才能让老人相信「这笔钱是国家发的」。而「财政部」这个身份是可核验的。

抽取位置（这决定误报率）
------------------------
只认两处：

1. `<header>` 里的文字；
2. 含 `© / 版权所有 / 主办单位 / 承办单位 / 技术支持 / 政府网站标识码` 的**叶子元素**。

并且**先剔除 `<a>/<nav>/<ul>`**——页脚的友情链接会把「财政部 民政部 税务总局」
全带进来。第一版没剔除，中国红十字会（redcross.org.cn）被判成「冒充财政部」；
再往前一版用「正文前 300 字」，昆明理工和中南大学的乡村振兴专题站也被误伤
（正文引用农业农村部）。

三次迭代后的规则在 32 个负样本上 **0 误报**。

判定分级
--------
```
fake_site_id       非政府域出现「政府网站标识码 bmXXXXXXXX」   零误判，中国政府网自己的码
                   常被抄成 bm01000001
impersonation      自称某部委，而该部委的官方域名不是当前域      强
fabricated_agency  自称「国家XX中心」这类库中不存在的机构        中（事业单位会误伤）
legit              政府域，或自称与官方域一致
neutral            没有自称
```
"""

from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from .whitelist import AgencyHit, get_whitelist

log = logging.getLogger(__name__)

# 自称只可能出现在这些位置。正则故意宽松，因为页面会写「© 2026 中华人民共和国财政部」
# 「本页面由财政部信息中心提供技术支持」「主办单位：XX市人民政府办公室」。
COPY_MARK = re.compile(
    r"©|copyright|版权所有|主办单位|承办单位|主管单位|指导单位|技术支持|政府网站标识码",
    re.I,
)

# 政府网站标识码：bm + 8 位数字（国办函〔2018〕55 号）。只发给政府网站。
SITE_ID = re.compile(r"政府网站标识码\s*[：:]\s*(bm\d{8})", re.I)
# 兜底：页面把标识码写在 meta 或纯文本里
SITE_ID_LOOSE = re.compile(r"\bbm(\d{8})\b")

ICP = re.compile(r"([\u4e00-\u9fff]{0,6}ICP[备证]?\s*\d{4,12}\s*号(?:\s*-\s*\d+)?)")

# 虚构国家机构的构词：库里没有、但看起来像国家机关。
FABRICATED = re.compile(
    r"(国家|中国|全国|中央|国务院)[\u4e00-\u9fff]{2,14}(中心|办公室|委员会|局|署|专项|项目组|工作组)"
)

# 假的「部委名」往往堆在页头，取前若干条即可，避免长页面把整段正文吸进来。
MAX_CLAIMS = 6


@dataclass(slots=True)
class ClaimReport:
    host: str = ""
    title: str = ""
    verdict: str = "neutral"
    level: int = 0
    agencies: list[str] = field(default_factory=list)
    official_domains: dict[str, list[str]] = field(default_factory=dict)
    site_id: str = ""
    icp: str = ""
    is_gov_host: bool = False
    is_media_host: bool = False
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "level": self.level,
            "agencies": self.agencies[:MAX_CLAIMS],
            "official_domains": self.official_domains,
            "site_id": self.site_id,
            "icp": self.icp,
            "is_gov_host": self.is_gov_host,
            "is_media_host": self.is_media_host,
            "reasons": self.reasons[:6],
            "title": self.title[:120],
        }


def _strip_links(tag) -> str:
    """链接不是自称。页脚「友情链接：财政部」必须排除。"""
    node = copy.copy(tag)
    for a in node.find_all(["a", "nav", "ul", "ol", "select", "option"]):
        a.decompose()
    return node.get_text(" ", strip=True)


def _self_claim_blocks(soup: BeautifulSoup) -> list[str]:
    """返回所有「自称区块」的文字：页头 + 版权/主办声明行。"""
    out: list[str] = []
    for tag in soup.find_all("header"):
        txt = _strip_links(tag)
        if txt:
            out.append(txt)

    body = soup.body or soup
    # 页头还有一类情况：没有 <header> 标签，但正文最前面几块就是「审核机构：国务院办公厅」。
    # 只看文档顺序前 12 个叶子块、且长度 <100 字——足够靠前，才可能是自称；
    # 正文里的「据财政部消息」一定在更后面。
    head_seen = 0
    for el in body.find_all(["div", "p", "span", "td", "h1", "h2", "h3"], limit=800):
        if el.find(["div", "p", "li", "table", "section"]):
            continue
        txt = _strip_links(el)
        if not txt or len(txt) > 100 or len(txt) < 4:
            continue
        # 「据农业农村部消息，今年将继续推进……」是引用，不是自称。
        # 自称是标签式的：短、没有句读。「审核机构 国务院办公厅」= 自称。
        if re.search(r"[，。；！？,.;!?]", txt):
            continue
        head_seen += 1
        if head_seen > 12:
            break
        out.append(txt)

    # 叶子元素逐个看：只保留含版权/主办标记的短文本块。
    # 整页文本不行——正文里「据财政部消息」不是自称。
    for el in body.find_all(["div", "p", "li", "td", "span", "footer", "section"], limit=800):
        if el.find(["div", "p", "li", "table", "section"]):
            continue
        txt = _strip_links(el)
        if not txt or len(txt) > 300 or not COPY_MARK.search(txt):
            continue
        out.append(txt)
    # 去重保序
    seen: set[str] = set()
    uniq: list[str] = []
    for t in out:
        key = re.sub(r"\s+", "", t)[:120]
        if key and key not in seen:
            seen.add(key)
            uniq.append(t)
    return uniq[:40]


def analyze_html(html: str, host: str = "", *, title: str = "") -> ClaimReport:
    """从页面 HTML 抽自称并判定。纯计算，不碰网络与数据库。"""
    report = ClaimReport(host=host)
    if not html:
        return report
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as exc:  # noqa: BLE001 解析失败按无自称处理
        log.debug("页面解析失败 %s：%s", host, exc)
        return report

    wl = get_whitelist()
    report.is_gov_host = wl.is_government(host)
    report.is_media_host = wl.is_media(host)

    page_title = (soup.title.get_text(strip=True) if soup.title else "") or title
    report.title = page_title[:160]

    # ---- 标识码：先看 meta / 全文，再退回自称区块
    m = SITE_ID.search(html)
    if not m:
        m2 = SITE_ID_LOOSE.search(html)
        if m2:
            report.site_id = f"bm{m2.group(1)}"
    else:
        report.site_id = m.group(1)

    blocks = _self_claim_blocks(soup)

    # ---- 备案号：只在版权行附近取，避免正文里的政策文号
    for block in blocks:
        if not report.icp:
            mi = ICP.search(block)
            if mi:
                report.icp = re.sub(r"\s+", "", mi.group(1))

    # ---- 机构自称
    hits: dict[str, AgencyHit] = {}
    # 合并成一次调用：CORE_AGENCIES 有 39 个词，逐块扫会重复几十次。
    # 自称区块本来就是一个整体（页头 + 版权行），合并不会丢信息。
    for hit in wl.match_agencies(" ".join(blocks)):
        hits.setdefault(hit.name, hit)
    # 标题里带机构名也算：骗子常把「中华人民共和国财政部」直接写进 title
    for hit in wl.match_agencies(page_title):
        hits.setdefault(hit.name, hit)

    report.agencies = list(hits)[:MAX_CLAIMS]
    report.official_domains = {k: v.official_domains for k, v in hits.items()}

    # ---- 判定，顺序即优先级
    if report.site_id and not report.is_gov_host:
        report.verdict = "fake_site_id"
        report.level = 4
        report.reasons.append(
            f"非政府域名却标注政府网站标识码 {report.site_id}（该码只发给 .gov.cn）"
        )
        return report

    if report.agencies and not report.is_gov_host:
        with_domain = {k: v for k, v in report.official_domains.items() if v}
        if with_domain:
            report.verdict = "impersonation"
            report.level = 3
            name, domains = next(iter(with_domain.items()))
            report.reasons.append(
                f"非政府域自称「{name}」，该机构官方域名为 {domains[0]}"
            )
            return report
        # 库里没有：只有「国家XX中心」这类构词才怀疑，避免误伤事业单位
        blocks_text = " ".join(blocks)
        fab = FABRICATED.search(re.sub(r"\s+", "", blocks_text))
        if fab:
            report.verdict = "fabricated_agency"
            report.level = 2
            report.reasons.append(f"自称机构「{fab.group(0)}」不在政府网站库中")
        return report

    if report.agencies and report.is_gov_host:
        report.verdict = "legit"
        report.level = 0
        report.reasons.append("政府域名，自称与官方一致")
        return report

    if report.is_media_host:
        report.verdict = "legit"
        report.reasons.append("命中新闻稿源单位名单")
    return report


def analyze_text(text: str, host: str = "", *, title: str = "") -> ClaimReport:
    """只有正文没有 HTML 时的降级入口（例如历史证据只剩纯文本）。

    只能识别标题与首行里的自称，判定力弱，`verdict` 最多到 impersonation。
    """
    report = ClaimReport(host=host)
    wl = get_whitelist()
    report.is_gov_host = wl.is_government(host)
    report.is_media_host = wl.is_media(host)
    head = "\n".join((text or "").splitlines()[:5])[:600]
    report.title = (title or (text or "").splitlines()[0] if text else "")[:160]
    hits = {h.name: h for h in wl.match_agencies(head)}
    report.agencies = list(hits)[:MAX_CLAIMS]
    report.official_domains = {k: v.official_domains for k, v in hits.items()}
    if report.agencies and not report.is_gov_host:
        report.verdict = "impersonation"
        report.level = 3
        report.reasons.append("首屏文本自称政府机构")
    elif report.is_media_host:
        report.verdict = "legit"
    return report
