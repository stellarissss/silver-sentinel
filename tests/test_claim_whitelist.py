"""白名单与「自称/冒充」判定的回归用例。

这些用例锁的是三件容易反复犯的错：
1. 把白名单当过滤器（不在名单里就排除）；
2. 把页面里任何地方出现的机构名都算「自称」；
3. 把页脚友情链接当成自称。
"""

from __future__ import annotations

from silver_sentinel import triage
from silver_sentinel.claim import analyze_html
from silver_sentinel.models import Asset
from silver_sentinel.whitelist import get_whitelist


def _page(head: str = "", body: str = "", title: str = "") -> str:
    return (
        f"<html><head><title>{title}</title></head><body>"
        f"{head}{body}</body></html>"
    )


# ---------------------------------------------------------------- 白名单


def test_gov_suffix_is_government():
    wl = get_whitelist()
    assert wl.is_government("www.mof.gov.cn")
    assert wl.is_government("mof.gov.cn")


def test_gov_lookalike_is_not_government():
    """`gov.cn.evil.com` 不是政府站——判断后缀，不是包含。"""
    wl = get_whitelist()
    assert not wl.is_government("gov.cn.evil.com")
    assert not wl.is_government("fakegov.cn.xyz")


def test_ordinary_site_is_not_government():
    wl = get_whitelist()
    for host in ("www.53kf.com", "tuiyijunren.cn", "www.yige-tech.com", "www.39.net"):
        assert not wl.is_government(host)
        assert not wl.is_media(host)


def test_media_whitelist():
    wl = get_whitelist()
    assert wl.is_media("www.people.com.cn")
    assert wl.is_media("news.cctv.com")


def test_agency_domains_and_alias():
    wl = get_whitelist()
    assert "mof.gov.cn" in wl.agency_domains("财政部")
    assert "nhc.gov.cn" in wl.agency_domains("卫健委")      # 简称走别名表
    assert "gov.cn" in wl.agency_domains("国务院")          # 登记名是「中国政府网」
    assert wl.agency_domains("国家惠民补贴申领中心") == []   # 虚构机构查不到


# ---------------------------------------------------------------- 自称抽取


def test_fake_site_id_is_detected():
    html = _page(
        head='<div class="gov-header">中华人民共和国财政部 · 国家税务总局</div>',
        body='<div class="gov-footer">© 2026 中华人民共和国财政部 · 政府网站标识码：bm01000001</div>',
        title="2026年个人财政补贴申领",
    )
    r = analyze_html(html, "np4w53.cn")
    assert r.verdict == "fake_site_id"
    assert r.site_id == "bm01000001"
    assert r.level == 4


def test_same_site_id_on_gov_domain_is_legit():
    html = _page(
        body="<div>© 中国政府网 · 政府网站标识码：bm01000001</div>",
        title="中国政府网",
    )
    r = analyze_html(html, "www.gov.cn")
    assert r.verdict != "fake_site_id"


def test_impersonation_uses_official_domain():
    html = _page(
        body='<div class="audit">审核机构 国务院办公厅</div>',
        title="中稀同心 - 惠民资金审核记录表",
    )
    r = analyze_html(html, "s.qka91.com")
    assert r.verdict == "impersonation"
    assert r.official_domains


def test_footer_friend_links_are_not_self_claim():
    """红十字会页脚是友情链接列表，不能算「自称财政部」。"""
    html = _page(
        body=(
            '<div>© 中国红十字会 版权所有</div>'
            '<div>友情链接：<a href="#">财政部</a> <a href="#">民政部</a> '
            '<a href="#">国家税务总局</a></div>'
        ),
        title="中国红十字会",
    )
    r = analyze_html(html, "www.redcross.org.cn")
    assert r.verdict == "neutral"


def test_body_citation_is_not_self_claim():
    """正文里「据农业农村部消息」不是自称。"""
    html = _page(
        body=(
            "<div>中南大学乡村振兴研究中心</div>"
            "<div>据农业农村部消息，今年将继续推进乡村振兴重点工作，"
            "具体安排已在国务院常务会议审议通过。</div>"
        ),
        title="中南大学乡村振兴研究中心网站",
    )
    r = analyze_html(html, "xczx.csu.edu.cn")
    assert r.verdict in ("neutral", "legit")


def test_normal_site_has_no_claim():
    html = _page(
        body='<div>© 2026 快服科技 版权所有 粤ICP备12345678号</div>',
        title="客服系统_在线客服系统",
    )
    r = analyze_html(html, "www.53kf.com")
    assert r.verdict == "neutral"
    assert r.agencies == []


def test_media_host_is_legit():
    html = _page(body="<div>© 人民网 版权所有</div>", title="人民网")
    r = analyze_html(html, "www.people.com.cn")
    assert r.verdict == "legit"
    assert r.is_media_host


# ---------------------------------------------------------------- 分级


def _asset(host: str, score: float = 0.0) -> Asset:
    return Asset(kind="domain", value=host, normalized=host, tier="candidate", score=score, meta={})


def test_triage_fake_site_id_goes_watch():
    a = _asset("np4w53.cn")
    a.score = 95.0
    d = triage.decide(a, facts={"claim": {"verdict": "fake_site_id", "site_id": "bm01000001"}})
    assert d.tier == "watch"
    assert d.urgent is True
    assert "bm01000001" in d.reasons[0]


def test_triage_impersonation_goes_watch():
    a = _asset("s.qka91.com")
    d = triage.decide(
        a,
        facts={"claim": {"verdict": "impersonation", "agencies": ["财政部"],
                         "official_domains": {"财政部": ["mof.gov.cn"]}}},
    )
    assert d.tier == "watch"
    assert "mof.gov.cn" in d.reasons[0]


def test_triage_legit_goes_cold():
    """白名单命中不该占据待处理队列前排。"""
    a = _asset("www.gov.cn")
    d = triage.decide(a, facts={"claim": {"verdict": "legit"}})
    assert d.tier == "cold"


def test_triage_neutral_keeps_score_logic():
    a = _asset("www.example.com")
    d = triage.decide(a, facts={"claim": {"verdict": "neutral"}})
    assert d.tier in ("cold", "candidate")


# ---------------------------------------------------------------- 评分叠加


def test_fake_site_id_dominates_keyword_score():
    from silver_sentinel.scoring.reassess import assess_now

    a = _asset("np4w53.cn")
    claim = {"verdict": "fake_site_id", "site_id": "bm01000001", "agencies": [], "official_domains": {}}
    assessment, _ = assess_now(a, facts={"claim": claim}, text="")
    assert assessment.score >= 95.0
    assert assessment.verdict == "high_risk"
    assert any(s.rule_id == "IMP-001" for s in assessment.signals)


def test_legit_caps_score():
    from silver_sentinel.scoring.reassess import assess_now

    a = _asset("www.mof.gov.cn")
    claim = {"verdict": "legit", "agencies": ["财政部"], "official_domains": {"财政部": ["mof.gov.cn"]}}
    assessment, _ = assess_now(a, facts={"claim": claim}, text="")
    assert assessment.score <= 20.0
