"""涉老判定：这个站是不是在骗老人的钱。

测的不是「分高不高」，而是四个真实样本进去、四种结论出来：

    np4w53 / hksm38   伪造财政补贴申领   → P0（受众+身份+权威+动作）
    nuanyang          智慧养老服务平台   → P0（受众+权威+APK）
    s.qka91           惠民资金审核表     → 涉老（受众+权威）
    某养老院官网       正规机构           → 不涉老
    泰文赌场           博彩               → 不涉老

最后两条是反向约束：没有它们，把词表堆满「养老/补贴」也能过前面的用例。
"""

from __future__ import annotations

from silver_sentinel.elder import assess

NP4W53_TEXT = """
2026年个人财政补贴申领
财政部 国家税务总局 国家市场监督管理总局
政府网站标识码 1100000001
本次补贴为一次性发放，请如实填写以下信息
姓名 身份证号 银行卡号 手机验证码
剩余名额 37 个 倒计时 04:59:59 立即领取
"""

NUANYANG_TEXT = """
中国老龄康养 - 智慧养老服务平台 | 国家民政部 · 卫健委 主导建设
面向全国 60 岁以上老年人提供康养服务登记
下载安装 APP 完成实名认证
"""

QKA91_TEXT = """
中稀同心 - 中国稀土 惠民资金审核记录表
国务院办公厅审核
请填写申请人信息以便核验
"""

BENIGN_TEXT = """
北京市朝阳区某养老院 - 收费标准及护理服务
本院成立于 2008 年，床位 200 张，提供生活照料、康复护理、文化娱乐服务。
联系我们：010-8888xxxx 地址：朝阳区某路 88 号
"""

CASINO_TEXT = """
mz88 สล็อตออนไลน์รวมทุกค่าย คาสิโนยอดนิยม
เข้าสู่ระบบ สมัครสมาชิก โปรโมชั่น
แจ็คพอตล่าสุด ถอนเงิน
"""


def test_fake_subsidy_page_is_p0():
    facts = {
        "claim": {"verdict": "fake_site_id", "site_id": "1100000001",
                  "agencies": ["财政部", "国家税务总局"]},
        "features": {"id_inputs": 2},
    }
    sig = assess(facts, NP4W53_TEXT)
    assert sig.is_elder and sig.priority == "P0"
    assert sig.hits["identity"] and sig.hits["authority"] and sig.hits["action"]


def test_pension_platform_with_apk_is_p0():
    facts = {
        "claim": {"verdict": "impersonation", "agencies": ["民政部"]},
        "apk_links": ["https://x/1.apk"],
    }
    sig = assess(facts, NUANYANG_TEXT)
    assert sig.is_elder and sig.priority == "P0"


def test_unfreeze_scheme_is_elder_but_not_p0():
    """只有受众 + 权威，没有身份索取和动作：涉老，但证据不够 P0。"""
    facts = {"claim": {"verdict": "impersonation", "agencies": ["国务院办公厅"]}}
    sig = assess(facts, QKA91_TEXT)
    assert sig.is_elder
    assert sig.priority == "P1"


def test_real_nursing_home_is_not_elder():
    """正规养老院满页都是「养老」「护理」「收费」，但它不要身份证、不冒充部委。"""
    sig = assess({"claim": {"verdict": "neutral"}}, BENIGN_TEXT)
    assert not sig.is_elder
    assert sig.reason == "只有受众指向，缺证据"


def test_casino_is_not_elder():
    sig = assess({}, CASINO_TEXT)
    assert not sig.is_elder
    assert sig.reason == "无受众指向"


# ---------------------------------------------------------------- 分级联动


def _asset_with(facts: dict):
    from silver_sentinel.models import Asset

    a = Asset(kind="domain", value="np4w53.cn", normalized="np4w53.cn",
              tier="candidate", score=60.0, verdict="suspicious", meta={"facts": facts})
    return a


def test_elder_p0_goes_straight_to_watch():
    from silver_sentinel import triage

    facts = {
        "claim": {"verdict": "neutral"},
        "elder": {"elder": True, "priority": "P0", "reason": "受众+身份+权威",
                  "hits": {"audience": ["补贴"], "identity": ["身份证"]}},
    }
    d = triage.decide(_asset_with(facts))
    assert d.tier == "watch" and d.urgent


def test_purpose_gate_cannot_suppress_elder_target():
    """涉老诈骗的落地页结构上就是 landing，用途闸门会把它判成经营型。
    这条闸门必须排在涉老之后——否则等于把目标本身筛掉。"""
    from silver_sentinel import triage

    facts = {
        "claim": {"verdict": "neutral"},
        "purpose": {"purpose": "landing", "suppressed": True,
                    "confidence": 0.95, "suppressed_reason": "落地页"},
        "elder": {"elder": True, "priority": "P0", "reason": "四要素", "hits": {}},
    }
    d = triage.decide(_asset_with(facts))
    assert d.tier == "watch", "用途闸门不能把涉老站降到冷存/候选"


def test_elder_p1_never_falls_to_cold():
    from silver_sentinel import triage

    a = _asset_with({"elder": {"elder": True, "priority": "P1", "reason": "受众+权威"}})
    a.score = 3.0
    a.verdict = "insufficient"
    d = triage.decide(a)
    assert d.tier != "cold"


def test_marketing_page_with_free_gift_is_not_elder():
    """「免费领取」是营销动作，不是受众指向。

    线上误报：baidu-ads.com（百度广告代理商）因为页面写了
    「免费咨询 / 推广 App / 限时优惠」，被判成「涉老 P1」。
    受众词必须是「这是给谁的」，不能是「怎么做」。
    """
    text = "百度广告全方位代运营 免费咨询 推广App 促进销量 限时优惠 免费领取方案白皮书"
    sig = assess({}, text)
    assert not sig.is_elder
    assert sig.reason == "无受众指向"


def test_audience_plus_marketing_action_is_not_enough():
    """「养老 + 免费领取 + 立即下载」是营销页的通用写法。

    线上误报：tuiyijunren.cn（正规退役军人资讯站）被判「涉老 P1」。
    涉老必须有冒充权威或索取身份——正常机构不会做这两件事。
    """
    text = "退役军人养老政策解读 免费领取政策汇编 立即下载 App 限时"
    sig = assess({}, text)
    assert not sig.is_elder
    assert "缺冒充或身份索取" in sig.reason


def test_audience_plus_authority_is_elder():
    """有冒充就算——不需要动作配合。"""
    text = "智慧养老服务平台 国家民政部 卫健委 主导建设"
    sig = assess({"claim": {"verdict": "impersonation", "agencies": ["民政部"]}}, text)
    assert sig.is_elder


def test_mentioning_id_card_in_a_guide_is_not_identity_theft():
    """办事指南写「带身份证」不是索取身份。"""
    text = "退役军人优待证办理指南：请携带身份证、退役证到户籍所在地服务站办理"
    sig = assess({}, text)
    assert not sig.hits["identity"], sig.hits["identity"]

    theft = "请填写身份证号、银行卡号并输入短信验证码完成核验"
    sig2 = assess({}, theft)
    assert sig2.hits["identity"]


def test_quoting_a_ministry_is_not_impersonation():
    """正文引用部委政策 ≠ 冒充部委。

    线上误报：tuiyijunren.cn 正文写「根据民政部、退役军人事务部有关规定」，
    被判「涉老 P1」。只有写成「本项目由民政部主导建设」才算。
    """
    quote = "根据民政部有关规定，退役军人可申请养老优待。政策解读如下。"
    assert not assess({}, quote).hits["authority"]

    claim = "本平台由民政部、卫健委主导建设，请实名登记。"
    assert assess({}, claim).hits["authority"]


def test_login_page_describing_sms_code_is_not_identity_theft():
    """「登录入口支持账号密码、短信验证码」是功能说明，不是索取。

    线上误报：meituanshangjiabandenglurukou.shop（仿冒美团商家版）。
    它是钓鱼站，但判据不该靠「录入」误匹配「登录入口」的「录入」两个字。
    """
    text = "美团商家版 官方登录入口 登录入口支持账号密码、短信验证码等多种验证方式"
    assert not assess({}, text).hits["identity"]
