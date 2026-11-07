"""误报护栏：这些页面的字面特征和骗局高度重合，但业务上完全无关。

线上实测过三次同型误报，都是「正规商业页面 + 通用运营词」被推进自动盯防：

1. 微信投票 SaaS（weixin100.com.cn）——页面写「高效引流方案」「专属客服」，
   「引流」当时在 scam_signature 簇里，KW-001 直接给 26 分；
2. 同一页面还命中 CT-006（引导至私域）——因为规则写的是「客服 + 微信」同现，
   而任何微信生态服务商都会同时出现这两个词；
3. 成人内容站（dou-yin.org）——仿品牌域名 + 引导下载 APK + 未备案，
   三组结构特征把分数推到 57，但它和涉老诈骗没有关系。

三条护栏各自独立，改动其中一条不应该把另一条弄坏，所以分四个用例钉住。
"""

from __future__ import annotations

import pytest

WEIXIN_VOTE_SAAS = (
    "微信投票活动页面精美，操作步骤简单3分钟完成投票活动创建。"
    "关注公众号投票，系统提供快速增粉，高效引流方案。"
    "专属客服服务，快速响应，优秀的网络投票系统。"
    "免费创建微信投票活动，验证码防刷，IP 限制，GPS 地址位置限制。"
)

ADULT_APK_SITE = (
    "抖阴APP官方下载入口。抖阴短视频在线播放平台，午夜影院级体验，"
    "支持抖阴安卓版、抖阴iOS版。热门 福利姬 女神性感裸舞 极致诱惑。"
    "成人在线视频 无码 人妻 偷拍。邀请好友下载，拉新奖励，层级分红。"
)


def _assess(host: str, text: str, **facts):
    """不带数据库，直接跑一遍重评用的纯计算入口。"""
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import assess_now

    asset = Asset(kind="domain", value=host, normalized=host, meta={"facts": dict(facts)})
    asset.reviewed_by = None
    return assess_now(asset, text=text)


def _rule_ids(result) -> set[str]:
    return {s.rule_id for s in result.signals}


def test_vote_saas_does_not_hit_scam_signature():
    """「引流」是运营通用词，不能再让 KW-001 起火。"""
    result, merged = _assess(
        "weixin100.com.cn", WEIXIN_VOTE_SAAS, icp_registered=False, brand_lookalike=True
    )
    assert "scam_signature" not in (merged.get("keyword_clusters") or [])
    assert "sales_jargon" in (merged.get("keyword_clusters") or [])
    assert "KW-001" not in _rule_ids(result)


def test_vote_saas_not_pushed_into_watch():
    """带未备案 + 品牌相似域名这些真信号，也只能停在可疑档，不到自动盯防。"""
    result, _ = _assess(
        "weixin100.com.cn", WEIXIN_VOTE_SAAS, icp_registered=False, brand_lookalike=True
    )
    assert result.score < 40, f"{result.score} 已进入高可疑区间：{sorted(_rule_ids(result))}"


def test_customer_service_plus_wechat_is_not_private_domain():
    """客服与微信同现只是微信生态服务商的常态，不构成「引导至私域」。"""
    plain, _ = _assess("vote.example.com", "专属客服服务，关注公众号投票，微信投票系统")
    assert "CT-006" not in _rule_ids(plain)

    action, _ = _assess("scam.example.com", "详情请加微信 abc123 咨询，客服在线")
    assert "CT-006" in _rule_ids(action), "真实引流动作必须仍然命中"


def test_adult_site_is_off_topic_and_stays_below_watch():
    """成人内容站按主题无关处理：只留结构特征，内容信号一律不采信。"""
    from silver_sentinel.scoring.engine import detect_off_topic

    assert detect_off_topic(ADULT_APK_SITE) == "adult"

    result, merged = _assess("dou-yin.org", ADULT_APK_SITE, icp_registered=False, brand_lookalike=True)
    assert merged.get("off_topic") == "adult"
    assert result.score < 40, f"{result.score} 仍会被自动盯防：{sorted(_rule_ids(result))}"


def test_elder_scam_with_adult_words_is_not_exempted():
    """躲进成人词里不管用：出现涉老定性词就不再走主题豁免。"""
    from silver_sentinel.scoring.engine import detect_off_topic

    mixed = ADULT_APK_SITE + "顺便推广国家养老补贴，免费领取鸡蛋，专家讲座报名。"
    assert detect_off_topic(mixed) == ""


@pytest.mark.parametrize("jargon", ["引流", "转化", "复购", "讲师", "区域经理"])
def test_sales_jargon_never_counts_as_strong_cluster(jargon: str):
    """这些词一个都不能留在强簇里，否则任意 SaaS 页面都能被推成骗局特征。"""
    from silver_sentinel.discover.keywords import get_library

    match = get_library().match_text(f"我们提供{jargon}方案，助力企业增长")
    clusters = {h.cluster for h in match.hits if h.term == jargon}
    assert clusters == {"sales_jargon"}
