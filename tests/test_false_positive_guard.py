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


ACCELERATOR_SITE = (
    "uu加速器无限试用 绿灯加速器 下载 安卓 苹果 排行 小蜜蜂加速器站长 "
    "instagram加速器软件 雷霆加速官网 起飞加速器免费版下载 免费vps加速器外网 "
    "猎豹加速器网页版登录 苹果免费加速期 怎么浏览外网新闻 极光加速器官网下载最新版 "
    "加速器免费使用一天 黑洞加速器apk"
)


def test_accelerator_site_is_off_topic_and_stays_below_watch():
    """翻墙工具聚合站与涉老诈骗无关。

    线上案例 gongxiaoshe88.com：域名拼音撞上「供销社」，正文是加速器下载站，
    旧规则给 51.2 分直接进 watch。它的违法点（未备案、分发 APK）与目标人群
    都不在涉老范畴，按主题无关处理，只留结构特征。
    """
    from silver_sentinel.scoring.engine import detect_off_topic

    assert detect_off_topic(ACCELERATOR_SITE) == "accelerator"

    result, merged = _assess(
        "gongxiaoshe88.com", ACCELERATOR_SITE, icp_registered=False, brand_lookalike=True
    )
    assert merged.get("off_topic") == "accelerator"
    assert result.score < 40, f"{result.score} 仍会被自动盯防：{sorted(_rule_ids(result))}"


def test_authority_term_alone_cannot_reach_watch():
    """机构名单独出现不能把资产推进 watch，必须配上政策/涉老话术。"""
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import assess_now
    from silver_sentinel.triage import decide

    shell, _ = _assess("gongxiaoshe88.com", "供销社 官网 系统 网站 应用 中心 平台")
    assert "KW-001" not in _rule_ids(shell)
    assert "KW-004" in _rule_ids(shell)

    asset = Asset(
        kind="domain",
        value="minzheng-buttie.com",
        normalized="minzheng-buttie.com",
        meta={"facts": {"icp_registered": False}},
    )
    asset.reviewed_by = None
    real, merged = assess_now(
        asset,
        text=(
            "民政局 高龄津贴 申领中心 面向 60 岁以上老人发放养老补贴，"
            "免费领取鸡蛋，登记信息即可，专家讲座报名"
        ),
    )
    assert "KW-001" in _rule_ids(real), "机构名 + 政策 + 涉老话术必须升级为强信号"
    # 分数差一点点也要进盯防：冒充 × 说服的结构组合比加权分可靠
    asset.score = real.score
    asset.verdict = real.verdict
    assert decide(asset, facts=merged).tier == "watch"


GAMBLING_SITE = (
    "平台优惠彩金申请 当日娱乐 次日领取优惠彩金 超级救援金 电子游艺 视讯大闯关 "
    "请各位会员按照活动要求完成有效投注后 于次日联系在线客服进行彩金领取 "
    "滴滴棋牌 存款未到账 提款未到账 码商 备用网址 开元棋牌 补偿彩金"
)


def test_gambling_cluster_is_off_topic_and_stays_below_watch():
    """跨境赌博站群与涉老诈骗不同主题。

    线上实测：didi3663/didi8398/didi2758… 一次进来 20 个同模板域名，
    正文是「彩金、有效投注、存提款、备用网址」，靠「退款客服 + 支付宝背书
    + 未备案」堆到 42.9 分，长期占据候选池前排。它们该靠域名/证书/收款
    地址建图去关联，而不是靠内容评分抢盯防位。
    """
    from silver_sentinel.scoring.engine import detect_off_topic

    assert detect_off_topic(GAMBLING_SITE) == "gambling"

    result, merged = _assess(
        "didi3663.com", GAMBLING_SITE, icp_registered=False, brand_lookalike="didi"
    )
    assert merged.get("off_topic") == "gambling"
    assert result.score < 40, f"{result.score} 仍在候选池前排：{sorted(_rule_ids(result))}"


def test_parked_domain_page_is_off_topic():
    """待售/停放域名是候选池里最常见的噪声，按页面类型直接豁免。"""
    from silver_sentinel.scoring.engine import detect_off_topic

    parked = (
        "可售/This domain name is for sale 联系邮箱 AI音乐市场规模及 douyinyue.com 应用场景 "
        "douyinyue.com 是专注于AI音乐服务的专业平台 联系邮箱 微信：apples_cn Buy"
    )
    assert detect_off_topic(parked) == "parked"

    result, merged = _assess("douyinyue.com", parked, icp_registered=False)
    assert merged.get("off_topic") == "parked"
    assert result.score < 30, f"{result.score} 仍被当成涉诈线索：{sorted(_rule_ids(result))}"


def test_growth_hacking_copy_is_not_private_domain():
    """「快速加粉，玩转微信营销」是营销文案，不是把人拉进私域。"""
    copy, _ = _assess(
        "vote.example.com",
        "公众号投票链接怎么做，系统提供快速增粉，高效引流方案，让你玩转微信营销活动",
    )
    assert "CT-006" not in _rule_ids(copy)

    real, _ = _assess("scam.example.com", "详情请加我微信 abc12345，老师一对一指导")
    assert "CT-006" in _rule_ids(real)
