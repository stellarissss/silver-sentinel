"""域名形态学：把「批量生成的随机串」从每天几十万个 CT 记录里挑出来。

这一层存在的理由
----------------
词库只认「域名里写了什么」。而涉老站群的域名是批量生成的：

    np4w53.cn   hksm38.com.cn   l4k9j.com.cn   m5w1p.com.cn

`np4w53` 去掉数字只剩 `npw`，`hksm38` 去掉数字是四个辅音——任何中文词根、
拼音、英文词表都命不中。它们共享的不是词，是**生成器**：短、无音节、字母
与数字混排。

测试的重点不是「分数准不准」，而是：
1. 真站群能被挑出来（否则 CT 层永远是 0 召回）；
2. 正规站不会被误挑（否则每天几千个噪声进池，等于没筛）。
"""

from __future__ import annotations

import pytest

from silver_sentinel.discover.morph import ABUSED_TLDS, assess, is_random_label

# 已取证确认为涉老诈骗的域名（同一模板、同一服务器）
CAMP = [
    "np4w53.cn",
    "hksm38.com.cn",
    "l4k9j.com.cn",
    "m5w1p.com.cn",
    "s.qka91.com",
    "mz80h.cn",
    "xc16.cc",
]

# 正规站与合法业务域名
LEGIT = [
    "baidu.com",
    "gov.cn",
    "taobao.com",
    "alipay.com",
    "weixin.qq.com",
    "huicetong.com.cn",     # 惠策通
    "xindazx.cn",           # 新大咨询
    "laoweimin.cn",         # 老魏民
    "yiliaogsp.com",
    "ryylchina.com",        # 贵阳养老院
    "winstep.cc",
    "huanlelingjidanxiazai.asia",
]


@pytest.mark.parametrize("host", CAMP)
def test_campaign_domains_score_high(host: str):
    """站群域名必须过门槛。实测 0.74~0.92。"""
    assert assess(host).score >= 0.62, f"{host} 被漏掉了：{assess(host).as_dict()}"


@pytest.mark.parametrize("host", LEGIT)
def test_legit_domains_score_low(host: str):
    """正规站必须被压下去。实测 ≤0.31。"""
    assert assess(host).score < 0.55, f"{host} 误报：{assess(host).as_dict()}"


def test_camp_and_legit_are_separable():
    """两组之间要有明显间隔，不能靠调阈值硬凑。"""
    camp = min(assess(h).score for h in CAMP)
    legit = max(assess(h).score for h in LEGIT)
    assert camp - legit >= 0.3, f"间隔太小：camp={camp:.2f} legit={legit:.2f}"


def test_subdomain_uses_apex_label():
    """s.qka91.com 的形态要看 qka91，不是看子域 s。"""
    assert assess("s.qka91.com").label == "qka91"
    assert assess("s.qka91.com").score > 0.6


def test_service_labels_are_ignored():
    """api.com / cdn.cn 这种「服务名当域名」的，不按随机串处理。"""
    for host in ("api.com", "cdn.cn", "m.top"):
        assert assess(host).score == 0.0
        assert "服务标签" in assess(host).reasons


def test_www_prefix_does_not_change_verdict():
    """www.np4w53.cn 要跟 np4w53.cn 同分——子域不改变命名形态。"""
    assert assess("www.np4w53.cn").score == assess("np4w53.cn").score


def test_hyphenated_domains_are_penalized():
    """带连字符的多是正常项目名（my-shop、hello-world）。"""
    assert assess("rong-guangdong.com").score < 0.2


def test_pure_letter_long_labels_score_zero():
    """长纯字母域名不可能是生成器输出。"""
    for host in ("huicetong.com.cn", "laoweimin.cn"):
        assert assess(host).score == 0.0


def test_abused_tld_gets_small_boost_only():
    """后缀只影响排序，不能靠 .top 就把分顶上去。"""
    assert "top" in ABUSED_TLDS
    same_label_top = assess("d2k9f.top").score
    same_label_com = assess("d2k9f.com").score
    assert same_label_top > same_label_com
    assert same_label_top - same_label_com <= 0.1


def test_empty_and_garbage_input():
    assert assess("").score == 0.0
    assert assess("localhost").score < 0.6
    assert assess("...").score == 0.0


def test_is_random_label_helper_matches_threshold():
    assert is_random_label("np4w53")
    assert not is_random_label("laoweimin")
