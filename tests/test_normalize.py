"""规范化与指标抽取。"""

from __future__ import annotations

import pytest

from silver_sentinel.normalize import (
    brand_lookalike,
    extract_indicators,
    is_free_hosting,
    is_shortener,
    levenshtein,
    luhn_ok,
    normalize_domain,
    normalize_url,
    registrable_domain,
    shingle_hash,
)


def test_normalize_url_strips_tracking_params():
    url, host = normalize_url("HTTP://KuaiShou-YinFa.TOP:80/reg/?utm_source=wx&invite=888&spm=a1#top")
    assert host == "kuaishou-yinfa.top"
    assert "utm_source" not in url
    assert "spm" not in url
    assert "invite=888" in url
    assert url.startswith("http://kuaishou-yinfa.top/")


def test_normalize_url_keeps_meaningful_query_sorted():
    url, _ = normalize_url("https://a.com/x?b=2&a=1")
    assert url.endswith("a=1&b=2")


def test_normalize_domain_variants():
    assert normalize_domain("https://WWW.Example.COM/path?x=1") == "www.example.com"
    assert normalize_domain(" example.com ") == "example.com"


@pytest.mark.parametrize(
    "host,expected",
    [
        ("a.b.com.cn", "b.com.cn"),
        ("sub.example.com", "example.com"),
        ("example.com", "example.com"),
        ("x.co.uk", "x.co.uk"),
    ],
)
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_shortener_and_free_hosting():
    assert is_shortener("t.cn")
    assert is_shortener("http://dwz.cn/abc")
    assert not is_shortener("example.com")
    assert is_free_hosting("scam.vercel.app")
    assert not is_free_hosting("example.com")


def test_extract_indicators_covers_chinese_contact_channels():
    text = """
    领鸡蛋加微信：laoren_fuli88，QQ群 123456789，
    电话 13812345678，客服 010-88886666。
    充值地址 TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE
    银行卡 6222020200112233445
    下载 apk 包名 com.guohui.minsheng
    网址 https://guohui-minsheng.top/reg?invite=1
    """
    data = extract_indicators(text)

    assert "13812345678" in data["phones"]
    assert "laoren_fuli88" in data["wechat"]
    assert "123456789" in data["qq"]
    assert any(w.startswith("T") for w in data["wallets"])
    assert "com.guohui.minsheng" in data["apk_packages"]
    assert any("guohui-minsheng.top" in u for u in data["urls"])


def test_phone_not_matched_inside_long_digits():
    data = extract_indicators("订单号 1381234567890123 已完成")
    assert "13812345678" not in data["phones"]


def test_luhn_validation():
    assert luhn_ok("6222020200112233445") in (True, False)  # 结构校验不抛错
    assert luhn_ok("4111111111111111") is True
    assert luhn_ok("4111111111111112") is False


def test_brand_lookalike_detects_variants():
    brands = {"kuaishou", "alipay"}
    hit = brand_lookalike("kuaishou-yinfa.top", brands)
    assert hit and hit[0] == "kuaishou"
    assert brand_lookalike("kuaishou.top", brands) is None  # 完全一致交给其他信号
    assert brand_lookalike("alipav.com", brands) is not None


def test_levenshtein():
    assert levenshtein("kuaishou", "kuaishou") == 0
    assert levenshtein("kuaishou", "kuaishuo") == 2


def test_shingle_hash_is_stable_and_discriminating():
    a = shingle_hash("国家惠民补贴 领取养老补贴 下载注册 邀请好友")
    b = shingle_hash("国家惠民补贴 领取养老补贴 下载注册 邀请好友")
    c = shingle_hash("今日天气晴朗 适合出门散步")
    assert a == b
    assert a != c
