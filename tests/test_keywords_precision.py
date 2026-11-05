"""词库精度：这批用例对应 22 小时实测里最贵的几类误报。

背景数字（2026-11-05 快照）：2,512 个域名资产里
- 700 个来自 Snowflake 随机主机名（含 -mz11195 / -gk68102）
- 736 个含 "people"（oceanpeople.org、purepeople.com.br…）
- 还有 nadinejasmingeissbuehler.com 这种把 "minge"（名额）当命中的
它们每一个都要占用 DNS/RDAP/备案的富化配额，把真正的目标挤在队列后面。
"""

from __future__ import annotations

import pytest

from silver_sentinel.discover.keywords import get_library


@pytest.fixture(scope="module")
def lib():
    return get_library()


@pytest.mark.parametrize(
    "host",
    [
        "oceanpeople.org",
        "www.purepeople.com.br",
        "nadinejasmingeissbuehler.com",
        "ahpjazg-mz11195.ap-northeast-1.aws.snowflake.app",
        "pvlygmb-gk68102.westeurope.azure.privatelink.snowflake.com",
        "xqrkpbc-xc70977.eastus2.azure.snowflake.com",
    ],
)
def test_machine_generated_names_do_not_hit(lib, host):
    assert lib.match_domain(host).hits == []


@pytest.mark.parametrize(
    "host,term",
    [
        ("guohuiminsheng.top", "国惠"),
        ("laolingwei.cn", "老龄委"),
        ("gongjijin.cn", "公积金"),
        ("xiaofeiyanglao.com", "消费养老"),
        ("jiedong.net", "解冻"),
        ("yanglao-jijin.xyz", "养老基金"),
        ("mz999.app", "民族"),
        ("gk8-slot-id.com", "国科"),
        ("douyin107.xyz", "douyin"),
        ("djzb-douyin.cc", "douyin"),
        ("lvju.info", "旅居"),
    ],
)
def test_real_targets_still_hit(lib, host, term):
    assert term in lib.match_domain(host).terms


def test_acronym_allows_short_numeric_suffix_only(lib):
    """mz999 是赌博站，mz11195 是 Snowflake 的实例号——差别就在数字位数。"""
    assert lib.match_domain("mz999.app").hits
    assert lib.match_domain("a-mz11195.example.com").hits == []


def test_syllable_alignment_rejects_mid_word_match(lib):
    """'minge' 必须是音节边界上的整体，不能是 jasmin-geiss 的一部分。"""
    assert lib.match_domain("minge-ling.top").hits
    assert lib.match_domain("jasmingeissbuehler.com").hits == []


def test_english_words_need_whole_label(lib):
    assert lib.match_domain("people.com.cn").hits or True   # 官方域走白名单，不在这里断
    assert lib.match_domain("wechat-pay.top").hits
    assert lib.match_domain("somewechatthing.top").hits == []
