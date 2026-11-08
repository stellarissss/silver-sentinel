"""同源折叠：把「同一批东西」收成一行。

两条约束：

1. **不能错组**。共享主机上住着几百个无关的站，按 IP 聚合会造出假团伙。
   所以这里没有 IP 分组，且通用标题（首页/登录/404）一律不成组。
2. **不能丢信息**。折叠是视图，不是合并——组里每一条的 id 都还在，
   点开能进详情，证据包照样逐条导出。
"""

from __future__ import annotations

from silver_sentinel import grouping


def test_year_is_ignored_in_title():
    """线上 81 条标题只差年份，归一化后必须一致，否则一组都折不起来。"""
    a = grouping.normalize_title("2026年个人财政补贴申领")
    b = grouping.normalize_title("2025年个人财政补贴申领")
    assert a == b == "个人财政补贴申领"


def test_same_template_groups_together():
    k1, kind1, label1 = grouping.compute(
        kind="url", value="https://a.cn/",
        meta={"web_observation": {"title": "2026年个人财政补贴申领"}},
        facts={"features": {"text_len": 900}},
    )
    k2, kind2, _ = grouping.compute(
        kind="url", value="https://b.cn/",
        meta={"web_observation": {"title": "2027年个人财政补贴申领"}},
        facts={"features": {"text_len": 1200}},
    )
    assert k1 and k1 == k2
    assert kind1 == kind2 == "template"
    assert "个人财政补贴申领" in label1


def test_generic_titles_do_not_group():
    """「首页」「登录」「404」没有区分度，按标题折叠会把半个互联网收成一组。"""
    for title in ("首页", "登录", "404 Not Found", "安全检测", "Loading"):
        key, _, _ = grouping.compute(
            kind="url", value="https://x.cn/",
            meta={"web_observation": {"title": title}},
            facts={"features": {"text_len": 500}},
        )
        assert key == "", title


def test_short_title_does_not_group():
    key, _, _ = grouping.compute(
        kind="url", value="https://x.cn/",
        meta={"web_observation": {"title": "补贴"}},
        facts={"features": {"text_len": 500}},
    )
    assert key == ""


def test_short_and_long_text_are_different_templates():
    """标题相同但一个是 12 字空壳、一个是 3000 字长文，不可能是同一套模板：
    前者是诱饵，后者是内容页。"""
    k1, _, _ = grouping.compute(
        kind="url", value="https://a.cn/",
        meta={"web_observation": {"title": "惠民补贴申领"}},
        facts={"features": {"text_len": 80}},
    )
    k2, _, _ = grouping.compute(
        kind="url", value="https://b.cn/",
        meta={"web_observation": {"title": "惠民补贴申领"}},
        facts={"features": {"text_len": 2400}},
    )
    assert k1 != k2


def test_cert_beats_template():
    cert = {"serial": "0A1B", "issuer": "CN=LiteSSL", "subject": "CN=np4w53.cn",
            "dns_count": 91, "dns_names": ["a.cn", "b.cn"]}
    key, kind, label = grouping.compute(
        kind="domain", value="np4w53.cn", meta={}, facts={"cert": cert}
    )
    assert key.startswith("cert:")
    assert kind == "cert"
    assert "91" in label


def test_cert_without_serial_does_not_group():
    """拿不到序列号就没有「同一张证书」的把握。宁可不成组，也不要错组。"""
    key, _, _ = grouping.compute(
        kind="domain", value="x.cn", meta={},
        facts={"cert": {"issuer": "CN=LiteSSL", "subject": "CN=x.cn"}},
    )
    assert key == ""


def test_backend_beats_template():
    key, kind, label = grouping.compute(
        kind="url", value="https://a.cn/",
        meta={"web_observation": {"title": "2026年个人财政补贴申领"}},
        facts={"backend_hosts": ["d7k2m.cn"], "features": {"text_len": 800}},
    )
    assert key == "backend:d7k2m.cn"
    assert kind == "backend"
    assert "d7k2m.cn" in label


def test_campaign_has_highest_priority():
    key, kind, _ = grouping.compute(
        kind="url", value="https://a.cn/",
        meta={"campaign_id": 7, "web_observation": {"title": "2026年个人财政补贴申领"}},
        facts={"backend_hosts": ["d7k2m.cn"]},
    )
    assert key == "campaign:7"
    assert kind == "campaign"


def test_group_row_picks_highest_scoring_member():
    members = [
        {"id": 1, "value": "a.cn", "score": 95.0, "tier": "watch", "verdict": "high_risk"},
        {"id": 2, "value": "b.cn", "score": 42.0, "tier": "candidate", "verdict": "suspicious"},
        {"id": 3, "value": "c.cn", "score": 88.0, "tier": "confirmed", "verdict": "confirmed"},
    ]
    row = grouping.group_row(key="template:x", kind="template", label="同模板", members=members)
    # 代表行取「档位最高」的：已确认那条即使分数不是最高，也最该被看见
    assert row["id"] == 3
    assert row["group"]["size"] == 3
    assert row["group"]["max_score"] == 95.0
    assert [m["id"] for m in row["group"]["members"]] == [3, 1, 2]
