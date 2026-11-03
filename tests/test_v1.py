"""v1.0 新增模块的测试。

覆盖重点不是「跑通」，而是「出错时会怎样」：
- 事件日志被篡改能否发现
- 词库对正常文本会不会误报
- 分级会不会把正常社区通知当诈骗
- 内网地址会不会被沙箱放行（SSRF）
- 图归并会不会把无关资产连成一伙
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from silver_sentinel.core.eventlog import EventLog, GENESIS
from silver_sentinel.discover.dnsprobe import SeedGenerator
from silver_sentinel.discover.keywords import KeywordLibrary, get_library
from silver_sentinel.enrich.icp import ICPResult, _iter_records, _pick
from silver_sentinel.enrich.registry import RegistryInfo, _parse_dt
from silver_sentinel.graph.schema import RELATION_WEIGHTS, edge_weight, node_key, parse_key
from silver_sentinel.models import TIER_CANDIDATE, TIER_COLD, TIER_CONFIRMED, TIER_WATCH, Asset
from silver_sentinel.sandbox.web import _is_private_host
from silver_sentinel.triage import decide


# ---------------------------------------------------------------- 事件日志


def test_eventlog_hash_chain_detects_tamper(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    for i in range(6):
        log.append("discovered", {"domain": f"n{i}.top"})
    log.close()

    reopened = EventLog(path)
    assert reopened.verify()["ok"] is True
    assert reopened.head()[0] == 6

    # 改写中间一行
    lines = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[2])
    row["payload"]["domain"] = "tampered.top"
    lines[2] = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = reopened.verify()
    assert result["ok"] is False
    assert result["broken_at_line"] == 3


def test_eventlog_detects_deleted_line(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    for i in range(5):
        log.append("x", {"i": i})
    log.close()

    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = EventLog(path).verify()
    assert result["ok"] is False
    assert "序号断裂" in result["reason"] or "前序哈希" in result["reason"]


def test_eventlog_resumes_sequence(tmp_path: Path):
    path = tmp_path / "events.jsonl"
    a = EventLog(path)
    a.append("a", {})
    a.close()
    b = EventLog(path)
    b.append("b", {})
    b.close()
    assert EventLog(path).verify()["checked"] == 2


# ---------------------------------------------------------------- 词库


def test_keyword_library_matches_pinyin_domains():
    lib = get_library()
    cases = {
        "guohui-minsheng.top": "国惠",
        "zhongke-nengyuan.com": "中科",
        "guokeyuan.top": "国科",
        "yanglao-jijin.xyz": "养老",
    }
    for domain, expect in cases.items():
        result = lib.match_domain(domain)
        assert result.score >= 0.4, f"{domain} 分数过低：{result.score}"
        assert any(expect in t for t in result.terms), f"{domain} 未命中 {expect}：{result.terms}"


def test_keyword_library_does_not_flag_benign():
    lib = get_library()
    for domain in ("xinyu-tech.com", "shenzhen-logistics.net", "example.org"):
        assert lib.match_domain(domain).score < 0.3, domain


def test_keyword_library_whitelists_government():
    lib = get_library()
    assert lib.is_whitelisted("www.gov.cn")
    assert lib.is_whitelisted("beian.miit.gov.cn")
    assert lib.is_whitelisted("taobao.com")
    # 伪造的「gov」域名不能被放行
    assert not lib.is_whitelisted("gov-cn-top.top")
    assert not lib.is_whitelisted("gov.cn.attacker.top")


def test_keyword_weak_terms_downgraded_without_strong_cluster():
    """「免费测血压」这类正常社区活动不应被当成诈骗。"""
    lib = get_library()
    benign = lib.match_text("本周六上午在社区服务中心免费测量血压，请携带身份证")
    scam = lib.match_text("国家惠民补贴发放中心：55岁以上老人凭身份证领取2万元养老补贴")
    assert benign.score < scam.score
    assert benign.score < 0.5


def test_keyword_library_stats_shape():
    stats = KeywordLibrary().stats()
    assert stats["terms"] > 300
    assert set(stats["by_cluster"]) >= {"authority", "scam_signature", "policy_theme"}


# ---------------------------------------------------------------- 分级


def _asset(**kw) -> Asset:
    base = dict(kind="domain", value="x.top", normalized="x.top", score=0.0,
                verdict="insufficient", tier=TIER_CANDIDATE, meta={})
    base.update(kw)
    return Asset(**base)


def test_triage_promotes_new_domain_with_hard_evidence():
    asset = _asset(score=55.0, verdict="high_risk")
    decision = decide(asset, facts={"domain_age_days": 3, "forces_apk_download": True})
    assert decision.tier == TIER_WATCH
    assert decision.urgent is True
    assert any("3 天" in r for r in decision.reasons)


def test_triage_confirms_only_on_official():
    confirmed = decide(_asset(score=95.0, verdict="confirmed"), facts={"official_listed": True})
    assert confirmed.tier == TIER_CONFIRMED

    # 机器最高只到 watch
    machine = decide(_asset(score=95.0, verdict="high_risk"), facts={})
    assert machine.tier == TIER_WATCH


def test_triage_downgrades_benign_text():
    asset = _asset(kind="text", value="社区通知", normalized="社区通知", score=0.0)
    decision = decide(asset, facts={})
    assert decision.tier == TIER_COLD


def test_triage_registered_site_is_not_auto_cleared():
    """有备案不代表清白——黑产也买壳公司。只降一档，不排除。"""
    asset = _asset(score=88.0, verdict="high_risk")
    asset.icp_status = "registered"
    asset.icp_entity = "某健康管理有限公司"
    decision = decide(asset, facts={"domain_age_days": 10})
    # 88 分仍然进 watch —— 备案是减分项，不足以抵消这么强的证据
    assert decision.tier == TIER_WATCH

    # 中等分 + 已备案才降档
    mid = _asset(score=56.0, verdict="high_risk")
    mid.icp_status = "registered"
    mid.icp_entity = "某健康管理有限公司"
    mid_decision = decide(mid, facts={"domain_age_days": 10})
    assert mid_decision.tier == TIER_CANDIDATE
    assert any("已备案" in r for r in mid_decision.reasons)


def test_triage_never_auto_downgrades_confirmed():
    from silver_sentinel.triage import apply

    asset = _asset(score=10.0, tier=TIER_CONFIRMED, verdict="insufficient")
    apply(asset, facts={})
    assert asset.tier == TIER_CONFIRMED


# ---------------------------------------------------------------- 图


def test_node_key_roundtrip():
    key = node_key("domain", "GuoHui.TOP")
    assert key == "domain:guohui.top"
    assert parse_key(key) == ("domain", "guohui.top")


def test_edge_weight_hierarchy():
    """共用证书必须比共用 IP 更能说明同源。"""
    assert edge_weight("SHARES_CERT") > edge_weight("RESOLVES_TO")
    assert edge_weight("USES_WALLET") > edge_weight("HOSTED_ON")
    assert edge_weight("UNKNOWN_REL") > 0


def test_all_relations_have_weights():
    for rel, (weight, _desc) in RELATION_WEIGHTS.items():
        assert 0 < weight <= 1.0, rel


# ---------------------------------------------------------------- 沙箱安全


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "10.1.2.3", "192.168.1.1", "169.254.169.254", "::1"],
)
def test_sandbox_blocks_private_hosts(host: str):
    assert _is_private_host(host) is True


@pytest.mark.parametrize("host", ["example.com", "8.8.8.8", "1.1.1.1"])
def test_sandbox_allows_public_hosts(host: str):
    assert _is_private_host(host) is False


def test_sandbox_rejects_non_http_scheme():
    from silver_sentinel.sandbox.web import WebSandbox

    obs = WebSandbox().observe("file:///etc/passwd")
    assert obs.error and "协议" in obs.error


# ---------------------------------------------------------------- 富化


@pytest.mark.parametrize(
    "payload,expect",
    [
        ({"data": [{"domainName": "a.top", "unitName": "某公司"}]}, 1),
        ({"data": {"list": [{"domain": "b.top"}]}}, 1),
        ({"result": {"records": [{"domain": "c.top"}]}}, 1),
        ([{"domain": "d.top"}], 1),
        ({"code": 0}, 0),
        (None, 0),
    ],
)
def test_icp_response_parsing_tolerates_vendor_shapes(payload, expect):
    assert len(_iter_records(payload)) == expect


def test_icp_unknown_is_not_unregistered():
    """未查到 ≠ 未备案。这是举报材料里最容易被追问的一点。"""
    res = ICPResult(domain="x.top", status="unknown", error="service down")
    assert res.status != "unregistered"


def test_rdap_datetime_parsing():
    assert _parse_dt("2026-01-02T03:04:05Z").year == 2026
    assert _parse_dt("2026-01-02").month == 1
    assert _parse_dt("not-a-date") is None
    assert _parse_dt(None) is None


def test_registry_info_serializes():
    info = RegistryInfo(domain="a.top", age_days=12, ok=True)
    payload = info.as_dict()
    assert payload["domain"] == "a.top"
    assert payload["age_days"] == 12


# ---------------------------------------------------------------- 词根生成


def test_seed_generator_produces_varied_roots():
    sg = SeedGenerator()
    stats = sg.stats()
    assert stats["seeds"] > 80

    batch = sg.candidates(0, 40)
    assert len(batch) == 40
    assert all("." in domain for domain, _ in batch)
    assert len({d for d, _ in batch}) == 40      # 同批内不重复


def test_seed_generator_rotates():
    sg = SeedGenerator()
    a = [d for d, _ in sg.candidates(0, 10)]
    b = [d for d, _ in sg.candidates(10, 10)]
    assert a != b


# ---------------------------------------------------------------- 发现入库


def test_inject_respects_whitelist(fresh_db):
    from silver_sentinel.discover.engine import DiscoveryEngine

    engine = DiscoveryEngine()
    result = engine.inject(["taobao.com", "guohui-test.top", "not-a-domain"])
    assert result["added"] == 1
    assert result["skipped"] == 2


def test_inject_deduplicates(fresh_db):
    from silver_sentinel.discover.engine import DiscoveryEngine

    engine = DiscoveryEngine()
    first = engine.inject(["dup-check.top"])
    second = engine.inject(["dup-check.top"])
    assert first["added"] == 1
    assert second["added"] == 0
