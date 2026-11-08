"""用途分类与闸门的回归用例。

锁住四条设计约束，任何一条被改坏都会让「词库保广、用途保细」失效：

1. 客服站/论坛/电商/企业站被识别并降级，但记录不删；
2. 任何硬证据（伪造标识码、冒充、APK 分发、证件类表单）都让用途判定让位；
3. 冲突不排除——规则与模型不一致时判 unknown，宁可多看；
4. 配置开关能一键回退（SILVER_PURPOSE_SUPPRESS=0）。
"""

from __future__ import annotations

from silver_sentinel import triage
from silver_sentinel.features import FEATURE_NAMES, extract
from silver_sentinel.models import TIER_CANDIDATE, TIER_COLD, TIER_WATCH, Asset
from silver_sentinel.purpose import (
    NON_TARGET,
    PurposeResult,
    analyze,
    classify_rules,
    decide_suppression,
    fuse,
)


def _asset(score: float = 20.0, **kwargs) -> Asset:
    base = dict(kind="domain", value="example.cn", normalized="example.cn",
                tier=TIER_CANDIDATE, score=score, verdict="insufficient", meta={})
    base.update(kwargs)
    return Asset(**base)


def _reqs(*hosts: str) -> list[dict]:
    return [{"url": f"https://{h}/a.js", "method": "GET"} for h in hosts]


# ---------------------------------------------------------------- 特征


def test_feature_vector_is_stable_and_complete():
    bundle = extract(url="https://a.cn/", html="<html><body><p>你好</p></body></html>", text="你好世界")
    vector = bundle.vector()
    assert len(vector) == len(FEATURE_NAMES)
    assert all(isinstance(x, float) for x in vector)


def test_cs_sdk_counts_unique_hosts_not_requests():
    """同一个客服域名发 50 条请求，仍然只是 1 个 SDK。"""
    reqs = [{"url": f"https://static.53kf.com/{i}.js"} for i in range(50)]
    bundle = extract(url="https://x.cn/", html="", text="在线客服", requests=reqs)
    assert bundle.values["cs_sdk_hosts"] == 1.0


def test_use_terms_count_distinct_words_not_repeats():
    """重复 40 次「购物车」不应把电商分会刷到天花板。"""
    bundle = extract(url="https://x.cn/", html="", text="购物车" * 40)
    assert bundle.values["use_ecom"] == 1.0


# ---------------------------------------------------------------- 规则分类


def test_customer_service_site():
    html = (
        "<html><body><nav><a href='/'>首页</a><a href='/price'>价格</a></nav>"
        "<div>在线客服 工单 坐席 会话 访客 智能客服 客服机器人 呼叫中心 客户服务 帮助中心</div>"
        "<a href='/a'>a</a>" * 30
        + "</body></html>"
    )
    bundle = extract(url="https://www.example-cs.com/", html=html,
                     text="在线客服 工单 坐席 会话 访客 智能客服 客服机器人 呼叫中心 客户服务 帮助中心",
                     requests=_reqs("static.53kf.com", "cdn.example-cs.com"))
    result = classify_rules(bundle, host="www.example-cs.com")
    assert result.purpose == "customer_service"
    assert result.confidence >= 0.55


def test_forum_site():
    text = "论坛 版块 楼主 回帖 发帖 置顶 精华 威望 讨论区 版主 楼层"
    html = "<html><body>" + "".join(f"<a href='/{i}'>帖子{i}</a>" for i in range(60)) + "</body></html>"
    bundle = extract(url="https://bbs.example.cn/", html=html, text=text)
    result = classify_rules(bundle, host="bbs.example.cn")
    assert result.purpose == "forum"


def test_ecommerce_site():
    text = "购物车 立即购买 商品详情 库存 运费 订单 下单 优惠券 促销 店铺 卖家 包邮 规格"
    bundle = extract(url="https://shop.example.cn/", html="<html><body>x</body></html>", text=text,
                     requests=_reqs("pay.example.cn"))
    result = classify_rules(bundle, host="shop.example.cn")
    assert result.purpose == "ecommerce"


def test_corporate_site():
    text = "关于我们 解决方案 产品中心 联系我们 企业文化 公司简介 发展历程 招贤纳士 合作伙伴 资质证书"
    html = "<html><body><nav><a href='/a'>关于我们</a></nav></body></html>"
    bundle = extract(url="https://www.example-tech.com/", html=html, text=text)
    result = classify_rules(bundle, host="www.example-tech.com")
    assert result.purpose == "corporate"


def test_landing_page():
    text = "立即领取 限时 名额 扫码 加微信 免费领取 一键申请 提交申请"
    html = "<html><body><form><input name='phone'></form></body></html>"
    bundle = extract(url="https://x.top/", html=html, text=text, forms=[{"inputs": ["手机号"]}])
    result = classify_rules(bundle, host="x.top")
    assert result.purpose == "landing"


# ---------------------------------------------------------------- 抑制判定


def _cs_result() -> PurposeResult:
    return PurposeResult(purpose="customer_service", confidence=0.9, source="rule")


def test_cs_is_suppressed_without_hard_evidence():
    ok, reason = decide_suppression(_cs_result(), {})
    assert ok and "客服" in reason


def test_fake_site_id_overrides_purpose():
    """伪造政府标识码的站，即使版式像企业站，也不许被用途闸门放走。"""
    facts = {"claim": {"verdict": "fake_site_id", "site_id": "bm01000001"}}
    ok, reason = decide_suppression(PurposeResult(purpose="corporate", confidence=0.95), facts)
    assert not ok and "硬证据" in reason


def test_impersonation_overrides_purpose():
    facts = {"claim": {"verdict": "impersonation"}}
    ok, _ = decide_suppression(PurposeResult(purpose="forum", confidence=0.95), facts)
    assert not ok


def test_scam_keywords_override_purpose():
    result = PurposeResult(purpose="corporate", confidence=0.9, scam_hits=2)
    ok, reason = decide_suppression(result, {})
    assert not ok and "骗局专属词" in reason


def test_apk_links_override_purpose():
    ok, reason = decide_suppression(PurposeResult(purpose="corporate", confidence=0.9),
                                    {"apk_links": ["https://x/a.apk"]})
    assert not ok and "安装包" in reason


def test_id_form_overrides_purpose():
    bundle = extract(url="https://x.cn/", html="", text="关于我们 解决方案",
                     forms=[{"inputs": ["身份证号"]}])
    ok, reason = decide_suppression(PurposeResult(purpose="corporate", confidence=0.9), {}, bundle)
    assert not ok and "证件" in reason


# ---------------------------------------------------------------- 闸门（triage）


def test_gate_sends_cs_to_cold():
    asset = _asset(score=30.0)
    facts = {"purpose": {"purpose": "customer_service", "label": "客服系统",
                         "confidence": 0.9, "suppressed": True,
                         "suppressed_reason": "用途为「客服系统」"}}
    decision = triage.decide(asset, facts=facts)
    assert decision.tier == TIER_COLD


def test_gate_keeps_high_score_in_candidate():
    """评分 ≥75 的「客服站」只降到候选，不直接冷存——宁可多看。"""
    asset = _asset(score=82.0)
    facts = {"purpose": {"purpose": "forum", "label": "论坛社区", "confidence": 0.9,
                         "suppressed": True, "suppressed_reason": "用途为「论坛社区」"}}
    decision = triage.decide(asset, facts=facts)
    assert decision.tier == TIER_CANDIDATE


def test_gate_does_not_touch_impersonation():
    asset = _asset(score=90.0)
    facts = {
        "claim": {"verdict": "impersonation", "agencies": ["民政部"],
                  "official_domains": {"民政部": ["mca.gov.cn"]}},
        "purpose": {"purpose": "corporate", "label": "企业官网", "confidence": 0.95,
                    "suppressed": True, "suppressed_reason": "用途为「企业官网」"},
    }
    decision = triage.decide(asset, facts=facts)
    assert decision.tier == TIER_WATCH
    assert any("冒充" in r for r in decision.reasons)


def test_gate_ignores_unsuppressed_purpose():
    asset = _asset(score=30.0)
    facts = {"purpose": {"purpose": "customer_service", "confidence": 0.9, "suppressed": False}}
    decision = triage.decide(asset, facts=facts)
    assert decision.tier == TIER_CANDIDATE


def test_portal_goes_to_candidate_not_cold():
    asset = _asset(score=30.0)
    facts = {"purpose": {"purpose": "portal", "label": "行业门户", "confidence": 0.8,
                         "suppressed": True, "suppressed_reason": "用途为「行业门户」"}}
    decision = triage.decide(asset, facts=facts)
    assert decision.tier == TIER_CANDIDATE


def test_non_target_set_matches_design():
    """设计约束：客服/论坛/电商/企业/新闻/政府都在强非目标集合里。"""
    assert {"customer_service", "forum", "ecommerce", "corporate", "news", "government"} <= NON_TARGET


# ---------------------------------------------------------------- 配置与降级


def test_analyze_respects_suppress_switch(monkeypatch):
    monkeypatch.setenv("SILVER_PURPOSE_SUPPRESS", "0")
    from silver_sentinel.config import Settings

    fresh = Settings()
    monkeypatch.setattr("silver_sentinel.config.settings", fresh)
    bundle = extract(url="https://x.cn/", html="", text="在线客服 工单 坐席 会话 访客",
                     requests=_reqs("static.53kf.com"))
    result = analyze(bundle, host="x.cn", facts={})
    assert result.suppressed is False


def test_analyze_disabled_returns_unknown(monkeypatch):
    monkeypatch.setenv("SILVER_PURPOSE_ENABLED", "0")
    from silver_sentinel.config import Settings

    monkeypatch.setattr("silver_sentinel.config.settings", Settings())
    bundle = extract(url="https://x.cn/", html="", text="在线客服")
    result = analyze(bundle, host="x.cn", facts={})
    assert result.purpose == "unknown"
    assert result.source == "none"


# ---------------------------------------------------------------- 规则与模型融合


def _probs(p: float) -> dict[str, float]:
    return {"target_shaped": p, "operational": 1 - p}


def test_fuse_vetoes_rule_when_model_suspects_landing():
    """规则判「企业站」，但模型认为 90% 是落地页 → 不做排除。"""
    rule = PurposeResult(purpose="corporate", confidence=0.62, source="rule")
    out = fuse(rule, 0.90, _probs(0.90))
    assert out.purpose == "unknown"
    assert "不做排除" in out.reasons[0]


def test_fuse_does_not_veto_high_confidence_rule():
    """规则很确定时，模型不能靠一次概率就推翻——否则模型一抖就漏一个客服站。"""
    rule = PurposeResult(purpose="customer_service", confidence=0.95, source="rule")
    out = fuse(rule, 0.95, _probs(0.95))
    assert out.purpose == "customer_service"


def test_fuse_confirms_weak_rule():
    rule = PurposeResult(purpose="forum", confidence=0.57, source="rule")
    out = fuse(rule, 0.05, _probs(0.05))
    assert out.purpose == "forum"
    assert out.confidence > 0.57


def test_fuse_unknown_to_operational_only_when_very_confident():
    rule = PurposeResult(purpose="unknown", confidence=0.3, source="rule")
    assert fuse(rule, 0.09, _probs(0.09)).purpose == "operational"
    # 0.12 已经超过阈值：宁可留在 unknown（照常走风险判定），也不排除
    assert fuse(rule, 0.12, _probs(0.12)).purpose == "unknown"


def test_fuse_keeps_landing_untouched():
    rule = PurposeResult(purpose="landing", confidence=0.7, source="rule")
    out = fuse(rule, 0.95, _probs(0.95))
    assert out.purpose == "landing"


def test_fuse_respects_whitelist_over_model():
    rule = PurposeResult(purpose="government", confidence=1.0, source="rule")
    out = fuse(rule, 0.99, _probs(0.99), is_government=True)
    assert out.purpose == "government"
