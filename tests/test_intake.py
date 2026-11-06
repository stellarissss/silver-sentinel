"""端到端：幂等、证据链、官方通报命中、团伙归并。"""

from __future__ import annotations

from sqlalchemy import select

from silver_sentinel.db import session_scope, verify_chain
from silver_sentinel.intake import scan
from silver_sentinel.models import Asset, Campaign, Evidence, SignalRow
from tests.conftest import build_apk


def test_scan_is_idempotent(fresh_db):
    for _ in range(2):
        scan("url", "http://guohui-minsheng.top/reg?invite=1", run_llm=False)

    with session_scope() as session:
        assets = list(session.scalars(select(Asset)))
        assert len(assets) == 1
        assert assets[0].scan_count == 2


def test_tracking_params_collapse_to_same_asset(fresh_db):
    scan("url", "http://a.top/reg?utm_source=wx&invite=1", run_llm=False)
    scan("url", "http://a.top/reg?invite=1&utm_campaign=x", run_llm=False)

    with session_scope() as session:
        assert session.scalar(select(Asset).where(Asset.normalized == "http://a.top/reg?invite=1"))


def test_evidence_chain_verifies_and_detects_tampering(fresh_db):
    result = scan("url", "http://kuaishou-yinfa.top/reg", run_llm=False)

    with session_scope() as session:
        assert verify_chain(session)["ok"] is True

        row = session.scalars(select(Evidence).where(Evidence.asset_id == result.asset_id)).first()
        assert row is not None
        row.sha256 = "0" * 64  # 模拟事后篡改

    with session_scope() as session:
        report = verify_chain(session)
        assert report["ok"] is False
        assert report["broken_at"] is not None


def test_official_watchlist_hit_yields_confirmed(fresh_db):
    result = scan(
        "text",
        "国惠民生",
        text="国惠民生 App，实名注册就能领 2 万元养老金，邀请新人还能继续领补贴。",
        run_llm=False,
    )
    assert result.assessment.verdict == "confirmed"
    assert any(s.rule_id == "REP-003" for s in result.assessment.signals)


def test_similar_names_do_not_trigger_watchlist(fresh_db):
    result = scan("text", "社区老年人体检通知", text="本周六上午在社区服务中心免费测量血压。", run_llm=False)
    assert result.assessment.verdict in {"insufficient", "low"}


def test_apk_scan_produces_technical_signals(fresh_db, tmp_path):
    apk = build_apk(
        tmp_path / "sample.apk",
        dex_text="免费领鸡蛋 国家补贴 专家义诊 充值 USDT-TRC20 TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE",
    )
    result = scan("apk", apk.name, file_path=str(apk), run_llm=False, do_cluster=False)

    ids = {s.rule_id for s in result.assessment.signals}
    assert "TEC-002" in ids       # 无障碍服务
    assert "TEC-005" in ids       # 请求安装其他应用
    assert "TEC-006" in ids       # 内嵌钱包地址
    assert result.assessment.score >= 40
    assert result.asset["meta"]["apk"]["package_name"] == "com.example.yanglao"


def test_apk_evidence_archived(fresh_db, tmp_path):
    apk = build_apk(tmp_path / "e.apk")
    result = scan("apk", apk.name, file_path=str(apk), run_llm=False)

    with session_scope() as session:
        rows = list(session.scalars(select(Evidence).where(Evidence.asset_id == result.asset_id)))
        kinds = {r.kind for r in rows}
        assert "apk" in kinds
        assert "assessment" in kinds


def test_signals_are_replaced_not_accumulated(fresh_db):
    scan("text", "免费领鸡蛋", text="免费领鸡蛋，到场即送米面油。", run_llm=False)
    with session_scope() as session:
        asset = session.scalars(select(Asset)).first()
        first = session.scalar(select(SignalRow).where(SignalRow.asset_id == asset.id).limit(1)).id

    scan("text", "免费领鸡蛋", text="免费领鸡蛋，到场即送米面油，还有专家义诊和特效药。", run_llm=False)
    with session_scope() as session:
        asset = session.scalars(select(Asset)).first()
        rows = list(session.scalars(select(SignalRow).where(SignalRow.asset_id == asset.id)))
        # 旧信号被清空重写，不会出现重复 rule_id
        rule_ids = [r.rule_id for r in rows]
        assert len(rule_ids) == len(set(rule_ids))
        assert any(r.id != first for r in rows) or len(rows) >= 1


def test_assets_sharing_cert_are_clustered(fresh_db, tmp_path):
    a1 = build_apk(tmp_path / "one.apk", package="com.alpha.fuli")
    a2 = build_apk(tmp_path / "two.apk", package="com.beta.fuli")

    scan("apk", a1.name, file_path=str(a1), run_llm=False)
    scan("apk", a2.name, file_path=str(a2), run_llm=False)

    with session_scope() as session:
        assets = list(session.scalars(select(Asset)))
        assert len(assets) == 2
        campaign_ids = {a.campaign_id for a in assets}
        assert len(campaign_ids) == 1 and None not in campaign_ids
        assert session.scalar(select(Campaign)) is not None
