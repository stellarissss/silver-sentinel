"""举报材料生成：结构完整性、渠道差异、法条引用。"""

from __future__ import annotations

from silver_sentinel.db import session_scope
from silver_sentinel.intake import scan
from silver_sentinel.respond import CHANNELS, advise, build, export_bundle, one_pager


def _prepare() -> int:
    text = (
        "免费领鸡蛋，健康讲座到场即送米面油。国家惠民补贴，实名注册领 2 万元养老金。"
        "应用商店搜不到，点击继续安装。邀请好友拿直推奖励。充值使用 USDT-TRC20。"
        "专家义诊，特效药包治百病。"
    )
    return scan("url", "http://guohui-minsheng.top/reg?invite=1", text=text, run_llm=False).asset_id


def test_report_contains_required_sections(fresh_db):
    asset_id = _prepare()
    with session_scope() as session:
        draft = build(session, asset_id, "12321")
        body = draft.body

    for section in ["被举报对象", "事实经过", "判定依据", "证据清单", "涉嫌违反的规定", "诉求"]:
        assert section in body

    assert "12321.cn" in body
    assert "《中华人民共和国刑法》第二百六十六条" in body
    assert "线索而非定性结论" in body
    assert draft.payload["signal_count"] > 0
    assert draft.payload["evidence_count"] > 0


def test_report_marks_verdict_conservatively(fresh_db):
    asset_id = _prepare()
    with session_scope() as session:
        body = build(session, asset_id, "12321").body
    assert "高度可疑" in body or "确认涉诈" in body
    assert "确定是诈骗" not in body


def test_bundle_covers_multiple_channels(fresh_db):
    asset_id = _prepare()
    with session_scope() as session:
        bundle = export_bundle(session, asset_id, ["12321", "12377", "cyberpolice", "12315"])

    assert len(bundle["reports"]) == 4
    assert {r["channel"] for r in bundle["reports"]} == {"12321", "12377", "cyberpolice", "12315"}
    assert bundle["one_pager"]["actions"]
    for report in bundle["reports"]:
        assert report["body"].strip()


def test_every_channel_is_documented(fresh_db):
    for meta in CHANNELS.values():
        assert meta["name"]
        assert meta["best_for"]
        assert meta["fields"]


def test_one_pager_is_actionable(fresh_db):
    asset_id = _prepare()
    with session_scope() as session:
        page = one_pager(session, asset_id)

    assert page["score"] > 0
    assert len(page["actions"]) >= 3
    assert any(h["number"] == "96110" for h in page["hotlines"])


def test_advice_differs_by_verdict():
    assert advise("confirmed") != advise("low")
    assert any("96110" in x for x in advise("confirmed"))
    assert advise("insufficient")


def test_unknown_channel_falls_back(fresh_db):
    asset_id = _prepare()
    with session_scope() as session:
        draft = build(session, asset_id, "not-a-channel")
    assert draft.channel == "12321"
