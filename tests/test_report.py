"""半自动举报：类别判定、正文裁剪、证据包完整性、填表载荷。

重点验证四件容易出问题的事：
1. 500 字硬上限下，诉求段不能被裁掉；
2. 正文不出现主观推断句（那是材料被退回的常见原因）；
3. 证据包里的 manifest 哈希与真实文件一致（否则校验会失败）；
4. 12377 的 cookie 预置与类别 id 必须成对出现，否则表单会被判无效。
"""

from __future__ import annotations

import hashlib
import json
import zipfile

import pytest

from silver_sentinel.db import session_scope
from silver_sentinel.evidence import append
from silver_sentinel.models import Asset, SignalRow
from silver_sentinel.report import channels, harmtype, narrative, service

PAGE_TEXT = (
    "国家惠民养老补贴申领中心 关于开展2026年度高龄老人养老补贴申领工作的通知 "
    "凡年满65周岁的城乡居民，均可申领本年度养老补贴，标准为每人每月800元，一次性补发12个月共9600元。"
    "本次申领实行先登记后发放，名额有限，请符合条件的老人于本月底前完成登记，逾期视为放弃。"
    "补贴申领登记：姓名、身份证号、银行卡号、手机验证码。"
    "该页面使用了常见的欺骗手法，说明其可能并非官方渠道。"
)


@pytest.fixture
def seeded(fresh_db):
    """一个典型的「仿冒养老补贴」资产，带正文/HTML/截图三类证据。"""
    with session_scope() as s:
        a = Asset(
            kind="domain",
            value="guohui-yanglao-bt.cn",
            normalized="guohui-yanglao-bt.cn",
            score=86.0,
            confidence=0.82,
            verdict="confirmed",
            tier="confirmed",
            icp_status="none",
        )
        a.meta = {
            "facts": {
                "page_title": "国家惠民养老补贴申领中心",
                "ips": ["45.132.77.19"],
                "registrar": "Alibaba Cloud Computing Ltd.",
                "domain_age_days": 11,
                "apk_links": ["http://guohui-yanglao-bt.cn/a.apk"],
            }
        }
        s.add(a)
        s.flush()
        asset_id = a.id
        for cat, title, detail in [
            ("impersonation", "仿冒国家机关网站", "页面使用国家机关名称与红头公文样式，未标注真实主办单位。"),
            ("financial", "索取银行卡与短信验证码", "表单同时要求银行卡号与银行短信验证码。"),
            ("persuasion", "以养老补贴名义诱导", "以每月800元、一次性补发9600元吸引老人登记。"),
        ]:
            s.add(SignalRow(asset_id=asset_id, rule_id=f"T-{cat[:3]}", category=cat,
                            title=title, detail=detail, weight=20, confidence=0.8))
        append(s, asset_id, "page_text", PAGE_TEXT.encode(), note="页面正文快照", extension=".txt")
        append(s, asset_id, "page_html", b"<html><body>mock</body></html>", note="HTML 原文", extension=".html")
        append(s, asset_id, "screenshot", b"\x89PNG\r\n\x1a\n" + b"0" * 64, note="首屏截图", extension=".png")
        asset_id = a.id
    return asset_id


def test_harm_routes_elder_to_special_zone(seeded):
    with session_scope() as s:
        a = s.get(Asset, seeded)
        signals = list(s.query(SignalRow).filter_by(asset_id=seeded))
        h = harmtype.classify(a, signals)
    assert h.harm in {"fraud", "impersonation"}
    assert h.big == "010"
    assert "养老诈骗" in h.small_name
    assert h.platform == "WEBSITE"


def test_harm_gambling_and_porn_map_to_right_big():
    class Fake:
        kind = "domain"
        value = "bet-xyz.cn"
        normalized = "bet-xyz.cn"
        notes = ""
        meta = {}

    h = harmtype.classify(Fake(), [])
    assert h.big == "006" and "博彩" in h.small_name

    class Fake2(Fake):
        value = "se-av.cn"
        normalized = "se-av.cn"

    assert harmtype.classify(Fake2(), []).big == "004"


def test_quotes_drop_subjective_sentences():
    quotes = narrative.pick_quotes(PAGE_TEXT, limit=4, width=60)
    assert quotes, "应当能摘出页面原话"
    assert not any("说明其可能" in q for q in quotes)
    assert any("银行卡号" in q or "养老补贴" in q for q in quotes)


def test_brief_respects_limit_and_keeps_demand(seeded):
    with session_scope() as s:
        a = s.get(Asset, seeded)
        signals = list(s.query(SignalRow).filter_by(asset_id=seeded))
        ev = list(s.query(__import__("silver_sentinel.models", fromlist=["Evidence"]).Evidence).filter_by(asset_id=seeded))
        ctx = narrative.Ctx(asset=a, signals=signals, evidence=ev,
                            harm=harmtype.classify(a, signals), page_text=PAGE_TEXT)
        out = narrative.brief(ctx, channels.get("12377"))
    assert len(out) <= 500
    assert "请核查并依法采取阻断访问" in out
    assert "【对象】" in out
    assert "说明其可能" not in out


def test_brief_is_stable_when_page_text_missing(seeded):
    with session_scope() as s:
        a = s.get(Asset, seeded)
        signals = list(s.query(SignalRow).filter_by(asset_id=seeded))
        ctx = narrative.Ctx(asset=a, signals=signals, evidence=[],
                            harm=harmtype.classify(a, signals), page_text="")
        out = narrative.brief(ctx, channels.get("12377"))
    assert len(out) <= 500
    assert "【页面原文】" not in out      # 没原文就不编


def test_channel_routes_put_regulator_first():
    ids = [c.id for c in channels.for_harm("impersonation")]
    assert ids[0] == "12377"
    assert "12321" in ids


def test_build_produces_verifiable_bundle(seeded):
    with session_scope() as s:
        row = service.build(s, seeded, "12377", reporter="测试举报人")
        assert row.code.startswith("rb")
        assert row.status == "draft"
        assert row.body and len(row.body) <= 500

        zpath = service.file_of(row, "zip")
        ppath = service.file_of(row, "pdf")
        assert zpath.exists() and ppath.exists()

        with zipfile.ZipFile(zpath) as zf:
            names = set(zf.namelist())
            assert "manifest.json" in names and "manifest.sha256" in names
            assert any(n.endswith(".pdf") for n in names)
            manifest = json.loads(zf.read("manifest.json"))
            # 逐条核对：manifest 记的哈希必须等于包内真实文件
            for f in manifest["files"]:
                assert hashlib.sha256(zf.read(f["name"])).hexdigest() == f["sha256"], f["name"]
            assert manifest["target"]["value"] == "guohui-yanglao-bt.cn"
            assert manifest["harm"]["small"] == harmtype.classify(
                s.get(Asset, seeded), list(s.query(SignalRow).filter_by(asset_id=seeded))
            ).small


def test_fill_payload_targets_real_selectors(seeded):
    with session_scope() as s:
        row = service.build(s, seeded, "12377")
        fill = row.fill
    actions = [st["action"] for st in fill["steps"]]
    assert actions[0] == "wait"
    assert "select" in actions and "fill" in actions
    assert "highlight" in actions
    # 12377 必须先落 cookie，否则页面会跳回首页
    assert any(p["name"] == "bigHarmType" for p in fill["pre"])
    cookies = {p["name"]: p["value"] for p in fill["pre"]}
    assert cookies["bigHarmType"] == "010"

    content = next(st for st in fill["steps"] if st.get("selector") == "#report_content")
    assert content["value"] == row.body
    assert len(content["value"]) <= 500


def test_12321_payload_uses_radio_and_checkbox(seeded):
    with session_scope() as s:
        row = service.build(s, seeded, "12321")
        fill = row.fill
    actions = [st["action"] for st in fill["steps"]]
    assert "radio" in actions
    assert "check" in actions
    assert any(st.get("selector") == "#xuzhi" for st in fill["steps"])
    assert len(row.body) <= 2200


def test_mail_channel_has_subject_and_sha(seeded):
    with session_scope() as s:
        row = service.build(s, seeded, "registrar_abuse")
        assert row.body.startswith("主题：Abuse report")
        assert "sha256=" in row.body
        assert "http://guohui-yanglao-bt.cn" in row.body


def test_mark_state_machine(seeded):
    with session_scope() as s:
        row = service.build(s, seeded, "12377")
        code = row.code
        service.mark(s, code, "opened")
        r2 = service.mark(s, code, "submitted", receipt="BJ20261105001")
        assert r2.status == "submitted"
        assert r2.opened_at and r2.submitted_at
        assert r2.receipt == "BJ20261105001"
        with pytest.raises(ValueError):
            service.mark(s, code, "weird")


def test_body_override_is_trimmed_to_channel_limit(seeded):
    with session_scope() as s:
        long_body = "测" * 900
        row = service.build(s, seeded, "12377", body_override=long_body)
        assert len(row.body) == 500
