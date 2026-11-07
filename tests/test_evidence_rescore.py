"""证据读取与重评：这两件事决定了「抓了上千条却没有高价值线索」。

线上症状：证据仓里有 page_text，但明文被脱敏，读取方直接 open 文件拿到空串，
于是评分只吃域名（上限 38.8），watch 门槛 50 永远够不到。

这里覆盖三条不变量：
1. 明文不在时，读取必须能从密文还原；
2. 有正文时重评必须真的用上正文，分数与信号都要变；
3. 重评是幂等的——同一条正文证据不重复重算。
"""

from __future__ import annotations

import base64
import os

import pytest
from sqlalchemy import select


@pytest.fixture
def vault_key(fresh_db, monkeypatch):
    """给测试环境一把固定的 vault 密钥，并清掉单例。"""
    import silver_sentinel.vault as vault_mod

    key = base64.b64encode(b"\x01" * 32).decode()
    monkeypatch.setattr(vault_mod, "_vault", None)
    from silver_sentinel.config import settings

    settings.vault_key = key
    settings.vault_key_file = ""
    settings.vault_passphrase = ""
    yield
    monkeypatch.setattr(vault_mod, "_vault", None)
    settings.vault_key = ""


def _make_asset(session, value="demo-huimin.cc", **kw):
    from silver_sentinel.models import Asset

    asset = Asset(kind="domain", value=value, normalized=value, **kw)
    session.add(asset)
    session.flush()
    return asset


def test_read_bytes_falls_back_to_vault(fresh_db, vault_key):
    """明文被 SILVER_VAULT_REMOVE_PLAINTEXT 删掉后仍要读得出原文。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append, path_of, read_bytes, read_status
    from silver_sentinel.vault import get_vault

    payload = "惠民补贴申领中心 每日收益 拉人头".encode()
    with session_scope() as s:
        asset = _make_asset(s)
        row = append(s, asset.id, "page_text", payload, extension=".txt", mime="text/plain")
        evidence_id = row.id
        sha = row.sha256

    # 模拟证据仓：加密一份，然后删掉明文
    get_vault().seal_local(sha, payload)
    path = path_of(row)
    os.unlink(path)

    with session_scope() as s:
        row = s.get(type(row), evidence_id)
        assert read_bytes(row) == payload
        assert read_status(row) == "vault"


def test_read_bytes_returns_empty_when_really_missing(fresh_db, vault_key):
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append, path_of, read_bytes, read_status

    with session_scope() as s:
        asset = _make_asset(s)
        row = append(s, asset.id, "page_text", b"abc", extension=".txt")
        evidence_id = row.id
    os.unlink(path_of(row))

    with session_scope() as s:
        row = s.get(type(row), evidence_id)
        assert read_bytes(row) == b""
        assert read_status(row) == "missing"


def test_rescore_uses_page_text(fresh_db, vault_key):
    """同一资产：仅域名 vs 有正文，分数必须拉开差距。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append, path_of
    from silver_sentinel.models import Asset, SignalRow
    from silver_sentinel.scoring.reassess import rescore
    from silver_sentinel.vault import get_vault

    text = (
        "国家项目 惠民补贴 领取登记\n"
        "每日收益 3%，拉人头再返 20%\n"
        "请用浏览器打开，扫码安装 安卓版下载\n"
        "客服 QQ 123456789 微信 vx888888\n"
    )

    with session_scope() as s:
        asset = _make_asset(s)
        row = append(s, asset.id, "page_text", text.encode(), extension=".txt", mime="text/plain")
        asset_id, sha, ev_id = asset.id, row.sha256, row.id
        asset.score = 8.0
        asset.verdict = "insufficient"

    get_vault().seal_local(sha, text.encode())
    with session_scope() as s:
        os.unlink(path_of(s.get(type(row), ev_id)))

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        result = rescore(s, asset, trigger="test")
        signals = list(s.scalars(select(SignalRow).where(SignalRow.asset_id == asset_id)))

    assert result["text_len"] >= len(text) - 5
    assert result["after"]["score"] > 30, result
    assert result["signals"] >= 3
    assert len(signals) >= 3
    assert result["after"]["tier"] in ("candidate", "watch")


def test_rescore_is_idempotent_for_same_evidence(fresh_db, vault_key):
    """同一条正文不重复进待办队列，否则流水线会无限重算同一批资产。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append
    from silver_sentinel.models import Asset
    from silver_sentinel.pipeline import pending_assets
    from silver_sentinel.scoring.reassess import rescore

    with session_scope() as s:
        asset = _make_asset(s, value="idem-demo.cc")
        append(s, asset.id, "page_text", "惠民补贴 领取 每日收益".encode(), extension=".txt")
        asset_id = asset.id
        asset.scan_count = 1

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        rescore(s, asset, trigger="test")

    assert asset_id not in pending_assets(limit=50)


def test_rescore_picks_up_new_evidence(fresh_db, vault_key):
    """同一资产又取到一份新正文时，必须重新进待办。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append
    from silver_sentinel.models import Asset
    from silver_sentinel.pipeline import pending_assets
    from silver_sentinel.scoring.reassess import rescore

    with session_scope() as s:
        asset = _make_asset(s, value="idem-demo2.cc")
        append(s, asset.id, "page_text", "惠民补贴 领取".encode(), extension=".txt")
        asset_id = asset.id
        asset.scan_count = 1

    with session_scope() as s:
        rescore(s, s.get(Asset, asset_id), trigger="test")

    with session_scope() as s:
        append(s, asset_id, "page_text", "民族资产解冻 每日收益".encode(), extension=".txt")

    assert asset_id in pending_assets(limit=50)


def test_off_topic_page_only_keeps_structural_signals(fresh_db):
    """体育站群页面不该被当成涉老诈骗。

    这类域名常长成 fj-weixin-qq.cc，正文里又有「比分/直播/录像」，
    字面上会撞上词库与远程协助规则，但主题完全无关。
    """
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import assess_now

    asset = Asset(kind="domain", value="fj-weixin-qq.cc", normalized="fj-weixin-qq.cc")
    text = ("足球直播 篮球直播 NBA CBA 英超 西甲 德甲 比分 赛事 录像 集锦 " * 20) + "向日葵"
    assessment, facts = assess_now(asset, text=text)

    assert facts.get("off_topic") == "sports"
    ids = {s.rule_id for s in assessment.signals}
    assert "PER-007" not in ids
    assert "KW-001" not in ids
    assert assessment.score < 45


def test_single_brand_term_is_not_strong_keyword(fresh_db):
    """只有品牌词命中（站群域名）时，不给「强主题词根」信号，只给弱品牌信号。"""
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import assess_now

    asset = Asset(kind="domain", value="jrs-weixin-qq.cc", normalized="jrs-weixin-qq.cc")
    assessment, _facts = assess_now(asset, text="")
    ids = {s.rule_id for s in assessment.signals}
    assert "KW-001" not in ids
    assert "KW-003" in ids


def test_authority_term_alone_is_only_a_weak_signal(fresh_db):
    """只有机构名、没有正文时只算弱信号。

    域名本身叫「国惠中科」当然可疑，但 gongxiaoshe88.com 这类把拼音域名
    挂上加速器下载站的抢注案例说明：**光凭域名拼音撞上机构名**不能定性。
    取证后如果正文出现政策/涉老话术，重评会自动升到 KW-001。
    """
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import assess_now

    asset = Asset(kind="domain", value="guohui-zhongke.cn", normalized="guohui-zhongke.cn")
    assessment, _facts = assess_now(asset, text="")
    ids = {s.rule_id for s in assessment.signals}
    assert "KW-004" in ids
    assert "KW-001" not in ids

    # 同一域名，正文出现涉老政策话术后必须升级为强信号
    text = "国惠中科惠民补贴申领中心 面向 60 岁以上老人发放养老补贴 登记信息即可领取"
    upgraded, _ = assess_now(asset, text=text)
    assert "KW-001" in {s.rule_id for s in upgraded.signals}
    assert upgraded.score > assessment.score


def test_voting_saas_is_not_watch_level(fresh_db):
    """正规 SaaS 页面（微信投票工具）不该进 watch。

    它同时命中「品牌词 + 无备案 + 品牌相似域名 + 客服」，
    旧规则会推到 56 分；收紧后应停在候选池。
    """
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import assess_now

    asset = Asset(kind="domain", value="weixin100.com.cn", normalized="weixin100.com.cn")
    asset.meta = {"facts": {"brand_lookalike": "weixin"}}
    text = (
        "宝石投票系统的优势 免费创建微信投票 支持图文、音视频上传 实时预览 "
        "可设置票数上限，验证码防刷，投票频率，IP限制 手机验证码 专属客服服务 "
        "感谢您对平台的支持和信任，投票活动创建，可以咨询微信客服"
    )
    assessment, _facts = assess_now(asset, text=text)
    ids = {s.rule_id for s in assessment.signals}
    assert "PER-006" not in ids
    assert assessment.score < 50


def test_manual_dismiss_survives_retier(fresh_db):
    """人工排除必须扛得住规则口径变更后的重定级。

    生产库里的演示包（silver-sample.apk，70.3 分）曾长期占据 watch 第一名，
    把真线索挤下去。排除之后再跑 rescore --retier 不能把它拉回来。
    """
    from types import SimpleNamespace

    from silver_sentinel.cli import cmd_dismiss
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import TIER_DISMISSED, Asset
    from silver_sentinel.scoring.reassess import rescore_by_id

    with session_scope() as s:
        asset = Asset(
            kind="apk",
            value="silver-sample.apk",
            normalized="silver-sample.apk",
            score=70.3,
            tier="watch",
            verdict="high_risk",
            meta={"facts": {}},
        )
        s.add(asset)
        s.flush()
        aid = asset.id

    cmd_dismiss(SimpleNamespace(asset_id=aid, reason="演示用样例包，非真实线索", by="test"))

    rescore_by_id(aid, trigger="retier")

    with session_scope() as s:
        fresh = s.get(Asset, aid)
        assert fresh.tier == TIER_DISMISSED
        assert fresh.reviewed_by == "test"
        assert "示例" in (fresh.dismiss_reason or "") or "样例" in (fresh.dismiss_reason or "")
