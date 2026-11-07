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
    """只有品牌词命中（站群域名）时，不给「强主题词根」信号。"""
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import assess_now

    asset = Asset(kind="domain", value="jrs-weixin-qq.cc", normalized="jrs-weixin-qq.cc")
    assessment, _facts = assess_now(asset, text="")
    assert "KW-001" not in {s.rule_id for s in assessment.signals}


def test_brand_plus_role_still_triggers_keyword(fresh_db):
    """「品牌 + 角色」的双命中仍应触发，避免把真冒充一起放过。"""
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import assess_now

    asset = Asset(kind="domain", value="weixin-kefu.com", normalized="weixin-kefu.com")
    assessment, _facts = assess_now(asset, text="")
    assert "KW-001" in {s.rule_id for s in assessment.signals}
