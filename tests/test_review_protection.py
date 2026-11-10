"""人工审批结论不可被机器重评覆盖。

生产事故（v1.16.4）：人工把仿冒财政部补贴站群判为 confirmed 后，
周期研判每轮挑 40 个高分资产重评，把它们打回 high_risk。根因有两层：

1. `_apply_claim()` 对 fake_site_id 无条件把 assessment.verdict 提为 high_risk，
   覆盖了 `assess()` 因 reviewed=True 已给出的 confirmed；
2. `apply_assessment()` 把机器 verdict 直接写库，没有看 `reviewed_by`。

这里锁死两条不变量：已复核资产重评只刷新分数/信号，不改判定；
且已复核资产不再进入周期研判待办，省掉无谓重算与锁竞争。
"""

from __future__ import annotations

_FAKE_SITE_ID_CLAIM = {
    "verdict": "fake_site_id",
    "authority": "中华人民共和国财政部",
    "site_id": "bm01000001",
}


def _make_asset(session, value, *, reviewed_by="", verdict="high_risk", tier="watch"):
    from silver_sentinel.models import Asset

    asset = Asset(
        kind="domain",
        value=value,
        normalized=value,
        reviewed_by=reviewed_by,
        verdict=verdict,
        tier=tier,
        score=95.0,
        confidence=0.95,
        scan_count=1,
    )
    session.add(asset)
    session.flush()
    return asset


def test_rescore_never_overwrites_human_verdict(fresh_db):
    """伪造标识码提级也压不过人工 confirmed。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import rescore

    with session_scope() as s:
        asset = _make_asset(s, "fake-gov-subsidy.cn", reviewed_by="人工审批", verdict="confirmed")
        asset.meta = {"facts": {"claim": dict(_FAKE_SITE_ID_CLAIM)}}
        asset_id = asset.id

    with session_scope() as s:
        result = rescore(s, s.get(Asset, asset_id), trigger="test")
        assert result["after"]["verdict"] == "confirmed"

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        assert asset.verdict == "confirmed"
        assert asset.reviewed_by == "人工审批"
        # 分数、置信度、信号照常刷新，只是判定不被覆盖
        assert float(asset.score) >= 95.0


def test_rescore_writes_verdict_for_unreviewed(fresh_db):
    """未复核资产仍按机器结论正常落档，保护不能一刀切。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset
    from silver_sentinel.scoring.reassess import rescore

    with session_scope() as s:
        asset = _make_asset(s, "fake-gov-unreviewed.cn", verdict="insufficient")
        asset.meta = {"facts": {"claim": dict(_FAKE_SITE_ID_CLAIM)}}
        asset_id = asset.id

    with session_scope() as s:
        result = rescore(s, s.get(Asset, asset_id), trigger="test")
        assert result["after"]["verdict"] == "high_risk"

    with session_scope() as s:
        assert s.get(Asset, asset_id).verdict == "high_risk"


def test_pending_assets_skips_reviewed(fresh_db):
    """已终审资产不进周期研判待办；未复核且有正文的仍要进。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append
    from silver_sentinel.pipeline import pending_assets

    with session_scope() as s:
        reviewed = _make_asset(s, "reviewed-high-score.cn", reviewed_by="人工审批", verdict="confirmed")
        unreviewed = _make_asset(s, "unreviewed-high-score.cn", verdict="high_risk")
        reviewed_id, unreviewed_id = reviewed.id, unreviewed.id
        append(s, reviewed_id, "page_text", "个人财政补贴 立即申报".encode(), extension=".txt")
        append(s, unreviewed_id, "page_text", "个人财政补贴 立即申报".encode(), extension=".txt")

    ids = pending_assets(limit=50)
    assert reviewed_id not in ids
    assert unreviewed_id in ids
