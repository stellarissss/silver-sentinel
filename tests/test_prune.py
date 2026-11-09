"""清理取证失败死站：安全口径、最小留痕、级联与恢复。"""

from __future__ import annotations

import json

from sqlalchemy import select

from silver_sentinel.db import session_scope
from silver_sentinel.models import (
    Asset,
    AssetSnapshot,
    Campaign,
    CaptureTask,
    DiscoveryEvent,
    Evidence,
    ReportBundle,
    ScanRun,
    SignalRow,
    WatchTarget,
)
from silver_sentinel.prune import (
    PRUNE_SOURCE,
    archive_record,
    build_tombstone,
    error_class,
    prune,
    restore,
    select_candidates,
)


def _add(session, value: str, **kw) -> Asset:
    asset = Asset(kind="domain", value=value, normalized=value, **kw)
    session.add(asset)
    session.flush()
    return asset


def _seed(session) -> dict[str, int]:
    """构造一批覆盖各排除条件的资产，返回 name -> id。"""
    campaign = Campaign(key="c-test", name="测试团伙")
    session.add(campaign)
    session.flush()

    dead1 = _add(
        session, "dead-port.example",
        capture_state="failed", capture_error="端口无法连接（HTTP/HTTPS 均不通）",
        tier="cold", score=12.0, discovery_source="ct_poll",
    )
    dead2 = _add(
        session, "dead-nx.example",
        capture_state="dead", capture_error="DNS 解析失败（NXDOMAIN）",
        tier="candidate", score=18.0,
    )
    with_ev = _add(session, "with-evidence.example", capture_state="failed", tier="cold")
    session.add(Evidence(asset_id=with_ev.id, kind="page_text", sha256="a" * 64))
    with_campaign = _add(
        session, "with-campaign.example", capture_state="failed",
        tier="cold", campaign_id=campaign.id,
    )
    watched = _add(session, "watched.example", capture_state="failed", tier="watch")
    high_risk = _add(
        session, "high-risk.example", capture_state="failed",
        tier="cold", verdict="high_risk",
    )
    reviewed = _add(
        session, "reviewed.example", capture_state="failed",
        tier="cold", reviewed_by="analyst",
    )
    bundled = _add(session, "bundled.example", capture_state="failed", tier="cold")
    session.add(ReportBundle(code="B1", asset_id=bundled.id, channel="test"))
    alive = _add(session, "alive.example", capture_state="captured", tier="cold")

    # dead1 的关联数据，用来验证级联与解引用
    session.add(CaptureTask(asset_id=dead1.id, state="failed"))
    session.add(AssetSnapshot(asset_id=dead1.id, title="旧快照"))
    session.add(SignalRow(asset_id=dead1.id, rule_id="r1", category="c", title="t", weight=1.0, confidence=1.0))
    session.add(ScanRun(asset_id=dead1.id))
    session.add(WatchTarget(kind="asset", value="dead-port.example", asset_id=dead1.id))
    session.add(DiscoveryEvent(source="ct_poll", value="dead-port.example",
                               normalized="dead-port.example", asset_id=dead1.id))
    session.flush()
    return {
        "dead1": dead1.id, "dead2": dead2.id, "with_ev": with_ev.id,
        "with_campaign": with_campaign.id, "watched": watched.id,
        "high_risk": high_risk.id, "reviewed": reviewed.id,
        "bundled": bundled.id, "alive": alive.id,
    }


def test_error_class_categories():
    assert error_class("端口无法连接（HTTP/HTTPS 均不通）") == "端口无法连接"
    assert error_class("DNS 解析失败（NXDOMAIN）") == "DNS NXDOMAIN"
    assert error_class("被 Cloudflare 挑战 拦截") == "WAF 拦截"
    assert error_class("TimeoutError: Page.goto") == "超时"
    assert error_class("") == "(无错误文本)"


def test_select_candidates_only_pure_dead_sites(fresh_db):
    with session_scope() as s:
        ids = _seed(s)
        picked = {a.id for a in select_candidates(s)}
    assert picked == {ids["dead1"], ids["dead2"]}


def test_include_observed_and_high_risk_widen_criteria(fresh_db):
    with session_scope() as s:
        ids = _seed(s)
        picked = {
            a.id for a in select_candidates(s, include_observed=True, include_high_risk=True)
        }
    assert picked == {
        ids["dead1"], ids["dead2"], ids["watched"], ids["high_risk"],
    }


def test_dry_run_writes_nothing(fresh_db):
    with session_scope() as s:
        _seed(s)
    result = prune()
    assert result["dry_run"] is True
    assert result["candidates"] == 2
    assert "端口无法连接" in result["by_error"]
    with session_scope() as s:
        assert s.scalar(select(Asset).where(Asset.value == "dead-port.example")) is not None
        assert s.scalar(
            select(DiscoveryEvent).where(DiscoveryEvent.source == PRUNE_SOURCE)
        ) is None
    assert not (fresh_db / "archive").exists()


def test_archive_record_and_tombstone_are_self_contained(fresh_db):
    with session_scope() as s:
        ids = _seed(s)
        asset = s.get(Asset, ids["dead1"])
        record = archive_record(asset, reason="r", pruned_at="2026-11-09T00:00:00")
        tomb = build_tombstone(asset, archive_name="a.jsonl", reason="r", pruned_at="2026-11-09T00:00:00")
    assert record["value"] == "dead-port.example"
    assert record["capture_state"] == "failed"
    assert record["reason"] == "r"
    assert "meta" in record and "group_key" in record
    assert tomb.source == PRUNE_SOURCE
    assert tomb.raw["asset_id"] == ids["dead1"]
    assert tomb.raw["archive"] == "a.jsonl"
    assert "端口无法连接" in tomb.raw["capture_error"]


def test_apply_archives_tombstones_deletes_and_dereferences(fresh_db):
    with session_scope() as s:
        ids = _seed(s)
    result = prune(apply=True, reason="测试清理")
    assert result["applied"] is True
    assert result["deleted"] == 2
    assert result["tombstones"] == 2

    archive = fresh_db / result["archive"]
    assert archive.exists()
    lines = [json.loads(x) for x in archive.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(lines) == 2
    assert {x["value"] for x in lines} == {"dead-port.example", "dead-nx.example"}
    assert all(x["reason"] == "测试清理" for x in lines)

    with session_scope() as s:
        remaining = {a.value for a in s.scalars(select(Asset))}
        assert "dead-port.example" not in remaining
        assert "dead-nx.example" not in remaining
        # 有价值的一律保留
        for kept in ("with-evidence.example", "with-campaign.example", "watched.example",
                     "high-risk.example", "reviewed.example", "bundled.example", "alive.example"):
            assert kept in remaining
        # CASCADE 子表清空
        assert s.scalar(select(CaptureTask).where(CaptureTask.asset_id == ids["dead1"])) is None
        assert s.scalar(select(AssetSnapshot).where(AssetSnapshot.asset_id == ids["dead1"])) is None
        assert s.scalar(select(SignalRow).where(SignalRow.asset_id == ids["dead1"])) is None
        # NO ACTION / 无 FK 的两张表解引用，行本身保留
        scan = s.scalar(select(ScanRun))
        watch = s.scalar(select(WatchTarget))
        assert scan is not None and scan.asset_id is None
        assert watch is not None and watch.asset_id is None
        # 历史发现流水保留
        assert s.scalar(
            select(DiscoveryEvent).where(DiscoveryEvent.source == "ct_poll")
        ) is not None
        tombs = list(s.scalars(select(DiscoveryEvent).where(DiscoveryEvent.source == PRUNE_SOURCE)))
        assert len(tombs) == 2
        assert all(t.raw["archive"] == archive.name for t in tombs)


def test_restore_is_idempotent(fresh_db):
    with session_scope() as s:
        _seed(s)
    applied = prune(apply=True)
    archive = fresh_db / applied["archive"]

    first = restore(archive, apply=True)
    assert first["restored"] == 2 and first["skipped"] == 0
    second = restore(archive, apply=True)
    assert second["restored"] == 0 and second["skipped"] == 2
    with session_scope() as s:
        assert s.scalar(select(Asset).where(Asset.value == "dead-port.example")) is not None


def test_cli_prune_assets_registered():
    from silver_sentinel.cli import build_parser

    args = build_parser().parse_args(
        ["prune-assets", "--apply", "--include-observed", "--limit", "5"]
    )
    assert args.command == "prune-assets"
    assert args.apply is True
    assert args.include_observed is True
    assert args.limit == 5
    assert args.func.__name__ == "cmd_prune_assets"
