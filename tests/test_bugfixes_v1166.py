"""v1.16.6 批量修复回归：举报证据读取、配置、副本、接口参数、归档恢复等。

每条都对应一个能从代码直接复现的缺陷，不改断言去迁就实现。
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from silver_sentinel.api import app
from silver_sentinel.db import session_scope
from silver_sentinel.domain import utcnow
from silver_sentinel.models import Asset, DiscoveryEvent, Evidence


def _asset(session, value: str, **kw) -> Asset:
    row = Asset(kind="domain", value=value, normalized=value, **kw)
    session.add(row)
    session.flush()
    return row


def test_report_service_reads_vault_evidence(fresh_db, monkeypatch):
    """明文被删后 _evidence_paths 仍要拿到内容，否则举报包是空的。"""
    from silver_sentinel.report import service

    with session_scope() as s:
        a = _asset(s, "vault.example")
        ev = Evidence(
            asset_id=a.id, kind="page_text", sha256="a" * 64,
            prev_hash="", chain_hash="", size=12,
            captured_at=utcnow(), path="evidence/does-not-exist.txt", storage="vault",
        )
        s.add(ev)
        aid = a.id
        sha = ev.sha256

    payload = "测试正文".encode()
    monkeypatch.setattr("silver_sentinel.evidence.read_bytes", lambda row: payload)
    with session_scope() as s:
        rows, blobs = service._evidence_paths(s, aid)
    assert len(rows) == 1
    assert blobs.get(sha) == payload
    assert "测试正文" in service._page_text(rows, blobs)


def test_bundle_shrink_accepts_bytes():
    from silver_sentinel.report.bundle import _shrink

    data, mime = _shrink(b"\x89PNG\r\n\x1a\nnonsense")
    assert data  # 压缩失败也要原样返回，不能丢证据
    assert mime in ("image/png", "image/jpeg")


def test_config_reads_report_env(fresh_db, monkeypatch):
    from silver_sentinel.config import Settings

    monkeypatch.setenv("SILVER_REPORT_EXTENSION_TOKEN", "secret-token")
    monkeypatch.setenv("SILVER_REPORT_REPORTER", "张三")
    monkeypatch.setenv("SILVER_REPORT_MAX_SHOTS", "3")
    s = Settings()
    assert s.report_extension_token == "secret-token"
    assert s.report_reporter == "张三"
    assert s.report_max_shots == 3


def test_replica_skips_same_device(fresh_db, monkeypatch):
    """同盘副本不是备份，vault 密文与 DB 快照都应跳过。"""
    from silver_sentinel.core import replica as mod

    monkeypatch.setattr(mod, "_same_device", lambda: True)
    monkeypatch.setattr(mod.settings, "replica_backend", "dir")
    monkeypatch.setattr(mod.settings, "replica_enabled", True)
    monkeypatch.setattr(mod.settings, "replica_target", str(fresh_db / "replica"))
    r = mod.Replica()
    assert r.sync_vault_blobs() == 0
    assert r.sync_db() is False
    assert "same_device_warning" in r.run_once()


def test_assets_reject_invalid_pagination(fresh_db):
    with TestClient(app) as c:
        assert c.get("/api/assets?limit=0").status_code == 422
        assert c.get("/api/assets?offset=-1").status_code == 422
        assert c.get("/api/runs?limit=100000").status_code == 422
        assert c.get("/api/assets?limit=5&offset=0").status_code == 200


def test_discover_events_total_follows_source(fresh_db):
    with session_scope() as s:
        for src in ("ct_poll", "ct_poll", "pivot"):
            s.add(
                DiscoveryEvent(
                    source=src, kind="domain", value=f"{src}.example",
                    normalized=f"{src}.example", score_hint=0.1,
                )
            )
    with TestClient(app) as c:
        data = c.get("/api/discover/events?source=ct_poll").json()
    assert data["total"] == 2, data
    assert len(data["items"]) == 2


def test_prune_restore_dedups_by_kind_and_normalized(fresh_db):
    """唯一约束是 (kind, normalized)，只按 normalized 去重会误跳过一条。"""
    from silver_sentinel.prune import restore

    with session_scope() as s:
        _asset(s, "same.example")  # 已存在的是 domain/same.example
    archive = Path(fresh_db) / "archive.jsonl"
    archive.write_text(
        json.dumps({"kind": "url", "normalized": "same.example", "value": "https://same.example", "score": 0}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    out = restore(archive, apply=True)
    assert out["restored"] == 1, out
    assert out["skipped"] == 0, out


def test_serve_uses_settings_and_password(fresh_db, monkeypatch):
    """直接调 serve() 也必须读配置、生成口令，不能硬编码 0.0.0.0:8000。"""
    import silver_sentinel.api as api_mod

    calls: dict = {}
    monkeypatch.setattr(api_mod.settings, "web_host", "127.0.0.1")
    monkeypatch.setattr(api_mod.settings, "web_port", 18700)
    monkeypatch.setattr(api_mod.webauth, "ensure_password", lambda host: "pw")
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: calls.update(kw))
    api_mod.serve()
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 18700
