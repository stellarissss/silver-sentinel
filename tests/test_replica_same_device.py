"""同盘 dir 副本必须整轮跳过，而不只是跳过 vault/DB。

线上实测：只跳过 vault 密文与数据库快照后，事件分片与明文证据仍以
377 个文件/小时往同盘副本里堆，磁盘照样吃到 97%。同盘「副本」本来就不是
备份，四类同步都不该跑。
"""

from __future__ import annotations


def _replica(fresh_db, monkeypatch):
    from silver_sentinel.core import replica as mod

    monkeypatch.setattr(mod, "_same_device", lambda: True)
    monkeypatch.setattr(mod.settings, "replica_backend", "dir")
    monkeypatch.setattr(mod.settings, "replica_enabled", True)
    monkeypatch.setattr(mod.settings, "replica_target", str(fresh_db / "replica"))
    return mod.Replica()


def test_run_once_skips_all_syncs_on_same_device(fresh_db, monkeypatch):
    r = _replica(fresh_db, monkeypatch)
    calls: list[str] = []
    for name in ("sync_events", "sync_evidence", "sync_vault_blobs", "sync_db"):
        monkeypatch.setattr(r, name, lambda *a, _n=name, **kw: calls.append(_n) or 0)

    out = r.run_once(include_db=True)
    assert out["ok"] is True
    assert out["skipped"] is True
    assert "same_device_warning" in out
    assert calls == [], f"同盘仍调用了同步：{calls}"


def test_each_sync_is_individually_guarded(fresh_db, monkeypatch):
    """被 CLI 单独调用时也不能绕过同盘判断。"""
    r = _replica(fresh_db, monkeypatch)
    assert r.sync_events() == 0
    assert r.sync_evidence() == 0
    assert r.sync_vault_blobs() == 0
    assert r.sync_db() is False


def test_different_device_still_syncs(fresh_db, monkeypatch):
    """改成异盘后同步必须恢复，不能把整个副本功能一刀切关掉。"""
    from silver_sentinel.core import replica as mod

    monkeypatch.setattr(mod, "_same_device", lambda: False)
    monkeypatch.setattr(mod.settings, "replica_backend", "dir")
    monkeypatch.setattr(mod.settings, "replica_enabled", True)
    monkeypatch.setattr(mod.settings, "replica_target", str(fresh_db / "replica"))
    r = mod.Replica()
    out = r.run_once(include_db=True)
    assert "skipped" not in out
    assert "event_bytes" in out
    assert "evidence_files" in out
