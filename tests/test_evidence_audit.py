"""证据体检：记录、明文、密文三者对齐。

线上踩过的坑：开了「上传后删明文」之后，`row.path` 指向的文件本来就不存在，
密文在 `data/vault/blobs/xx/<sha>.ssv`。只按 path 判断，会把 1.7 万条正常
证据全报成丢失——排查时一度以为 2.3 万条只剩 142 个文件。
"""

from __future__ import annotations

import base64
import os

import pytest
from sqlalchemy import func, select


@pytest.fixture
def vaulted(fresh_db, monkeypatch):
    """启用密文仓：dir 后端 + 上传后删明文。"""
    import silver_sentinel.vault as vault_mod
    from silver_sentinel.config import settings

    monkeypatch.setattr(vault_mod, "_vault", None)
    monkeypatch.setattr(settings, "vault_enabled", True)
    monkeypatch.setattr(settings, "vault_backend", "dir")
    monkeypatch.setattr(settings, "vault_key", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setattr(settings, "vault_node_id", "node-test")
    monkeypatch.setattr(settings, "vault_remove_plaintext", True)
    monkeypatch.setattr(settings, "vault_target", str(fresh_db / "remote"))
    yield settings
    monkeypatch.setattr(vault_mod, "_vault", None)


def _asset(session, value="demo-huimin.cc"):
    from silver_sentinel.models import Asset

    asset = Asset(kind="domain", value=value, normalized=value, tier="candidate")
    session.add(asset)
    session.flush()
    return asset


def test_same_content_is_stored_once(fresh_db):
    """同一资产、同一类证据、内容一样：文件只存一份，行也只有一行。

    周期性取证时，一个挂 Cloudflare 的站每轮都落一份一模一样的拦截页截图。
    线上 2.3 万条证据里有 4100 条是这种重复。重新取证是常态，重复记账不是。
    """
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append
    from silver_sentinel.models import Evidence

    with session_scope() as session:
        asset = _asset(session)
        first = append(session, asset.id, "page_html", b"<html>same</html>", extension=".html")
        second = append(session, asset.id, "page_html", b"<html>same</html>", extension=".html")
        assert first.id == second.id

    with session_scope() as session:
        assert session.scalar(select(func.count(Evidence.id))) == 1


def test_changed_content_adds_a_row(fresh_db):
    """内容变了必须新记一条——否则变更历史就断了。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append
    from silver_sentinel.models import Evidence

    with session_scope() as session:
        asset = _asset(session)
        append(session, asset.id, "page_html", b"<html>v1</html>", extension=".html")
        append(session, asset.id, "page_html", b"<html>v2</html>", extension=".html")

    with session_scope() as session:
        assert session.scalar(select(func.count(Evidence.id))) == 2


def test_dedupe_is_per_asset(fresh_db):
    """两个站共用同一张 WAF 拦截图：文件一份，但每条资产都要有记录。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append
    from silver_sentinel.models import Evidence

    with session_scope() as session:
        a = _asset(session, "a.cn")
        b = _asset(session, "b.cn")
        append(session, a.id, "screenshot", b"PNG-SAME", extension=".png")
        append(session, b.id, "screenshot", b"PNG-SAME", extension=".png")

    with session_scope() as session:
        assert session.scalar(select(func.count(Evidence.id))) == 2


def test_redaction_marks_vault_and_stays_readable(fresh_db, vaulted):
    """删明文之后：storage 变 vault，文件不在证据目录，但内容仍读得出。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append, path_of, read_bytes, read_status
    from silver_sentinel.models import Evidence
    from silver_sentinel.vault import Vault

    with session_scope() as session:
        asset = _asset(session)
        row = append(session, asset.id, "page_html", b"<html>secret</html>", extension=".html")
        ev_id, plain_path = row.id, path_of(row)

    assert plain_path.is_file()
    assert Vault().push()["pushed"] == 1

    with session_scope() as session:
        row = session.get(Evidence, ev_id)
        assert row.storage == "vault"
        assert not path_of(row).exists()
        assert read_bytes(row) == b"<html>secret</html>"
        assert read_status(row) == "vault"


def test_audit_reports_no_loss_after_redaction(fresh_db, vaulted):
    """这正是线上误判的场景：明文全被删了，但一条都没丢。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append, audit
    from silver_sentinel.vault import Vault

    with session_scope() as session:
        asset = _asset(session)
        for i in range(5):
            append(session, asset.id, "page_text", f"text {i}".encode(), extension=".txt")
    Vault().push()

    out = audit()
    assert out["total"] == 5
    assert out["vault"] == 5
    assert out["plain"] == 0
    assert out["missing"] == 0
    assert out["missing_ids"] == []
    assert out["orphan_blobs"] == 0


def test_audit_finds_real_loss(fresh_db, vaulted):
    """密文被外力删掉才算真丢失，要报出来，不能静默。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append, audit
    from silver_sentinel.vault import Vault, blob_path

    with session_scope() as session:
        asset = _asset(session)
        row = append(session, asset.id, "page_text", b"gone", extension=".txt")
        sha = row.sha256
    Vault().push()
    blob_path(sha).unlink()

    out = audit()
    assert out["missing"] == 1
    assert out["missing_ids"]


def test_repair_backfills_storage_column(fresh_db, vaulted):
    """老库的 storage 是空串：修复后要能正确归类，且不动文件。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append, repair
    from silver_sentinel.models import Evidence
    from silver_sentinel.vault import Vault

    with session_scope() as session:
        asset = _asset(session)
        keep = append(session, asset.id, "page_html", b"<html>a</html>", extension=".html")
        sealed = append(session, asset.id, "page_text", b"plain text", extension=".txt")
        keep_id, sealed_id = keep.id, sealed.id
    Vault().push()

    with session_scope() as session:
        for row in session.scalars(select(Evidence)).all():
            row.storage = ""  # 模拟迁移前的空值

    out = repair(fix=True)
    assert out["fixed"]["to_vault"] >= 1

    with session_scope() as session:
        assert session.get(Evidence, sealed_id).storage == "vault"
        assert session.get(Evidence, keep_id).storage == "vault"


def test_gc_removes_orphan_blobs(fresh_db, vaulted):
    """没有记录引用的密文只是占盘，删掉不影响任何可读性。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append, gc_orphans
    from silver_sentinel.vault import Vault, blob_path

    with session_scope() as session:
        asset = _asset(session)
        row = append(session, asset.id, "page_text", b"kept", extension=".txt")
        kept = row.sha256
    Vault().push()

    orphan = blob_path("f" * 64)
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(b"junk")

    dry = gc_orphans(dry_run=True)
    assert dry["removed"] == 1
    assert orphan.exists(), "dry-run 不能删东西"

    real = gc_orphans(dry_run=False)
    assert real["removed"] == 1
    assert not orphan.exists()
    assert blob_path(kept).exists()


def test_push_skips_copy_when_target_is_same_disk(fresh_db, vaulted, monkeypatch):
    """「远端」和本地同盘时，push 不该再写一份。

    线上就是这种配置：data/ 与 vault-store/ 都在 /dev/vda1，1.6G 密文
    被完整复制成 3.3G，磁盘长期 92%。同盘双份不是备份。
    """
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append
    from silver_sentinel.vault import Vault, blob_path

    monkeypatch.setattr(vaulted, "vault_skip_same_device_copy", True)
    with session_scope() as session:
        asset = _asset(session)
        row = append(session, asset.id, "page_text", b"only-once", extension=".txt")
        sha = row.sha256

    out = Vault().push()
    assert out["pushed"] == 1
    assert out["bytes"] == 0, "同盘复制不该产生任何上传字节"
    assert blob_path(sha).is_file()
    remote = vaulted.data_dir / "remote" / "blobs" / sha[:2] / f"{sha}.ssv"
    assert not remote.exists()


def test_dedupe_remote_removes_duplicate_copy(fresh_db, vaulted):
    """重复副本可回收，但本地那份必须还在。"""
    from silver_sentinel.db import session_scope
    from silver_sentinel.evidence import append
    from silver_sentinel.vault import Vault, blob_path

    with session_scope() as session:
        asset = _asset(session)
        row = append(session, asset.id, "page_text", b"duplicated", extension=".txt")
        sha = row.sha256

    vault = Vault()
    vault.push()  # 默认配置：写一份到「远端」
    remote = vaulted.data_dir / "remote" / "blobs" / sha[:2] / f"{sha}.ssv"
    assert remote.is_file()

    dry = vault.dedupe_remote(dry_run=True)
    assert dry["removed"] == 1
    assert remote.is_file(), "dry-run 不能删"

    real = vault.dedupe_remote(dry_run=False)
    assert real["removed"] == 1
    assert not remote.exists()
    assert blob_path(sha).is_file(), "本地那份不能被顺手删掉"
