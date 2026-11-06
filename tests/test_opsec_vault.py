"""OPSEC 与加密证据仓的测试。

重点不在「函数能跑」，而在三条底线：
1. 没代理时可疑目标必须被拒绝（fail-closed），不能悄悄直连；
2. 密文改一个字节就解不开，且换密钥也解不开；
3. 第二个节点只凭账本 + 密文就能重建全部证据，且两边的哈希链都能自证。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest

from silver_sentinel.opsec import EgressBlocked, Guard, ProxyPool
from silver_sentinel.vault import VaultError, _open_with_length, _seal_with_length

# ---------------------------------------------------------------- OPSEC


def _guard(**kwargs) -> Guard:
    guard = Guard(**kwargs)
    guard.own_ips = {"203.0.113.9"}
    guard.own_hostnames = {"collector-01"}
    return guard


def test_classify_blocks_internal_and_regulator() -> None:
    guard = _guard(enabled=True, allow_direct=False, proxies=ProxyPool([]))
    assert guard.classify("http://169.254.169.254/latest/meta-data/") == "blocked"
    assert guard.classify("http://127.0.0.1:8000/") == "internal"
    assert guard.classify("https://www.12377.cn/report") == "blocked"
    assert guard.classify("https://crt.sh/?q=test") == "intel"
    assert guard.classify("https://wyvern.ct.digicert.com/2026h2/") == "intel"
    assert guard.classify("https://ct.cloudflare.com/logs/nimbus2026/") == "intel"
    assert guard.classify("https://www.gstatic.com/ct/log_list/v3/log_list.json") == "intel"
    assert guard.classify("https://some-scam.top/") == "suspect"
    assert guard.classify("http://203.0.113.9/") == "blocked"      # 自己的 IP
    assert guard.classify("file:///etc/passwd") == "blocked"


def test_preflight_fail_closed_without_proxy() -> None:
    guard = _guard(enabled=True, allow_direct=False, proxies=ProxyPool([]))
    with pytest.raises(EgressBlocked):
        guard.preflight("https://some-scam.top/")
    # 情报源即使没代理也允许（不暴露给对手）
    assert guard.preflight("https://crt.sh/") == "intel"

    relaxed = _guard(enabled=True, allow_direct=True, proxies=ProxyPool([]))
    assert relaxed.preflight("https://some-scam.top/") == "suspect"


def test_proxy_pool_rotation_and_cooldown() -> None:
    pool = ProxyPool(["socks5h://127.0.0.1:9050", "socks5h://127.0.0.1:9150"])
    first = pool.pick()
    second = pool.pick()
    assert first is not None and second is not None
    assert first.url != second.url
    pool.report(first, False)
    assert first.failures == 1
    assert first.cooldown_until > 0


def test_redact_removes_infrastructure_fingerprint() -> None:
    guard = _guard(enabled=True, allow_direct=True, proxies=ProxyPool([]))
    guard.extra_identifiers = {"ops@example.org"}
    text = (
        "采集自 203.0.113.9（内网 192.168.1.5）主机 collector-01，"
        "路径 /root/.codebuddy/data，联系人 ops@example.org"
    )
    cleaned = guard.redact(text)
    assert "203.0.113.9" not in cleaned
    assert "collector-01" not in cleaned
    assert "192.168.1.5" not in cleaned
    assert "ops@example.org" not in cleaned
    assert "[ip-redacted]" in cleaned


def test_find_leaks_blocks_export() -> None:
    guard = _guard(enabled=True, allow_direct=True, proxies=ProxyPool([]))
    payload = {"note": "由 203.0.113.9 采集", "nested": [{"host": "collector-01"}]}
    findings = guard.find_leaks(payload)
    assert len(findings) == 2
    with pytest.raises(RuntimeError):
        guard.assert_clean(payload)


def test_honeypot_detects_reflection_and_own_ip() -> None:
    guard = _guard(enabled=True, allow_direct=True, proxies=ProxyPool([]))
    hit = guard.honeypot_check("your address is 203.0.113.9", canary="ssvabc")
    assert hit["suspected"] and hit["score"] > 0

    reflected = guard.honeypot_check("echo ssvabc", canary="ssvabc")
    assert reflected["suspected"]

    clean = guard.honeypot_check("欢迎参加免费领鸡蛋活动", canary="ssvabc")
    assert not clean["suspected"]


# ---------------------------------------------------------------- 加密


def test_seal_roundtrip_and_tamper_detection() -> None:
    key = os.urandom(32)
    data = "受害者聊天记录".encode()
    sha = hashlib.sha256(data).hexdigest()

    blob = _seal_with_length(data, key, sha)
    assert blob.startswith(b"SSV1")
    assert _open_with_length(blob, key, sha) == data

    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    with pytest.raises(VaultError):
        _open_with_length(bytes(tampered), key, sha)

    with pytest.raises(VaultError):
        _open_with_length(blob, os.urandom(32), sha)

    # 换一个 SHA-256 作为 AAD 也必须失败：防止密文被改名挪用
    with pytest.raises(VaultError):
        _open_with_length(blob, key, hashlib.sha256(b"other").hexdigest())


# ---------------------------------------------------------------- 双节点同步


def _prepare(path, *, monkeypatch, key_b64: str, node: str):
    from silver_sentinel.config import settings
    from silver_sentinel.db import get_engine, reset_engine
    from silver_sentinel.models import Base

    (path / "evidence").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "data_dir", path)
    monkeypatch.setattr(settings, "vault_enabled", True)
    monkeypatch.setattr(settings, "vault_backend", "dir")
    monkeypatch.setattr(settings, "vault_key", key_b64)
    monkeypatch.setattr(settings, "vault_node_id", node)
    monkeypatch.setattr(settings, "vault_remove_plaintext", False)
    settings.db_url = f"sqlite:///{path / 'sentinel.db'}"
    reset_engine(settings.db_url)
    Base.metadata.create_all(get_engine())


def test_two_nodes_share_evidence(tmp_path, monkeypatch) -> None:
    from sqlalchemy import func, select

    from silver_sentinel import evidence as evidence_mod
    from silver_sentinel.config import settings
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset, Evidence
    from silver_sentinel.vault import Vault

    key_b64 = base64.b64encode(os.urandom(32)).decode()
    remote = tmp_path / "remote"
    monkeypatch.setattr(settings, "vault_target", str(remote))

    # 节点 A：采集并固化
    _prepare(tmp_path / "a", monkeypatch=monkeypatch, key_b64=key_b64, node="node-a")
    with session_scope() as session:
        asset = Asset(kind="domain", value="scam.example", normalized="scam.example", tier="candidate")
        session.add(asset)
        session.flush()
        evidence_mod.append(session, asset.id, "html", b"<html>free eggs</html>", extension=".html")

    vault_a = Vault()
    assert vault_a.push()["pushed"] == 1
    assert vault_a.verify()["ok"] is True
    assert (remote / "blobs").is_dir()

    # 明文不能出现在远端：远端只应有 .ssv 密文与账本
    remote_files = [p.name for p in remote.rglob("*") if p.is_file()]
    assert any(n.endswith(".ssv") for n in remote_files)
    assert not any(n.endswith(".html") for n in remote_files)

    # 节点 B：只凭账本 + 密文重建
    _prepare(tmp_path / "b", monkeypatch=monkeypatch, key_b64=key_b64, node="node-b")
    vault_b = Vault()
    result = vault_b.pull()
    assert result["imported"] == 1

    with session_scope() as session:
        assert session.scalar(select(func.count(Evidence.id))) == 1
        assert session.scalar(select(func.count(Asset.id))) == 1
        row = session.scalars(select(Evidence)).first()
        assert row.sha256 == hashlib.sha256(b"<html>free eggs</html>").hexdigest()
        assert row.chain_hash
        # 研判结果随账本一起过河，新节点不是一堆"未研判"
        pulled_asset = session.scalars(select(Asset)).first()
        assert pulled_asset.value == "scam.example"

    assert vault_b.verify()["ok"] is True
    # 拉取后再推送，B 也把自己的账本写上去（双向）
    assert vault_b.push()["pushed"] == 1
    assert (remote / "ledger" / "node-b.jsonl").is_file()


def test_manifest_tamper_is_detected(tmp_path, monkeypatch) -> None:
    from silver_sentinel import evidence as evidence_mod
    from silver_sentinel.config import settings
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset
    from silver_sentinel.vault import Vault

    key_b64 = base64.b64encode(os.urandom(32)).decode()
    monkeypatch.setattr(settings, "vault_target", str(tmp_path / "remote"))
    _prepare(tmp_path / "a", monkeypatch=monkeypatch, key_b64=key_b64, node="node-a")

    with session_scope() as session:
        asset = Asset(kind="domain", value="x.example", normalized="x.example", tier="candidate")
        session.add(asset)
        session.flush()
        evidence_mod.append(session, asset.id, "html", b"a", extension=".html")
        evidence_mod.append(session, asset.id, "html", b"b", extension=".html")

    vault = Vault()
    vault.push()
    assert vault.verify()["ok"] is True

    # 改掉第二条的备注，链必须断
    lines = vault.manifest_path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["evidence"]["note"] = "被篡改"
    lines[1] = json.dumps(second, ensure_ascii=False, separators=(",", ":"))
    vault.manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = vault.verify(deep=False)
    assert result["ok"] is False
    assert "哈希" in result["nodes"][0]["reason"]


def test_key_mismatch_cannot_open_remote_blob(tmp_path, monkeypatch) -> None:
    from silver_sentinel import evidence as evidence_mod
    from silver_sentinel.config import settings
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset
    from silver_sentinel.vault import Vault

    remote = tmp_path / "remote"
    monkeypatch.setattr(settings, "vault_target", str(remote))
    key_a = base64.b64encode(os.urandom(32)).decode()
    _prepare(tmp_path / "a", monkeypatch=monkeypatch, key_b64=key_a, node="node-a")
    with session_scope() as session:
        asset = Asset(kind="domain", value="y.example", normalized="y.example", tier="candidate")
        session.add(asset)
        session.flush()
        evidence_mod.append(session, asset.id, "html", b"secret", extension=".html")
    Vault().push()

    # 换一把钥匙的节点拉不动
    key_b = base64.b64encode(os.urandom(32)).decode()
    _prepare(tmp_path / "b", monkeypatch=monkeypatch, key_b64=key_b, node="node-b")
    result = Vault().pull()
    assert result["imported"] == 0
