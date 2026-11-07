"""发现落库：主机归并、证书指纹留存。

实测依据：22 小时里 CT 产生 2,512 个主机资产，但只对应 1,251 个注册域；
同时 2,512 条资产里 `fingerprint` 全为空——最强的同源证据被丢掉了，
图谱只能连 DNS，连不出「同一张证书签了 30 个仿冒站」这种团伙结构。
"""

from __future__ import annotations

from silver_sentinel.db import session_scope
from silver_sentinel.discover.engine import CertObservation, DiscoveryEngine
from silver_sentinel.models import Asset


def _obs(domain: str, fp: str = "a" * 64) -> CertObservation:
    return CertObservation(
        domain=domain,
        all_domains=[domain],
        issuer="CN=YE1,O=Let's Encrypt,C=US",
        not_before="2026-10-01T00:00:00+00:00",
        fingerprint=fp,
        log_url="https://ct.example/log",
        entry_index=1,
        source="ct_poll",
    )


def test_subdomains_collapse_to_registrable_domain(fresh_db):
    engine = DiscoveryEngine()
    rows = [
        (_obs("www.guohui-yanglao.cn"), "domain", "guohui-yanglao.cn", 0.85, ["国惠"], "www.guohui-yanglao.cn"),
        (_obs("blog.guohui-yanglao.cn"), "domain", "guohui-yanglao.cn", 0.85, ["国惠"], "blog.guohui-yanglao.cn"),
    ]
    with session_scope() as session:
        created = engine._persist(session, rows)
    assert created == 1
    with session_scope() as session:
        assets = session.query(Asset).all()
        assert len(assets) == 1
        assert assets[0].normalized == "guohui-yanglao.cn"
        assert sorted(assets[0].meta["hosts"]) == ["blog.guohui-yanglao.cn", "www.guohui-yanglao.cn"]


def test_cert_fingerprint_is_persisted(fresh_db):
    engine = DiscoveryEngine()
    with session_scope() as session:
        engine._persist(
            session,
            [(_obs("jiedong-vip.top", "b" * 64), "domain", "jiedong-vip.top", 0.95, ["解冻"], "jiedong-vip.top")],
        )
    with session_scope() as session:
        asset = session.query(Asset).one()
        assert asset.fingerprint == "b" * 64


def test_ct_log_list_payload_survives_unexpected_compression(monkeypatch):
    """服务端压缩、客户端没解时，不能把整份 CT 日志清单丢掉。

    线上实测：gstatic 用 br 回 log_list.json，而服务器 venv 没装 brotli，
    `resp.json()` 在 UTF-8 解码处抛 ValueError，于是每次启动都退回内置清单。
    内置清单会随日志冻结过期，这正是「进程在跑、一条新证书都不进来」的成因。
    """
    import gzip
    import json

    from silver_sentinel.discover.ct import _json_payload

    payload = {"operators": [{"name": "test", "logs": [{"description": "x"}]}]}
    raw = gzip.compress(json.dumps(payload).encode())

    class Resp:
        headers = {"content-encoding": ""}  # 假装客户端没有解开
        content = raw

        def json(self):
            raise ValueError("'utf-8' codec can't decode byte 0x1f in position 0")

    assert _json_payload(Resp()) == payload
