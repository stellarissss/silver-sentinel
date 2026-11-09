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


# ---------------------------------------------------------------- 批量证书主动扫描


def _rand_host(i: int, tld: str = "cn") -> str:
    """生成器吐出来的名字：短、字母数字混排、读不出来。i 保证唯一。"""
    import hashlib

    h = hashlib.sha1(f"seed{i}".encode()).hexdigest()
    letter = lambda j: chr(97 + int(h[j:j + 2], 16) % 26)  # noqa: E731
    digit = lambda j: str(int(h[j:j + 2], 16) % 10)  # noqa: E731
    return f"{letter(0)}{digit(2)}{letter(4)}{letter(6)}{digit(8)}.{tld}"


def _bulk_obs(count: int = 20, fp: str = "c" * 64, offset: int = 0) -> CertObservation:
    domains = [_rand_host(offset + i) for i in range(count)]
    return CertObservation(
        domain=domains[0],
        all_domains=domains,
        issuer="CN=LiteSSL,O=LiteSSL,C=CN",
        not_before="2026-11-01T00:00:00+00:00",
        fingerprint=fp,
        log_url="https://ct.example/log",
        entry_index=9,
    )


def test_bulk_cert_adopted_without_any_keyword_hit(fresh_db):
    """证书形状本身就是线索：不靠域名命中任何词库。

    线上的 88/94 条涉老都来自两张证书，且是因为「先抓到站、再读证书」才
    发现的。这条通道的判据只看 SAN 形状，能发现一个词都不命中的新站群。
    """
    engine = DiscoveryEngine()
    obs = _bulk_obs()
    engine._on_ct_batch([obs])

    assert engine.stats.bulk_adopted > 0
    queued = [row for row in engine.pending if row[4] == ["bulk_cert_scan"]]
    assert queued, "应有一批通过批量证书入池"
    assert all(row[3] == 0.58 for row in queued)
    assert all((row[0].source == "ct_bulk") for row in queued)


def test_bulk_cert_is_deduped_by_fingerprint(fresh_db):
    """一张 90 域名证书会产生 90 条观测，不能采纳 90 次。"""
    engine = DiscoveryEngine()
    obs = _bulk_obs()
    engine._on_ct_batch([obs, obs, obs])
    assert engine.stats.bulk_scanned == 1


def test_normal_multi_san_cert_is_ignored(fresh_db):
    """正常业务证书（baidu 那种）不该被当站群：名字都读得出来。"""
    engine = DiscoveryEngine()
    domains = [
        "click.hm.baidu.com", "baifubao.com", "map.baidu.com", "tieba.baidu.com",
        "zhidao.baidu.com", "wenku.baidu.com", "image.baidu.com", "news.baidu.com",
        "baiducontent.com", "bdstatic.com",
    ]
    obs = CertObservation(
        domain="baidu.com", all_domains=domains, issuer="CN=GlobalSign",
        not_before="2026-01-01T00:00:00+00:00", fingerprint="d" * 64,
        log_url="https://ct.example/log", entry_index=1,
    )
    engine._on_ct_batch([obs])
    assert engine.stats.bulk_adopted == 0


def test_bulk_scan_respects_daily_budget(fresh_db):
    """一天最多采纳 BULK_SCAN_DAILY 张，防止取证队列被批量证书灌爆。"""
    from silver_sentinel.discover.engine import BULK_SCAN_DAILY

    engine = DiscoveryEngine()
    for i in range(BULK_SCAN_DAILY + 3):
        engine._on_ct_batch([_bulk_obs(fp=f"{i:064d}", offset=i * 100)])
    assert engine.stats.bulk_scanned == BULK_SCAN_DAILY
