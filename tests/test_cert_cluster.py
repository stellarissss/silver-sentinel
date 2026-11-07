"""证书级关联：同一个团伙最硬的证据是「共用一张证书」。

线上背景：发现链路只按词库匹配单条域名，一张证书带 10~30 个 SAN，其中
往往只有 1~2 个域名含可疑词。剩下的兄弟站在内容上「干净」，靠词库永远
捞不到，但它们和已知可疑域名共享同一张证书——这比任何词都硬。

这里钉住四件事：

1. 强命中域名的证书兄弟会进待落库队列（冷档）；
2. 弱命中不扩散，避免噪音指数级放大；
3. 同一批里多个域名共用证书时互相标记（一次签发给整个站群）；
4. 库里已有同指纹的可疑资产时，新域名直接进候选池。
"""

from __future__ import annotations

import pytest


@pytest.fixture
def db(fresh_db):
    from silver_sentinel.db import session_scope

    return session_scope


def _obs(domain: str, names: list[str], fp: str = "fp-1"):
    from silver_sentinel.discover.ct import CertObservation

    return CertObservation(
        domain=domain,
        all_domains=names,
        issuer="Test CA",
        not_before="2026-01-01",
        fingerprint=fp,
        log_url="test",
        entry_index=0,
    )


def _engine():
    from silver_sentinel.discover.engine import DiscoveryEngine

    return DiscoveryEngine()


def test_strong_hit_spreads_cert_siblings():
    eng = _engine()
    # 「补帖」命中 variant，「扶贫」命中 policy_theme——任一强簇即可扩散
    obs = _obs(
        "butie-fafang.cn",
        ["butie-fafang.cn", "www.butie-fafang.cn", "laoren-butie.cn", "shanzhai-gov.top"],
    )
    eng._on_ct_batch([obs])

    values = [item[2] for item in list(eng.pending)]
    assert "butie-fafang.cn" in values
    assert "shanzhai-gov.top" in values
    # 兄弟进的是冷档提示，不抢真线索的优先级
    hints = {item[2]: item[3] for item in list(eng.pending)}
    assert hints["shanzhai-gov.top"] <= 0.35
    assert eng.stats.cert_siblings >= 2


def test_weak_hit_does_not_spread():
    """弱命中（只有载体词）扩散会放大噪音：一个词带出整张证书的几十个域名。"""
    eng = _engine()
    obs = _obs("app.foo.cn", ["app.foo.cn", "bar.cn", "baz.cn"])
    eng._on_ct_batch([obs])
    assert eng.stats.cert_siblings == 0


def test_whitelisted_sibling_skipped():
    eng = _engine()
    obs = _obs(
        "fupin-zhongxin.cn",
        ["fupin-zhongxin.cn", "www.mca.gov.cn", "fupin-bangfu.cn"],
    )
    eng._on_ct_batch([obs])
    values = [item[2] for item in list(eng.pending)]
    assert "www.mca.gov.cn" not in values
    assert "fupin-bangfu.cn" in values


def test_same_batch_cert_mates_marked(db):
    eng = _engine()
    fp = "same-batch-fp"
    rows = [
        (_obs("a-butie.cn", ["a-butie.cn"], fp), "domain", "a-butie.cn", 0.0, [], "a-butie.cn"),
        (_obs("b-butie.cn", ["b-butie.cn"], fp), "domain", "b-butie.cn", 0.0, [], "b-butie.cn"),
    ]
    from silver_sentinel.models import Asset

    with db() as s:
        created = eng._persist(s, rows)
        assert created == 2
        a = s.query(Asset).filter_by(normalized="a-butie.cn").one()
        b = s.query(Asset).filter_by(normalized="b-butie.cn").one()
        # 同批签发 = 站群，即便自己一个词都没命中，也进候选池
        assert a.tier == "candidate"
        assert b.tier == "candidate"
        assert a.meta.get("cert_siblings") == 1
        assert "同批签发" in a.discovery_reason


def test_cluster_from_known_asset(db):
    from silver_sentinel.models import Asset

    fp = "known-fp-001"
    with db() as s:
        s.add(
            Asset(
                kind="domain",
                value="known-bad.cn",
                normalized="known-bad.cn",
                tier="watch",
                score=62.0,
                fingerprint=fp,
                meta={"triaged": True},
            )
        )

    eng = _engine()
    rows = [(_obs("new-mate.cn", ["new-mate.cn"], fp), "domain", "new-mate.cn", 0.0, [], "new-mate.cn")]
    with db() as s:
        eng._persist(s, rows)

    with db() as s:
        asset = s.query(Asset).filter_by(normalized="new-mate.cn").one()
        assert asset.tier == "candidate"
        assert asset.meta.get("cert_cluster") == "known-bad.cn"
        assert "同证书" in asset.discovery_reason


def test_cold_asset_promoted_on_stronger_hit(db):
    from silver_sentinel.models import Asset

    eng = _engine()
    with db() as s:
        s.add(
            Asset(
                kind="domain",
                value="fupin-x.cn",
                normalized="fupin-x.cn",
                tier="cold",
                score=0.0,
                meta={"discover_hint": 0.3},
            )
        )

    rows = [(_obs("fupin-x.cn", ["fupin-x.cn"]), "domain", "fupin-x.cn", 0.85, ["扶贫"], "fupin-x.cn")]
    with db() as s:
        eng._persist(s, rows)

    with db() as s:
        asset = s.query(Asset).filter_by(normalized="fupin-x.cn").one()
        assert asset.tier == "candidate"
        assert eng.stats.cold_promoted == 1


def test_triaged_cold_asset_not_promoted(db):
    """已被研判过的冷档不动：发现信号不能覆盖评分结论。"""
    from silver_sentinel.models import Asset

    eng = _engine()
    with db() as s:
        s.add(
            Asset(
                kind="domain",
                value="ok-site.cn",
                normalized="ok-site.cn",
                tier="cold",
                score=8.0,
                meta={"discover_hint": 0.3, "triaged": True},
            )
        )

    rows = [(_obs("ok-site.cn", ["ok-site.cn"]), "domain", "ok-site.cn", 0.85, ["扶贫"], "ok-site.cn")]
    with db() as s:
        eng._persist(s, rows)

    with db() as s:
        assert s.query(Asset).filter_by(normalized="ok-site.cn").one().tier == "cold"
        assert eng.stats.cold_promoted == 0
