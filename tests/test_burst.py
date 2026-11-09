"""批量单域名证书聚合（v1.16）。

现场回归依据：v1.15 的 `_adopt_bulk_cert` 要求 `len(all_domains) >= 8`，
而线上 CT 观测 99% 是 1~2 个 SAN，`bulk_assets = 0`。这组用例锁住新判据：
「一批证书各挂一个域名」也必须能被识别，且正常站、多 SAN 证书、不同
签发者/后缀/时间桶都不能被误并成一批。
"""

from __future__ import annotations

import hashlib
import json
import time

import pytest

from silver_sentinel.discover.burst import (
    BURST_MIN_SIZE,
    FAMILY_MIN_SIZE,
    BurstDetector,
    family_key,
    issuer_key,
    name_signature,
    time_bucket,
)
from silver_sentinel.discover.engine import BURST_DAILY, CertObservation, DiscoveryEngine

_CONS = "bcdfghjkmnpqrstvwxz"
_DIGS = "23456789"


def _burst_domain(i: int, tld: str = "cn") -> str:
    """生成与实测站群同形态的域名：6 位、少元音、字母数字混排。"""
    h = hashlib.sha1(f"burst-{i}".encode()).digest()
    return (
        f"{_CONS[h[0] % len(_CONS)]}{_CONS[h[1] % len(_CONS)]}"
        f"{_DIGS[h[2] % len(_DIGS)]}{_CONS[h[3] % len(_CONS)]}"
        f"{_DIGS[h[4] % len(_DIGS)]}{_DIGS[h[5] % len(_DIGS)]}.{tld}"
    )


def _obs(domain: str, *, issuer: str = "CN=WE1,O=Let's Encrypt,C=US",
         nb: str = "2026-11-09T13:52:36+00:00", sans: int = 1,
         fp: str = "a" * 64) -> CertObservation:
    all_domains = [domain] if sans == 1 else [domain, f"www.{domain}"]
    return CertObservation(
        domain=domain,
        all_domains=all_domains,
        issuer=issuer,
        not_before=nb,
        fingerprint=fp,
        log_url="https://ct.example/log",
        entry_index=1,
        source="ct_poll",
    )


# ---------------------------------------------------------------- 归一化

def test_issuer_key_ignores_rotating_intermediate_cn():
    """WE1/WE2 是同一家 CA 轮换的中间证书，不能把一批劈成两桶。"""
    assert issuer_key("CN=WE1,O=Let's Encrypt,C=US") == issuer_key("CN=YR2,O=Let's Encrypt,C=US")
    assert issuer_key("CN=WE1,O=Google Trust Services,C=US") != issuer_key("CN=WE1,O=Let's Encrypt,C=US")


def test_time_bucket_is_10_minutes():
    assert time_bucket("2026-11-09T13:52:36+00:00") == time_bucket("2026-11-09T13:57:01+00:00")
    assert time_bucket("2026-11-09T13:52:36+00:00") != time_bucket("2026-11-09T14:02:00+00:00")


def test_name_signature_groups_same_generator():
    sigs = {name_signature(_burst_domain(i)) for i in range(8)}
    assert len(sigs) == 1
    assert name_signature("xindazx.cn") != sigs.pop()


# ---------------------------------------------------------------- 聚合器

def test_a_batch_of_single_domain_certs_fires():
    det = BurstDetector()
    names = [_burst_domain(i) for i in range(BURST_MIN_SIZE)]
    fired: list[tuple[str, float]] = []
    for i, d in enumerate(names):
        hit = det.observe(_obs(d, fp=f"{i:064d}"))
        if hit:
            fired = hit
    assert fired, "同签发者/同形态/同时间桶的一批单域名证书应触发"
    assert {d for d, _ in fired} == set(names)
    assert det.stats["bursts"] == 1


def test_www_plus_apex_is_one_site_not_two():
    """`www.x + x` 是同一站点的证书，不能算成两个域名凑批次。"""
    det = BurstDetector()
    names = [_burst_domain(i) for i in range(BURST_MIN_SIZE)]
    for i, d in enumerate(names):
        det.observe(_obs(d, sans=2, fp=f"{i:064d}"))
    assert det.stats["bursts"] == 1  # 8 个不同域名，仍只触发一次（不是重复计数）


def test_normal_domains_never_fire():
    det = BurstDetector()
    for d in ("baidu.com", "xindazx.cn", "huicetong.com", "michaelsaschalau.com",
              "docs.zk.link", "cctv-bet.vip", "guohui-yanglao.cn", "news.qq.com"):
        assert det.observe(_obs(d)) == []
    assert det.stats["candidates"] == 0
    assert det.stats["bursts"] == 0


def test_multi_san_cert_does_not_enter_burst():
    """多 SAN 证书交给 _adopt_bulk_cert，别在聚合器里重复计数。"""
    det = BurstDetector()
    big = [_burst_domain(i) for i in range(12)]
    o = _obs(big[0])
    o.all_domains = big
    assert det.observe(o) == []
    assert det.stats["candidates"] == 0
    assert det.stats["bursts"] == 0


def test_different_issuer_tld_or_time_do_not_merge():
    """三个桶各差一个凑不满，累加起来 21 条也不该触发——证明分桶真的生效。"""
    det = BurstDetector()
    for i in range(BURST_MIN_SIZE - 1):
        d = _burst_domain(i)
        det.observe(_obs(d, issuer="CN=WE1,O=Google Trust Services,C=US", fp=f"g{i:063d}"))
        det.observe(_obs(_burst_domain(i, tld="top"), fp=f"t{i:063d}"))
        det.observe(_obs(d, nb="2026-11-09T14:12:00+00:00", fp=f"l{i:063d}"))
    assert det.stats["candidates"] == 3 * (BURST_MIN_SIZE - 1)
    assert det.stats["bursts"] == 0, "不同签发者/后缀/时间桶不应被混成一批"


def test_cooldown_prevents_same_batch_reappearing():
    det = BurstDetector()
    names = [_burst_domain(i) for i in range(BURST_MIN_SIZE)]
    for i, d in enumerate(names):
        det.observe(_obs(d, fp=f"{i:064d}"))
    assert det.stats["bursts"] == 1
    for i, d in enumerate(names):
        assert det.observe(_obs(d, fp=f"{i:064d}")) == []
    assert det.stats["bursts"] == 1


def test_allowed_callback_filters_whitelisted():
    det = BurstDetector()
    names = [_burst_domain(i) for i in range(BURST_MIN_SIZE)]
    blocked = {names[0]}
    for i, d in enumerate(names):
        det.observe(_obs(d, fp=f"{i:064d}"), allowed=lambda r: r not in blocked)
    assert det.stats["bursts"] == 0, "少一个就不该凑够一批"


def test_prune_drops_stale_buckets():
    det = BurstDetector(ttl=0.0)
    names = [_burst_domain(i) for i in range(BURST_MIN_SIZE - 1)]
    for i, d in enumerate(names):
        det.observe(_obs(d, fp=f"{i:064d}"))
    # ttl=0：下一条进来时旧桶已被清掉，凑不满
    assert det.observe(_obs(_burst_domain(99))) == []
    assert det.as_dict()["open_buckets"] <= 1


# ---------------------------------------------------------------- 引擎接入

def test_engine_adopts_burst_into_pending(fresh_db):
    """_on_ct_batch 喂一批单域名证书 → 产生 ct_burst 候选，且受取证保护。"""
    engine = DiscoveryEngine()
    names = [_burst_domain(i) for i in range(BURST_MIN_SIZE)]
    obs = [_obs(d, fp=f"{i:064d}") for i, d in enumerate(names)]
    # 词库对这些随机串必然零命中，正好验证「不依赖关键词」
    engine._on_ct_batch(obs)
    assert engine.stats.burst_batches == 1
    assert engine.stats.burst_adopted == BURST_MIN_SIZE
    with engine._pending_lock:
        burst_rows = [r for r in engine.pending if r[0] is not None and r[0].source == "ct_burst"]
    assert len(burst_rows) == BURST_MIN_SIZE
    assert all(r[3] >= 0.58 for r in burst_rows)
    assert all("burst_cert" in r[4] for r in burst_rows)


def test_engine_burst_daily_budget(fresh_db):
    engine = DiscoveryEngine()
    # 每批换一个合法的 10 分钟桶（不同桶 = 不同冷却键），跑满日预算 + 3
    for m in range(BURST_DAILY + 3):
        names = [_burst_domain(i + m * 20) for i in range(BURST_MIN_SIZE)]
        nb = f"2026-11-09T{m // 6:02d}:{(m % 6) * 10:02d}:00+00:00"
        engine._on_ct_batch([_obs(d, nb=nb, fp=f"{m:02d}{i:062d}")
                             for i, d in enumerate(names)])
    assert engine.stats.burst_batches == BURST_DAILY


def test_engine_persists_burst_await_capture(fresh_db):
    """ct_burst 属于已拿结构化证据的线索：入库即受 await_capture 保护。"""
    from sqlalchemy import select

    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset

    engine = DiscoveryEngine()
    names = [_burst_domain(i) for i in range(BURST_MIN_SIZE)]
    engine._on_ct_batch([_obs(d, fp=f"{i:064d}") for i, d in enumerate(names)])
    with engine._pending_lock:
        rows = list(engine.pending)
        engine.pending.clear()
    with session_scope() as s:
        engine._persist(s, rows)
    with session_scope() as s:
        for d in names:
            row = s.scalar(select(Asset).where(Asset.normalized == d))
            assert row is not None
            assert row.meta.get("await_capture") is True


# ---------------------------------------------------------------- 前缀族（v1.16.1 主判据）

# 离线重放 8000 条生产 CT 事件校准出来的五族，域名与形态分都取自现场。
_FAMILIES = {
    "yl|com": ["yl8387.com", "yl5837.com", "yl2828.com", "yl770.com", "yl1990.com"],
    "cctv|com": ["05cctv.com", "15cctv.com", "cctv668.com", "cctv9527.com", "cctv1234.com"],
    "mz|top": ["mz790.top", "mz749.top", "mz920.top", "mz88.top", "mz1234.top"],
    "zk|cc": ["zk881.cc", "zk234.cc", "zk7788.cc", "zk12.cc", "zk5678.cc"],
    "boc|top": ["boc123.top", "boc456.top", "boc8899.top", "boc77.top", "boc2024.top"],
}


def test_family_key_maps_long_running_generator_domains():
    """现场站群：固定字母前缀 + 变数字；数字在前（05cctv）也要认。"""
    for expected, names in _FAMILIES.items():
        assert {family_key(d) for d in names} == {expected}
    assert family_key("yl770.com") == "yl|com"          # 线上反复出现
    assert family_key("05cctv.com") == "cctv|com"        # 数字前缀


def test_family_key_rejects_normal_and_hyphenated():
    for d in ("baidu.com", "cctv.com", "google.com", "cctv-bet.vip",
              "docs.zk.link", "michaelsaschalau.com", "guohui-yanglao.cn",
              "xindazx.cn", "huicetong.com"):
        assert family_key(d) is None, d


def test_family_key_is_tld_scoped():
    assert family_key("yl8387.com") != family_key("yl8387.top")
    assert family_key("yl8387.com") == "yl|com"


@pytest.mark.parametrize("family", sorted(_FAMILIES))
def test_prefix_family_fires_at_five_domains(family):
    """主力判据：同族累计 5 个即触发，不要求同一时刻签发（长期运营族）。"""
    det = BurstDetector()
    names = _FAMILIES[family][:FAMILY_MIN_SIZE]
    fired: list[tuple[str, float]] = []
    for i, d in enumerate(names):
        # 故意摊到不同的日子，证明判据不吃证书签发时刻
        hit = det.observe(_obs(d, nb=f"2026-08-{i + 1:02d}T00:00:00+00:00"))
        if hit:
            fired = hit
    assert {d for d, _ in fired} == set(names)
    assert det.stats["families"] == 1
    assert det.stats["windows"] == 0
    assert det.stats["bursts"] == 1


def test_digit_prefix_family_is_grouped_with_letter_prefix():
    """`05cctv.com`（数字在前）与 `cctv668.com`（字母在前）必须归同一族。

    只认「字母前缀 + 数字」会把冒充央视族劈成两半，各自都凑不满 5 个。
    """
    assert family_key("05cctv.com") == family_key("cctv668.com") == "cctv|com"
    det = BurstDetector()
    fired: list[tuple[str, float]] = []
    for d in _FAMILIES["cctv|com"][:FAMILY_MIN_SIZE]:
        hit = det.observe(_obs(d))
        if hit:
            fired = hit
    assert len(fired) == FAMILY_MIN_SIZE
    assert det.stats["families"] == 1 and det.stats["windows"] == 0


def test_family_shape_gate_blocks_readable_prefix():
    """`web####.com` 五个确实同族，但形态分 0.36 被闸门挡在桶外。"""
    names = ["web2024.com", "web2025.com", "web2026.com", "web2027.com", "web2028.com"]
    assert {family_key(d) for d in names} == {"web|com"}
    det = BurstDetector()
    for d in names:
        assert det.observe(_obs(d)) == []
    assert det.stats["candidates"] == 0
    assert det.stats["bursts"] == 0


def test_family_observation_not_double_counted_into_window():
    """命中族的观测只进族桶：candidates 每条恰好 +1，不留空桶。"""
    det = BurstDetector()
    for d in _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]:
        det.observe(_obs(d))
    assert det.stats["candidates"] == FAMILY_MIN_SIZE
    assert det.stats["windows"] == 0
    assert det.as_dict()["open_buckets"] == 0


def test_family_and_window_have_separate_buckets():
    det = BurstDetector()
    for d in _FAMILIES["mz|top"][:FAMILY_MIN_SIZE]:
        det.observe(_obs(d))
    for i, d in enumerate(_burst_domain(i) for i in range(BURST_MIN_SIZE)):
        det.observe(_obs(d, fp=f"{i:064d}"))
    assert det.stats["families"] == 1
    assert det.stats["windows"] == 1
    assert det.stats["bursts"] == 2


def test_family_cooldown_accumulates_instead_of_dropping():
    """核心回归：冷却期内新域名必须继续入桶，不能在 return [] 时丢掉。

    历史追平时一个族会一次涌入几十个域名，旧实现只采纳前 5 个、
    其余在冷却里全部丢弃。
    """
    det = BurstDetector(cooldown=999999.0)
    first = _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]
    later = ["yl2201.com", "yl3302.com", "yl4403.com", "yl5504.com", "yl6605.com"]
    for d in first + later:
        det.observe(_obs(d))
    assert det.stats["bursts"] == 1
    assert det.stats["candidates"] == 10, "冷却期内 5 个新域名被丢了"
    det.cooldown = 0.0        # 模拟冷却结束
    hit = det.observe(_obs("yl7707.com"))
    assert hit and det.stats["bursts"] == 2
    assert {d for d, _ in hit} >= set(later)


def test_seen_domains_not_readopted():
    """CT 补历史 / 游标回退重放同一批：域名级去重挡住，不再占桶。"""
    det = BurstDetector()
    names = _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]
    for d in names:
        det.observe(_obs(d))
    assert det.stats["candidates"] == FAMILY_MIN_SIZE
    for d in names:
        assert det.observe(_obs(d)) == []
    assert det.stats["candidates"] == FAMILY_MIN_SIZE
    assert det.stats["bursts"] == 1
    assert det.as_dict()["seen_domains"] == FAMILY_MIN_SIZE


def test_adoptable_false_queues_observations():
    """引擎日预算耗尽时只累积不产出，预算恢复后第一批即补采。"""
    det = BurstDetector()
    names = _FAMILIES["zk|cc"][:FAMILY_MIN_SIZE]
    for d in names:
        assert det.observe(_obs(d), adoptable=False) == []
    assert det.stats["candidates"] == FAMILY_MIN_SIZE
    assert det.stats["bursts"] == 0
    assert det.as_dict()["open_buckets"] == 1
    hit = det.observe(_obs("zk9900.cc"))
    assert hit and len(hit) == FAMILY_MIN_SIZE + 1
    assert det.stats["bursts"] == 1


def test_limit_truncation_keeps_remaining_domains():
    """limit 截断后剩余域名留在桶里等下一批，不随 clear 一起消失。"""
    det = BurstDetector(cooldown=0.0)
    first: list[tuple[str, float]] = []
    for d in _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]:
        hit = det.observe(_obs(d), limit=2)
        if hit:
            first = hit
    assert len(first) == 2
    assert det.as_dict()["open_buckets"] == 1, "剩下 3 个域名应留在桶里"
    second: list[tuple[str, float]] = []
    for d in ("yl2201.com", "yl3302.com"):
        hit = det.observe(_obs(d), limit=2)
        if hit:
            second = hit
    assert len(second) == 2
    assert not ({d for d, _ in first} & {d for d, _ in second}), "两批不该重复采纳"


# ---------------------------------------------------------------- 引擎证据链

def test_engine_reason_records_family_evidence(fresh_db):
    """证据链要写清是「哪条判据」判的，不能一律写成同签发者同时段。"""
    engine = DiscoveryEngine()
    names = _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]
    engine._on_ct_batch([_obs(d) for d in names])
    assert engine.stats.burst_batches == 1
    assert engine.stats.burst_adopted == FAMILY_MIN_SIZE
    with engine._pending_lock:
        rows = [r for r in engine.pending if r[0] is not None and r[0].source == "ct_burst"]
    assert len(rows) == FAMILY_MIN_SIZE
    assert all("站群前缀族 yl|com" in r[0].note for r in rows)


def test_engine_window_reason_mentions_same_issuer(fresh_db):
    engine = DiscoveryEngine()
    names = [_burst_domain(i) for i in range(BURST_MIN_SIZE)]
    engine._on_ct_batch([_obs(d, fp=f"{i:064d}") for i, d in enumerate(names)])
    with engine._pending_lock:
        rows = [r for r in engine.pending if r[0] is not None and r[0].source == "ct_burst"]
    assert rows and all("同签发者同时段" in r[0].note for r in rows)


def test_engine_budget_exhaustion_queues_observations(fresh_db):
    """预算耗尽不跳过 observe：线索排队，次日额度恢复后第一批即补采。"""
    engine = DiscoveryEngine()
    engine._burst_day = time.strftime("%Y-%m-%d")
    engine._burst_today = BURST_DAILY
    for d in _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]:
        engine._on_ct_batch([_obs(d)])
    assert engine.stats.burst_batches == 0
    assert engine._burst.as_dict()["open_buckets"] >= 1, "预算耗尽把线索丢了"
    engine._burst_today = 0        # 次日额度恢复
    engine._on_ct_batch([_obs("yl9999.com")])
    assert engine.stats.burst_batches == 1
    assert engine.stats.burst_adopted >= FAMILY_MIN_SIZE


# ---------------------------------------------------------------- 历史回放与写入加固

def test_replay_ct_observations_adopts_family_and_persists(fresh_db):
    """历史 CT 流水按前缀族重新聚合：族批次入库，证据链写族键，受取证保护。"""
    from sqlalchemy import select

    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset

    engine = DiscoveryEngine()
    names = _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]
    result = engine.replay_ct_observations([_obs(d) for d in names])
    assert result["batches"] == 1 and result["adopted"] == FAMILY_MIN_SIZE
    assert result["families"] == 1 and result["windows"] == 0
    assert result["created"] == FAMILY_MIN_SIZE
    with session_scope() as s:
        for d in names:
            row = s.scalar(select(Asset).where(Asset.normalized == d))
            assert row is not None
            assert row.discovery_source == "ct_burst"
            assert "站群前缀族 yl|com" in (row.discovery_reason or "")
            assert row.meta.get("await_capture") is True


def test_replay_ct_is_idempotent(fresh_db):
    engine = DiscoveryEngine()
    names = _FAMILIES["mz|top"][:FAMILY_MIN_SIZE]
    first = engine.replay_ct_observations([_obs(d) for d in names])
    assert first["created"] == FAMILY_MIN_SIZE
    # 模拟重启后再跑一次：聚合器仍能识别族，但不该重复建资产
    second = DiscoveryEngine().replay_ct_observations([_obs(d) for d in names])
    assert second["batches"] == 1
    assert second["created"] == 0


def test_replay_ct_ignores_daily_budget(fresh_db):
    """补漏是运维操作，不占实时发现当天的 12 批配额。"""
    engine = DiscoveryEngine()
    engine._burst_day = time.strftime("%Y-%m-%d")
    engine._burst_today = BURST_DAILY
    result = engine.replay_ct_observations(
        [_obs(d) for d in _FAMILIES["zk|cc"][:FAMILY_MIN_SIZE]]
    )
    assert result["batches"] == 1
    assert result["created"] == FAMILY_MIN_SIZE


def test_flush_retries_on_sqlite_lock(fresh_db, monkeypatch):
    """WAL 的 BUSY_SNAPSHOT 只能整体重跑事务：发现线索不能一次失败就丢。"""
    from sqlalchemy.exc import OperationalError

    engine = DiscoveryEngine()
    for d in _FAMILIES["zk|cc"][:FAMILY_MIN_SIZE]:
        engine._adopt_burst(_obs(d), unlimited=True)
    assert engine.pending
    calls = {"n": 0}
    real = engine._persist

    def flaky(session, rows):
        calls["n"] += 1
        if calls["n"] == 1:
            raise OperationalError("INSERT", {}, Exception("database is locked"))
        return real(session, rows)

    monkeypatch.setattr(engine, "_persist", flaky)
    engine._flush(force=True)
    assert calls["n"] == 2
    assert engine.stats.db_errors == 0
    assert engine.stats.queued == FAMILY_MIN_SIZE


def test_cli_discover_replay_ct_action_registered():
    from silver_sentinel.cli import build_parser

    args = build_parser().parse_args(
        ["discover", "replay-ct", "--dry-run", "--limit", "10"]
    )
    assert args.action == "replay-ct"
    assert args.dry_run is True
    assert args.limit == 10


def test_burst_pending_rows_record_own_domain_and_drop_fingerprint(fresh_db):
    """一批证书各挂一个域名：流水不能共用触发那张证书的 domain / 指纹。

    共用一个 fingerprint 会被 `_cert_clusters` 误判成「同证书团伙」。
    """
    engine = DiscoveryEngine()
    names = _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]
    engine._on_ct_batch([_obs(d, fp=f"fp{i:060d}") for i, d in enumerate(names)])
    with engine._pending_lock:
        rows = [r for r in engine.pending if r[0] is not None and r[0].source == "ct_burst"]
    assert len(rows) == FAMILY_MIN_SIZE
    for obs, _kind, value, *_rest in rows:
        assert obs.domain == value
        assert obs.all_domains == [value]
        assert obs.fingerprint == ""
        assert "站群前缀族 yl|com" in obs.note


def test_replay_appends_family_reason_to_existing_asset(fresh_db):
    """回放命中的多数是存量资产：族依据要追加进发现原因，且不能重复追加。"""
    from sqlalchemy import select

    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset

    names = _FAMILIES["yl|com"][:FAMILY_MIN_SIZE]
    DiscoveryEngine().replay_ct_observations([_obs(d) for d in names])
    with session_scope() as s:
        row = s.scalar(select(Asset).where(Asset.normalized == names[0]))
        assert "站群前缀族 yl|com" in (row.discovery_reason or "")
        row.discovery_reason = "旧结论"          # 模拟研判改写过的原因
    DiscoveryEngine().replay_ct_observations([_obs(d) for d in names])
    with session_scope() as s:
        row = s.scalar(select(Asset).where(Asset.normalized == names[0]))
        assert "旧结论" in row.discovery_reason
        assert row.discovery_reason.count("站群前缀族") == 1
        assert row.meta.get("await_capture") is True


def test_ct_event_parser_accepts_json_column_dict_and_string():
    """`DiscoveryEvent.raw` 是 JSON 列，SQLAlchemy 给 dict；回放必须两种都认。

    线上第一版只处理字符串，整批 4128 条被静默跳过、回放产出 0——这个
    用例锁住这个坑。
    """
    from silver_sentinel.cli import _ct_event_to_observation

    payload = {
        "domain": "yl8387.com",
        "all_domains": ["yl8387.com"],
        "issuer": "CN=WE1,O=Let's Encrypt,C=US",
        "not_before": "2026-09-15T00:00:00+00:00",
        "fingerprint": "a" * 64,
        "log_url": "https://ct.example/log",
        "entry_index": 7,
        "source": "ct_poll",
    }
    for raw in (payload, json.dumps(payload, ensure_ascii=False)):
        obs = _ct_event_to_observation(raw)
        assert obs is not None
        assert obs.domain == "yl8387.com"
        assert obs.source == "ct_poll"
        assert obs.entry_index == 7
    assert _ct_event_to_observation("{}") is None
    assert _ct_event_to_observation(None) is None
    assert _ct_event_to_observation("not json") is None
