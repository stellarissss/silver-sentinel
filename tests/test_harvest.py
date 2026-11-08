"""外部线索发现（urlscan 标题检索）。

这一层存在的理由只有一条：**CT 只认域名里写了什么，而涉老诈骗的域名是随机串**。
线上 4,311 条资产里涉老样本为 0，不是判不出来，是从来没看见过——
`np4w53.cn` 的 label 去掉数字只剩 `npw`，域名词库必然打空。

所以这里的测试重点不是「能不能搜到」，而是：
1. 命中结果能走通与 CT 相同的落库路径（否则等于白搜）；
2. 保留完整主机名（`s.qka91.com` 是落地页，归并成 `qka91.com` 就丢了入口）；
3. 一条查询失败不能带走整轮。
"""

from __future__ import annotations

from silver_sentinel.discover.harvest import (
    RAW_QUERIES,
    TITLE_QUERIES,
    Harvester,
    HarvestHit,
    UrlscanSource,
    score_title,
)

# ---------------------------------------------------------------- 打分


def test_institutional_title_is_deprioritized_but_kept():
    """「XX 市养老服务中心」也可能是仿的——降权，但不丢。"""
    assert score_title("2026年个人财政补贴申领") > score_title("XX市养老服务中心")
    assert score_title("XX市养老服务中心") > 0.30, "降权后仍要能进候选池"


def test_queries_are_phrases_not_industry_words():
    """查询词必须是「骗子会写在标题里的话」。

    实测 `page.title:"养老"` 返回 82 条，全是养老院官网、管理系统、大学学院；
    而 `page.title:"个人财政补贴"` 只返回 3 条，全是同模板诈骗站。
    所以词表里不该出现行业词。
    """
    flat = [q for qs in TITLE_QUERIES.values() for q in qs]
    assert "养老" not in flat
    assert "个人财政补贴" in flat
    assert "民族资产解冻" in flat


# ---------------------------------------------------------------- 解析


def test_fetch_parses_urlscan_payload(monkeypatch):
    payload = {
        "results": [
            {"page": {"domain": "np4w53.cn", "title": "2026年个人财政补贴申领",
                      "url": "https://np4w53.cn/"}},
            {"page": {"domain": "np4w53.cn", "title": "重复项", "url": "https://np4w53.cn/x"}},
            {"page": {"domain": "", "title": "无域名", "url": "https://x/"}},
        ]
    }

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return payload

    class _Client:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **kw):
            return _Resp()

    monkeypatch.setattr("silver_sentinel.discover.harvest.httpx.Client", _Client)
    hits = UrlscanSource(size=10, pause=0).fetch("个人财政补贴")
    assert [h.host for h in hits] == ["np4w53.cn"], "同域去重，空域名丢弃"
    assert hits[0].title.startswith("2026年")
    assert hits[0].source == "urlscan"


def test_one_failed_query_does_not_kill_the_round(monkeypatch):
    src = UrlscanSource(size=10, pause=0)
    calls = {"n": 0}

    def boom(query):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("429 too many requests")
        return [HarvestHit(host="hksm38.com.cn", title="2026年个人财政补贴申领",
                           url="", query=query, score=0.72)]

    monkeypatch.setattr(src, "fetch", boom)
    h = Harvester(src, per_round=3)
    hits = h.run_round()
    assert len(hits) == 2, "3 个查询里坏了 1 个，另外 2 个照常"
    assert h.stats.errors == 1
    assert "429" in h.stats.last_error


def test_rotation_covers_all_queries():
    """轮换要覆盖全部查询词，不能只跑前几个。

    高产出词在轮换表里出现两次（权重 2），所以按表长跑一整圈才算覆盖。
    """
    h = Harvester(UrlscanSource(size=1, pause=0), per_round=1)
    seen = {h.next_queries()[0][1] for _ in range(len(h._flat))}
    all_words = {q for qs in TITLE_QUERIES.values() for q in qs}
    assert all_words <= seen, f"漏掉的词：{all_words - seen}"
    missing_raw = {q for qs in RAW_QUERIES.values() for q in qs}
    assert missing_raw <= {q[4:] for q in seen if q.startswith("raw:")}


def test_cursor_survives_restart(tmp_path):
    """游标必须落盘。线上十轮全跑 subsidy 前四个词，就是因为重启归零。"""
    state = tmp_path / "harvest_state.json"
    first = Harvester(UrlscanSource(size=1, pause=0), per_round=3, state_path=state)
    got = [q for _c, q in first.next_queries()]
    second = Harvester(UrlscanSource(size=1, pause=0), per_round=3, state_path=state)
    assert [q for _c, q in second.next_queries()] != got, "重启后不该从头发车"


def test_raw_queries_use_lucene_expression(monkeypatch):
    """带有 raw: 前缀的查询直接当表达式，不再包 page.title。"""
    seen = {}

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"results": []}

    class _Client:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **kw):
            seen["q"] = kw.get("params", {}).get("q")
            return _Resp()

    monkeypatch.setattr("silver_sentinel.discover.harvest.httpx.Client", _Client)
    UrlscanSource(pause=0).fetch("raw:page.url:apk AND page.language:zh")
    assert seen["q"] == "page.url:apk AND page.language:zh"


# ---------------------------------------------------------------- 落库


def test_harvest_hits_land_with_source_and_full_host(fresh_db, monkeypatch):
    """完整主机名要保留。`s.qka91.com` 是民族资产解冻的落地页。"""
    from silver_sentinel.db import get_session_factory
    from silver_sentinel.discover.engine import DiscoveryEngine
    from silver_sentinel.models import Asset

    engine = DiscoveryEngine()
    engine._harvester = Harvester(UrlscanSource(size=1, pause=0), per_round=1)
    monkeypatch.setattr(
        engine._harvester,
        "run_round",
        lambda: [
            HarvestHit(host="s.qka91.com", title="中稀同心 - 惠民资金审核记录表",
                       url="https://s.qka91.com/", query="惠民资金", score=0.72),
            HarvestHit(host="www.xindazx.cn", title="沈阳补贴指南",
                       url="https://www.xindazx.cn/", query="补贴申领", score=0.72),
        ],
    )

    queued = engine._harvest_once()
    engine._flush(force=True)
    assert queued == 2

    s = get_session_factory()()
    got = {a.value: a for a in s.query(Asset).all()}
    assert "s.qka91.com" in got, "子域不能被归并掉——那是唯一入口"
    assert "xindazx.cn" in got, "www. 前缀去掉，其余保留"
    assert got["s.qka91.com"].discovery_source == "urlscan"
    assert got["s.qka91.com"].tier == "candidate"
    assert "惠民资金" in (got["s.qka91.com"].discovery_reason or "")


def test_harvest_skips_whitelisted_and_duplicates(fresh_db, monkeypatch):
    from silver_sentinel.discover.engine import DiscoveryEngine

    engine = DiscoveryEngine()
    engine._harvester = Harvester(UrlscanSource(size=1, pause=0), per_round=1)
    monkeypatch.setattr(
        engine._harvester,
        "run_round",
        lambda: [
            HarvestHit(host="www.gov.cn", title="中国政府网", url="", query="补贴", score=0.7),
            HarvestHit(host="np4w53.cn", title="2026年个人财政补贴申领", url="",
                       query="补贴", score=0.72),
            HarvestHit(host="np4w53.cn", title="2026年个人财政补贴申领", url="",
                       query="惠民资金", score=0.72),
        ],
    )
    assert engine._harvest_once() == 1, "白名单丢弃，同域只入一次"


# ---------------------------------------------------------------- 待取证保护

def test_external_lead_is_not_downgraded_before_capture(fresh_db):
    """线上实测过的坑：6 条外部线索里 3 条在取证前掉进 cold，再没出现过。

    quick 研判只看域名，`np4w53.cn` 这种随机串一律判「证据不足」；
    而 backfill 只补 watch/candidate，压下去就永远等不到取证。
    """
    from silver_sentinel import triage
    from silver_sentinel.models import Asset

    a = Asset(kind="domain", value="np4w53.cn", normalized="np4w53.cn",
              tier="candidate", score=0.0, verdict="insufficient",
              discovery_source="urlscan",
              meta={"await_capture": True, "triaged": True,
                    "facts": {"is_shortener": False}})
    d = triage.decide(a)
    assert d.tier == "candidate"
    assert "待取证" in d.reasons[0]


def test_external_lead_still_promotes_on_hard_evidence(fresh_db):
    """保护不是免死金牌：伪造标识码这类硬证据仍然直接进 watch。"""
    from silver_sentinel import triage
    from silver_sentinel.models import Asset

    a = Asset(kind="domain", value="np4w53.cn", normalized="np4w53.cn",
              tier="candidate", score=95.0, verdict="high_risk",
              discovery_source="urlscan",
              meta={"await_capture": True,
                    "facts": {"claim": {"verdict": "fake_site_id",
                                        "site_id": "bm01000001"}}})
    assert triage.decide(a).tier == "watch"


def test_repeat_harvest_pulls_cold_lead_back(fresh_db, monkeypatch):
    """被域名级研判压成 cold 的线索，再次被外部源命中要拉回候选。"""
    from silver_sentinel.db import get_session_factory
    from silver_sentinel.discover.engine import DiscoveryEngine
    from silver_sentinel.models import Asset

    with get_session_factory()() as s:
        s.add(Asset(kind="domain", value="np4w53.cn", normalized="np4w53.cn",
                    tier="cold", score=0.0, verdict="insufficient",
                    discovery_source="urlscan",
                    meta={"triaged": True, "discover_hint": 0.72}))
        s.commit()

    engine = DiscoveryEngine()
    engine._harvester = Harvester(UrlscanSource(size=1, pause=0), per_round=1)
    monkeypatch.setattr(
        engine._harvester, "run_round",
        lambda: [HarvestHit(host="np4w53.cn", title="2026年个人财政补贴申领",
                            url="", query="个人财政补贴", score=0.72)],
    )
    engine._harvest_once()
    engine._flush(force=True)

    s = get_session_factory()()
    a = s.query(Asset).filter(Asset.value == "np4w53.cn").first()
    assert a.tier == "candidate"
    assert (a.meta or {}).get("await_capture") is True
