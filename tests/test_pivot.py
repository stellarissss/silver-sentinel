"""同源扩散：从一个站带出一窝。

实测依据（2026-11-08）
---------------------
`l4k9j.com.cn` 一张证书签了 30 个域名：

    a7k2m.com.cn  b3t8n.com.cn  ...  z7x4c.com.cn

全部同一天、同一个生成器、全部 `.com.cn`。这 30 个域名在生产库里一条记录
都没有——词库打空，CT 扫到也会丢掉。

所以这里的测试要守住三件事：
1. 一张证书能完整带出一批（不能只拿第一个）；
2. 共享证书（几百个域名的云平台证书）不能带——那会把整个云厂商拉进来；
3. 配额用尽后要老实停下，不能把源打到封禁。
"""

from __future__ import annotations

from silver_sentinel.discover.pivot import (
    CertSpotterSource,
    PivotEngine,
    PivotHit,
    UrlscanSameIP,
    _clean_names,
    _TokenBucket,
)

# 真实证书 SAN（截自 l4k9j.com.cn 的签发记录）
BATCH = [
    "a7k2m.com.cn", "b3t8n.com.cn", "c2r7h.com.cn", "d4v9g.com.cn", "d5s2a.com.cn",
    "e6s3l.com.cn", "f9t4w.com.cn", "g5h1c.com.cn", "h2n7v.com.cn", "h8g3f.com.cn",
    "i2u7y.com.cn", "j8k1l.com.cn", "k8j6f.com.cn", "l4k9j.com.cn", "m5w1p.com.cn",
]


# ---------------------------------------------------------------- 名字清洗


def test_clean_names_strips_wildcards_and_duplicates():
    raw = ["*.np4w53.cn", "np4w53.cn", "A7K2M.com.cn", "a7k2m.com.cn", "x.local", ""]
    out = _clean_names(raw, origin="np4w53.cn")
    assert "np4w53.cn" not in out, "自身要去掉"
    assert "*.np4w53.cn" not in out
    assert "a7k2m.com.cn" in out, "大小写归一"
    assert out.count("a7k2m.com.cn") == 1
    assert "x.local" not in out


def test_clean_names_handles_newline_separated_values():
    """证书的 name_value 是一坨换行分隔的文本，crt.sh 风格。"""
    out = _clean_names(["a.com\nb.com\nc.com"], origin="z.com")
    assert out == ["a.com", "b.com", "c.com"]


# ---------------------------------------------------------------- 证书扩散


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _client(payload):
    class _C:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **kw):
            return _Resp(payload)

    return _C


def test_certspotter_returns_whole_batch(monkeypatch):
    """一张证书 30 个域名 → 29 条候选（去掉自身）。"""
    payload = [{"not_before": "2026-10-08T16:00:00Z", "dns_names": BATCH}]
    monkeypatch.setattr(
        "silver_sentinel.discover.pivot.httpx.Client", _client(payload)
    )
    src = CertSpotterSource()
    hits = src.lookup("l4k9j.com.cn")
    assert len(hits) == len(BATCH) - 1
    assert "m5w1p.com.cn" in {h.domain for h in hits}
    assert all(h.source == "cert_sibling" for h in hits)
    assert "共用证书" in hits[0].detail


def test_certspotter_skips_shared_cloud_certificate(monkeypatch):
    """几百个域名的证书是云平台/共享证书，不能当站群。"""
    huge = [f"site{i}.example.com" for i in range(200)]
    payload = [{"not_before": "2026-10-08", "dns_names": huge}]
    monkeypatch.setattr(
        "silver_sentinel.discover.pivot.httpx.Client", _client(payload)
    )
    assert CertSpotterSource().lookup("site1.example.com") == []


def test_certspotter_deduplicates_across_issuances(monkeypatch):
    """同一域名续签过多次，同名不能重复出。"""
    payload = [
        {"not_before": "2026-10-08", "dns_names": ["a7k2m.com.cn", "l4k9j.com.cn"]},
        {"not_before": "2026-11-01", "dns_names": ["a7k2m.com.cn", "l4k9j.com.cn"]},
    ]
    monkeypatch.setattr(
        "silver_sentinel.discover.pivot.httpx.Client", _client(payload)
    )
    hits = CertSpotterSource().lookup("l4k9j.com.cn")
    assert [h.domain for h in hits] == ["a7k2m.com.cn"]


def test_certspotter_failure_is_quiet(monkeypatch):
    """源挂了返回空，不能把扩散流程炸掉。"""

    class _Boom:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, *a, **kw):
            raise RuntimeError("503 Service Unavailable")

    monkeypatch.setattr("silver_sentinel.discover.pivot.httpx.Client", _Boom)
    assert CertSpotterSource().lookup("np4w53.cn") == []


# ---------------------------------------------------------------- 同 IP 扩散


def test_urlscan_same_ip(monkeypatch):
    payload = {
        "results": [
            {"page": {"domain": "np4w53.cn", "title": "2026年个人财政补贴申领"}},
            {"page": {"domain": "hksm38.com.cn", "title": "2026年个人财政补贴申领"}},
            {"page": {"domain": "np4w53.cn", "title": "重复"}},
        ]
    }
    monkeypatch.setattr(
        "silver_sentinel.discover.pivot.httpx.Client", _client(payload)
    )
    hits = UrlscanSameIP().lookup("204.194.55.233", origin="np4w53.cn")
    assert [h.domain for h in hits] == ["hksm38.com.cn"]
    assert hits[0].source == "same_ip"


def test_urlscan_rejects_empty_ip():
    assert UrlscanSameIP().lookup("") == []
    assert UrlscanSameIP().lookup("not-an-ip") == []


# ---------------------------------------------------------------- 配额


def test_token_bucket_exhausts():
    b = _TokenBucket(3)
    assert all(b.take() for _ in range(3))
    assert not b.take()
    assert b.as_dict()["left"] == 0


def test_certspotter_stops_when_quota_used(monkeypatch):
    """配额用尽后不再发请求——被打死一次要等一小时。"""
    calls = {"n": 0}

    def _factory(*a, **kw):
        calls["n"] += 1
        return _client([{"not_before": "2026-10-08", "dns_names": ["x.com"]}])()

    monkeypatch.setattr("silver_sentinel.discover.pivot.httpx.Client", _factory)
    src = CertSpotterSource(bucket=_TokenBucket(2))
    src.lookup("a.cn")
    src.lookup("b.cn")
    src.lookup("c.cn")
    assert calls["n"] == 2, "第三次不该再发请求"


# ---------------------------------------------------------------- 编排


def test_pivot_engine_filters_noise(monkeypatch):
    """扩散出来的 CDN / 统计域名不进队列。"""
    engine = PivotEngine()
    monkeypatch.setattr(
        engine.cert, "lookup", lambda d, **kw: [
            PivotHit("a7k2m.com.cn", "cert_sibling", d),
            PivotHit("www.googletagmanager.com", "cert_sibling", d),
            PivotHit("a7k2m.com.cn", "cert_sibling", d),
        ]
    )
    hits = engine.expand("l4k9j.com.cn", use_ip=False)
    assert [h.domain for h in hits] == ["a7k2m.com.cn"], "去重 + 过滤噪声"


def test_pivot_engine_survives_one_source_failing(monkeypatch):
    engine = PivotEngine()

    def boom(domain, **kw):
        raise RuntimeError("network down")

    monkeypatch.setattr(engine.cert, "lookup", boom)
    monkeypatch.setattr(
        engine.ip, "lookup", lambda ip, **kw: [PivotHit("hksm38.com.cn", "same_ip", ip)]
    )
    hits = engine.expand("np4w53.cn", ips=["204.194.55.233"])
    assert [h.domain for h in hits] == ["hksm38.com.cn"]
    assert engine.stats["errors"] == 1
