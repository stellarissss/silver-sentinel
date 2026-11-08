"""恶意 IP 池：把「同一台服务器」变成可检索的证据。

为什么要单独一层
----------------
域名是一次性的，被骗的人举报一个就换一个；服务器不是。
`np4w53.cn` 与 `hksm38.com.cn` 同模板、同 IP（204.194.55.233）、同 ASN。

所以「新域名解析到了已知涉老 IP」这条信号比任何文本特征都硬：不需要打开
页面、不需要话术命中、不需要证书，只要一次 DNS。

测试重点不是存得住，而是**池子会不会被污染**：
1. Cloudflare / 阿里云这类共享 IP 绝不能进池（否则每个 IP 都命中）；
2. 内网地址不能进池；
3. 池满了要淘汰最久没命中的，不能把新证据挤掉。
"""

from __future__ import annotations

import json

from silver_sentinel.discover.ippool import BadIPPool, is_private


def _pool(tmp_path, **kw):
    return BadIPPool(tmp_path / "bad_ips.json", **kw)


# ---------------------------------------------------------------- 入池门禁


def test_observe_records_asset_and_reason(tmp_path):
    pool = _pool(tmp_path)
    assert pool.observe("204.194.55.233", asset="np4w53.cn", reason="涉老 P0")
    entry = pool.lookup("204.194.55.233")
    assert entry is not None
    assert entry.assets == ["np4w53.cn"]
    assert entry.reason == "涉老 P0"


def test_shared_infra_is_rejected(tmp_path):
    """Cloudflare / 阿里云 / AWS 上的 IP 上是几十万站点，命中即误报。"""
    pool = _pool(tmp_path)
    for ip, asn in (
        ("104.21.69.16", "CLOUDFLARENET"),
        ("47.239.114.160", "Alibaba (US) Technology Co., Ltd."),
        ("3.1.2.3", "Amazon.com, Inc."),
        ("151.101.1.1", "Fastly"),
    ):
        assert not pool.observe(ip, asset="x.cn", asn=asn), f"{ip} 不该入池"
    assert len(pool) == 0


def test_force_bypasses_shared_check_for_manual_confirm(tmp_path):
    """人工确认过的资产不受共享设施限制——那是人看着屏幕下的结论。"""
    pool = _pool(tmp_path)
    assert pool.observe("104.21.69.16", asset="x.cn", asn="CLOUDFLARENET", force=True)
    assert pool.lookup("104.21.69.16") is not None


def test_private_and_invalid_addresses_are_refused(tmp_path):
    pool = _pool(tmp_path)
    for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "172.20.0.5", "169.254.1.1", "8.8.8", ""):
        assert not pool.observe(ip, asset="x.cn"), f"{ip} 不该入池"
    assert len(pool) == 0


def test_is_private_helper():
    assert is_private("10.0.0.1")
    assert is_private("172.16.0.1")
    assert is_private("192.168.0.1")
    assert is_private("not-an-ip")
    assert not is_private("204.194.55.233")
    assert not is_private("8.8.8.8")


# ---------------------------------------------------------------- 命中与统计


def test_note_hit_accumulates(tmp_path):
    pool = _pool(tmp_path)
    pool.observe("204.194.55.233", asset="np4w53.cn", reason="涉老 P0")
    pool.note_hit("204.194.55.233", "zz19k.cn")
    pool.note_hit("204.194.55.233", "zz20m.cn")
    entry = pool.lookup("204.194.55.233")
    assert entry.hits == 2
    assert entry.last_hit_host == "zz20m.cn"


def test_multiple_assets_on_same_ip_are_merged(tmp_path):
    """同机两个站是「团伙」而不是两条互不相干的记录。"""
    pool = _pool(tmp_path)
    pool.observe("204.194.55.233", asset="np4w53.cn", reason="涉老 P0")
    pool.observe("204.194.55.233", asset="hksm38.com.cn", reason="涉老 P0")
    entry = pool.lookup("204.194.55.233")
    assert set(entry.assets) == {"np4w53.cn", "hksm38.com.cn"}
    assert len(pool) == 1


def test_remove(tmp_path):
    pool = _pool(tmp_path)
    pool.observe("204.194.55.233", asset="np4w53.cn")
    assert pool.remove("204.194.55.233")
    assert pool.lookup("204.194.55.233") is None
    assert not pool.remove("204.194.55.233")


# ---------------------------------------------------------------- 持久化


def test_persists_across_restart(tmp_path):
    pool = _pool(tmp_path)
    pool.observe("204.194.55.233", asset="np4w53.cn", reason="涉老 P0")
    pool.note_hit("204.194.55.233", "zz19k.cn")
    pool.prune_dirty()

    again = _pool(tmp_path)
    entry = again.lookup("204.194.55.233")
    assert entry is not None
    assert entry.assets == ["np4w53.cn"]
    assert entry.hits == 1


def test_corrupt_file_falls_back_to_empty(tmp_path):
    """池子文件坏了不能让发现层起不来。"""
    path = tmp_path / "bad_ips.json"
    path.write_text("{ this is not json", encoding="utf-8")
    pool = BadIPPool(path)
    assert len(pool) == 0


def test_as_dict_shape(tmp_path):
    pool = _pool(tmp_path)
    pool.observe("204.194.55.233", asset="np4w53.cn", reason="涉老 P0")
    pool.note_hit("204.194.55.233", "zz19k.cn")
    payload = pool.as_dict()
    assert payload["size"] == 1
    assert payload["hits"] == 1
    assert payload["entries"][0]["ip"] == "204.194.55.233"


def test_eviction_when_full(tmp_path):
    """池满时淘汰最久没命中的，保住刚进来的证据。"""
    pool = _pool(tmp_path, limit=1000)
    # 直接灌满（绕过 limit 的下限保护靠 observe 的逐条新增）
    for i in range(1000):
        pool.observe(f"11.{i // 250}.{i % 250}.{i % 200 + 1}", asset=f"a{i}.cn")
    pool.observe("204.194.55.233", asset="np4w53.cn", reason="涉老 P0")
    assert len(pool) <= 1000
    assert pool.lookup("204.194.55.233") is not None


def test_json_is_valid_utf8(tmp_path):
    pool = _pool(tmp_path)
    pool.observe("204.194.55.233", asset="np4w53.cn", reason="涉老 P0（伪造政府标识码）")
    pool.prune_dirty()
    raw = json.loads((tmp_path / "bad_ips.json").read_text(encoding="utf-8"))
    assert raw["ips"]["204.194.55.233"]["reason"].startswith("涉老 P0")
