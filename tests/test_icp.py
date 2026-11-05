"""ICP 备案与违法违规名单解析。

这些用例对应真实踩过的坑：接口出错被当成「未备案」、备案了但已被列管
却只看备案状态。两者都会让研判结论失真。
"""

from __future__ import annotations

import pytest

from silver_sentinel.enrich import icp as icp_mod


def _client(monkeypatch) -> icp_mod.ICPClient:
    monkeypatch.setattr(icp_mod.settings, "icp_api_base", "http://127.0.0.1:16181", raising=False)
    monkeypatch.setattr(icp_mod.settings, "icp_enabled", True, raising=False)
    monkeypatch.setattr(icp_mod.settings, "icp_violation_check", False, raising=False)
    monkeypatch.setattr(icp_mod.settings, "icp_cache_days", 0, raising=False)
    return icp_mod.ICPClient()


REGISTERED = {
    "code": 200,
    "success": True,
    "params": {
        "list": [
            {
                "domain": "baidu.com",
                "mainLicence": "京ICP证030173号",
                "serviceLicence": "京ICP证030173号-1",
                "unitName": "北京百度网讯科技有限公司",
                "natureName": "企业",
            }
        ],
        "total": 1,
    },
}

EMPTY = {"code": 200, "success": True, "params": {"list": [], "total": 0}}
BROKEN = {"code": 500, "success": False, "msg": "工信部服务器异常"}


def test_registered_domain_extracts_entity(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.setattr(client, "_get", lambda url: REGISTERED)
    res = client.lookup("baidu.com")
    assert res.status == "registered"
    assert res.license == "京ICP证030173号"
    assert "百度" in res.entity


def test_empty_list_is_unregistered(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.setattr(client, "_get", lambda url: EMPTY)
    assert client.lookup("wechat-art.xyz").status == "unregistered"


def test_interface_failure_is_unknown_not_unregistered(monkeypatch):
    """接口 500 时绝不能断言「未备案」。

    这是最贵的一类错误：一次接口故障会批量制造「未备案」结论，
    进而让一批无关域名进入候选池，还会写进举报材料。
    """
    client = _client(monkeypatch)
    monkeypatch.setattr(client, "_get", lambda url: BROKEN)
    res = client.lookup("example.com")
    assert res.status == "unknown"
    assert "500" in res.error


def test_non_dict_payload_is_unknown(monkeypatch):
    client = _client(monkeypatch)
    monkeypatch.setattr(client, "_get", lambda url: "<html>502</html>")
    assert client.lookup("example.com").status == "unknown"


@pytest.mark.parametrize(
    ("level", "title", "expected"),
    [
        (2, "", "clean"),
        (1, "违法违规网站", "listed"),
        (0, "", "listed"),
        (2, "处置通知", "listed"),
        (None, "", "unknown"),
    ],
)
def test_violation_semantics(monkeypatch, level, title, expected):
    client = _client(monkeypatch)
    monkeypatch.setattr(
        client, "_get", lambda url: {"code": 200, "success": True,
                                     "params": {"blackListLevel": level, "title": title}}
    )
    result = client._check_violation("x.example")
    assert result.get("violation", "unknown") == expected


def test_violation_does_not_leak_into_registration(monkeypatch):
    """违法违规查询挂了，不能影响备案结论。"""
    client = _client(monkeypatch)
    monkeypatch.setattr(icp_mod.settings, "icp_violation_check", True, raising=False)
    calls = {"n": 0}

    def fake_get(url):
        calls["n"] += 1
        if "bweb" in url:
            raise OSError("timeout")
        return REGISTERED

    monkeypatch.setattr(client, "_get", fake_get)
    res = client.lookup("baidu.com")
    assert res.status == "registered"
    assert res.violation == "unknown"
    assert calls["n"] == 2
