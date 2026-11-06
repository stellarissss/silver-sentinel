"""访问口令：签名、过期、放行规则。

这几个点错了会直接导致两种事故：要么外网裸奔，要么自己人被挡在外面。
"""

from __future__ import annotations

import time

import pytest

from silver_sentinel import webauth


@pytest.fixture(autouse=True)
def _password(monkeypatch):
    from silver_sentinel.config import settings

    monkeypatch.setattr(settings, "web_password", "测试口令-A1", raising=False)
    monkeypatch.setattr(settings, "data_dir", settings.data_dir, raising=False)
    webauth._fails.clear()
    yield
    webauth._fails.clear()


def test_session_roundtrip():
    token = webauth.issue()
    assert webauth.verify(token)


def test_session_rejects_tampering():
    token = webauth.issue()
    head, _, sig = token.partition(".")
    # 必须真的换掉最后一个字符：签名是 base64 字母表，直接写死替换成 "0"
    # 有 1/64 的概率恰好等于原字符，那时候 token 没变，断言就假失败了
    tail = "1" if sig[-1] != "1" else "2"
    assert not webauth.verify(f"{head}.{sig[:-1]}{tail}")
    assert not webauth.verify(f"{head}x.{sig}")
    assert not webauth.verify("")
    assert not webauth.verify(None)
    assert not webauth.verify("garbage")


def test_session_expires(monkeypatch):
    token = webauth.issue(ttl=-1)
    assert not webauth.verify(token)


def test_password_change_invalidates_old_session(monkeypatch):
    token = webauth.issue()
    from silver_sentinel.config import settings

    monkeypatch.setattr(settings, "web_password", "换了口令", raising=False)
    assert not webauth.verify(token)


def test_password_compare_handles_chinese():
    assert webauth.check_password("测试口令-A1")
    assert not webauth.check_password("测试口令-A2")
    assert not webauth.check_password("")


def test_public_paths():
    assert not webauth.needs_auth("/api/ping")
    assert not webauth.needs_auth("/static/style.css")
    assert not webauth.needs_auth("/login")
    assert not webauth.needs_auth("/auth/login")
    assert webauth.needs_auth("/")
    assert webauth.needs_auth("/api/assets")
    assert webauth.needs_auth("/api/report/bundles/abc/file")


def test_failure_throttle():
    key = "1.2.3.4"
    for _ in range(webauth._FAIL_LIMIT):
        assert not webauth.too_many_failures(key)
        webauth.note_failure(key)
    assert webauth.too_many_failures(key)
    webauth.clear_failures(key)
    assert not webauth.too_many_failures(key)


def test_old_failures_expire(monkeypatch):
    key = "5.6.7.8"
    base = time.time()
    for _ in range(webauth._FAIL_LIMIT):
        webauth._fails.setdefault(key, []).append(base - webauth._FAIL_WINDOW - 5)
    assert not webauth.too_many_failures(key)


def test_middleware_blocks_api_without_session():
    from starlette.testclient import TestClient

    from silver_sentinel.api import app

    with TestClient(app) as client:
        assert client.get("/api/stats").status_code == 401
        assert client.get("/api/ping").status_code == 200
        # 页面请求走跳转，不是 401——浏览器要能落到登录页
        r = client.get("/", follow_redirects=False)
        assert r.status_code in (302, 307)
        assert "/login" in r.headers.get("location", "")


def test_middleware_accepts_bearer(monkeypatch):
    from starlette.testclient import TestClient

    from silver_sentinel.api import app
    from silver_sentinel.config import settings

    # HTTP 头不允许非 ASCII，这条用例换成 ASCII 口令；中文口令由 compare_digest 那例覆盖
    monkeypatch.setattr(settings, "web_password", "test-pass-A1", raising=False)

    with TestClient(app) as client:
        r = client.get("/api/stats", headers={"Authorization": "Bearer test-pass-A1"})
        assert r.status_code == 200
        r = client.get("/api/stats", headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401


def test_login_flow_sets_cookie():
    from starlette.testclient import TestClient

    from silver_sentinel.api import app

    with TestClient(app) as client:
        bad = client.post("/auth/login", data={"password": "nope", "next": "/"})
        assert bad.status_code == 401

        ok = client.post("/auth/login", data={"password": "测试口令-A1", "next": "/"}, follow_redirects=False)
        assert ok.status_code == 303
        assert "ss_session" in ok.headers.get("set-cookie", "")
        assert client.get("/").status_code == 200
        assert client.get("/api/stats").status_code == 200

        client.get("/auth/logout", follow_redirects=False)
        assert client.get("/api/stats").status_code == 401


def test_login_rejects_open_redirect():
    from starlette.testclient import TestClient

    from silver_sentinel.api import app

    with TestClient(app) as client:
        r = client.post(
            "/auth/login",
            data={"password": "测试口令-A1", "next": "//evil.example/x"},
            follow_redirects=False,
        )
        # 站外地址一律落回首页，避免变成跳板
        assert r.headers.get("location") == "/"
