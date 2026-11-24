"""浏览器运行时缺失的降级修复回归测试。

2026-11-24 新机事故：wheel 装了但 playwright 没装 → ms-playwright 空目录 →
每次取证「浏览器不可用」→ 3 次后 os._exit(3) → systemd Restart=always 一分钟内
重启 358 次。根因是把「浏览器压根没装」（重启无用）误当成「进程毒化」（重启可
自愈）。本测试钉死三条：

1. 永久性错误文本被正确分型；
2. 永久性错误走长冷却降级，绝不 os._exit；
3. 可恢复错误仍保留 os._exit 的重启自愈；
4. 降级期内 capture_asset 直接短路，不再拉起浏览器。
"""

from __future__ import annotations

import pytest


@pytest.fixture
def capmod():
    """拿到 capture 模块并隔离浏览器失败状态，避免测试间串扰。"""
    import silver_sentinel.capture as cap

    saved = (
        cap._BROWSER_FAILS[0],
        cap._BROWSER_DOWN_UNTIL[0],
        cap._BROWSER_FAIL_LIMIT,
        cap._BROWSER_DOWN_COOLDOWN,
    )
    cap._BROWSER_FAILS[0] = 0
    cap._BROWSER_DOWN_UNTIL[0] = 0.0
    yield cap
    (
        cap._BROWSER_FAILS[0],
        cap._BROWSER_DOWN_UNTIL[0],
        cap._BROWSER_FAIL_LIMIT,
        cap._BROWSER_DOWN_COOLDOWN,
    ) = saved


@pytest.mark.parametrize(
    "text",
    [
        "浏览器不可用：ModuleNotFoundError: No module named 'playwright'",
        "浏览器不可用：ModuleNotFoundError: No module named \"playwright\"",
        "浏览器不可用：Error: Executable doesn't exist at /opt/ms-playwright/chromium",
        "浏览器不可用：Please run the following command to install new browsers",
        "浏览器不可用：RuntimeError: 检查 PLAYWRIGHT_BROWSERS_PATH 与 `playwright install chromium`",
        "浏览器不可用：浏览器可执行文件缺失 browser executable not found",
    ],
)
def test_permanent_browser_errors_are_classified(capmod, text):
    assert capmod._is_permanent_browser_error(text) is True


@pytest.mark.parametrize(
    "text",
    [
        "浏览器不可用：RuntimeError: Sync API inside the asyncio loop",
        "浏览器不可用：Cannot switch to a different thread",
        "取证超时，已重建执行线程",
        "",
    ],
)
def test_recoverable_browser_errors_are_not_permanent(capmod, text):
    assert capmod._is_permanent_browser_error(text) is False


def test_permanent_error_degrades_without_exiting(capmod, monkeypatch):
    """永久性错误：进降级冷却、告警一次，绝不 os._exit。"""
    exited = []
    events = []
    monkeypatch.setattr(capmod.os, "_exit", lambda code: exited.append(code))
    monkeypatch.setattr(capmod, "emit", lambda kind, **kw: events.append((kind, kw)))
    monkeypatch.setattr(capmod.time, "monotonic", lambda: 1000.0)

    capmod._note_browser_failure(
        "浏览器不可用：ModuleNotFoundError: No module named 'playwright'"
    )

    assert exited == [], "浏览器未安装时绝不能 os._exit 触发重启死循环"
    assert capmod._browser_hard_down() is True
    assert capmod._BROWSER_DOWN_UNTIL[0] == pytest.approx(1000.0 + 3600.0)
    assert any(kind == "capture.browser_missing" for kind, _ in events)

    # 第二次调用：已处于降级，不应重复告警（去重）
    events.clear()
    capmod._note_browser_failure(
        "浏览器不可用：ModuleNotFoundError: No module named 'playwright'"
    )
    assert events == []


def test_recoverable_error_still_exits_after_limit(capmod, monkeypatch):
    """可恢复的进程毒化：达到阈值仍 os._exit（保留原有自愈能力）。"""
    exited = []
    monkeypatch.setattr(capmod.os, "_exit", lambda code: exited.append(code))
    monkeypatch.setattr(capmod, "emit", lambda kind, **kw: None)
    monkeypatch.setattr(capmod.time, "sleep", lambda _s: None)

    for _ in range(capmod._BROWSER_FAIL_LIMIT):
        capmod._note_browser_failure(
            "浏览器不可用：RuntimeError: Sync API inside the asyncio loop"
        )

    assert exited == [3], "进程级毒化仍应主动退出让 systemd 重启自愈"


def test_degraded_state_short_circuits_capture(capmod):
    """降级期内 capture_asset 直接返回失败，不拉起浏览器、不进线程池。"""
    capmod._BROWSER_DOWN_UNTIL[0] = 9999999999.0  # 远期时间戳，确保处于降级
    result = capmod.capture_asset(12345)
    assert result["ok"] is False
    assert "降级" in result["reason"]
    assert "playwright install chromium" in result["reason"]
