"""取证浏览器进程泄漏修复的回归测试。

根因：取证超时换线程 → close() 跨线程调用线程绑定的 playwright.stop() 失败
被吞 → driver(node) 变孤儿，chromium 子树滞留，累积几十个把 2G 机器换页
风暴打死。修复：记录 driver PID，close() 用进程树强杀兜底；取证前节流收割
孤儿 driver。这里验证这些纯逻辑，不实际启动 Chromium。
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import types

from silver_sentinel.sandbox.web import (
    WebSandbox,
    _kill_process_tree,
    _playwright_driver_pid,
    _process_alive,
)


def test_playwright_driver_pid_extracts_from_internal_chain():
    """能从 Playwright 内部对象链取出 driver PID。"""
    fake = types.SimpleNamespace(
        _impl_obj=types.SimpleNamespace(
            _connection=types.SimpleNamespace(
                _transport=types.SimpleNamespace(
                    _proc=types.SimpleNamespace(pid=424242)
                )
            )
        )
    )
    assert _playwright_driver_pid(fake) == 424242


def test_playwright_driver_pid_returns_none_on_broken_chain():
    """内部实现缺失时安全降级为 None，不让主流程崩。"""
    assert _playwright_driver_pid(object()) is None
    assert _playwright_driver_pid(None) is None
    assert _playwright_driver_pid(types.SimpleNamespace(_impl_obj=None)) is None


def test_process_alive_detects_dead_and_live():
    """存活判定对当前进程为真，对不存在的 PID 为假。"""
    assert _process_alive(os.getpid()) is True
    assert _process_alive(-1) is False
    # 一个极不可能存在的 PID
    assert _process_alive(2_000_000_000) is False


def test_kill_process_tree_kills_children_before_parent():
    """杀进程树时子孙全部被清除，不留孤儿。"""
    # 起一个父进程 + 两个子进程，验证整棵被杀掉
    script = (
        "import subprocess,sys,time;"
        "kids=[subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']) for _ in range(2)];"
        "print(kids[0].pid,kids[1].pid,flush=True);"
        "time.sleep(60)"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline().strip()
    kid_pids = [int(x) for x in line.split()]
    assert len(kid_pids) == 2
    try:
        killed = _kill_process_tree(proc.pid)
        # 至少父 + 2 子 = 3（子进程可能在 ps 快照前已退出则略少，此处应稳定为 3）
        assert killed >= 1
        # 等待退出
        proc.wait(timeout=5)
        for kp in kid_pids:
            deadline = time.time() + 3
            while _process_alive(kp) and time.time() < deadline:
                time.sleep(0.05)
            assert not _process_alive(kp), f"子进程 {kp} 未被清除"
    finally:
        if proc.poll() is None:
            proc.kill()
        for kp in kid_pids:
            if _process_alive(kp):
                try:
                    os.kill(kp, signal.SIGKILL)
                except ProcessLookupError:
                    pass


def test_reap_orphans_keeps_active_driver(monkeypatch):
    """收割只杀孤儿，保留当前活跃 driver。"""
    box = WebSandbox()
    active = os.getpid() + 1000  # 伪造一个活跃 PID（不真实存在）
    box._driver_pid = active

    me = os.getpid()
    orphan1, orphan2 = active + 1, active + 2
    # 伪造 ps 输出：2 个孤儿（ppid=本进程）+ 1 个活跃 + 1 个别的父进程（不该动）
    fake_ps = "\n".join(
        [
            f"{orphan1} {me} /opt/venv/playwright/driver/node cli.js run-driver",
            f"{orphan2} {me} /opt/venv/playwright/driver/node cli.js run-driver",
            f"{active} {me} /opt/venv/playwright/driver/node cli.js run-driver",
            f"{active + 9} 1 /opt/venv/playwright/driver/node cli.js run-driver",
        ]
    )
    monkeypatch.setattr(os, "popen", lambda cmd: _FakePopen(fake_ps))
    killed: list[int] = []
    monkeypatch.setattr(
        "silver_sentinel.sandbox.web._kill_process_tree",
        lambda pid: (killed.append(pid), 1)[1],
    )
    monkeypatch.setattr(
        "silver_sentinel.sandbox.web._process_alive", lambda pid: True
    )
    box.reap_orphan_drivers()
    assert orphan1 in killed, "孤儿1 应被收割"
    assert orphan2 in killed, "孤儿2 应被收割"
    assert active not in killed, "活跃 driver 不能被误杀"
    assert active + 9 not in killed, "其它父进程的子进程不能被误杀"
    assert box.stats.get("orphans_reaped") == 2


class _FakePopen:
    def __init__(self, text: str):
        self._text = text

    def read(self) -> str:
        return self._text


def test_close_kills_stale_driver_when_stop_fails(monkeypatch):
    """close() 在 stop 失效时仍从 OS 层强杀登记的 driver PID。"""
    box = WebSandbox()
    stale_pid = os.getpid() + 2000  # 伪造不存在的 PID
    box._driver_pid = stale_pid

    # 模拟 stop() 抛异常被吞（跨线程场景）
    class FakeBrowser:
        def close(self):
            raise RuntimeError("Event loop is closed")

    class FakePlaywright:
        def stop(self):
            raise RuntimeError("Cannot switch to a different thread")

    box._browser = FakeBrowser()
    box._playwright = FakePlaywright()
    box._owner_thread = 999999

    killed: list[int] = []
    monkeypatch.setattr(
        "silver_sentinel.sandbox.web._process_alive", lambda pid: True
    )
    monkeypatch.setattr(
        "silver_sentinel.sandbox.web._kill_process_tree",
        lambda pid: (killed.append(pid), 3)[1],
    )
    box.close()
    assert stale_pid in killed, "stop 失效时必须从 OS 层强杀残留 driver"
    assert box._driver_pid is None
    assert box._browser is None
    assert box._playwright is None
    assert box._owner_thread is None
    assert box.available is False
