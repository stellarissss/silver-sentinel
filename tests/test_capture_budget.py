"""动态取证容量：以"不用/少量 swap"为标准，按实时性能调配条数。

线上 2026-11-27 复盘：固定可用内存阈值 350MB 在小内存机（1.9G，进程常驻
925MB）上永远够不到，取证每轮被拦、近乎停摆，而 swap 已用 1.5G 却没被检测。
新逻辑采样 swap 用量 + 可用内存 + swapin 速率，动态给出本轮 0/1/2 条。

钉死四件事：
1. swap 超上限 / 内存低于下限 / 剧烈换入 → 0 条（停一轮）；
2. swap 空闲且内存宽裕 → max_batch 条；
3. 中间态 → 1 条；
4. adaptive 关闭 → 退回固定阈值；滞回避免阈值边缘反复横跳。
"""

from __future__ import annotations

import pytest


@pytest.fixture
def budget_env(monkeypatch):
    """隔离采样与配置：固定时间、可控 swap，配置走注入的 get_int/get_bool。"""
    import silver_sentinel.capture as cap

    state = {
        "avail": 800.0,
        "swap_used": 0.0,
        "swapin": 0,
        "now": 1000.0,
        "adaptive": True,
        "max_batch": 2,
        "swap_limit": 256,
        "floor": 120,
    }

    monkeypatch.setattr(cap, "available_memory_mb", lambda: state["avail"])
    monkeypatch.setattr(cap, "_swap_snapshot", lambda: (state["swap_used"], state["swapin"]))
    monkeypatch.setattr(cap.time, "monotonic", lambda: state["now"])
    # 复位滞回状态，避免测试间串扰
    monkeypatch.setattr(cap, "_BUDGET_LAST", [0.0, 0])
    monkeypatch.setattr(cap, "_BUDGET_LAST_SLOTS", [1])

    def fake_bool(key, default=False):
        return state["adaptive"]

    def fake_int(key, default=0):
        return {
            cap.runtime_settings.CAPTURE_MAX_BATCH: state["max_batch"],
            cap.runtime_settings.CAPTURE_SWAP_LIMIT_MB: state["swap_limit"],
            cap.runtime_settings.CAPTURE_MIN_FREE_MEM_MB: state["floor"],
        }.get(key, default)

    monkeypatch.setattr(cap.runtime_settings, "get_bool", fake_bool)
    monkeypatch.setattr(cap.runtime_settings, "get_int", fake_int)
    return cap, state


def test_swap_over_limit_and_growing_stops(budget_env):
    """swap 超上限且仍在换入 → 硬停（真正在吃 swap）。"""
    cap, s = budget_env
    s["swap_used"] = 300.0  # > 256
    cap.capture_budget()     # 采一次基线
    s["now"] += 1.0
    s["swapin"] = 200        # 200 页/s > 64，正在换入
    b = cap.capture_budget()
    assert b.slots == 0
    assert "swap" in b.reason


def test_swap_over_limit_but_idle_runs_slow(budget_env):
    """swap 存量超上限但静止、内存宽裕 → 1 条低速，给系统回收窗口。"""
    cap, s = budget_env
    s["swap_used"] = 300.0
    s["avail"] = 800.0
    b = cap.capture_budget()
    assert b.slots == 1
    assert "静止" in b.reason


def test_low_available_memory_stops(budget_env):
    cap, s = budget_env
    s["avail"] = 100.0  # < floor 120
    b = cap.capture_budget()
    assert b.slots == 0
    assert "内存" in b.reason


def test_swapin_thrashing_stops(budget_env):
    cap, s = budget_env
    # 先采一次基线，再让 swapin 在 1 秒内暴涨 → 判定颠簸
    cap.capture_budget()
    s["now"] += 1.0
    s["swapin"] = 2000  # 2000 页/s > 1024 上限
    b = cap.capture_budget()
    assert b.slots == 0
    assert "颠簸" in b.reason


def test_idle_swap_and_plenty_memory_full_speed(budget_env):
    cap, s = budget_env
    s["swap_used"] = 10.0   # <= 25% of 256
    s["avail"] = 800.0      # >= floor*2
    b = cap.capture_budget()
    assert b.slots == s["max_batch"]


def test_middle_state_single_slot(budget_env):
    cap, s = budget_env
    s["swap_used"] = 150.0  # 介于 25% 和 100% 之间
    s["avail"] = 400.0      # 未达 floor*2=240*... 实际 >=240, 但 swap 不空闲
    b = cap.capture_budget()
    assert b.slots == 1


def test_adaptive_off_falls_back_to_fixed_threshold(budget_env, monkeypatch):
    cap, s = budget_env
    s["adaptive"] = False
    s["swap_used"] = 0.0
    monkeypatch.setattr(cap.settings, "capture_min_free_mem_mb", 200)
    s["avail"] = 300.0
    assert cap.capture_budget().slots == 1
    s["avail"] = 150.0
    assert cap.capture_budget().slots == 0


def test_hysteresis_on_resume_ratio(budget_env):
    """上一轮暂停后，swap 要降到上限的 95% 以下才按空闲档恢复。"""
    cap, s = budget_env
    # 先因内存下限进入暂停
    s["avail"] = 50.0
    assert cap.capture_budget().slots == 0
    # 内存恢复但 swap 停在 250（上限 256 的 95%=243 之上）→ 不能进满速档，
    # 只能常规 1 条（滞回恢复线拦住 max_batch）
    s["avail"] = 800.0
    s["swap_used"] = 250.0
    assert cap.capture_budget().slots == 1
    # swap 降到空闲档（≤ 上限 25% = 64MB）→ 满速
    s["swap_used"] = 50.0
    assert cap.capture_budget().slots == 2


def test_swap_snapshot_reads_meminfo_and_vmstat(monkeypatch):
    """真实解析：SwapTotal/SwapFree 算已用，pswpin 取换入累计。"""
    import io

    import silver_sentinel.capture as cap

    meminfo = (
        "MemTotal:  2000000 kB\nSwapTotal: 1048576 kB\nSwapFree: 524288 kB\n"
    )
    vmstat = "pswpin 12345\npswpout 67890\n"
    files = [io.StringIO(meminfo), io.StringIO(vmstat)]

    def fake_open(*a, **k):
        return files.pop(0)

    monkeypatch.setattr("builtins.open", fake_open)
    used, swapin = cap._swap_snapshot()
    assert abs(used - 512.0) < 1, used
    assert swapin == 12345
