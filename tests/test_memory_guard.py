"""内存看门狗：小内存机器上不让取证把系统推入 swap 颠簸。

线上 v1.16.11 之后仍反复卡死，根因是内存见底时继续拉起 Chromium：
取证线程卡在 do_swap_page → 90s 超时 → 重建线程池但没关旧浏览器 →
新线程又拉起一个 Chromium → RSS 一路涨到 1.3G → 整机卡死。

这里钉住三件事：
1. available_memory_mb / memory_ok 阈值判断正确；
2. 超时重建线程池时会主动 close 浏览器（释放卡住的 Chromium）；
3. 浏览器回收阈值收紧到小内存机可接受的范围。
"""

from __future__ import annotations

import io


def test_available_memory_mb_reads_memavailable(monkeypatch):
    from silver_sentinel import capture

    fake = "MemTotal:  2000000 kB\nMemFree: 100000 kB\nMemAvailable: 350000 kB\n"
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.StringIO(fake))
    val = capture.available_memory_mb()
    assert abs(val - 350000 / 1024) < 1, val


def test_available_memory_mb_fallback_on_error(monkeypatch):
    from silver_sentinel import capture

    def boom(*a, **k):
        raise OSError("no proc")

    monkeypatch.setattr("builtins.open", boom)
    # 读不到就返回宽松大值，不挡取证
    assert capture.available_memory_mb() >= 1024


def test_memory_ok_respects_threshold(monkeypatch):
    from silver_sentinel import capture

    monkeypatch.setattr(capture.settings, "capture_min_free_mem_mb", 350)
    monkeypatch.setattr(capture, "available_memory_mb", lambda: 350.0)
    assert capture.memory_ok() is True       # 等于阈值 -> 放行
    monkeypatch.setattr(capture, "available_memory_mb", lambda: 349.9)
    assert capture.memory_ok() is False      # 低于阈值 -> 暂停
    monkeypatch.setattr(capture, "available_memory_mb", lambda: 800.0)
    assert capture.memory_ok() is True

    # 阈值为 0 -> 关闭看门狗，任何内存都放行
    monkeypatch.setattr(capture.settings, "capture_min_free_mem_mb", 0)
    monkeypatch.setattr(capture, "available_memory_mb", lambda: 1.0)
    assert capture.memory_ok() is True


def test_reset_pool_closes_browser(monkeypatch):
    """超时重建线程池必须先关掉卡住的浏览器，否则内存一路累积。"""
    from silver_sentinel import capture

    closed = []

    class FakeSandbox:
        def close(self):
            closed.append(True)

    monkeypatch.setattr(capture, "get_web_sandbox", lambda: FakeSandbox())
    capture._reset_capture_pool()
    assert closed == [True], "重建线程池时应主动 close 浏览器释放内存"
    # 重建后仍是单 worker 线程池
    assert capture._CAPTURE_POOL._max_workers == 1


def test_worker_skips_tick_when_budget_zero(monkeypatch):
    """取证容量为 0（swap/内存吃紧）时 worker 不灌任务、不拉浏览器，任务留在队列。

    v1.16.16 起判定入口从固定阈值 memory_ok 换成 capture_budget（见新测试文件）。
    这里只钉住 worker 对「容量为 0」的响应：跳过本轮，不碰 backfill/run_batch。
    """
    from silver_sentinel import capture, worker

    calls = {"backfill": 0, "run_batch": 0}

    def fake_backfill(*a, **k):
        calls["backfill"] += 1
        return 0

    def fake_run_batch(*a, **k):
        calls["run_batch"] += 1
        return {"ran": 0, "ok": 0}

    zero = capture.CaptureBudget(0, 120.0, 512.0, 0.0, "swap 达上限")
    monkeypatch.setattr("silver_sentinel.capture.capture_budget", lambda: zero)
    monkeypatch.setattr("silver_sentinel.capture.backfill", fake_backfill)
    monkeypatch.setattr("silver_sentinel.capture.run_batch", fake_run_batch)

    cw = worker.CaptureWorker()
    ran = cw.tick()
    assert ran == 0
    assert calls == {"backfill": 0, "run_batch": 0}, "容量为 0 时不应取证"
    assert cw.idle_rounds >= 1


def test_recycle_threshold_is_small_memory_friendly():
    """浏览器回收阈值必须收紧，避免堆增长把小机器吃满。"""
    from silver_sentinel.sandbox.web import WebSandbox

    assert WebSandbox.RECYCLE_EVERY_RUNS <= 60
    assert WebSandbox.RECYCLE_EVERY_SECONDS <= 3 * 3600
