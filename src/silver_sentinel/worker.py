"""常驻工作线程：把「取证」从主周期里拆出来，并给每条后台线装心跳。

为什么拆
--------
原来的结构是：调度线程每 60 秒跑一次 run_cycle，取证是其中第 3 步。
于是一个周期有多长，取证就有多稀疏——建图 40 秒、富化 20 秒、取证 45 秒，
一轮两分钟，实际取证速率只有设计的 1/3。更糟的是任何一步卡住，取证全停。

现在：
- 调度线程只管研判 / 富化 / 建图，绝不等 Chromium；
- 取证线程独立常驻，抓到一条就继续抓下一条，队列空了才慢下来；
- 巡检线程每 30 分钟清一次台账与临时文件，磁盘不够时主动降级；
- 看门狗每 60 秒检查上面三条线的心跳，线程死了就重拉——24/7 无人值守时，
  「线程悄悄死掉、界面还在转圈」比报错更难发现。

所有线程都用 daemon=True：主进程退出时不留孤儿进程。
"""

from __future__ import annotations

import logging
import shutil
import threading
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy import delete, func, select

from .config import settings
from .db import session_scope
from .domain import utcnow
from .models import CaptureTask, TaskRun

log = logging.getLogger(__name__)

# name -> {"at": monotonic, **info}
_HEARTBEATS: dict[str, dict[str, Any]] = {}
_HB_LOCK = threading.Lock()

_STOP = threading.Event()
_THREADS: dict[str, threading.Thread] = {}
_STARTED = False
_START_LOCK = threading.Lock()


def beat(name: str, **info: Any) -> None:
    with _HB_LOCK:
        entry = _HEARTBEATS.setdefault(name, {})
        entry.update(info)
        entry["at"] = time.monotonic()
        entry["iso"] = utcnow().isoformat()


def heartbeat_snapshot() -> dict[str, Any]:
    now = time.monotonic()
    with _HB_LOCK:
        return {
            name: {**info, "age_s": round(now - info.get("at", now), 1)}
            for name, info in _HEARTBEATS.items()
        }


def is_alive(name: str) -> bool:
    thread = _THREADS.get(name)
    return bool(thread and thread.is_alive())


def capture_worker_alive() -> bool:
    return is_alive("capture")


# ---------------------------------------------------------------- 取证线程


class CaptureWorker:
    """单线程取证循环。

    Chromium 在这台 2G 机器上只能开一个：并发两个必然 OOM，而 OOM 会让
    整个进程被内核杀掉，比慢一点严重得多。所以「快」靠的是不空转，不是并发。
    """

    def __init__(self) -> None:
        self.interval = max(5, settings.capture_interval_seconds)
        self.runs = 0
        self.captured = 0
        self.failed = 0
        self.idle_rounds = 0
        self.last: dict[str, Any] = {}

    def tick(self) -> int:
        """跑一条。返回实际执行条数。"""
        from .capture import backfill, queue_summary, run_batch

        added = backfill(limit=settings.capture_backfill_limit)
        result = run_batch(limit=1)
        ran = int(result.get("ran") or 0)
        ok = int(result.get("ok") or 0)
        self.runs += 1
        self.captured += ok
        self.failed += max(0, ran - ok)
        self.last = {
            "at": utcnow().isoformat(),
            "added": added,
            "ran": ran,
            "ok": ok,
            "queue": queue_summary(),
        }
        beat("capture", runs=self.runs, ok=self.captured, failed=self.failed, ran=ran)
        return ran

    def run_forever(self) -> None:
        log.info("取证线程已启动，基础间隔 %ss", self.interval)
        # 启动先跑一轮：进程重启后积压的任务不该再等一个 tick
        while not _STOP.is_set():
            ran = 0
            try:
                if settings.capture_enabled:
                    ran = self.tick()
            except Exception as exc:  # noqa: BLE001 一条失败不能杀掉整条线
                self.failed += 1
                beat("capture", error=f"{type(exc).__name__}: {exc}"[:200])
                log.warning("取证线程异常：%s", exc, exc_info=True)
            if ran:
                # 有活就立刻接上：这里的 1 秒只是让调度线程透口气，
                # 不是节拍。原来用 `interval - elapsed`，一条取证 5 秒就要
                # 白等 10 秒，等于自废三分之二吞吐。
                self.idle_rounds = 0
                pause = 1.0
            else:
                self.idle_rounds += 1
                # 队列空时逐步退避到 4 倍间隔，减少 SQLite 轮询与日志噪声
                pause = min(self.interval * 4, self.interval * (1 + self.idle_rounds * 0.5))
            _STOP.wait(max(0.5, pause))


# ---------------------------------------------------------------- 巡检线程


def housekeeping() -> dict[str, Any]:
    """台账、临时文件、回收站的定期清理。长期跑不清理，磁盘一定会满。"""
    from .evidence import cleanup_tmp, purge_trash

    removed_runs = 0
    try:
        with session_scope() as s:
            max_id = s.scalar(select(func.max(TaskRun.id))) or 0
            if max_id > 3000:
                res = s.execute(delete(TaskRun).where(TaskRun.id <= max_id - 3000, TaskRun.status != "running"))
                removed_runs = res.rowcount or 0
    except Exception as exc:  # noqa: BLE001
        log.debug("清理任务台账失败：%s", exc)

    tmp = cleanup_tmp(3600)
    trash = {"removed": 0}
    try:
        trash = purge_trash(7)
    except Exception as exc:  # noqa: BLE001
        log.debug("清理回收站失败：%s", exc)

    usage = shutil.disk_usage(settings.data_dir)
    free_gb = usage.free / 1024**3
    out = {
        "task_runs_removed": removed_runs,
        "tmp_removed": tmp,
        "trash_removed": trash.get("removed", 0),
        "disk_free_gb": round(free_gb, 2),
        "disk_used_pct": round(usage.used / usage.total * 100, 1),
    }
    if free_gb < 2:
        log.warning("磁盘剩余 %.1fGB，已进入低空间模式（暂停 APK 下载）", free_gb)
    beat("housekeeping", **out)
    return out


def low_disk(threshold_gb: float = 1.5) -> bool:
    try:
        return shutil.disk_usage(settings.data_dir).free / 1024**3 < threshold_gb
    except OSError:
        return False


# ---------------------------------------------------------------- 看门狗

_FACTORIES: dict[str, Callable[[], None]] = {}


def register(name: str, factory: Callable[[], None]) -> None:
    """登记一条后台线。factory 负责跑循环，通常是某个对象的 run_forever。"""
    _FACTORIES[name] = factory


def _spawn(name: str) -> None:
    factory = _FACTORIES.get(name)
    if factory is None:
        return
    thread = threading.Thread(target=factory, name=f"ss-{name}", daemon=True)
    _THREADS[name] = thread
    thread.start()


def start_all() -> None:
    global _STARTED
    with _START_LOCK:
        if _STARTED:
            return
        _STARTED = True
    _STOP.clear()
    for name in _FACTORIES:
        _spawn(name)
    threading.Thread(target=_supervise, name="ss-supervisor", daemon=True).start()
    log.info("后台线程已启动：%s", "、".join(_FACTORIES) or "无")


def _supervise() -> None:
    """心跳看门狗：线程死了重拉，心跳停了记录告警。"""
    while not _STOP.wait(60):
        for name in list(_FACTORIES):
            thread = _THREADS.get(name)
            if thread is not None and thread.is_alive():
                continue
            log.error("后台线程 %s 已停止，正在重启", name)
            beat("supervisor", restarted=name)
            _spawn(name)
        # 调度线程与发现引擎不在 _FACTORIES 里（它们有自己的生命周期管理），
        # 这里补一刀，避免「发现停了但界面一切正常」。
        try:
            from .pipeline import get_scheduler

            get_scheduler().ensure_running()
        except Exception:  # noqa: BLE001
            log.debug("调度线程检查失败", exc_info=True)
        try:
            from .discover.engine import get_engine

            get_engine().ensure_running()
        except Exception:  # noqa: BLE001
            log.debug("发现引擎检查失败", exc_info=True)


def stop_all() -> None:
    _STOP.set()


def stats() -> dict[str, Any]:
    with _HB_LOCK:
        hb = dict(_HEARTBEATS)
    out: dict[str, Any] = {"threads": {name: is_alive(name) for name in _FACTORIES}}
    capture = hb.get("capture") or {}
    out["capture"] = {
        "runs": capture.get("runs", 0),
        "ok": capture.get("ok", 0),
        "failed": capture.get("failed", 0),
        "age_s": round(time.monotonic() - capture["at"], 1) if capture.get("at") else None,
        "last": (capture.get("ran") if capture else None),
        "error": capture.get("error", ""),
    }
    return out


# ---------------------------------------------------------------- 默认装配

_capture_worker: CaptureWorker | None = None


def get_capture_worker() -> CaptureWorker:
    global _capture_worker
    if _capture_worker is None:
        _capture_worker = CaptureWorker()
    return _capture_worker


def start_background() -> None:
    """装配并启动全部后台线。重复调用无副作用。"""
    if settings.capture_enabled:
        worker = get_capture_worker()
        register("capture", worker.run_forever)

    def _housekeeping_loop() -> None:
        # 启动先跑一次，把上次进程留下的临时文件清掉
        try:
            housekeeping()
        except Exception:  # noqa: BLE001
            log.debug("首次巡检失败", exc_info=True)
        while not _STOP.wait(1800):
            try:
                housekeeping()
            except Exception:  # noqa: BLE001
                log.warning("巡检失败", exc_info=True)

    register("housekeeping", _housekeeping_loop)
    start_all()


def capture_queue_health() -> dict[str, Any]:
    """取证队列健康度：积压、失败率、最老任务。

    「最老任务」只统计**到期**（next_run_at <= now）的任务。退避中的任务本来
    就要等，把它算成积压会让健康检查一直报 stalled——线上就出现过 5 条退避
    任务把 oldest_queued 顶到 46 分钟，其实浏览器空闲、没有任何该跑没跑的活。
    """
    now = utcnow()
    with session_scope() as s:
        counts = dict(
            s.execute(select(CaptureTask.state, func.count(CaptureTask.id)).group_by(CaptureTask.state)).all()
        )
        oldest_due = s.scalar(
            select(func.min(CaptureTask.created_at)).where(
                CaptureTask.state == "queued", CaptureTask.next_run_at <= now
            )
        )
        due_count = s.scalar(
            select(func.count(CaptureTask.id)).where(
                CaptureTask.state == "queued", CaptureTask.next_run_at <= now
            )
        ) or 0
        recent = list(
            s.scalars(select(CaptureTask).where(CaptureTask.finished_at.is_not(None)).order_by(CaptureTask.id.desc()).limit(50))
        )
    done = sum(1 for t in recent if t.state == "done")
    rate = round(done / len(recent), 3) if recent else None
    age_min = round((now - oldest_due).total_seconds() / 60, 1) if oldest_due else 0
    # 线程心跳停了（>5 分钟）比队列数字更早说明问题：线程死掉时队列看起来
    # 一切正常，只是永远不动。
    hb = heartbeat_snapshot().get("capture") or {}
    hb_age = hb.get("age_s")
    queued = counts.get("queued", 0)
    return {
        "queued": queued,
        "queued_due": due_count,
        "queued_scheduled": max(0, queued - due_count),
        "running": counts.get("running", 0),
        "failed_total": counts.get("failed", 0),
        "done_total": counts.get("done", 0),
        "success_rate_recent": rate,
        "oldest_queued_minutes": age_min,
        "worker_heartbeat_age_s": hb_age,
        "stalled": bool((age_min and age_min > 45) or (hb_age is not None and hb_age > 300)),
    }


__all__ = [
    "beat",
    "heartbeat_snapshot",
    "capture_worker_alive",
    "start_background",
    "stats",
    "housekeeping",
    "low_disk",
    "capture_queue_health",
    "stop_all",
]
