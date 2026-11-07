"""监控调度。

刻意不用 Celery/Redis：单进程 + 数据库里存 next_run_at 足够，
部署成本低、断了能续、多实例时靠唯一约束和行级更新避免重复执行。

有一条硬约束值得写在这里：SQLite 只允许一个写事务。取证和采集都要跑几十秒，
期间还在自己开事务写证据。如果调度器把「先写一条 ScanRun」的事务一直揣在手里
再去调取证，第二个写请求必然 `database is locked`（WAL 只解决读写并发，不解决写写）。
所以一次执行被拆成三段：

    短事务读快照 → 无事务执行（网络/渲染/落证据）→ 短事务回写结果

任何新加的监控逻辑都必须遵守这个形状。
"""

from __future__ import annotations

import logging
import threading
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .collectors import crtsh, typosquat
from .config import settings
from .db import session_scope
from .domain import utcnow
from .intake import scan
from .models import ScanRun, WatchTarget

log = logging.getLogger(__name__)

MAX_NEW_PER_RUN = 15

# 资产已经没了（被合并或清理）时不该继续当失败重试，直接停掉盯防
_GONE_REASONS = ("资产不存在", "资产消失")

# 调度重入保护：后台 tick 与界面「立即检查」共用同一把锁
_RUN_LOCK = threading.Lock()


def ensure_schedule(session: Session) -> None:
    now = utcnow()
    for target in session.scalars(select(WatchTarget).where(WatchTarget.enabled.is_(True))):
        if target.next_run_at is None:
            target.next_run_at = now
    session.flush()


def due_targets(session: Session, now=None) -> list[WatchTarget]:
    now = now or utcnow()
    return list(
        session.scalars(
            select(WatchTarget)
            .where(WatchTarget.enabled.is_(True), WatchTarget.next_run_at <= now)
            .order_by(WatchTarget.next_run_at)
            .limit(20)
        )
    )


def reap_stale_runs(session: Session, older_than_minutes: int = 120) -> int:
    """把上次进程崩溃留下的 running 记录收尾，否则报表里会一直挂着"运行中"。"""
    deadline = utcnow() - timedelta(minutes=older_than_minutes)
    stale = list(
        session.scalars(
            select(ScanRun).where(ScanRun.status == "running", ScanRun.started_at <= deadline)
        )
    )
    for run in stale:
        run.status = "error"
        run.error = "执行中断（进程重启）"
        run.finished_at = utcnow()
    return len(stale)


def _backoff_minutes(fail_count: int) -> int:
    """连续失败退避到 24 小时，避免把带宽全耗在一个已经挂掉的站上。"""
    return min(1440, 30 * (2 ** min(5, max(1, fail_count))))


def _open_run(target_id: int, trigger: str) -> int | None:
    with session_scope() as s:
        run = ScanRun(target_id=target_id, trigger=trigger, status="running")
        s.add(run)
        s.flush()
        return run.id


def _close_run(
    run_id: int | None,
    target_id: int,
    *,
    status: str,
    error: str,
    stats: dict,
    interval_minutes: int,
    changed: bool,
) -> None:
    """短事务回写：运行记录 + 目标的 next_run_at / 失败计数 / 变更计数。"""
    now = utcnow()
    with session_scope() as s:
        if run_id is not None:
            run = s.get(ScanRun, run_id)
            if run is not None:
                run.finished_at = now
                run.status = status
                run.error = error[:300]
                run.stats = stats

        target = s.get(WatchTarget, target_id)
        if target is None:
            return
        target.last_run_at = now
        if changed:
            target.change_count = (target.change_count or 0) + 1
            target.last_change_at = now

        if status == "skipped":
            # 目标已失效：不复位 next_run_at，避免每轮都被捞出来空跑
            return
        if error:
            target.fail_count = (target.fail_count or 0) + 1
            target.next_run_at = now + timedelta(minutes=_backoff_minutes(target.fail_count))
        else:
            target.fail_count = 0
            target.next_run_at = now + timedelta(minutes=max(15, interval_minutes))


def _retire_target(target_id: int, reason: str) -> None:
    """目标指向的资产已经不在了：停用盯防，别让它无限退避。"""
    with session_scope() as s:
        target = s.get(WatchTarget, target_id)
        if target is not None:
            target.enabled = False
            target.note = f"{target.note or ''}\n[自动停用] {reason}".strip()[:1000]
            target.next_run_at = None


def _run_asset_target(target_id: int, run_id: int | None, row: dict) -> dict:
    """资产级盯防：把目标塞进取证队列，由常驻取证线程执行。

    以前这里是同步调 capture_asset：一个目标 20 秒，10 个到期目标就是 200 秒，
    调度线程全程握着浏览器，取证队列只能干等——「断断续续」的另一半原因。
    现在只负责排队；真正抓页面的是 worker，抓完自然会写变更事件。
    """
    from .capture import capture_asset, enqueue
    from .worker import capture_worker_alive

    label = row["value"]
    stats: dict = {"kind": row["kind"], "value": label, "scanned": 1, "found": 0}
    error = ""
    changes: list[str] = []

    asset_id = row["asset_id"] or 0
    if not asset_id:
        # kind=asset 但没挂 asset_id：老数据或人工建歪了，靠域名兜回来
        from .models import Asset

        with session_scope() as s:
            hit = s.scalar(select(Asset).where(Asset.value == label).limit(1))
            asset_id = hit.id if hit else 0
    if not asset_id:
        _close_run(
            run_id, target_id,
            status="skipped", error="资产已不存在", stats=stats,
            interval_minutes=row["interval"], changed=False,
        )
        _retire_target(target_id, "找不到对应资产")
        return {"target": label, "status": "skipped", "stats": stats, "error": "资产已不存在"}

    # 取证线程活着就只排队（最高优先级），让队列统一调度；
    # 线程没起来（老部署/手工跑）才退回同步执行。
    if capture_worker_alive():
        enqueue(asset_id, reason="watch", priority=1)
        stats["queued"] = True
        _close_run(
            run_id, target_id,
            status="ok", error="", stats=stats,
            interval_minutes=row["interval"], changed=False,
        )
        return {"target": label, "status": "ok", "stats": stats, "error": ""}

    try:
        result = capture_asset(asset_id)
        stats["captured"] = bool(result.get("ok"))
        stats["status"] = result.get("status")
        stats["evidence"] = result.get("evidence", [])
        changes = list(result.get("changes") or [])
        stats["changes"] = changes
        if result.get("busy"):
            # 取证闸门被别人占着：这是排队问题，不是目标坏了，按正常间隔重排
            stats["busy"] = True
        elif not result.get("ok"):
            error = str(result.get("reason") or result.get("error") or "")[:300]
    except Exception as exc:  # noqa: BLE001 单目标异常不能掀翻整轮调度
        error = f"{type(exc).__name__}: {exc}"[:300]
        log.warning("资产复访失败 %s：%s", label, error)

    if stats.get("busy"):
        _close_run(
            run_id, target_id,
            status="ok", error="", stats=stats,
            interval_minutes=row["interval"], changed=False,
        )
        return {"target": label, "status": "ok", "stats": stats, "error": ""}

    if error and any(r in error for r in _GONE_REASONS):
        _close_run(
            run_id, target_id,
            status="skipped", error=error, stats=stats,
            interval_minutes=row["interval"], changed=False,
        )
        _retire_target(target_id, f"资产已不存在（{row['asset_id']}）")
        return {"target": label, "status": "skipped", "stats": stats, "error": error}

    status = "error" if error else "ok"
    _close_run(
        run_id, target_id,
        status=status, error=error, stats=stats,
        interval_minutes=row["interval"], changed=bool(changes),
    )
    return {"target": label, "status": status, "stats": stats, "error": error}


def _run_scan_target(target_id: int, run_id: int | None, row: dict) -> dict:
    """发现源目标：CT / 品牌变体 / 域名，扫出结果后逐个进扫描。

    采集（网络）在事务外做，每扫一条用 scan() 自己的事务，别攒成一个大事务。
    """
    label = row["value"]
    stats: dict = {"kind": row["kind"], "value": label, "scanned": 0, "found": 0}
    error = ""
    discovered: list[str] = []

    try:
        if row["kind"] == "keyword":
            rows = crtsh.search_keyword(label, limit=120)
            discovered = [r["domain"] for r in rows][: MAX_NEW_PER_RUN * 3]
        elif row["kind"] == "brand":
            rows = typosquat.probe(label, limit=40)
            discovered = [r["domain"] for r in rows]
            stats["resolved"] = len(discovered)
        elif row["kind"] == "domain":
            discovered = [label]
    except Exception as exc:  # noqa: BLE001
        error = str(exc)[:300]
        log.warning("发现源采集失败 %s=%s：%s", row["kind"], label, error)

    for item in discovered[:MAX_NEW_PER_RUN]:
        kind = "domain" if "." in item else "text"
        try:
            result = scan(kind, item, trigger="schedule", run_llm=False, do_cluster=False)
            stats["scanned"] += 1
            if result.assessment.verdict in {"suspicious", "high_risk", "confirmed"}:
                stats["found"] += 1
        except Exception:  # noqa: BLE001
            log.debug("扫描失败：%s", item, exc_info=True)

    if stats["scanned"]:
        try:
            from .analyzers.cluster import cluster

            with session_scope() as s:
                cluster(s)
        except Exception:  # noqa: BLE001 团伙聚类失败不影响扫描结果
            log.warning("聚类失败", exc_info=True)

    status = "error" if error else "ok"
    _close_run(
        run_id, target_id,
        status=status, error=error, stats=stats,
        interval_minutes=row["interval"], changed=False,
    )
    return {"target": label, "status": status, "stats": stats, "error": error}


def run_target(target_id: int) -> dict:
    """执行单个监控目标：读快照 → 出事务执行 → 短事务回写。"""
    with session_scope() as s:
        target = s.get(WatchTarget, target_id)
        if target is None:
            return {"target": f"#{target_id}", "status": "skipped", "error": "目标已不存在"}
        if not target.enabled:
            return {"target": target.value, "status": "skipped", "error": "目标已停用"}
        row = {
            "id": target.id,
            "kind": target.kind,
            "value": target.value,
            "asset_id": target.asset_id,
            "interval": target.interval_minutes or 360,
        }

    run_id = _open_run(target_id, "schedule")
    if row["asset_id"] or row["kind"] == "asset":
        return _run_asset_target(target_id, run_id, row)
    return _run_scan_target(target_id, run_id, row)


def run_due(limit: int = 10) -> list[dict]:
    """执行到期的监控目标。

    后台线程和界面上的「立即检查」都会调到这里，重入会让同一个目标被抓两遍，
    所以用一个非阻塞锁去重：抢不到就表示上一轮还在跑，直接返回空。
    """
    if not _RUN_LOCK.acquire(blocking=False):
        log.info("上一轮调度尚未结束，跳过本次触发")
        return []
    try:
        # 先把待办目标 id 捞出来再提交事务：这之后手里没有任何连接，
        # 取证要跑多久都不会挡住别的写入方。
        with session_scope() as session:
            ensure_schedule(session)
            reap_stale_runs(session)
            ids = [t.id for t in due_targets(session)[:limit]]

        out: list[dict] = []
        for target_id in ids:
            try:
                out.append(run_target(target_id))
            except Exception as exc:  # noqa: BLE001 一个目标炸了不能拖垮整轮
                log.warning("监控目标 %s 执行异常", target_id, exc_info=True)
                out.append({"target": f"#{target_id}", "status": "error", "error": str(exc)[:300]})
        return out
    finally:
        _RUN_LOCK.release()


def start_background(stop_event: threading.Event | None = None) -> threading.Thread:
    stop = stop_event or threading.Event()

    def _loop() -> None:
        log.info("监控调度已启动，tick=%ss", settings.monitor_tick_seconds)
        while not stop.is_set():
            try:
                results = run_due()
                if results:
                    log.info("本轮执行 %s 个监控任务", len(results))
            except Exception:
                log.warning("调度轮询异常", exc_info=True)
            stop.wait(settings.monitor_tick_seconds)

    thread = threading.Thread(target=_loop, name="silver-monitor", daemon=True)
    thread.start()
    return thread
