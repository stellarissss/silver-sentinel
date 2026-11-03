"""监控调度。

刻意不用 Celery/Redis：单进程 + 数据库里存 next_run_at 足够，
部署成本低、断了能续、多实例时靠唯一约束和行级更新避免重复执行。
"""

from __future__ import annotations

import logging
import threading
import time
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


def execute_target(session: Session, target: WatchTarget) -> dict:
    run = ScanRun(target_id=target.id, trigger="schedule", status="running")
    session.add(run)
    session.flush()

    discovered: list[str] = []
    stats: dict = {"kind": target.kind, "value": target.value, "scanned": 0, "found": 0}
    error = ""

    try:
        if target.kind == "keyword":
            rows = crtsh.search_keyword(target.value, limit=120)
            domains = [r["domain"] for r in rows][:MAX_NEW_PER_RUN * 3]
            discovered = domains

        elif target.kind == "brand":
            rows = typosquat.probe(target.value, limit=40)
            discovered = [r["domain"] for r in rows]
            stats["resolved"] = len(discovered)

        elif target.kind == "domain":
            discovered = [target.value]

        for item in discovered[:MAX_NEW_PER_RUN]:
            kind = "domain" if "." in item else "text"
            try:
                result = scan(kind, item, trigger="schedule", run_llm=False, do_cluster=False, session=session)
                stats["scanned"] += 1
                if result.assessment.verdict in {"suspicious", "high_risk", "confirmed"}:
                    stats["found"] += 1
            except Exception:
                log.debug("扫描失败：%s", item, exc_info=True)

        from .analyzers.cluster import cluster

        cluster(session)

    except Exception as exc:  # 单个目标失败不应中断整个调度
        error = str(exc)[:300]
        log.warning("监控任务失败 %s=%s：%s", target.kind, target.value, error)

    now = utcnow()
    run.finished_at = now
    run.status = "error" if error else "ok"
    run.error = error
    run.stats = stats

    target.last_run_at = now
    target.next_run_at = now + timedelta(minutes=max(15, target.interval_minutes))
    session.flush()

    return {"target": target.value, "status": run.status, "stats": stats, "error": error}


def run_due(limit: int = 10) -> list[dict]:
    out: list[dict] = []
    with session_scope() as session:
        ensure_schedule(session)
        for target in due_targets(session)[:limit]:
            out.append(execute_target(session, target))
            session.commit()
    return out


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
