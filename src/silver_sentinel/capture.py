"""取证闭环：自动把「看见的目标」变成「可提交的证据」。

原来的链路是「发现 → 入库 → 打分 → 结束」，页面证据一条都没有，所以 91% 的
资产判「证据不足」。这里补上中间那段：排队、执行、落证据、算指纹、检测变更、
回灌新域名、自动纳入监控。

三条边界
--------
1. 只读：不提交表单、不登录、不执行安装包。
2. 可追溯：每条证据进哈希链，失败也留一条 capture_error，不静默。
3. 有配额：APK 是唯一能迅速吃满磁盘的东西，单文件与单日都有硬上限。
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import threading
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from datetime import timedelta
from pathlib import Path
from typing import Any

try:
    from PIL import Image
except ImportError:  # pragma: no cover - 依赖声明里有 Pillow，这里只兜底
    # 缺 Pillow 时不要整个取证模块 import 失败（会连带 /api/capture/queue 一起 500）：
    # 截图照存，只是算不出 dHash 指纹。
    Image = None  # type: ignore[assignment]
from sqlalchemy import and_, func, or_, select

from . import runtime_settings
from .collectors import apk_fetch
from .config import settings
from .core.eventlog import emit
from .db import session_scope
from .domain import AssetKind, utcnow
from .evidence import append as append_evidence
from .evidence import append_file as append_evidence_file
from .evidence import read_bytes as read_evidence_bytes
from .models import (
    TIER_CANDIDATE,
    TIER_COLD,
    TIER_CONFIRMED,
    TIER_DISMISSED,
    TIER_WATCH,
    Asset,
    AssetSnapshot,
    CaptureTask,
    DiscoveryEvent,
    Evidence,
    WatchTarget,
)
from .sandbox.web import get_web_sandbox

log = logging.getLogger(__name__)

# 证据矩阵里固定展示的格子。缺哪一格、为什么缺，界面要能直接回答。
EXPECTED_KINDS: list[tuple[str, str]] = [
    ("page_html", "页面 HTML"),
    ("page_text", "页面正文"),
    ("screenshot", "首屏截图"),
    ("screenshot_full", "全页截图"),
    ("network", "网络请求"),
    ("tls_cert", "TLS 证书"),
    ("forms", "表单结构"),
    ("apk", "安装包"),
]

KIND_LABEL = {k: v for k, v in EXPECTED_KINDS}
KIND_LABEL.update({"assessment": "研判快照", "text": "原始文本", "qrcode": "二维码", "dns": "解析记录"})

PRIORITY = {TIER_CONFIRMED: 10, TIER_WATCH: 25, TIER_CANDIDATE: 60, TIER_COLD: 200}

# 冷档填谷的上次时间（monotonic）。进程重启后归零，最多多抓一条，无副作用。
_COLD_FILL_AT = 0.0


def _cold_fill_ready() -> bool:
    gap = int(getattr(settings, "capture_cold_fill_seconds", 0) or 0)
    return gap > 0 and (time.monotonic() - _COLD_FILL_AT) >= gap

# 失败分三类，冷却时间完全不同。混在一起按「失败 3 次 → 等 6 小时」处理，
# 结果是死域名每天被重新拉起 4 次，每次二三十秒只换来同一句 NXDOMAIN，
# 真正活着的目标反而排在后面。线上 181 条失败里 115 条属于前两类。
FAILURE_DEAD = "dead"          # 域名没了 / 端口拒连：永久性，隔天再看
FAILURE_BLOCKED = "blocked"    # WAF、证书、空响应：可能是临时封锁，隔天再看
FAILURE_TRANSIENT = "transient"  # 超时、连接重置：分钟级重试有意义

_DEAD_MARKERS = (
    "ERR_NAME_NOT_RESOLVED",
    "ERR_NAME_RESOLUTION_FAILED",
    "ERR_CONNECTION_REFUSED",
    "ERR_ADDRESS_UNREACHABLE",
    "NXDOMAIN",
    "无法解析",
    "无可访问地址",
)
_BLOCKED_MARKERS = (
    "ERR_SSL",
    "ERR_CERT",
    "ERR_EMPTY_RESPONSE",
    "ERR_HTTP2_PROTOCOL_ERROR",
    "出站被拒",
    "内网地址",
)


def classify_failure(error: str) -> str:
    """把 Playwright 的报错归成「还值不值得再花一次浏览器」。

    宁可把不确定的归到 transient（多试一次），也不要把临时故障判死：
    判死的代价是这条线索 3 天内不再取证，而多试一次的代价只是几十秒。
    """
    text = (error or "").upper()
    if not text.strip():
        return FAILURE_TRANSIENT
    if any(marker.upper() in text for marker in _DEAD_MARKERS):
        return FAILURE_DEAD
    if any(marker.upper() in text for marker in _BLOCKED_MARKERS):
        return FAILURE_BLOCKED
    return FAILURE_TRANSIENT


def retry_delay(kind: str) -> timedelta:
    """按失败性质给冷却时间。"""
    if kind == FAILURE_DEAD:
        return timedelta(hours=settings.capture_dead_retry_hours)
    if kind == FAILURE_BLOCKED:
        return timedelta(hours=settings.capture_blocked_retry_hours)
    return timedelta(minutes=10)

_MAX_HTML = 8_000_000
_MAX_TEXT = 2_000_000
_MAX_NETWORK = 4_000_000

# 一次只跑一个 Chromium：手动点「立即取证」、队列 worker、监控复访会同时来敲门。
# 而且 Playwright 的同步 API 绑死创建它的线程——同一实例换线程用会直接报
# "Cannot switch to a different thread"。所以不是加锁，是固定放在一个专用线程里执行。
_CAPTURE_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ss-capture")
# 单次取证的硬上限。沙箱自身 45 秒超时，加上 APK 下载与截图，
# 240 秒还没回来就一定有东西卡住了，直接换线程比干等 10 分钟强。
_CAPTURE_TIMEOUT = 240


# ---------------------------------------------------------------- 队列


def priority_of(asset: Asset) -> int:
    base = PRIORITY.get(asset.tier, 80)
    # 同档内分数高的先取证：高危目标早一分钟看到页面都有意义
    return max(1, base - int(min(20, (asset.score or 0) / 5)))


def enqueue(asset_id: int, *, reason: str = "", priority: int | None = None) -> bool:
    """入队。已有排队/执行中的任务时不重复入队，只把优先级提到更高。"""
    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return False
        if asset.kind not in (AssetKind.DOMAIN.value, AssetKind.URL.value) and reason != "manual":
            return False
        if asset.tier in (TIER_DISMISSED,) and reason != "manual":
            return False
        if asset.tier == TIER_COLD and reason not in ("manual", "cold-fill"):
            return False

        existing = s.scalar(
            select(CaptureTask).where(
                CaptureTask.asset_id == asset_id,
                CaptureTask.state.in_(("queued", "running")),
            )
        )
        pri = priority if priority is not None else priority_of(asset)
        if existing is not None:
            if pri < existing.priority:
                existing.priority = pri
            return False
        s.add(
            CaptureTask(
                asset_id=asset_id,
                priority=pri,
                reason=reason or "auto",
                next_run_at=utcnow(),
            )
        )
    return True


def seed_retry_state() -> int:
    """升级后第一次启动：给历史失败资产补一个冷却时间。

    老版本只有「失败 3 次 → 等 6 小时」一把尺子，库里躺着 150+ 个已经判死的
    资产。不补这一步，升级后第一轮 backfill 会把它们全部重新排队，浏览器
    先花一个小时把死域名再跑一遍，新线索排在后面——正是要修的那个「断断续续」。
    按存下来的错误文本分类，直接给对应冷却，老数据也能平滑过渡。
    """
    now = utcnow()
    with session_scope() as s:
        rows = list(
            s.scalars(
                select(Asset).where(
                    Asset.capture_state == "failed",
                    Asset.capture_retry_at.is_(None),
                )
            )
        )
        for asset in rows:
            kind = classify_failure(asset.capture_error or "")
            asset.capture_retry_at = now + retry_delay(kind)
            if kind == FAILURE_DEAD:
                asset.capture_state = "dead"
        return len(rows)


def queue_summary() -> dict[str, Any]:
    now = utcnow()
    with session_scope() as s:
        rows = s.execute(
            select(CaptureTask.state, func.count(CaptureTask.id)).group_by(CaptureTask.state)
        ).all()
        counts = {state: n for state, n in rows}
        # 「最老到期任务」以 next_run_at 为准，不用 created_at：一条重试了三次
        # 的任务 created_at 可能是一小时前，但它十分钟前才重新到期。用创建时间
        # 算等待时长，会把「刚退避完」误报成「积压了 53 分钟」（线上实测），
        # 进而触发 stalled 告警甚至看门狗重启——重启并不能让它跑得更快。
        oldest_due = s.scalar(
            select(func.min(CaptureTask.next_run_at)).where(
                CaptureTask.state == "queued", CaptureTask.next_run_at <= now
            )
        )
        next_due = s.scalar(
            select(func.min(CaptureTask.next_run_at)).where(
                CaptureTask.state == "queued", CaptureTask.next_run_at > now
            )
        )
        due_count = s.scalar(
            select(func.count(CaptureTask.id)).where(
                CaptureTask.state == "queued", CaptureTask.next_run_at <= now
            )
        ) or 0
        failed = list(
            s.scalars(
                select(CaptureTask)
                .where(CaptureTask.state == "failed")
                .order_by(CaptureTask.id.desc())
                .limit(5)
            )
        )
        pending_assets = s.scalar(
            select(func.count(Asset.id)).where(
                Asset.capture_state == "pending",
                Asset.tier.in_((TIER_CONFIRMED, TIER_WATCH, TIER_CANDIDATE)),
                Asset.kind.in_(("domain", "url")),
            )
        ) or 0
        # 「现在就能重试」的失败资产。冷却中的不算活——把它们算进积压会让
        # 健康检查永远显示有活没干（starved），而实际上只是还没到点。
        retryable_assets = s.scalar(
            select(func.count(Asset.id)).where(
                Asset.capture_state.in_(("failed", "dead")),
                Asset.tier.in_((TIER_CONFIRMED, TIER_WATCH, TIER_CANDIDATE)),
                Asset.kind.in_(("domain", "url")),
                or_(Asset.capture_retry_at.is_(None), Asset.capture_retry_at <= now),
            )
        ) or 0
        dead_assets = s.scalar(
            select(func.count(Asset.id)).where(Asset.capture_state == "dead")
        ) or 0
    queued = counts.get("queued", 0)
    return {
        "queued": queued,
        "queued_due": due_count,
        "queued_scheduled": max(0, queued - due_count),
        "running": counts.get("running", 0),
        "done": counts.get("done", 0),
        "failed": counts.get("failed", 0),
        "skipped": counts.get("skipped", 0),
        "pending_assets": pending_assets,
        "retryable_assets": retryable_assets,
        "dead_assets": dead_assets,
        "oldest_queued": oldest_due.isoformat() if oldest_due else None,
        # 队列健康度：界面上要能直接看出「是在干活、还是卡住了」
        "oldest_queued_minutes": round((now - oldest_due).total_seconds() / 60, 1) if oldest_due else 0,
        # 下一次退避到期还有多久：为 0 表示队列里没有等着的活
        "next_due_in_minutes": round((next_due - now).total_seconds() / 60, 1) if next_due else 0,
        "worker": _worker_snapshot(),
        "recent_failures": [
            {"asset_id": t.asset_id, "error": t.error[:200], "attempts": t.attempts} for t in failed
        ],
    }


def _worker_snapshot() -> dict[str, Any]:
    try:
        from .worker import heartbeat_snapshot

        hb = heartbeat_snapshot().get("capture") or {}
        return {
            "runs": hb.get("runs", 0),
            "ok": hb.get("ok", 0),
            "failed": hb.get("failed", 0),
            "age_s": hb.get("age_s"),
            "error": hb.get("error", ""),
        }
    except Exception:  # noqa: BLE001
        return {}


def run_batch(limit: int = 2) -> dict[str, Any]:
    """执行一批取证。单进程串行：2G 内存跑不了并发 Chromium。"""
    now = utcnow()
    claimed: list[tuple[int, int]] = []
    with session_scope() as s:
        # 进程重启会把「running」的任务留在库里。不回收的话这条资产从此
        # 既不会被 re-enqueue（enqueue 见到 running 就跳过），也不会被执行——
        # 界面上就是一个永远转圈的「执行中」。
        stale = list(
            s.scalars(
                select(CaptureTask).where(
                    CaptureTask.state == "running",
                    # 单条取证硬超时 240 秒；超过 10 分钟还挂着，只可能是进程被
                    # 杀掉时留下的行。回收得越快，重启后的空窗越短。
                    CaptureTask.started_at < now - timedelta(minutes=10),
                )
            )
        )
        for task in stale:
            task.state = "queued"
            task.next_run_at = now
            task.error = "上次执行被中断（进程重启），已重新排队"
        if stale:
            log.info("回收 %s 个中断的取证任务", len(stale))

        tasks = list(
            s.scalars(
                select(CaptureTask)
                .where(CaptureTask.state == "queued", CaptureTask.next_run_at <= now)
                .order_by(CaptureTask.priority, CaptureTask.id)
                .limit(max(1, limit))
            )
        )
        for task in tasks:
            task.state = "running"
            task.started_at = now
            task.attempts = (task.attempts or 0) + 1
            claimed.append((task.id, task.asset_id))

    results: list[dict[str, Any]] = []
    for task_id, asset_id in claimed:
        try:
            result = capture_asset(asset_id)
            ok = bool(result.get("ok"))
            error = "" if ok else str(result.get("error") or result.get("reason") or "")[:500]
        except Exception as exc:  # noqa: BLE001
            log.exception("取证异常 asset=%s", asset_id)
            result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            ok, error = False, str(result["error"])[:500]

        with session_scope() as s:
            task = s.get(CaptureTask, task_id)
            kind = "" if ok else classify_failure(error)
            retry_at = None
            if task is not None:
                attempts = task.attempts or 1
                # 资产已经不在了（被合并或清理）：任务作废，不要退避重试三次
                if result.get("reason") in ("资产不存在", "资产已删除"):
                    task.state = "skipped"
                    task.finished_at = utcnow()
                    task.error = "资产已不存在"
                elif ok:
                    task.state = "done"
                    task.finished_at = utcnow()
                    task.stats = {
                        k: result.get(k)
                        for k in ("evidence", "apk", "changes", "egress", "status")
                        if result.get(k) is not None
                    }
                elif kind in (FAILURE_DEAD, FAILURE_BLOCKED):
                    # 永久性失败不做分钟级重试：十分钟后再拉起一次 Chromium
                    # 只会得到同一句 ERR_NAME_NOT_RESOLVED，纯烧配额。
                    # 直接落 failed，冷却期由 asset.capture_retry_at 控制。
                    task.state = "failed"
                    task.finished_at = utcnow()
                    task.error = f"[{kind}] {error}"[:500]
                    retry_at = utcnow() + retry_delay(kind)
                elif attempts < 3:
                    # 退避重试：10 分钟 → 40 分钟 → 放弃
                    task.state = "queued"
                    task.error = error
                    task.next_run_at = utcnow() + timedelta(minutes=10 * (4 ** (attempts - 1)))
                    retry_at = task.next_run_at
                else:
                    task.state = "failed"
                    task.finished_at = utcnow()
                    task.error = error
                    retry_at = utcnow() + timedelta(hours=settings.capture_retry_cooldown_hours)
            asset = s.get(Asset, asset_id)
            if asset is not None and ok:
                asset.capture_state = "captured"
                asset.capture_error = ""
                asset.last_capture_at = utcnow()
                asset.capture_retry_at = None
            elif asset is not None and result.get("reason") not in ("资产不存在", "资产已删除"):
                # dead 与 failed 分开存：界面要能区分「站点没了」和「这次没抓好」，
                # 补队逻辑也按这两个值决定何时再试。
                asset.capture_state = "dead" if kind == FAILURE_DEAD else "failed"
                asset.capture_error = error
                asset.capture_retry_at = retry_at
        results.append({"asset_id": asset_id, "ok": ok, "error": error, "detail": result})
    return {"ran": len(results), "ok": sum(1 for r in results if r["ok"]), "results": results}


def backfill(limit: int = 30) -> int:
    """把「该取证但还没取」的资产补进队列。

    三类目标按优先级进队：
    1. 从未取过证的（capture_state=pending）——新线索，最需要；
    2. 取证失败过的（failed）——上次可能是网络抖动，过一阵值得再试；
    3. 取过证但超过 `capture_refresh_hours` 的——页面会改版，三天前的证据
       对「现在还在骗人吗」没有说服力。

    水位只按「立即可跑」的任务算（下一段详述），这是 24/7 连续取证的关键：

    线上实测过一种静默停摆——队列里躺着 5 条失败重试的任务，`next_run_at`
    分别在 5～16 分钟之后，而水位统计把它们算成「已占用」。于是每轮 backfill
    都判定 room<=0，一条新资产也补不进来；浏览器空转，积压的 600 多个待取证
    资产纹丝不动。表现就是「跑一阵 → 慢下来 → 像停了一样」。

    所以：
    - room 只看 **due**（next_run_at <= now）的任务，退避中的不占水位；
    - 水位就是 `target - due`，**不设总量上限**。总量上限看着稳妥，实际是
      同一个坑的另一种挖法：退避任务把上限占满后，due 归零，队列里 24 条
      全在等 10～40 分钟后的重试，浏览器彻底空转（线上实测 2.5 分钟零取证）。
      行数不会因此失控——每个资产最多一条在途任务，退避任务随重试自然清空；
    - 查询里排除**已在队列中**（queued/running）的资产，否则取到的前 N 条
      全是老面孔，enqueue 全部跳过，同样补不进新的；
    - 连续 3 次失败且还没过冷却期的资产视为「判死」，不再反复重试——
      死域名永久占位会挤掉真线索；冷却过后自动再试一次，不会永久放弃。
    """
    from datetime import timedelta

    from sqlalchemy import case, exists

    global _COLD_FILL_AT

    now = utcnow()
    with session_scope() as s:
        due = s.scalar(
            select(func.count(CaptureTask.id)).where(
                CaptureTask.state == "queued", CaptureTask.next_run_at <= now
            )
        ) or 0

        target = max(4, settings.capture_batch * 6)
        room = target - due

        # 同一资产已有排队/执行中的任务就不再进队
        in_flight = exists().where(
            CaptureTask.asset_id == Asset.id,
            CaptureTask.state.in_(("queued", "running")),
        )
        dead_before = now - timedelta(hours=settings.capture_retry_cooldown_hours)
        recently_dead = exists().where(
            CaptureTask.asset_id == Asset.id,
            CaptureTask.state == "failed",
            CaptureTask.attempts >= 3,
            CaptureTask.finished_at.is_not(None),
            CaptureTask.finished_at > dead_before,
        )

        if room <= 0:
            return 0

        stale_before = now - timedelta(hours=settings.capture_refresh_hours)
        tier_rank = case(
            (Asset.tier == TIER_CONFIRMED, 0),
            (Asset.tier == TIER_WATCH, 1),
            else_=2,
        )
        # 冷却期未到的一律不补：dead 隔 72 小时，被墙隔 24 小时，抖动 10 分钟。
        # 之前只有「连续 3 次失败 + 6 小时」一把尺子，死域名和真线索挤在同一个
        # 队列里，谁也没跑快。
        retry_ready = or_(
            Asset.capture_retry_at.is_(None),
            Asset.capture_retry_at <= now,
        )
        rows = list(
            s.scalars(
                select(Asset)
                .where(
                    Asset.tier.in_((TIER_CONFIRMED, TIER_WATCH, TIER_CANDIDATE)),
                    Asset.kind.in_(("domain", "url")),
                    or_(
                        Asset.capture_state.in_(("pending", "failed", "dead")),
                        and_(
                            Asset.capture_state == "captured",
                            or_(Asset.last_capture_at.is_(None), Asset.last_capture_at < stale_before),
                        ),
                    ),
                    retry_ready,
                    ~in_flight,
                    # 任务级「刚判死」只兜底没有 capture_retry_at 的老数据。
                    # 两者同时生效会打架：资产级说「10 分钟后可重试」，任务级
                    # 说「6 小时内不行」，结果队列空转、36 条可重试资产没人碰。
                    or_(Asset.capture_retry_at.is_not(None), ~recently_dead),
                )
                .order_by(tier_rank, Asset.score.desc(), Asset.last_capture_at.is_(None).desc(), Asset.first_seen.desc())
                .limit(min(limit, room))
            )
        )
        ids = [a.id for a in rows]
    added = 0
    for aid in ids:
        if enqueue(aid, reason="backfill"):
            added += 1

    # 队列真空时用冷档资产填谷：发现层一小时只产几个候选，浏览器大部分时间
    # 是闲的。冷档不是「无关」，只是「域名词根不够强」——用页面正文再复核
    # 一遍本来就要做的事，顺带让取证不断档。节流由 capture_cold_fill_seconds
    # 控制，优先级 200，任何时候都排在真线索后面。
    if added == 0 and due == 0 and _cold_fill_ready():
        with session_scope() as s:
            cold_id = s.scalar(
                select(Asset.id)
                .where(
                    Asset.tier == TIER_COLD,
                    Asset.capture_state == "pending",
                    Asset.kind.in_(("domain", "url")),
                    ~exists().where(
                        CaptureTask.asset_id == Asset.id,
                        CaptureTask.state.in_(("queued", "running")),
                    ),
                )
                .order_by(Asset.score.desc(), Asset.first_seen.desc())
                .limit(1)
            )
        if cold_id and enqueue(cold_id, reason="cold-fill", priority=PRIORITY[TIER_COLD]):
            _COLD_FILL_AT = time.monotonic()
            added += 1
    return added


# ---------------------------------------------------------------- 单资产取证


def _set_capture_state(asset_id: int, state: str, error: str = "") -> None:
    """把取证结果写到资产上。

    手动取证、调度批处理、监控复访都走同一条路，状态必须由这里统一落库，
    否则「上次取证」会一直空着，界面看起来像从没取过。
    """
    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return
        asset.capture_state = state
        asset.capture_error = (error or "")[:400]
        if state == "captured":
            asset.last_capture_at = utcnow()


def capture_asset(asset_id: int) -> dict[str, Any]:
    """取证入口：固定丢给唯一的工作线程，排队执行。

    两个原因必须这么做：
    1. 一次取证要拉起 Chromium（首屏 + 全页截图 + 网络录制），峰值几百 MB，
       2G 的小机器并发两次就是 OOM；
    2. Playwright 的同步对象与创建它的线程绑定，换线程复用会报
       `Cannot switch to a different thread`——加锁解决不了，只有换线程身份。

    等不到就如实返回「忙」，不要静默失败，也不要让调用方无限期挂着。
    """
    try:
        future = _CAPTURE_POOL.submit(_capture_asset_locked, asset_id)
    except RuntimeError:  # 线程池已关闭（进程在退）
        return {"ok": False, "reason": "取证线程池已关闭"}
    try:
        result = future.result(timeout=_CAPTURE_TIMEOUT)
    except FuturesTimeout:
        # 超时说明这个线程里的 Playwright 已经卡死（DNS 黑洞、无限重定向）。
        # 不换线程的话，后面每一次取证都会排在它后面直到进程重启——
        # 「取证断断续续」有一半是这么来的。
        _reset_capture_pool()
        log.warning("取证超时 %ss，已重建取证线程 asset=%s", _CAPTURE_TIMEOUT, asset_id)
        return {"ok": False, "busy": True, "reason": "取证超时，已重建执行线程"}
    except Exception as exc:  # noqa: BLE001 线程里的异常不该变成 500
        log.exception("取证线程异常 asset=%s", asset_id)
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"[:300]}
    else:
        # 浏览器起不来时，这个线程已经被 Playwright 留下的 event loop 毒化了，
        # 留在池里只会让后面每一次取证都报同一句话。换一个新线程。
        text = f"{result.get('reason') or ''}{result.get('error') or ''}"
        if "浏览器不可用" in text or "asyncio loop" in text or "different thread" in text:
            _reset_capture_pool()
        return result


def _reset_capture_pool() -> None:
    global _CAPTURE_POOL
    old = _CAPTURE_POOL
    _CAPTURE_POOL = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ss-capture")
    try:
        old.shutdown(wait=False, cancel_futures=True)
    except Exception:  # noqa: BLE001
        pass


def _fast_dead(host: str) -> str:
    """用一次 DNS 查询挡掉永久失效的域名，别为 NXDOMAIN 去拉 Chromium。

    线上失败清单里 64 条是 NXDOMAIN，每条都要走「https 超时 30 秒 → http
    再超时 30 秒」才判死；一次 DNS 查询 3 秒内就能给出同样的结论。

    只把**明确的 NXDOMAIN** 判死。超时、解析器故障、NoAnswer 一律放行给
    浏览器——宁可多花几十秒，也不能把一次 DNS 抖动当成站点下线，那会让
    真线索被冷落三天。
    """
    if not host or not settings.allow_network:
        return ""
    try:
        import dns.resolver

        dns.resolver.resolve(host, "A", lifetime=3.0)
        return ""
    except Exception as exc:  # noqa: BLE001
        if type(exc).__name__ == "NXDOMAIN":
            return "DNS 解析失败（NXDOMAIN）"
        return ""


def _capture_asset_locked(asset_id: int) -> dict[str, Any]:
    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "reason": "资产不存在"}
        kind, value = asset.kind, asset.value
        tier = asset.tier
        meta = dict(asset.meta or {})

    if kind not in (AssetKind.DOMAIN.value, AssetKind.URL.value):
        _set_capture_state(asset_id, "skipped", f"{kind} 不支持页面取证")
        return {"ok": False, "skipped": True, "reason": f"{kind} 不支持页面取证"}

    probe_host = _host_of(value) if kind == AssetKind.URL.value else value
    dead = _fast_dead(probe_host)
    if dead:
        _set_capture_state(asset_id, "dead", dead)
        return {"ok": False, "reason": dead}

    urls = _candidate_urls(kind, value)
    obs = None
    last_error = ""
    for url in urls:
        obs = get_web_sandbox().observe(url)
        if obs.status or obs.html or obs.screenshot:
            break
        last_error = obs.error or "无响应"
        # https 不通时换 http：老式落地页很多只开 80
        log.debug("取证失败 %s：%s", url, last_error)

    if obs is None:
        _set_capture_state(asset_id, "failed", "无可访问地址")
        return {"ok": False, "reason": "无可访问地址"}

    if not (obs.html or obs.screenshot or obs.text):
        _set_capture_state(asset_id, "failed", last_error or "页面无内容")
        return {"ok": False, "reason": last_error or "页面无内容", "status": obs.status}

    # 安装包链接：DOM 里找不到时，运行时请求里往往有（JS 拼出来的下载地址）。
    # 这一步不产生额外请求，纯属把已经抓到的流量再用一次。
    obs.apk_links = _merge_apk_candidates(obs)

    # ---- 落证据（失败也留痕）
    evidence_written: list[str] = []
    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "reason": "资产消失"}
        url_note = (obs.final_url or obs.url)[:180]

        if obs.html:
            append_evidence(
                s, asset_id, "page_html", obs.html.encode("utf-8")[:_MAX_HTML],
                note=f"页面 HTML 原文 {url_note}", extension=".html", mime="text/html",
            )
            evidence_written.append("page_html")
        if obs.text:
            append_evidence(
                s, asset_id, "page_text", obs.text.encode("utf-8")[:_MAX_TEXT],
                note=f"页面正文 {url_note}", extension=".txt", mime="text/plain",
            )
            evidence_written.append("page_text")
        if obs.screenshot:
            append_evidence(
                s, asset_id, "screenshot", obs.screenshot,
                note=f"首屏截图 {url_note}", extension=".png", mime="image/png",
            )
            evidence_written.append("screenshot")
        if obs.screenshot_full:
            append_evidence(
                s, asset_id, "screenshot_full", obs.screenshot_full,
                note=f"全页截图 {url_note}", extension=".jpg", mime="image/jpeg",
            )
            evidence_written.append("screenshot_full")
        if obs.requests:
            append_evidence(
                s, asset_id, "network",
                json.dumps(
                    {"url": obs.url, "final_url": obs.final_url, "requests": obs.requests[:500]},
                    ensure_ascii=False,
                ).encode("utf-8")[:_MAX_NETWORK],
                note=f"运行时网络请求 {len(obs.requests)} 条", extension=".json", mime="application/json",
            )
            evidence_written.append("network")
        if obs.tls:
            append_evidence(
                s, asset_id, "tls_cert",
                json.dumps(obs.tls, ensure_ascii=False).encode("utf-8"),
                note=f"TLS 证书 {obs.tls.get('issuer', '')[:80]}", extension=".json", mime="application/json",
            )
            evidence_written.append("tls_cert")
        if obs.forms:
            append_evidence(
                s, asset_id, "forms",
                json.dumps(obs.forms, ensure_ascii=False).encode("utf-8"),
                note=f"表单结构 {len(obs.forms)} 个", extension=".json", mime="application/json",
            )
            evidence_written.append("forms")

        # ---- 事实回写：这些字段会直接参与评分与分级
        facts = dict(meta.get("facts") or {})
        if obs.title:
            facts["page_title"] = obs.title[:200]
        facts["page_text_len"] = len(obs.text or "")
        facts["web_engine"] = obs.engine
        facts["web_status"] = obs.status
        facts["web_egress"] = obs.egress
        if obs.final_url and obs.final_url != obs.url:
            facts["final_url"] = obs.final_url[:500]
        if obs.tls:
            facts["tls_issuer"] = obs.tls.get("issuer", "")[:160]
            facts["tls_subject"] = obs.tls.get("subject", "")[:160]
        if obs.apk_links:
            facts["apk_links"] = obs.apk_links[:10]
            facts["forces_apk_download"] = True
        if obs.blocked:
            facts["blocked_requests"] = len(obs.blocked)
        if obs.error:
            facts["web_error"] = obs.error

        # 二维码：先看截图里有没有，再从页面图片的 data URI 兜底
        qr_links = _decode_qrcodes(obs)
        if qr_links:
            facts["qrcode_links"] = qr_links[:10]
            evidence_written.append("qrcode")

        if obs.requests:
            hosts = sorted({_host_of(r.get("url", "")) for r in obs.requests if r.get("url")})
            facts["page_third_party_hosts"] = [h for h in hosts if h][:15]
            posts = [
                r["url"] for r in obs.requests
                if r.get("method", "GET").upper() not in ("GET", "HEAD", "OPTIONS")
            ]
            if posts:
                facts["page_post_targets"] = posts[:10]

        # ---- 内容规则：页面正文就是最重要的证据
        content_signals = _content_signals(obs, facts)
        if content_signals:
            facts["content_rule_hits"] = [s["rule_id"] for s in content_signals]

        meta["facts"] = facts
        meta["web_observation"] = {
            k: obs.as_dict()[k]
            for k in ("final_url", "status", "title", "apk_links", "forms", "blocked",
                      "elapsed", "engine", "screenshot_bytes", "screenshot_full_bytes",
                      "honeypot", "egress", "tls")
        }
        asset.meta = meta

        # 关键一步：拿页面正文重算评分。
        # 之前这里只做 triage.apply，分数还是「只有域名」时算出来的——
        # 于是取证做得再多，也永远进不了 watch（域名特征上限 38.8 < 50）。
        from .scoring.reassess import rescore

        rescored = rescore(s, asset, facts=facts, text=obs.text or "", trigger="capture")
        decision_reasons = rescored["reasons"]
        new_tier = asset.tier
        new_score = float(asset.score or 0.0)
        s.flush()

    _set_capture_state(asset_id, "captured")

    # ---- APK 下载（在事务外做，别把长下载塞进数据库事务）
    apk_info: dict[str, Any] = {}
    apk_hints = list(obs.apk_links)
    apk_hints += [u for u in (facts.get("qrcode_links") or []) if ".apk" in u.lower()]
    if apk_hints:
        apk_info = _maybe_download_apk(asset_id, apk_hints, obs.final_url or obs.url, tier)
        if apk_info.get("ok"):
            evidence_written.append("apk")

    # ---- 指纹与变更
    changes = _record_snapshot(asset_id, obs, facts, apk_info)

    # ---- 自动纳管 + 回灌
    if new_tier in (TIER_WATCH, TIER_CONFIRMED):
        ensure_watch(asset_id)
    _backfill_domains(asset_id, facts, obs)

    emit(
        "capture.done",
        asset_id=asset_id,
        status=obs.status,
        evidence=len(evidence_written),
        apk=bool(apk_info.get("ok")),
        changes=changes,
        egress=obs.egress,
    )
    return {
        "ok": True,
        "asset_id": asset_id,
        "status": obs.status,
        "title": obs.title,
        "final_url": obs.final_url,
        "egress": obs.egress,
        "evidence": evidence_written,
        "apk": apk_info,
        "changes": changes,
        "tier": new_tier,
        "reasons": decision_reasons[:4],
        "score": new_score,
    }


def _candidate_urls(kind: str, value: str) -> list[str]:
    if kind == AssetKind.URL.value:
        return [value] if value.startswith(("http://", "https://")) else [f"http://{value}/"]
    if value.startswith(("http://", "https://")):
        return [value]
    return [f"https://{value}/", f"http://{value}/"]


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlsplit

        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


_APK_URL_RE = re.compile(r"https?://[^\s\"'<>]+\.apk(?:\?[^\s\"'<>]*)?", re.IGNORECASE)


def _merge_apk_candidates(obs) -> list[str]:
    """把 DOM、HTML、运行时请求、二维码四处看到的下载地址合并去重。

    移动端落地页的下载按钮常由一个 JS 函数拼出 URL，DOM 里只有一个
    `onclick`，真正发出去的请求才带 .apk。只扫 DOM 会漏掉一大半。
    """
    found: list[str] = list(obs.apk_links or [])
    for item in getattr(obs, "requests", []) or []:
        url = str(item.get("url") or "")
        if _APK_URL_RE.match(url) and url not in found:
            found.append(url)
    blob = (obs.html or "")[:2_000_000]
    for url in _APK_URL_RE.findall(blob):
        if url not in found:
            found.append(url)
    return found[:20]


# ---------------------------------------------------------------- 内容规则


def _content_signals(obs, facts: dict[str, Any]) -> list[dict[str, Any]]:
    """把页面内容里能直接指向诈骗的句式找出来，写成可引用的信号。

    规则本身在 rules/content.yaml，由 scoring 在下一轮读取；这里只做一次
    「即时判定」，让取证结果马上影响 tier，不用等下一轮重扫。
    """
    from .scoring.engine import assess, load_ruleset

    text = (obs.text or "") + "\n" + (obs.title or "")
    if not text.strip():
        return []
    result = assess(facts, text=text[:60000], ruleset=load_ruleset(), min_signals=1)
    return [
        {"rule_id": s.rule_id, "title": s.title, "weight": s.weight, "detail": s.detail[:120]}
        for s in result.signals
        if s.category in ("persuasion", "impersonation", "financial")
    ][:8]


# ---------------------------------------------------------------- 二维码


def _decode_qrcodes(obs) -> list[str]:
    if Image is None:
        return []
    try:
        from pyzbar.pyzbar import decode as qr_decode

        found: list[str] = []
        for blob in (obs.screenshot, obs.screenshot_full):
            if not blob:
                continue
            try:
                img = Image.open(io.BytesIO(blob))
                for item in qr_decode(img):
                    try:
                        val = item.data.decode("utf-8", "ignore").strip()
                    except Exception:  # noqa: BLE001
                        continue
                    if val.startswith(("http://", "https://")) and val not in found:
                        found.append(val[:500])
            except Exception:  # noqa: BLE001
                continue
        return found[:10]
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------- APK


def _apk_used_today() -> int:
    cutoff = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    with session_scope() as s:
        total = s.scalar(
            select(func.sum(Evidence.size)).where(
                Evidence.kind == "apk", Evidence.captured_at >= cutoff
            )
        )
    return int(total or 0)


# 配额是「先查已用、再下载」，两个线程同时进来就会各自看到旧值，
# 一起把当天的量顶穿。手工取证和调度线程确实可能撞上，这里串行化。
_APK_LOCK = threading.Lock()


def _maybe_download_apk(asset_id: int, links: list[str], page_url: str, tier: str) -> dict[str, Any]:
    with _APK_LOCK:
        return _download_apk_locked(asset_id, links, page_url, tier)


def _download_apk_locked(asset_id: int, links: list[str], page_url: str, tier: str) -> dict[str, Any]:
    tiers = {t.strip() for t in runtime_settings.get(runtime_settings.CAPTURE_AUTO_APK_TIERS, "watch,confirmed").split(",")}
    if tier == TIER_CANDIDATE:
        max_mb = 10
    elif tier in tiers:
        max_mb = runtime_settings.get_int(runtime_settings.CAPTURE_APK_MAX_MB, 50)
    else:
        return {"ok": False, "skipped": True, "reason": f"{tier} 档不自动下载"}

    daily_limit = runtime_settings.get_int(runtime_settings.CAPTURE_APK_DAILY_MB, 300) * 1024 * 1024
    used = _apk_used_today()
    if used >= daily_limit:
        return {"ok": False, "skipped": True, "reason": f"今日 APK 配额已用尽（{used // 1024 // 1024}MB）"}

    candidates = apk_fetch.candidate_links(links, page_url, limit=2)
    if not candidates:
        return {"ok": False, "skipped": True, "reason": "页面未发现安装包链接"}

    max_bytes = min(max_mb * 1024 * 1024, max(1, daily_limit - used))
    for link in candidates:
        result = apk_fetch.fetch(link, max_bytes=max_bytes, referer=page_url)
        if not result.ok:
            with session_scope() as s:
                append_evidence(
                    s, asset_id, "capture_error",
                    json.dumps({"stage": "apk", "url": link, "reason": result.reason}, ensure_ascii=False).encode(),
                    note=f"安装包下载失败：{result.reason}"[:200], extension=".json", mime="application/json",
                )
            continue

        with session_scope() as s:
            # 安装包可能有几十 MB，按文件写入，避免整块进内存
            append_evidence_file(
                s, asset_id, "apk", result.path,
                note=f"安装包源文件 {result.url[:120]} · {result.size // 1024}KB · sha256 {result.sha256[:16]}",
                mime="application/vnd.android.package-archive",
            )
            asset = s.get(Asset, asset_id)
            if asset is not None:
                meta = dict(asset.meta or {})
                meta["apk_file"] = {
                    "sha256": result.sha256,
                    "size": result.size,
                    "url": result.url[:300],
                    "path": result.path,
                }
                asset.meta = meta
        # 磁盘里只留一份：证据目录已按哈希存过
        try:
            Path(result.path).unlink(missing_ok=True)
        except OSError:
            pass
        return result.as_dict()
    return {"ok": False, "reason": "全部候选链接下载失败"}


# ---------------------------------------------------------------- 指纹与变更


def _simhash(text: str, bits: int = 64) -> str:
    tokens = re.findall(r"[\u4e00-\u9fa5]{2,}|[a-zA-Z]{4,}", text or "")
    if not tokens:
        return ""
    # 先做词频，避免超长页面把 CPU 拖死在 64 位循环里
    freq: dict[str, int] = {}
    for token in tokens[:12000]:
        freq[token] = freq.get(token, 0) + 1
    vector = [0] * bits
    for token, count in list(freq.items())[:4000]:
        digest = int(hashlib.md5(token.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(bits):
            vector[i] += count if (digest >> i) & 1 else -count
    value = 0
    for i in range(bits):
        if vector[i] > 0:
            value |= 1 << i
    return f"{value:016x}"


def _dhash(blob: bytes) -> str:
    if not blob or Image is None:
        return ""
    try:
        img = Image.open(io.BytesIO(blob)).convert("L").resize((9, 8), Image.LANCZOS)
        pixels = list(img.getdata())
        bits = 0
        for row in range(8):
            for col in range(8):
                left = pixels[row * 9 + col]
                right = pixels[row * 9 + col + 1]
                bits = (bits << 1) | (1 if left > right else 0)
        return f"{bits:016x}"
    except Exception:  # noqa: BLE001
        return ""


def _hamming(a: str, b: str) -> int:
    try:
        return (int(a, 16) ^ int(b, 16)).bit_count()
    except (TypeError, ValueError):
        return 0


def _record_snapshot(asset_id: int, obs, facts: dict[str, Any], apk_info: dict[str, Any]) -> list[str]:
    html_hash = _simhash(obs.text or obs.html or "")
    shot_hash = _dhash(obs.screenshot)
    cert_fp = ""
    if obs.tls:
        cert_fp = hashlib.sha256(
            f"{obs.tls.get('subject', '')}|{obs.tls.get('issuer', '')}|{obs.tls.get('valid_from', '')}".encode()
        ).hexdigest()[:32]
    ips = ",".join(sorted(set(facts.get("ips") or [])))[:400]
    apk_sha = (apk_info.get("sha256") or facts.get("apk_file", {}).get("sha256", ""))[:64]

    changes: list[str] = []
    with session_scope() as s:
        prev = s.scalar(
            select(AssetSnapshot)
            .where(AssetSnapshot.asset_id == asset_id)
            .order_by(AssetSnapshot.captured_at.desc(), AssetSnapshot.id.desc())
            .limit(1)
        )
        if prev is not None:
            if prev.html_simhash and html_hash and _hamming(prev.html_simhash, html_hash) > 14:
                changes.append("页面内容改版")
            if prev.shot_dhash and shot_hash and _hamming(prev.shot_dhash, shot_hash) > 12:
                changes.append("页面视觉变化")
            if prev.cert_fp and cert_fp and prev.cert_fp != cert_fp:
                changes.append("证书更换")
            if prev.ips and ips and set(prev.ips.split(",")) != set(ips.split(",")):
                changes.append("解析地址变化")
            if prev.apk_sha256 and apk_sha and prev.apk_sha256 != apk_sha:
                changes.append("安装包更换")
            if prev.http_status and prev.http_status < 400 <= (obs.status or 0):
                changes.append("页面下线")
            elif prev.http_status >= 400 and 0 < (obs.status or 0) < 400:
                changes.append("页面恢复")

        s.add(
            AssetSnapshot(
                asset_id=asset_id,
                html_simhash=html_hash,
                shot_dhash=shot_hash,
                cert_fp=cert_fp,
                ips=ips,
                apk_sha256=apk_sha,
                http_status=obs.status or 0,
                final_url=(obs.final_url or obs.url)[:500],
                title=(obs.title or "")[:300],
            )
        )
        # 只保留最近 6 条，够了；历史快照没有增量价值，只会把库撑大
        stale = list(
            s.scalars(
                select(AssetSnapshot)
                .where(AssetSnapshot.asset_id == asset_id)
                .order_by(AssetSnapshot.captured_at.desc(), AssetSnapshot.id.desc())
                .offset(6)
            )
        )
        for row in stale:
            s.delete(row)

        if changes:
            asset = s.get(Asset, asset_id)
            if asset is not None:
                meta = dict(asset.meta or {})
                history = list(meta.get("changes") or [])
                history.insert(0, {"at": utcnow().isoformat(), "items": changes})
                meta["changes"] = history[:20]
                asset.meta = meta
            s.add(
                DiscoveryEvent(
                    source="change",
                    kind="domain",
                    value=(asset.value if asset else "")[:300],
                    normalized=(asset.normalized if asset else "")[:300],
                    matched_terms=changes[:6],
                    score_hint=0.5,
                    asset_id=asset_id,
                    raw={"changes": changes, "status": obs.status},
                )
            )
    if changes:
        emit("capture.change", asset_id=asset_id, changes=changes)
    return changes


# ---------------------------------------------------------------- 监控纳管


MAX_AUTO_WATCH = 200


def ensure_watch(
    asset_id: int, *, interval_minutes: int | None = None, force: bool = False, by: str = ""
) -> bool:
    """把资产纳入周期复访。

    自动路径（force=False）只在 watch/confirmed 时生效；人工点「加入监控」时
    传 force=True，用户意图优先于分级——哪怕还是候选，也可能值得盯两天。
    """
    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return False
        if not force and asset.tier not in (TIER_WATCH, TIER_CONFIRMED):
            return False
        existing = s.scalar(
            select(WatchTarget).where(WatchTarget.kind == "asset", WatchTarget.value == asset.value[:200])
        )
        interval = interval_minutes or (120 if asset.tier == TIER_CONFIRMED else 360)
        if existing is not None:
            existing.asset_id = asset.id
            existing.enabled = True
            existing.interval_minutes = min(existing.interval_minutes or interval, interval)
            # 人工接管：曾经自动纳管的，手动确认后不再被配额淘汰掉
            if force:
                existing.auto = False
            return False

        auto_rows = list(
            s.scalars(select(WatchTarget).where(WatchTarget.auto.is_(True)))
        )
        if len(auto_rows) >= MAX_AUTO_WATCH:
            # 淘汰最低分：先看资产分，人工目标不在候选里
            def rank(row: WatchTarget) -> float:
                a = s.get(Asset, row.asset_id) if row.asset_id else None
                return a.score if a else 0.0

            victim = min(auto_rows, key=rank)
            s.delete(victim)
            s.flush()

        s.add(
            WatchTarget(
                kind="asset",
                value=asset.value[:200],
                asset_id=asset.id,
                interval_minutes=interval,
                auto=not force,
                note=(f"{by}手动加入" if force else f"{asset.tier} 自动纳管"),
                next_run_at=utcnow() + timedelta(minutes=interval),
            )
        )
    return True


def prune_watch() -> int:
    """把已经排除/冷存/降回候选的目标移出自动监控。人工加的保持不动。"""
    moved = 0
    with session_scope() as s:
        rows = list(s.scalars(select(WatchTarget).where(WatchTarget.auto.is_(True))))
        for row in rows:
            asset = s.get(Asset, row.asset_id) if row.asset_id else None
            # 分级落回候选后，自动盯防也应当撤回：否则 watchlist 会一直膨胀，
            # 而候选项本来就走低频轮转，不需要占盯防配额。
            if asset is None or asset.tier not in (TIER_WATCH, TIER_CONFIRMED):
                s.delete(row)
                moved += 1
    return moved


# ---------------------------------------------------------------- 回灌


def _backfill_domains(asset_id: int, facts: dict[str, Any], obs) -> None:
    """把取证时看到的新域名送回发现队列。

    这是「滚雪球」的关键：一个落地页会链到客服站、下载站、支付站，
    这些往往不在 CT 关键词命中里，但它们是同一个团伙。
    """
    from .discover.engine import get_engine
    from .normalize import is_pivot_noise, registrable_domain

    hosts: list[str] = []
    hosts.extend(facts.get("apk_links") or [])
    hosts.extend(facts.get("qrcode_links") or [])
    hosts.extend(facts.get("page_third_party_hosts") or [])
    hosts.extend(facts.get("page_post_targets") or [])
    if obs is not None:
        hosts.extend(obs.apk_links or [])

    candidates: list[str] = []
    for item in hosts:
        host = _host_of(item) if "://" in item else item.strip()
        if not host or "." not in host:
            continue
        root = registrable_domain(host)
        # 统计脚本、字体 CDN、客服组件不算「新发现的基础设施」
        if root and not is_pivot_noise(root) and root not in candidates:
            candidates.append(root)
    if not candidates:
        return

    try:
        get_engine().inject(candidates[:12], source="pivot", note=f"pivot from asset {asset_id}")
    except Exception:  # noqa: BLE001
        log.debug("回灌失败", exc_info=True)


# ---------------------------------------------------------------- 证据矩阵 / 导出


def evidence_matrix(asset_id: int) -> dict[str, Any]:
    with session_scope() as s:
        rows = list(
            s.scalars(
                select(Evidence)
                .where(Evidence.asset_id == asset_id, Evidence.deleted_at.is_(None))
                .order_by(Evidence.id.desc())
            )
        )
        asset = s.get(Asset, asset_id)
        state = (asset.capture_state or "pending") if asset else "pending"
        error = ((asset.capture_error or "") if asset else "")[:300]
    # 同类只留最新一条用于「预览/下载」，历史条数单独统计
    latest: dict[str, Evidence] = {}
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.kind] = counts.get(row.kind, 0) + 1
        if row.kind not in latest:
            latest[row.kind] = row

    items = []
    for kind, label in EXPECTED_KINDS:
        row = latest.get(kind)
        items.append(
            {
                "kind": kind,
                "label": label,
                "present": row is not None,
                "count": counts.get(kind, 0),
                "evidence_id": row.id if row else None,
                "size": row.size if row else 0,
                "captured_at": row.captured_at.isoformat() if row else None,
                "note": row.note if row else "",
                "mime": row.mime if row else "",
                "previewable": bool(
                    row and (row.mime or "").startswith(("image/", "text/", "application/json"))
                ),
            }
        )

    others = [
        {
            "kind": kind,
            "label": KIND_LABEL.get(kind, kind),
            "count": n,
            "evidence_id": latest[kind].id,
            "size": latest[kind].size,
            "captured_at": latest[kind].captured_at.isoformat(),
        }
        for kind, n in counts.items()
        if kind not in dict(EXPECTED_KINDS)
    ]
    return {
        "items": items,
        "others": others,
        "total": len(rows),
        "state": state,
        "error": error,
        "present": sum(1 for i in items if i["present"]),
        "expected": len(items),
    }


def asset_zip(asset_id: int) -> bytes:
    """把一份资产的全部证据打成一个 ZIP，附 manifest（含哈希链）。"""
    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            raise LookupError("资产不存在")
        rows = list(
            s.scalars(
                select(Evidence)
                .where(Evidence.asset_id == asset_id, Evidence.deleted_at.is_(None))
                .order_by(Evidence.id)
            )
        )
        payload = [
            {
                "id": e.id,
                "kind": e.kind,
                "kind_label": KIND_LABEL.get(e.kind, e.kind),
                "sha256": e.sha256,
                "chain_hash": e.chain_hash,
                "size": e.size,
                "captured_at": e.captured_at.isoformat(),
                "note": e.note,
                "file": f"{e.id:05d}-{e.kind}{_ext_of(e)}",
            }
            for e in rows
        ]
        manifest = {
            "asset": {"id": asset.id, "kind": asset.kind, "value": asset.value, "tier": asset.tier,
                      "score": asset.score, "verdict": asset.verdict},
            "generated_at": utcnow().isoformat(),
            "evidence": payload,
        }

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        for item, row in zip(payload, rows, strict=False):
            # 明文可能已被证据仓脱敏，这里必须解密后再写入；
            # 否则导出的证据包里只有 manifest，一个文件都没有。
            data = read_evidence_bytes(row)
            if data:
                zf.writestr(f"evidence/{item['file']}", data)
            else:
                zf.writestr(f"evidence/{item['file']}.MISSING.txt", f"sha256={row.sha256}\n该证据的明文与密文均不可读\n")
    return buf.getvalue()


def asset_zip_file(asset_id: int) -> Path:
    """落成临时文件再流式下发。

    含安装包的资产能到几十 MB，`asset_zip` 会把整包读进内存；
    两个人同时点下载就有几百 MB 的峰值。这里改成写盘 + FileResponse。
    """
    import tempfile

    tmp_dir = settings.data_dir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    # 下载中途断掉的临时包没人删（FileResponse 的 BackgroundTask 只在正常收尾时跑），
    # 顺手把一小时前的残骸扫掉，别让 tmp/ 慢慢吃掉磁盘
    cutoff = utcnow().timestamp() - 3600
    for stale in tmp_dir.glob("evidence-*.zip"):
        try:
            if stale.stat().st_mtime < cutoff:
                stale.unlink()
        except OSError:
            continue
    handle, name = tempfile.mkstemp(prefix=f"evidence-{asset_id}-", suffix=".zip", dir=tmp_dir)
    try:
        with os.fdopen(handle, "wb") as fh:
            fh.write(asset_zip(asset_id))
    except Exception:
        Path(name).unlink(missing_ok=True)
        raise
    return Path(name)


def _ext_of(row: Evidence) -> str:
    suffix = Path(row.path).suffix
    if suffix:
        return suffix
    return {"screenshot": ".png", "screenshot_full": ".jpg", "page_html": ".html",
            "page_text": ".txt"}.get(row.kind, ".bin")
