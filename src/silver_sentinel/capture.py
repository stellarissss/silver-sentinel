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
from .db import chain_write_scope, session_scope
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

# 「端口连不上」不等于「域名死了」：跨境链路、云 WAF、地域封锁都会表现成这样。
# 判死 24 小时而不是 72 小时，代价只是每条多一次 5 秒连接尝试。
_SOFT_DEAD_MARKERS = ("端口无法连接",)
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
    if any(marker.upper() in text for marker in _SOFT_DEAD_MARKERS):
        return FAILURE_BLOCKED
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
_CAPTURE_TIMEOUT = 150


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
                    # 单条取证硬超时 150 秒；超过 5 分钟还挂着，只可能是线程被
                    # Playwright 卡死后新线程又接了别的活。回收得越快，空窗越短。
                    CaptureTask.started_at < now - timedelta(minutes=5),
                )
            )
        )
        for task in stale:
            task.state = "queued"
            task.next_run_at = now
            task.error = "上次执行被中断（进程重启），已重新排队"
        if stale:
            log.info("回收 %s 个中断的取证任务", len(stale))
            # 下面那条 SELECT 按 state='queued' 找活，必须先把回收结果落库。
            # 以前靠 autoflush 隐式代劳；关掉隐式 flush 后不显式写一次，
            # SQL 层看到的仍是 running，这条任务就永远捞不回来。
            s.flush()

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
                elif attempts < 2:
                    # 第一次失败给 10 分钟：可能是瞬时抖动
                    task.state = "queued"
                    task.error = error
                    task.next_run_at = utcnow() + timedelta(minutes=10)
                    retry_at = task.next_run_at
                else:
                    # 第二次还是失败，就不再按分钟重试了。线上实测：一批
                    # Page.goto 超时的目标会按 10/40 分钟循环，每条占浏览器
                    # 一分钟以上，把新线索全堵在后面。两次能解释抖动，第三次
                    # 基本就是目标侧的问题，按 blocked 冷却一天。
                    task.state = "failed"
                    task.finished_at = utcnow()
                    task.error = f"[blocked] {error}"[:500]
                    retry_at = utcnow() + timedelta(hours=settings.capture_blocked_retry_hours)
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
    - 冷却期（`capture_retry_at`）由失败性质决定：死域名 3 天、被墙 1 天、
      抖动 10 分钟；冷却期内一律不补，冷却过后自动再试一次，不会永久放弃。
    - 队列真的空了才用冷档填谷，优先级 200，不挤占任何真线索。
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
        # 外部线索（urlscan / 举报）已经有人在页面上见过目标话术，
        # 不是「域名里猜出来的」。同样档位下先抓它们。
        # 同 IP 命中最靠前：那台服务器上已经躺着一条确认过的涉老站，
        # 比任何文本线索都硬——它不需要「猜中话术」，只需要一次 DNS。
        source_rank = case(
            (Asset.discovery_source == "ip_pool", 0),
            (Asset.discovery_source.in_((
                "urlscan", "report", "elder_seed", "cert_sibling", "ct_bulk", "ct_burst"
            )), 1),
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
                # 「从未取证」排在「已取证待复访」前面。
                # 线上出现过 3 条 pending 资产连续 8 分钟没进队：24 小时复访
                # 产生的大量 captured 资产按分数占了 limit，新线索永远轮不到，
                # 而 doctor 报 starved、看着像队列坏了。分级仍然优先于取证状态：
                # watch 的复访比 candidate 的首访更急。
                .order_by(
                    tier_rank,
                    source_rank,
                    (Asset.capture_state == "pending").desc(),
                    Asset.score.desc(),
                    Asset.last_capture_at.is_(None).desc(),
                    Asset.first_seen.desc(),
                )
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
            _note_browser_failure()
        else:
            _BROWSER_FAILS[0] = 0
        return result


# 连续多少次「浏览器不可用」就认定进程里的 Playwright 已经不可救。
#
# 换线程只在**第一次**有效：线上实测换完之后新线程仍然报
# `Sync API inside the asyncio loop`，因为毒化的是进程级的 greenlet /
# event loop 状态，不是某个线程的局部状态。继续换线程只是把同一个错误
# 重放一遍——队列里 300 个待取证资产一动不动，日志里全是同一行。
#
# 这时候唯一可靠的自愈是让进程重启。systemd 30 秒内拉起来，比人工
# 上去 kill 快得多，也比一条一条失败干净。
_BROWSER_FAILS = [0]
_BROWSER_FAIL_LIMIT = 3


def _note_browser_failure() -> None:
    _BROWSER_FAILS[0] += 1
    if _BROWSER_FAILS[0] < _BROWSER_FAIL_LIMIT:
        return
    log.error(
        "连续 %d 次浏览器不可用，进程已无法自愈，主动退出等待 systemd 重启",
        _BROWSER_FAILS[0],
    )
    try:
        emit("capture.browser_dead", restarts=_BROWSER_FAILS[0])
    except Exception:  # noqa: BLE001
        pass
    # 先让 systemd 看到一个「失败」而不是「干净退出」，否则 Restart=on-failure
    # 不会拉起它。sleep 2 秒是给 StartLimitBurst 留余量：systemd 默认
    # 10 秒内起 5 次就判定为「启动循环」，直接送进 failed 不再尝试。
    time.sleep(2)
    os._exit(3)


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


def _tcp_alive(host: str, port: int, timeout: float = 5.0, attempts: int = 2) -> bool:
    """端口连得上吗。只用来提前结束「必然失败」的取证，不替代浏览器。

    5 秒 + 一次重试：3 秒单次在跨境链路上会把慢目标误判成不可达，
    而误判的代价是把真线索推进冷却。多花 5 秒换掉一次误杀，值。
    """
    import socket

    for i in range(max(1, attempts)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            if i + 1 < attempts:
                time.sleep(0.5)
    return False


def _capture_asset_locked(asset_id: int) -> dict[str, Any]:
    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "reason": "资产不存在"}
        kind, value = asset.kind, asset.value
        tier = asset.tier
        state = asset.capture_state or "pending"
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
    # 端口级预检：443 和 80 都连不上时，浏览器必然要各等一个 30 秒超时。
    # 线上失败清单里大量 ERR_CONNECTION_REFUSED / 不可达就是这类，先花
    # 最多 6 秒排除，把时间留给能打开的页面。
    reachable = [
        u for u in urls
        if _tcp_alive(
            _host_of(u),
            443 if u.lower().startswith("https://") else 80,
        )
    ]
    if urls and not reachable:
        reason = "端口无法连接（HTTP/HTTPS 均不通）"
        _set_capture_state(asset_id, "dead", reason)
        return {"ok": False, "reason": reason}

    obs = None
    last_error = ""
    # 重试目标给短缰绳：上一次已经用满 30 秒还没打开，再给 30 秒基本是重复
    # 等待。首次取证仍用完整超时——慢站点第一次就该被耐心对待。
    budget = float(settings.sandbox_timeout)
    if state in ("failed", "dead"):
        # 20 秒：上一次已用满完整预算，但 12 秒对慢站太苛刻——二次超时会被
        # 判成 blocked 冷却一天，等于把「只是慢」的站冷藏了。
        budget = min(budget, 20.0)
    for url in reachable or urls:
        obs = get_web_sandbox().observe(url, timeout=budget)
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
    # 整段事务串行：chain_tip() 读到链尾到 commit 之间不能插进别的写事务，
    # 否则两条链会各自按旧链尾算 prev_hash，链就分叉（线上 id=15535 那处）。
    with chain_write_scope() as s:
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
        # 正文过短通常不是「没内容」，是「内容在图片/JS 里」——这类页面的
        # 词库分一定偏低，不能据此判定无害。记下来，给 ML 当特征，
        # 也让界面能提示「纯图落地页，需看截图」。
        if facts["page_text_len"] < 300:
            facts["low_text_page"] = True
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

        # ---- 自称与冒充：词库看「用了什么词」，这里看「说自己是哪个机构」。
        # 这是词库识别不了的：骗子的用词和正规站完全一样（补贴/养老/民政），
        # 但它必须声称自己是财政部，而财政部的官方域名只有一个。
        # 提到外面：用途分类也要用它；若放在 try 里，claim 一抛异常这里就未定义。
        claim_host = _host_of(obs.final_url or obs.url) or probe_host
        try:
            from .claim import analyze_html

            claim = analyze_html(obs.html or "", claim_host).as_dict()
            facts["claim"] = claim
            # 页面自己写的备案号，和「本域名实际备案」是两件事。
            # 先记下来，由 license_owners 用本地缓存比对，不在这里联网。
            if claim.get("icp"):
                facts["claimed_icp"] = claim["icp"]
                # 备案号 ↔ 域名的绑定关系是确定性的：号是真的，但它不属于你。
                # 只查本地缓存（ICP 缓存 30 天），不在这里联网。
                try:
                    from .enrich.icp import get_icp
                    from .normalize import registrable_domain

                    owners = get_icp().license_owners(claim["icp"])
                    cur = registrable_domain(claim_host)
                    if owners and cur and cur not in owners:
                        claim["verdict"] = "fake_icp"
                        claim["level"] = 4
                        claim["reasons"] = [
                            f"页面备案号 {claim['icp']} 归属 {owners[0]}，与当前域名不一致"
                        ]
                        facts["claim"] = claim
                except Exception as exc:  # noqa: BLE001
                    log.debug("备案号比对失败：%s", exc)
        except Exception as exc:  # noqa: BLE001 抽取失败不能影响取证
            log.debug("自称抽取失败 %s：%s", asset_id, exc)

        # ---- 用途分类：先回答「这个站是干什么的」。
        # 词库保广（发现阶段宁多收），用途保细（进队列后把客服站/论坛/电商
        # 挡在高危队列外）。它只影响排序，不产生风险分，也不删除资产。
        try:
            from .features import extract as extract_features
            from .purpose import analyze as analyze_purpose

            bundle = extract_features(
                url=obs.final_url or obs.url,
                html=obs.html or "",
                text=obs.text or "",
                facts=facts,
                requests=obs.requests,
                forms=obs.forms,
                tls=obs.tls,
                apk_links=obs.apk_links,
            )
            facts["features"] = bundle.as_dict()
            purpose = analyze_purpose(bundle, host=claim_host, facts=facts,
                                      text=(obs.text or "")[:20000])
            facts["purpose"] = purpose.as_dict()
        except Exception as exc:  # noqa: BLE001 用途分类失败不能影响取证
            log.debug("用途分类失败 %s：%s", asset_id, exc)

        # ---- 证书 SAN：一个站的证书里往往写着整批域名。
        #
        # 放在取证流程里而不是发现层：只有已经确认要看的目标，才值得多花
        # 一次 TLS 握手（200ms，标准库，零外部配额）。
        try:
            from .collectors.cert import fetch as fetch_cert

            cert = fetch_cert(claim_host or probe_host, timeout=8.0)
            if cert.ok:
                facts["cert"] = cert.as_dict()
                if len(cert.dns_names) > 1:
                    facts["cert_dns_names"] = cert.dns_names
                # Playwright 的 security_details 只给 subject/issuer，
                # 这里补上更完整的版本（含有效期与序列号）
                if cert.issuer and not facts.get("tls_issuer"):
                    facts["tls_issuer"] = cert.issuer
                if cert.subject and not facts.get("tls_subject"):
                    facts["tls_subject"] = cert.subject
        except Exception as exc:  # noqa: BLE001 证书取不到不影响取证
            log.debug("证书解析失败 %s：%s", asset_id, exc)

        # ---- 后端端点：数据往哪走。
        #
        # 首页只是一张诱饵，真正收身份证和银行卡的是第二跳。实测 np4w53 首页
        # 连 <form> 都没有，提交地址 https://d7k2m.cn/submit.php 只写在 1.html
        # 的 JS 里；十个同模板站共用这一个端点。
        #
        # 这一步必须在涉老判定之前做：第二跳的表单页才是「身份索取」的直接
        # 证据，而首页正文里一个证件字样都没有。
        hop = obs.second_hop or {}
        hop_text = ""
        try:
            from .collectors.endpoints import extract as extract_endpoints

            first = extract_endpoints(
                obs.html or "", obs.final_url or obs.url, dom_forms=obs.forms
            )
            second = None
            if hop.get("html"):
                hop_text = str(hop.get("text") or "")
                second = extract_endpoints(str(hop["html"]), str(hop.get("url") or ""))

            merged: list = []
            seen_keys: set[tuple[str, str]] = set()
            for ep in (second.endpoints if second else []) + first.endpoints:
                key = (ep.url, ep.method)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                merged.append(ep)

            facts["endpoints"] = [e.as_dict() for e in merged[:10]]
            host_union: list[str] = []
            for src in (second.backend_hosts if second else []) + first.backend_hosts:
                if src not in host_union:
                    host_union.append(src)
            facts["backend_hosts"] = host_union[:10]

            # 汇总所有端点上的敏感字段类型——这是 elder 的 identity 证据
            kinds: list[str] = []
            for ep in merged:
                for k in ep.sensitive:
                    if k not in kinds:
                        kinds.append(k)
            facts["sensitive_fields"] = kinds
            if any(e.disguised for e in merged):
                facts["disguised_fields"] = sorted(
                    {n for e in merged for n in e.disguised}
                )
            if hop:
                facts["form_page"] = {
                    "url": str(hop.get("url") or "")[:300],
                    "title": str(hop.get("title") or "")[:200],
                    "button": str(hop.get("button") or "")[:60],
                    "inputs": int(hop.get("inputs") or 0),
                    "navigated": bool(hop.get("navigated")),
                }
        except Exception as exc:  # noqa: BLE001 端点提取失败不能影响取证
            log.debug("端点提取失败 %s：%s", asset_id, exc)

        # ---- 诱饵 / 蜜罐：这一页是不是样子货。
        #
        # 暖阳那一批（26537.net）首页写着「安全检测中心，请稍候」，正文一个
        # 涉老词都没有，于是被判「证据不足」扔在候选池里躺着。判断没错，
        # 结论错了：它不是没有价值，它是**分发渠道**。
        #
        # 这一步要在涉老判定之前，因为诱饵的价值就是「把人送到下一跳」，
        # 那条证据要能进 elder 的「转化动作」。反过来，WAF 挑战页也被识别成
        # 「请稍候」，所以必须先把它从证据链里摘出去——拿它判低分等于
        # 用「我们被墙了」证明「对方没问题」。
        try:
            from .decoy import assess as assess_decoy

            sig = assess_decoy(
                html=obs.html or "",
                text=obs.text or "",
                title=obs.title or "",
                status=obs.status or 0,
                final_url=obs.final_url or obs.url,
                request_host=claim_host or probe_host,
                html_len=obs.html_len or len(obs.html or ""),
                forms=obs.forms,
                second_hop=hop,
                apk_links=obs.apk_links,
                download_entries=obs.download_entries,
                post_targets=facts.get("page_post_targets") or [],
                honeypot_report=obs.honeypot,
            )
            facts["decoy"] = sig.as_dict()
            if sig.is_decoy:
                log.info("诱饵页 %s：%s", value[:40], sig.reason)
            if sig.honeypot:
                log.info("反自动化措施 %s：%s", value[:40], "；".join(sig.honeypot_reasons[:2]))

            # 被 WAF 拦了：证据（截图/HTML）照样留，但这一趟不产生结论。
            # 按 blocked 冷却一天再试——把它当「内容为空」判低分，会让一批
            # 正常站永久沉底，而且再也捞不回来（capture_state 已是 captured）。
            if sig.is_interstitial():
                meta["facts"] = facts
                meta["decoy"] = sig.as_dict()
                asset.meta = meta
                asset.capture_state = "failed"
                asset.capture_error = f"被 {sig.blocked_by} 拦截，页面非目标内容"
                asset.capture_retry_at = utcnow() + timedelta(
                    hours=settings.capture_blocked_retry_hours
                )
                s.flush()
                return {
                    "ok": False,
                    "kind": FAILURE_BLOCKED,
                    "reason": f"被 {sig.blocked_by} 拦截（WAF 挑战页，待重试）",
                    "status": obs.status,
                }
        except Exception as exc:  # noqa: BLE001 诱饵判定失败不能影响取证
            log.debug("诱饵判定失败 %s：%s", asset_id, exc)

        # ---- 涉老判定：这个站是不是在骗老人的钱。
        # 与「用途」正交：用途回答「这站是干什么的」，涉老回答「冲着谁来的」。
        # 客服站也会被判用途，但不会被判涉老——两者的词表没有交集。
        try:
            from .elder import assess as assess_elder

            # 第二跳的表单页正文合并进去：首页写「补贴已到账」，2 跳才写
            # 「请输入身份证号 / 银行卡号」。只看首页等于只看到诱饵。
            elder_text = ((hop_text + "\n" if hop_text else "") + (obs.text or ""))[:40000]
            elder = assess_elder(facts, text=elder_text)
            facts["elder"] = elder.as_dict()
        except Exception as exc:  # noqa: BLE001 涉老判定失败不能影响取证
            log.debug("涉老判定失败 %s：%s", asset_id, exc)

        # ---- 主体实体：钱交给谁、联系谁。
        # 用与涉老判定同一份正文（首页 + 第二跳），落地页的收款信息常在第二跳。
        # 主体比 IP 硬：证书会重签、IP 会换，收款卡和微信号不会天天换。
        try:
            from .entities import as_dict as entities_as_dict
            from .entities import from_text as extract_entities

            facts["entities"] = entities_as_dict(extract_entities(elder_text))
        except Exception as exc:  # noqa: BLE001 实体抽取失败不能影响取证
            log.debug("主体实体抽取失败 %s：%s", asset_id, exc)

        # 取证完成，解除「不许降档」的保护——从此按证据说话
        meta.pop("await_capture", None)
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

    # ---- 同源折叠：算出这一条属于哪一批。
    #
    # 一次证书带 91 个域名、一个 submit.php 背后 77 个前端，列表页平铺出来
    # 就是九十行一模一样的东西，人工复核看不出「这是一批」。
    # 键的优先级在 grouping 里定：团伙 > 同证书 > 同收单端点 > 同模板。
    # 没有把握就不成组——错组比不组更糟，它会把无关的站折叠成「一伙的」。
    try:
        from .grouping import compute as compute_group

        gkey, gkind, glabel = compute_group(kind=kind, value=value, meta=meta, facts=facts)
        with session_scope() as s:
            row = s.get(Asset, asset_id)
            if row is not None and (row.group_key or "") != gkey:
                row.group_key = gkey
                row.group_kind = gkind
                if glabel:
                    row_meta = dict(row.meta or {})
                    row_meta["group_label"] = glabel
                    row.meta = row_meta
                s.flush()
    except Exception as exc:  # noqa: BLE001 分组失败不能影响取证结论
        log.debug("分组计算失败 %s：%s", asset_id, exc)

    # ---- 后端端点入库：一个 submit.php 背后是一整批域名。
    # 放在事务外，独立失败不影响本次取证结论。
    try:
        backends = _register_backend_assets(asset_id, value, facts)
        if backends:
            log.info("提交端点：%s 指向 %s", value, "、".join(backends[:4]))
    except Exception as exc:  # noqa: BLE001
        log.debug("后端端点登记异常 %s：%s", asset_id, exc)

    # ---- 证书 SAN 展开：一个站带出一批站。
    # 只对确认有问题的站做（涉老 / 高危安装包 / 高分），否则每抓一个正常站
    # 就展开一次，队列会被灌爆。
    elder = facts.get("elder") or {}
    worth_spread = (
        bool(isinstance(elder, dict) and elder.get("elder"))
        or bool(facts.get("apk_danger"))
        or float(new_score or 0.0) >= 60
    )
    if worth_spread:
        try:
            family = _register_cert_family(value, facts)
            if family:
                log.info("同证书展开：%s → %d 个", value, len(family))
        except Exception as exc:  # noqa: BLE001
            log.debug("同证书展开异常 %s：%s", asset_id, exc)

    # ---- APK 下载（在事务外做，别把长下载塞进数据库事务）
    apk_info: dict[str, Any] = {}
    apk_hints = list(obs.apk_links)
    apk_hints += [u for u in (facts.get("qrcode_links") or []) if ".apk" in u.lower()]
    if apk_hints:
        apk_info = _maybe_download_apk(asset_id, apk_hints, obs.final_url or obs.url, tier)
        if apk_info.get("ok"):
            evidence_written.append("apk")
        # 下载失败也要走一遍：`apk_too_large` / `apk_unparsed` 是「有包但没拿到」
        # 的证据，分级必须知道。只在成功时调用等于把这类站当成「没有安装包」。
        _apply_apk_signal(asset_id)

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
    # 下载入口（/go/download1 这种）排在真 .apk 之后：
    # 它们要多跳一次才知道是不是包，先给确定是包的机会。
    for entry in getattr(obs, "download_entries", []) or []:
        if entry not in found:
            found.append(entry)
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


CERT_FAMILY_LIMIT = 80


def _register_cert_family(value: str, facts: dict[str, Any]) -> list[str]:
    """把同一张证书上的域名入池。

    这是「广泛」唯一的物理量。实测 np4w53.cn 的证书 SAN 里有 91 个域名，
    抽 10 个测存活：9 个在线、同一个 IP、标题逐字相同。而我们库里只有 1 个。

    骗子可以一天换一个域名，但换域名就得重新签证书，而重签时脚本会把整批
    域名一起写进 SAN。证书是他们的注册表，我们只是去读它。

    只对「批量签发」展开——正常站（baidu.com）的 SAN 里也有 50 个域名，
    但那是业务域名，展开等于往库里灌垃圾。
    """
    from .discover.morph import is_bulk_batch
    from .normalize import is_pivot_noise, is_shared_infra, registrable_domain

    names = facts.get("cert_dns_names")
    if not isinstance(names, list) or len(names) < 8:
        return []
    if not is_bulk_batch([str(n) for n in names]):
        return []
    if not facts.get("cert_bulk"):
        # 判断成立就落个标记，复盘时能直接筛出「这批是一张证书带出来的」
        facts["cert_bulk"] = True

    me = registrable_domain(_host_of(value) or value)

    # 扩散深度上限 2 层：A 的证书带出 B 群，B 的证书带出 C 群就停。
    # 不设上限的话，一个高活跃团伙能在几天内把全库的证书都爬一遍，
    # 队列被历史垃圾塞满，新线索反而排不上。
    depth = 0
    try:
        with session_scope() as s:
            row = s.execute(
                select(Asset.meta).where(Asset.kind == "domain", Asset.value == me)
            ).scalar_one_or_none()
            depth = int((row or {}).get("spread_depth") or 0)
    except Exception:  # noqa: BLE001
        depth = 0
    if depth >= 2:
        return []

    roots: list[str] = []
    for raw in names:
        host = str(raw).lower().strip(".")
        if not host or "." not in host:
            continue
        root = registrable_domain(host)
        if not root or root == me or root in roots:
            continue
        if is_shared_infra(root) or is_pivot_noise(root):
            continue
        roots.append(root)
        # 实测一张证书最多挂 91 个域名（np4w53.cn）。限 40 会漏掉一半，
        # 而漏掉的那一半恰恰是最新签发的（SAN 通常按注册顺序排）。
        if len(roots) >= CERT_FAMILY_LIMIT:
            break

    created: list[str] = []
    for root in roots:
        try:
            with session_scope() as s:
                if s.execute(
                    select(Asset.id).where(Asset.kind == "domain", Asset.value == root)
                ).scalar_one_or_none():
                    continue
                s.add(
                    Asset(
                        kind="domain",
                        value=root,
                        normalized=root,
                        tier=TIER_CANDIDATE,
                        discovery_source="cert_san",
                        discovery_reason=f"与 {me} 同一张证书（批量签发，共 {len(names)} 个域名）",
                        score=0.0,
                        verdict="insufficient",
                        meta={
                            "bulk_cert_of": me,
                            "spread_depth": depth + 1,
                            # 取证前不接受域名级降档。
                            #
                            # 线上实测：这 40 个域名入池后不到 8 秒就被富化流程
                            # 重新判级（只有域名、0 分）→ 全部压进冷存。而冷存
                            # 不排队取证，等于刚发现就扔掉。
                            # 和 urlscan 线索是同一类东西：已经有人见过它们，
                            # 只是还没抓页面。
                            "await_capture": True,
                        },
                    )
                )
                s.add(
                    DiscoveryEvent(
                        source="cert_san",
                        kind="domain",
                        value=root,
                        normalized=root,
                        parent=me,
                        score_hint=0.6,
                        raw={"san_count": len(names)},
                    )
                )
                created.append(root)
        except Exception as exc:  # noqa: BLE001 单条失败不影响整批
            log.debug("同证书入池失败 %s：%s", root, exc)
    if created:
        emit("capture.cert_family", origin=me, created=len(created), san=len(names))
        log.info("同证书展开：%s 的证书带出 %d 个域名（SAN 共 %d）", me, len(created), len(names))
    return created


def _register_backend_assets(asset_id: int, value: str, facts: dict[str, Any]) -> list[str]:
    """把跨域提交端点登记成资产。

    为什么值得单独建一条资产：一个 `submit.php` 背后挂着几十个前端域名和一整批
    受害者记录。只记前端域名，等于每次都从头发现「这些站是一伙的」——而骗子
    换域名的速度比人工复核快得多。

    实测：np4w53 / hksm38 / bncp24 / gtds85 / mdyj91 / pqzv19 / tfbx42 /
    xmwk62 / zqtn56 / jrfy47 十个站，提交端点全是 `d7k2m.cn/submit.php`。

    只收「确实在收敏感信息」的跨域端点，共享设施（CDN/建站平台）一律不收，
    否则一次取证就能往库里灌几十个阿里云域名。
    """
    from .normalize import is_shared_infra, registrable_domain

    endpoints = facts.get("endpoints")
    if not isinstance(endpoints, list):
        return []

    me = registrable_domain(_host_of(value) or value)
    created: list[str] = []
    for ep in endpoints:
        if not isinstance(ep, dict) or ep.get("same_site"):
            continue
        if not (ep.get("sensitive") or ep.get("disguised")):
            continue
        host = str(ep.get("host") or "").lower().strip(".")
        if not host or "." not in host or is_shared_infra(host):
            continue
        target = registrable_domain(host)
        if not target or target == me:
            continue

        kinds = "/".join(str(x) for x in (ep.get("sensitive") or [])[:4]) or "敏感信息"
        try:
            with session_scope() as s:
                asset = s.execute(
                    select(Asset).where(Asset.kind == "domain", Asset.value == target)
                ).scalar_one_or_none()
                if asset is None:
                    asset = Asset(
                        kind="domain",
                        value=target,
                        normalized=target,
                        tier=TIER_CANDIDATE,
                        discovery_source="backend",
                        discovery_reason=f"{me} 的提交端点在收「{kinds}」",
                        score=0.0,
                        verdict="insufficient",
                        meta={},
                    )
                    s.add(asset)
                    s.flush()
                    created.append(target)
                    s.add(
                        DiscoveryEvent(
                            source="backend",
                            kind="domain",
                            value=target,
                            normalized=target,
                            parent=me,
                            score_hint=0.72,
                            raw={"endpoint": str(ep.get("url") or "")[:200], "fields": kinds},
                        )
                    )
                    emit("capture.backend", origin=me, endpoint=target, fields=kinds)
                meta = dict(asset.meta or {})
                serves = list(meta.get("serves") or [])
                if me not in serves:
                    serves.append(me)
                meta["serves"] = serves[:80]
                meta["role"] = "backend"
                meta["backend_evidence"] = {
                    "endpoint": str(ep.get("url") or "")[:200],
                    "method": str(ep.get("method") or "POST"),
                    "fields": kinds,
                    "seen_at": utcnow().isoformat(),
                }
                asset.meta = meta
        except Exception as exc:  # noqa: BLE001 登记失败不影响主流程
            log.debug("后端端点登记失败 %s：%s", target, exc)
    return created


def _parse_oversize(reason: str) -> int:
    """从「声明体积 80MB 超过上限 50MB」里取出体积。取不到返回 0。"""
    import re as _re

    m = _re.search(r"声明体积\s*(\d+)\s*MB", reason or "")
    return int(m.group(1)) if m else 0


def _disk_free_gb() -> float:
    """数据盘剩余空间（GB）。取不到就当成「够」，不要让 statvfs 失败挡住取证。"""
    import os as _os

    try:
        st = _os.statvfs(str(settings.data_dir))
        return st.f_bavail * st.f_frsize / (1024 ** 3)
    except OSError:
        return 999.0


def _apk_size_cap(tier: str) -> int:
    """单包上限（MB），按磁盘余量动态给。

    原来的 50MB 是「磁盘只剩 6.9G」时代的妥协。实测涉老诈骗包 80MB 很常见
    （uni-app 壳 + 加固 + 内置浏览器内核 + 离线视频），硬卡 50MB 等于
    只看得见小包，而小包往往只是引流壳，真正的收割包都做大了。
    """
    free = _disk_free_gb()
    if free < 3:
        return 80
    if free < 8:
        return 150
    return 300


def _apk_daily_limit_mb() -> int:
    """当天 APK 总配额（MB）。跟着磁盘走，而不是写一个固定数。

    固定 300MB 的后果：一个 80MB 的包就吃掉四分之一，三个包当天就停摆。
    """
    free = _disk_free_gb()
    if free < 3:
        return 200
    if free < 8:
        return 600
    return 2000


def _maybe_download_apk(asset_id: int, links: list[str], page_url: str, tier: str) -> dict[str, Any]:
    with _APK_LOCK:
        return _download_apk_locked(asset_id, links, page_url, tier)


def _download_apk_locked(asset_id: int, links: list[str], page_url: str, tier: str) -> dict[str, Any]:
    tiers = {t.strip() for t in runtime_settings.get(runtime_settings.CAPTURE_AUTO_APK_TIERS, "watch,confirmed").split(",")}
    if tier == TIER_CANDIDATE:
        # 候选档也下：真实涉老包的下载入口基本都是「点一下才跳」，
        # 而这些站多半停在候选档（内容判定还没到 watch）。
        max_mb = _apk_size_cap(tier)
    elif tier in tiers:
        configured = runtime_settings.get_int(runtime_settings.CAPTURE_APK_MAX_MB, 0)
        # 配了就用配置的，没配就跟着磁盘走
        max_mb = configured or _apk_size_cap(tier)
    else:
        return {"ok": False, "skipped": True, "reason": f"{tier} 档不自动下载"}

    if _disk_free_gb() < 1.5:
        return {"ok": False, "skipped": True, "reason": "数据盘剩余不足 1.5G，暂停下载安装包"}

    daily_limit = (
        runtime_settings.get_int(runtime_settings.CAPTURE_APK_DAILY_MB, 0) or _apk_daily_limit_mb()
    ) * 1024 * 1024
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
            with chain_write_scope() as s:
                append_evidence(
                    s, asset_id, "capture_error",
                    json.dumps({"stage": "apk", "url": link, "reason": result.reason}, ensure_ascii=False).encode(),
                    note=f"安装包下载失败：{result.reason}"[:200], extension=".json", mime="application/json",
                )
                # 体积超限不是「没有包」，而是「有包但装不下」。
                # 实测 26537.net（暖邻）声明 80MB、加固、manifest 加密——
                # 这三点凑一起本身就是结论，不该因为磁盘限制就被当成什么都没发生。
                oversize = _parse_oversize(result.reason)
                if oversize:
                    asset = s.get(Asset, asset_id)
                    if asset is not None:
                        meta = dict(asset.meta or {})
                        facts = dict(meta.get("facts") or {})
                        facts["apk_too_large"] = {"size_mb": oversize, "url": link[:300]}
                        meta["facts"] = facts
                        asset.meta = meta
            continue

        # 静态解析：包名、危险权限、无障碍服务。这些是「这包能干什么」的
        # 直接证据——涉老诈骗的包几乎都要读短信/无障碍/装应用。
        analysis: dict[str, Any] = {}
        try:
            from .collectors import apk as apk_collector

            analysis = apk_collector.analyze(result.path)
        except Exception as exc:  # noqa: BLE001 解析失败不影响证据落盘
            log.debug("APK 静态解析失败 %s：%s", result.url, exc)

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
                afacts = analysis.get("facts") or {}
                # 包真的拿到手了，之前那条「超限」记录就过期了。留着它会让
                # 分级理由一直写着「需人工取样」，而其实已经解析过。
                expired = dict(meta.get("facts") or {})
                if expired.pop("apk_too_large", None) is not None:
                    meta["facts"] = expired
                if afacts:
                    meta["apk_analysis"] = {
                        "package_name": afacts.get("package_name") or "",
                        "dangerous_permission_count": afacts.get("dangerous_permission_count") or 0,
                        "has_accessibility": bool(afacts.get("has_accessibility")),
                        "permissions": (afacts.get("permissions") or [])[:24],
                        "sha256": afacts.get("file_sha256") or "",
                        # 下面这几项决定「这个包能不能被信任」：
                        # manifest 解不出来时上面四个字段全是空的，看起来像
                        # 「一个干净的包」，实际是加固对抗。线上实测 26537.net
                        # 的 80MB 包把 AndroidManifest.xml 做成目录 + 加密，
                        # 解析返回 package_name="" / 0 权限，如果只存前四项，
                        # 下游会把它当无害包放走。
                        "file_size": afacts.get("file_size") or 0,
                        "manifest_obfuscated": bool(afacts.get("manifest_obfuscated")),
                        "apk_ok": bool(afacts.get("apk_ok")),
                        "cert_sha256": afacts.get("cert_sha256") or "",
                        "signer": afacts.get("signer") or "",
                        "packer": afacts.get("packer") or "",
                        "dex_count": afacts.get("dex_count") or 0,
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


def _apply_apk_signal(asset_id: int) -> None:
    """把安装包的能力变成档位。

    一个带无障碍服务 + 装包权限的 APK，不需要页面话术配合就已经能接管手机：
    读短信拿验证码、替用户点确认、再装下一个包。这类证据在「页面看起来像
    什么」之外，所以单独提级，不等下一轮重评。
    """
    from . import triage

    with session_scope() as s:
        asset = s.get(Asset, asset_id)
        if asset is None:
            return
        meta = dict(asset.meta or {})
        analysis = meta.get("apk_analysis") or {}
        if not analysis:
            # 没解析出权限不等于没事：包太大没下来（或压根没下）也要让分级知道。
            f = meta.get("facts") or {}
            if f.get("apk_too_large") or f.get("apk_unparsed"):
                triage.apply(asset, facts=f)
                note = ""
                if f.get("apk_too_large"):
                    size = (f.get("apk_too_large") or {}).get("size_mb")
                    note = f"分发 {size}MB 安装包（超自动下载上限，需人工取样）"
                elif f.get("apk_unparsed"):
                    note = "安装包对抗静态分析（manifest 加密/伪装）"
                if note and note not in (asset.discovery_reason or ""):
                    base = asset.discovery_reason or ""
                    asset.discovery_reason = (base + "；" if base else "") + note
                log.info("安装包未取得但需保留 asset=%s too_large=%s unparsed=%s",
                         asset_id, bool(f.get("apk_too_large")), bool(f.get("apk_unparsed")))
            return
        facts = dict(meta.get("facts") or {})
        facts["apk_analysis"] = analysis
        try:
            danger_count = int(analysis.get("dangerous_permission_count") or 0)
        except (TypeError, ValueError):
            danger_count = 0
        danger = bool(analysis.get("has_accessibility") or danger_count >= 5)
        facts["apk_danger"] = danger

        # 「解析不出来」不等于「干净」。
        # 实测 26537.net（暖邻）分发的 84MB 包：manifest 被做成目录、真文件改成
        # 大写藏在根目录并加密，静态解析拿到 0 权限。正常 App 不会这么干——
        # 这是专门用来躲自动化审计的。所以这里给「无法确认」单独一个事实，
        # 让 triage 知道该包既不能当无害，也不能凭权限表提级。
        try:
            size = int(analysis.get("file_size") or 0)
        except (TypeError, ValueError):
            size = 0
        unparsed = bool(analysis.get("manifest_obfuscated")) and size > 2 * 1024 * 1024
        facts["apk_unparsed"] = unparsed
        if unparsed:
            log.info("安装包对抗静态分析 asset=%s size=%dMB（manifest 加密/伪装）", asset_id, size // 1024 // 1024)

        meta["facts"] = facts
        asset.meta = meta
        if danger or unparsed:
            triage.apply(asset, facts=facts)
            log.info(
                "安装包高危能力 asset=%s 权限=%s 无障碍=%s 对抗=%s → %s",
                asset_id, danger_count, analysis.get("has_accessibility"), unparsed, asset.tier,
            )


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


def reconcile_watch(limit: int = MAX_AUTO_WATCH) -> dict[str, int]:
    """把 watch/confirmed 资产补进盯防池。

    纳管调用点散在 intake / rescore / 人工三处，任何一处漏掉（或历史上
    某次异常中断），资产就只剩 24 小时复访这一档低频动作——看起来一切
    在跑，实际没人盯。线上就出现过：watch 有 1 条，watch_targets 是空的，
    scan_runs 一天 0 条。

    只在配额内补，不淘汰已有目标：对账的职责是补齐，不是重新排座次。
    """
    added = 0
    with session_scope() as s:
        existing = set(s.scalars(select(WatchTarget.value).where(WatchTarget.kind == "asset")))
        current = s.scalar(
            select(func.count(WatchTarget.id)).where(WatchTarget.auto.is_(True))
        ) or 0
        room = max(0, limit - current)
        if room <= 0:
            return {"added": 0, "existing": len(existing), "room": 0}
        rows = s.scalars(
            select(Asset)
            .where(
                Asset.tier.in_((TIER_WATCH, TIER_CONFIRMED)),
                Asset.kind.in_(("domain", "url")),
            )
            .order_by(Asset.score.desc())
        )
        for asset in rows:
            key = asset.value[:200]
            if key in existing:
                continue
            s.add(
                WatchTarget(
                    kind="asset",
                    value=key,
                    asset_id=asset.id,
                    interval_minutes=(120 if asset.tier == TIER_CONFIRMED else 360),
                    auto=True,
                    note=f"{asset.tier} 自动纳管（对账）",
                    # 立刻排一次：对账发现的漏网目标通常已经很久没被看过
                    next_run_at=utcnow() + timedelta(minutes=5),
                )
            )
            existing.add(key)
            added += 1
            if added >= room:
                break
    if added:
        log.info("盯防对账：补入 %d 个目标", added)
    return {"added": added, "existing": len(existing), "room": room}


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
        get_engine().inject(candidates[:30], source="pivot", note=f"pivot from asset {asset_id}")
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
