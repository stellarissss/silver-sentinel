"""发现引擎：把「世界里新出现的东西」变成「候选池里的记录」。

核心原则
--------
**发现不等于判定。** 这里只回答「值不值得看一眼」，不回答「是不是诈骗」。
所以阈值设得很低（默认 0.30），命中即收；判定交给 scoring，分级交给 triage。
这条链路允许「宁可错杀」——错杀的成本只是几 KB 存储。

数据流
------
CT 日志 / certstream / DNS 探测 / 人工导入
        ↓ 规范化 + 白名单
    词库匹配（hint 分）
        ↓ 去重（内存 LRU + 库唯一键）
  DiscoveryEvent（只追加的流水）
        ↓ upsert
   Asset(tier=candidate) —— 进入研判队列
        ↓
   事件总线（前端实时看到）

吞吐设计
--------
批量落库：攒够 100 条或 2 秒写一次，避免每条一个事务。
去重分两级：内存 set 挡住同一批内的重复，数据库唯一键挡住跨批重复。
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from typing import Any

from sqlalchemy import select

from ..config import settings
from ..core.bus import bus
from ..core.eventlog import emit
from ..db import session_scope
from ..domain import utcnow
from ..models import (
    TIER_CANDIDATE,
    TIER_COLD,
    TIER_CONFIRMED,
    TIER_WATCH,
    Asset,
    DiscoveryEvent,
    KeywordHit,
)
from ..normalize import collapse_host
from .ct import CertObservation, CertStreamClient, CTLogFollower, CtrlShSearch
from .dnsprobe import DNSProbe, SeedGenerator
from .harvest import EXTERNAL_SOURCES, Harvester
from .ippool import BadIPPool
from .keywords import get_library
from .morph import assess as morph_assess
from .pivot import PivotEngine

log = logging.getLogger(__name__)

# 低于这个 hint 分的域名进冷存：仍然记录，但不进研判队列。
# 设得低是刻意的——「宁可错杀」，冷存比漏掉便宜。
COLD_THRESHOLD = 0.30

# 证书兄弟扩散：一张证书上的 SAN 几乎必然属于同一团伙。
# 诈骗站群习惯用一次签发带几十个域名，这是零成本的关联证据——
# 内容词库看不到的兄弟站，靠「同一张证书」就能捞出来。
#
# 门槛不是分数，而是「命中的簇」：域名命中分数普遍在 0.16~0.30，用 0.5 卡
# 等于永远不扩散；但只靠载体词（中心/平台/客服）扩散又会把整张证书的
# 无关域名全捞进来。判据是「至少命中一个强簇」。
CERT_SIBLING_MIN_SCORE = 0.30
CERT_SIBLING_CLUSTERS = frozenset(
    {"policy_theme", "authority", "elder_care", "scam_signature", "inducement", "variant"}
)
CERT_SIBLING_LIMIT = 8
CERT_SIBLING_HINT = 0.28   # 低于 0.30 门槛：进冷存，不与真线索抢取证队列

# ---- 批量签发批次（v1.13）
#
# 上面那条「兄弟域名进冷存」的规则有个致命前提：**一张证书挂几个域名**。
# 实测涉老站群完全相反——np4w53.cn 那张 LiteSSL 证书的 SAN 里有 **90 个**域名，
# 全是 `oi6o45.cn` `uw2v71.cn` `tx7y28.cn` 这种同一个生成器吐出来的。
#
# 一次签发 90 个、全部 .cn、全部同一天、全部同一个 CA，这不可能是巧合。
# 而按老规则：只取 8 个 + 全部进冷存 + 冷存不排队取证 = 90 个里 82 个
# 连记录都没有，剩下 8 个躺在冷存里永远等不到取证。
BULK_CERT_LIMIT = 60         # 批量批次的展开上限（一张证书最多带 60 个回家）
BULK_CERT_DAILY = 20         # 每天最多展开多少张批量证书，防止队列被灌爆
BULK_CERT_HINT = 0.58        # 高于 0.30：直接进候选池排队取证

# ---- 形态预筛（v1.12）：词库打空之后，还剩什么
#
# 涉老站群的域名是批量生成的随机串，词库必然打空。但「像随机串」本身不足以
# 定罪，所以这一层只做两件事：
#   1) 把形态分够的域名收进一个小池子（不落库，不占队列）；
#   2) 对池子做 DNS 解析，只有**解析到已知涉老 IP** 的才真正入池。
#
# 精度优先：第一版只放行 IP 命中，不放行「形态分高」本身。
# 实测 204.194.55.233 一台机器挂两个同模板涉老站，这条信号足够硬。
SHAPE_MIN_SCORE = 0.62       # 进形态池的门槛（实测正例 0.74~0.92，负例 ≤0.31）
SHAPE_POOL_LIMIT = 4000      # 池子上限，满了丢最低分
SHAPE_BATCH = 90             # 每轮解析多少个
SHAPE_INTERVAL = 25.0        # 轮询间隔（秒）
IP_POOL_INTERVAL = 600.0     # IP 池重建 / 同源扩散间隔（秒）
PIVOT_BUDGET = 6             # 每轮最多扩散几个资产。CertSpotter 免费 100 次/小时，
                             # 6×6=36 次留足余量；实测一批证书能带出 9~30 个域名。
IP_HIT_SCORE = 0.78          # 同 IP 命中的发现权重：高于任何词库命中，仍留给判定层复核
STRONG_HINT = 0.50           # 达到这个发现强度就先保护、再取证（见 _persist）
PIVOT_HIT_SCORE = 0.70       # 同证书扩散的发现权重：证据强度略低于同 IP（证书可共享但更难伪造）


@dataclass
class DiscoverStats:
    seen: int = 0
    matched: int = 0
    queued: int = 0
    duplicated: int = 0
    whitelisted: int = 0
    cold: int = 0
    db_errors: int = 0
    cert_siblings: int = 0
    cert_cluster: int = 0
    bulk_certs: int = 0
    cold_promoted: int = 0
    harvested: int = 0
    shape_seen: int = 0
    shape_resolved: int = 0
    ip_hits: int = 0
    ip_pool: int = 0
    pivot_hits: int = 0
    started_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        uptime = max(1.0, time.time() - self.started_at)
        return {
            "seen": self.seen,
            "matched": self.matched,
            "queued": self.queued,
            "duplicated": self.duplicated,
            "whitelisted": self.whitelisted,
            "cold": self.cold,
            "db_errors": self.db_errors,
            "cert_siblings": self.cert_siblings,
            "bulk_certs": self.bulk_certs,
            "cert_cluster": self.cert_cluster,
            "cold_promoted": self.cold_promoted,
            "harvested": self.harvested,
            "shape_seen": self.shape_seen,
            "shape_resolved": self.shape_resolved,
            "ip_hits": self.ip_hits,
            "ip_pool": self.ip_pool,
            "pivot_hits": self.pivot_hits,
            "uptime_seconds": round(uptime, 1),
            # 这两个数以前混在一起叫 rate_per_min，显示成 1.7/分，
            # 看起来像「系统几乎没在工作」——其实那是入池速度，不是采集速度。
            "certs_per_min": round(self.seen / uptime * 60, 1),
            "assets_per_min": round(self.queued / uptime * 60, 1),
            "rate_per_min": round(self.seen / uptime * 60, 1),
        }


class Deduper:
    """两级去重：内存 LRU 挡批量内重复，数据库唯一键挡跨批。"""

    def __init__(self, capacity: int = 200_000) -> None:
        self._seen: deque[str] = deque(maxlen=capacity)
        self._set: set[str] = set()
        self._lock = threading.Lock()

    def add(self, key: str) -> bool:
        """首次出现返回 True。"""
        with self._lock:
            if key in self._set:
                return False
            if len(self._seen) == self._seen.maxlen:
                old = self._seen[0]
                self._set.discard(old)
            self._seen.append(key)
            self._set.add(key)
            return True


class DiscoveryEngine:
    def __init__(self) -> None:
        self.lib = get_library()
        self.stats = DiscoverStats()
        self.deduper = Deduper(settings.discover_queue_capacity)
        self.pending: deque[tuple[CertObservation | None, str, str, float, list[str]]] = deque()
        self._pending_lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._followers: list[CTLogFollower] = []
        self._stream: CertStreamClient | None = None
        self._dns: DNSProbe | None = None
        self._seeds: SeedGenerator | None = None
        self._dns_offset = 0
        self._running = False
        self._last_flush = time.time()
        self._ct_sh = CtrlShSearch()
        self._ct_sh_last: dict[str, float] = {}
        self._harvester: Harvester | None = None
        # 形态池：CT 里「词库没命中但长得像批量生成」的域名，等 DNS 确认
        self._shape_pool: deque[tuple[float, str]] = deque(maxlen=SHAPE_POOL_LIMIT)
        self._shape_lock = threading.Lock()
        self._ippool: BadIPPool | None = None
        self._pivoter: PivotEngine | None = None
        self._bulk_day = ""
        self._bulk_today = 0

    # ------------------------------------------------------------ 生命周期
    def start(self) -> None:
        if self._running or not settings.discover_enabled:
            return
        self._running = True
        self._stop.clear()

        if settings.allow_network:
            (settings.data_dir / "ct_state").mkdir(parents=True, exist_ok=True)
            # 日志清单的选择放到后台线程做：探测 20 多条日志要十几秒，
            # 不能把 API 启动卡住（健康检查会被容器判死）。
            self._threads.append(
                threading.Thread(target=self._ct_manager, name="discover-ct-mgr", daemon=True)
            )
            self._threads.append(
                threading.Thread(target=self._dns_loop, name="discover-dns", daemon=True)
            )
            self._threads.append(
                threading.Thread(target=self._flush_loop, name="discover-flush", daemon=True)
            )
            if settings.harvest_enabled:
                self._threads.append(
                    threading.Thread(
                        target=self._harvest_loop, name="discover-harvest", daemon=True
                    )
                )
            self._ippool = BadIPPool(settings.data_dir / "bad_ips.json")
            self._pivoter = PivotEngine()
            self._threads.append(
                threading.Thread(target=self._shape_loop, name="discover-shape", daemon=True)
            )
            self._threads.append(
                threading.Thread(target=self._ippool_loop, name="discover-ippool", daemon=True)
            )
            self._seeds = SeedGenerator()
            self._dns = DNSProbe(settings.data_dir / "dns_cache.json")

            if settings.ct_stream_enabled and settings.ct_stream_url:
                self._stream = CertStreamClient(settings.ct_stream_url, self._on_ct_batch)
                self._stream.start()

        for t in self._threads:
            t.start()
        log.info("发现引擎已启动：CT 跟随 %s 条日志 + DNS 探测", settings.ct_poll_logs or "自动选择")

    # ------------------------------------------------------------ 日志清单管理
    def _resolve_logs(self) -> list[str]:
        configured = [u.strip() for u in settings.ct_poll_logs.split(",") if u.strip()]
        if configured:
            return configured
        from .ct import fetch_usable_logs

        return fetch_usable_logs(limit=settings.ct_poll_logs_limit)

    def _spawn_follower(self, url: str) -> None:
        slug = url.rstrip("/").rsplit("/", 1)[-1][:24] or "log"
        if not slug or slug == "log":
            parts = [p for p in url.rstrip("/").split("/") if p]
            slug = (parts[-1] if parts else "log")[:24]
        follower = CTLogFollower(
            url,
            settings.data_dir / "ct_state" / f"{slug}.json",
            batch=max(64, settings.ct_poll_batch),
        )
        self._followers.append(follower)
        # 每条日志一个线程：串行轮询时后几条会被前一条的慢请求拖死，
        # 而日志响应时间波动很大（实测 0.5s～5s）。
        t = threading.Thread(
            target=self._ct_loop, args=(follower,), name=f"discover-ct-{slug}", daemon=True
        )
        t.start()

    def _ct_manager(self) -> None:
        try:
            urls = self._resolve_logs()
        except Exception as exc:  # noqa: BLE001
            log.warning("解析 CT 日志清单失败：%s", exc)
            urls = []
        for url in urls:
            if self._stop.is_set():
                return
            self._spawn_follower(url)
        if not self._followers:
            log.warning("没有可用 CT 日志，发现层只剩 DNS 探测")

        # 每半小时检查一次：日志冻结了就换一条。这是它最容易「静默失效」的地方。
        while not self._stop.wait(1800):
            frozen = [f for f in list(self._followers) if f.frozen and not getattr(f, "retired", False)]
            if not frozen:
                continue
            try:
                candidates = self._resolve_logs()
            except Exception:  # noqa: BLE001
                continue
            used = {f.url.rstrip("/") for f in self._followers}
            for dead in frozen:
                dead.retired = True
                spare = [u for u in candidates if u.rstrip("/") not in used]
                if not spare:
                    log.warning("CT 日志 %s 已冻结，但找不到替换日志", dead.url)
                    continue
                used.add(spare[0].rstrip("/"))
                log.warning("CT 日志 %s 已冻结，改跟 %s", dead.url, spare[0])
                self._spawn_follower(spare[0])

    def stop(self) -> None:
        self._stop.set()
        self._running = False
        if self._stream:
            self._stream.stop()
        self._flush(force=True)

    def ensure_running(self) -> bool:
        """看门狗用：发现线程死掉后重建。

        重启会短暂出现重复线程（旧的还活着的那几条），所以加 10 分钟冷却，
        避免看门狗自己把引擎抖成震荡。重复的 flush 有锁、重复的探测会命中
        去重器，代价远小于「发现层悄悄停了三天没人知道」。
        """
        if not settings.discover_enabled or not settings.allow_network:
            return False
        if not self._running:
            self.start()
            return True
        if all(t.is_alive() for t in self._threads):
            return True
        now = time.monotonic()
        if now - getattr(self, "_last_restart", 0.0) < 600:
            return False
        log.error("发现线程有死亡（%d/%d 存活），重启引擎", sum(t.is_alive() for t in self._threads), len(self._threads))
        self._last_restart = now
        try:
            self.stop()
        except Exception:  # noqa: BLE001
            log.debug("停止旧引擎失败", exc_info=True)
        self._threads = [t for t in self._threads if t.is_alive()]
        self._running = False
        self.start()
        return True

    # ------------------------------------------------------------ CT 轮询
    def _ct_loop(self, follower) -> None:
        while not self._stop.is_set() and not getattr(follower, "retired", False):
            started = time.monotonic()
            try:
                # 连续取多批直到追平或预算用尽。单次只取一批的话，
                # 日志增速（实测 ~2000 条/分钟/日志）一旦超过 batch/interval，
                # 中间的证书就被永久跳过。
                follower.catch_up(
                    self._on_ct_batch,
                    max_batches=80,
                    budget=max(6.0, settings.ct_poll_interval * 0.8),
                )
            except Exception as exc:  # noqa: BLE001
                log.debug("CT 轮询异常 %s：%s", follower.url, exc)
            elapsed = time.monotonic() - started
            self._stop.wait(max(2.0, settings.ct_poll_interval - elapsed))

    def _on_ct_batch(self, observations: list[CertObservation]) -> None:
        for obs in observations:
            self.stats.seen += 1
            host = obs.domain.lower().strip(".")
            if not host or "." not in host:
                continue
            if self.lib.is_whitelisted(host):
                self.stats.whitelisted += 1
                continue
            # 一张证书常带 10~30 个 SAN，同一站点的 www/分中心/后台会各算一个资产：
            # 实测 22 小时里 2,512 个主机只对应 1,251 个注册域，一半是重复。
            # 归并到注册域，主机清单留在 meta.hosts，图里仍然能连到具体主机。
            domain = collapse_host(host) if settings.discover_collapse_subdomains else host
            if not domain:
                continue
            result = self.lib.match_domain(host)
            # 一个词都没命中 = 与我们的关注面无关，直接丢弃（这是唯一会丢的分支）
            if not result.hits and result.score < COLD_THRESHOLD:
                # v1.12：丢之前先看一眼形态。站群域名是随机串，词库天生看不见，
                # 但它们的「名字长相」留在 CT 里。这里只入形态池，不入库。
                self._offer_shape(host)
                self.stats.cold += 1
                continue
            # 只有「载体词」的域名（app./m./www. 这种前缀命中）价值为零：
            # 一个 "app" 就把全世界的 app.xxx.com 收进来，等于没有筛选。
            # 低于阈值一律算冷存，不入资产表——需要时还能从事件流水回放。
            if result.score < COLD_THRESHOLD:
                self.stats.cold += 1
                continue
            self.stats.matched += 1
            if not self.deduper.add(domain):
                self.stats.duplicated += 1
                continue
            obs_host = host
            with self._pending_lock:
                self.pending.append((obs, "domain", domain, result.score, result.terms, obs_host))

            # 同一张证书上的其他注册域：这是团伙级关联，内容词库看不到也能捞到
            if result.score >= CERT_SIBLING_MIN_SCORE and any(
                getattr(hit, "cluster", "") in CERT_SIBLING_CLUSTERS for hit in result.hits
            ):
                self._spread_cert_siblings(obs, domain)

    def _spread_cert_siblings(self, obs: CertObservation, origin: str) -> None:
        """把同一张证书上的其他注册域送进队列。

        诈骗站群常用一次签发带几十个域名，兄弟站可能还没建站、可能是后台、
        可能正文里一个词都没有。它们的价值不在内容，而在「和已知可疑域名
        共享同一张证书」——这比任何词库命中都硬。

        分两种处理：

        - **批量批次**（SAN >= 8 个且多数是随机串）：这是站群，兄弟域名直接
          进候选池排队取证，上限放宽到 60。实测 np4w53.cn 一张证书 90 个域名，
          抽 10 个测 9 个在线、标题逐字相同。老规则只取 8 个且全进冷存，
          等于 90 个里 82 个连记录都没有。
        - **零散兄弟**（共享主机、CDN 通用证书）：维持原样，进冷存不抢队列。

        用 `san:` 前缀独立去重：兄弟域名先以低分进来，之后自己命中关键词时
        仍能走正常路径升级，不会被「已存在」挡在门外。
        """
        from ..normalize import is_pivot_noise

        siblings: list[str] = []
        for raw in obs.all_domains:
            host = str(raw).lower().strip(".")
            if not host or "." not in host:
                continue
            root = collapse_host(host) if settings.discover_collapse_subdomains else host
            if not root or root == origin or root in siblings:
                continue
            if self.lib.is_whitelisted(root) or is_pivot_noise(root):
                continue
            siblings.append(root)

        if not siblings:
            return

        bulk = self._looks_like_bulk_batch(siblings) and self._bulk_budget_left()
        limit = BULK_CERT_LIMIT if bulk else CERT_SIBLING_LIMIT
        hint = BULK_CERT_HINT if bulk else CERT_SIBLING_HINT
        siblings = siblings[:limit]

        # 兄弟域名单独标记来源：证书关联命中多少，是判断「站群密度」的指标。
        # 共用同一个 obs 会把它记成 ct_poll，事后分不清是词库捞到的还是证书带来的。
        sib_obs = replace(obs, source="ct_san")

        added = 0
        with self._pending_lock:
            for root in siblings:
                if not self.deduper.add("san:" + root):
                    continue
                self.pending.append(
                    (sib_obs, "domain", root, hint, ["bulk_cert" if bulk else "cert_sibling"], root)
                )
                added += 1
        if added:
            self.stats.cert_siblings += added
            if bulk:
                self.stats.bulk_certs += 1
                log.info(
                    "批量签发：%s 的证书带出 %d 个域名（形态分达标的占多数）",
                    origin, added,
                )

    def _looks_like_bulk_batch(self, siblings: list[str]) -> bool:
        """这批兄弟域名看起来像不像「一个生成器吐出来的」。

        判据不是「名字里有随机串」，而是**比例**：一张证书上 60% 以上是
        随机串，才说明命名习惯统一。共享主机的证书一般是
        `shop.example.com` `blog.other.cn` 这种正常名字混着来。
        """
        try:
            from .morph import is_bulk_batch

            return is_bulk_batch(siblings)
        except Exception:  # noqa: BLE001 形态模块坏掉不该拖垮发现层
            return False

    def _bulk_budget_left(self) -> bool:
        """今天还开不开放批量展开。

        一张批量证书能带出 60 个候选，一天几十张就是几千条，取证队列会被
        历史垃圾塞满、新线索反而排不上。按天限额，超了就退回「8 个进冷存」。
        """
        today = time.strftime("%Y-%m-%d")
        if self._bulk_day != today:
            self._bulk_day = today
            self._bulk_today = 0
        if self._bulk_today >= BULK_CERT_DAILY:
            return False
        self._bulk_today += 1
        return True

    # ------------------------------------------------------------ DNS 探测
    def _dns_loop(self) -> None:
        # 先等 CT 跑起来，避免启动瞬间抢带宽
        self._stop.wait(20)
        while not self._stop.is_set():
            try:
                if not self._seeds or not self._dns:
                    break
                batch = self._seeds.candidates(self._dns_offset, 300)
                self._dns_offset = (self._dns_offset + 300) % max(1, len(self._seeds.seeds))
                found = self._dns.probe_many(d for d, _ in batch)
                origin_map = dict(batch)
                for res in found:
                    domain = res.domain
                    if self.lib.is_whitelisted(domain):
                        self.stats.whitelisted += 1
                        continue
                    match = self.lib.match_domain(domain)
                    score = max(match.score, 0.45)   # DNS 探测命中的词根本身带信号
                    self.stats.seen += 1
                    self.stats.matched += 1
                    if not self.deduper.add(domain):
                        self.stats.duplicated += 1
                        continue
                    obs = CertObservation(
                        domain=domain,
                        all_domains=[domain],
                        issuer="",
                        not_before="",
                        fingerprint="",
                        log_url="dns_probe",
                        entry_index=0,
                        source="dns_probe",
                    )
                    with self._pending_lock:
                        self.pending.append(
                            (obs, "domain", domain, score,
                             match.terms or [origin_map.get(domain, "")], domain)
                        )
                log.info(
                    "DNS 探测：%d 个候选，%d 个已注册（累计存在 %d）",
                    len(batch), len(found), self._dns.stats["exists"],
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("DNS 探测异常：%s", exc)
            self._stop.wait(45)

    # ------------------------------------------------------------ 落库
    # ------------------------------------------------------------ 外部线索
    def _harvest_loop(self) -> None:
        """按话术轮询外部索引（urlscan 标题检索）。

        为什么不是 CT 的补充而是并列：CT 只认「域名里写了什么」，
        而涉老诈骗的域名是随机串。这里的入口是「标题里写了什么」。
        实测 `page.title:"个人财政补贴"` 直接命中 np4w53/hksm38/l4k9j。

        启动等 90 秒：CT 跟随刚起来时要探测日志清单、建状态文件，
        这时候再打一组外部 API，两边都容易超时。
        """
        try:
            self._harvester = Harvester(
                per_round=settings.harvest_queries_per_round,
                # 游标落盘：不这样的话每次部署都从头开始跑前几个词。
                # 线上实测十轮全是 subsidy 簇，另外 25 个词一次都没出去过。
                state_path=settings.data_dir / "harvest_state.json",
            )
        except Exception as exc:  # noqa: BLE001 配置坏了不能让发现层起不来
            log.warning("外部线索源初始化失败：%s", exc)
            return
        if self._stop.wait(90):
            return
        while not self._stop.is_set():
            try:
                self._harvest_once()
            except Exception as exc:  # noqa: BLE001 一轮失败不杀线程
                log.warning("外部线索轮询异常：%s", exc, exc_info=True)
            if self._stop.wait(max(300, settings.harvest_interval_seconds)):
                return

    def _harvest_once(self) -> int:
        if self._harvester is None:
            return 0
        hits = self._harvester.run_round()
        if not hits:
            return 0

        queued = 0
        with self._pending_lock:
            for hit in hits:
                # 不归并到注册域：urlscan 明确告诉我们「这个 URL 上有这个标题」。
                # s.qka91.com 是民族资产解冻的落地页，qka91.com 可能压根没建站——
                # 归并过去等于把唯一入口弄丢了。（CT 那边归并是因为它只给域名。）
                host = (hit.host or "").lower().strip(".")
                if host.startswith("www."):
                    host = host[4:]
                if not host or "." not in host:
                    continue
                if self.lib.is_whitelisted(host):
                    self.stats.whitelisted += 1
                    continue
                if not self.deduper.add(host):
                    self.stats.duplicated += 1
                    continue
                self.pending.append(
                    (hit.observation(), "domain", host, hit.score, [hit.query], host)
                )
                queued += 1

        self.stats.harvested += queued
        emit(
            "discover.harvest",
            hits=len(hits),
            queued=queued,
            stats=self._harvester.as_dict(),
        )
        log.info("外部线索：%d 条命中，%d 条入池", len(hits), queued)
        return queued

    # ------------------------------------------------------------ 形态预筛
    def _offer_shape(self, host: str) -> None:
        """词库没命中的域名，交给形态学看一眼。只入池，不落库。"""
        if self._stop.is_set():
            return
        verdict = morph_assess(host)
        if verdict.score < SHAPE_MIN_SCORE:
            return
        if not self.deduper.add("shape:" + host):
            return
        with self._shape_lock:
            self._shape_pool.append((verdict.score, host))
        self.stats.shape_seen += 1

    def _shape_loop(self) -> None:
        """把形态池里的域名做一次 DNS，只有落在已知涉老 IP 上的才升级。

        为什么不是「形态分高就抓页面」：CT 每天几万个随机串，全抓等于自己
        造一个分布式扫描器，既慢又打草惊蛇。DNS 查询不进对方 web 日志，
        30 QPS 能覆盖全量，成本几乎为零。

        等 3 分钟再起：给 IP 池一点时间从已确认资产里长出来。
        """
        if self._stop.wait(180):
            return
        while not self._stop.is_set():
            try:
                self._shape_once()
            except Exception as exc:  # noqa: BLE001 一轮失败不杀线程
                log.warning("形态预筛异常：%s", exc)
            if self._stop.wait(SHAPE_INTERVAL):
                return

    def _shape_once(self) -> int:
        if self._dns is None or self._ippool is None:
            return 0
        with self._shape_lock:
            if not self._shape_pool:
                return 0
            batch = [self._shape_pool.pop() for _ in range(min(SHAPE_BATCH, len(self._shape_pool)))]
        hosts = [h for _s, h in batch]
        hits = 0
        for res in self._dns.probe_many(hosts):
            if not res.a_records:
                continue
            self.stats.shape_resolved += 1
            for ip in res.a_records:
                entry = self._ippool.lookup(ip)
                if entry is None:
                    continue
                self._ippool.note_hit(ip, res.domain)
                self._enqueue_ip_hit(res.domain, ip, entry.assets[:1])
                hits += 1
                break
        self.stats.ip_hits += hits
        self.stats.ip_pool = len(self._ippool)
        if hits:
            log.info("形态预筛：%d/%d 命中已知涉老 IP", hits, len(hosts))
            emit("discover.ip_hit", hosts=len(hosts), hits=hits, pool=len(self._ippool))
        return hits

    def _enqueue_ip_hit(self, host: str, ip: str, siblings: list[str]) -> None:
        note = f"与已确认涉老站共用服务器 {ip}"
        if siblings:
            note += f"（同机：{siblings[0]}）"
        self._enqueue_external(host, "ip_pool", note, IP_HIT_SCORE)

    def _enqueue_external(self, host: str, source: str, note: str, score: float) -> bool:
        """把外部线索（同 IP / 同证书 / 举报）送进待落库队列。

        与 CT 共用同一条落库路径，但带 note——落库时会写成 discovery_reason，
        复核的人能一眼看到「为什么这条值得看」。
        """
        host = (host or "").lower().strip(".")
        if host.startswith("www."):
            host = host[4:]
        if not host or "." not in host:
            return False
        if self.lib.is_whitelisted(host):
            self.stats.whitelisted += 1
            return False
        if not self.deduper.add(f"{source}:" + host):
            self.stats.duplicated += 1
            return False
        obs = CertObservation(
            domain=host,
            all_domains=[host],
            issuer="",
            not_before="",
            fingerprint="",
            log_url="",
            entry_index=0,
            source=source,
            note=note,
        )
        with self._pending_lock:
            self.pending.append((obs, "domain", host, score, [source], host))
        return True

    def _ippool_loop(self) -> None:
        """定期把「高置信资产」解析到的 IP 收进池，再用本地 DNS 缓存反查同机域名。

        反查这一步不花钱：我们为别的目的查过的 DNS 本身就是一张同服表。
        """
        if self._stop.wait(240):
            return
        while not self._stop.is_set():
            try:
                self._rebuild_ippool()
                self._pivot_once()
            except Exception as exc:  # noqa: BLE001
                log.warning("IP 池／同源扩散失败：%s", exc)
            if self._stop.wait(IP_POOL_INTERVAL):
                return

    def _pivot_once(self, *, budget: int = PIVOT_BUDGET) -> int:
        """对高置信资产做证书／同 IP 扩散，一次最多 3 个，慢慢来。

        为什么限额：CertSpotter 免费额度 100 次/小时，扩散是「有空才做」的
        后台活。实测一个 .com.cn 站群的证书能带出 30 个域名，3 次就够补一天。
        """
        if self._pivoter is None:
            return 0
        todo: list[tuple[int, str, list[str]]] = []
        with session_scope() as session:
            rows = session.execute(
                select(Asset.id, Asset.value, Asset.meta).where(
                    Asset.tier.in_((TIER_WATCH, TIER_CONFIRMED)),
                    Asset.kind == "domain",
                )
            ).all()
        for asset_id, value, meta in rows:
            meta = meta or {}
            facts = meta.get("facts") or {}
            elder = facts.get("elder") or {}
            priority = elder.get("priority") if isinstance(elder, dict) else ""
            is_elder = bool(elder.get("elder")) if isinstance(elder, dict) else False
            # 只对**涉老**的高置信资产扩散。
            #
            # 踩过的坑：条件里带了 `apk_danger`，结果把 apidevel.org（印尼赌博站，
            # 一个无障碍权限就够 apk_danger）当成了扩散源，一次拉进 35 个子域
            # ——bio./cdn./admin./pixel. 全是没用的基础设施。这套系统是涉老哨兵，
            # 赌博站的团伙规模再大也不该占队列。
            if not (is_elder and priority in ("P0", "P1")):
                continue
            if meta.get("pivot_at"):
                continue
            todo.append((asset_id, value, [str(ip) for ip in (facts.get("ips") or [])]))
            if len(todo) >= budget:
                break

        added = 0
        for asset_id, value, ips in todo:
            try:
                hits = self._pivoter.expand(value, ips=ips)
            except Exception as exc:  # noqa: BLE001
                log.debug("扩散失败 %s：%s", value, exc)
                continue
            kept = 0
            for hit in hits:
                if self._enqueue_external(hit.domain, hit.source, hit.detail, PIVOT_HIT_SCORE):
                    kept += 1
            added += kept
            with session_scope() as session:
                asset = session.get(Asset, asset_id)
                if asset is not None:
                    meta = dict(asset.meta or {})
                    meta["pivot_at"] = utcnow().isoformat()
                    meta["pivot_hits"] = kept
                    asset.meta = meta
            if kept:
                emit("discover.pivot", origin=value, hits=len(hits), queued=kept)
                log.info("同源扩散：%s 带出 %d 个域名（共命中 %d）", value, kept, len(hits))
        self.stats.pivot_hits += added
        return added

    def _rebuild_ippool(self) -> int:
        if self._ippool is None:
            return 0
        added = 0
        with session_scope() as session:
            rows = session.execute(
                select(Asset.value, Asset.tier, Asset.meta).where(
                    Asset.tier.in_((TIER_WATCH, TIER_CONFIRMED)),
                    Asset.kind == "domain",
                )
            ).all()
        for value, tier, meta in rows:
            facts = (meta or {}).get("facts") or {}
            elder = facts.get("elder") or {}
            priority = elder.get("priority") if isinstance(elder, dict) else ""
            # 只收「危害已明确」的资产。普通 watch 可能是误报（实测 8 条里 4 条是
            # 反诈曝光站、广告站、代办灰产），把它们放进池子等于往池里倒噪声。
            if not (tier == TIER_CONFIRMED or priority == "P0" or facts.get("apk_danger")):
                continue
            for ip in facts.get("ips") or []:
                reason = "涉老 P0" if priority == "P0" else ("安装包高危" if facts.get("apk_danger") else "已确认")
                if self._ippool.observe(
                    str(ip), asset=value, reason=reason, asn=str(facts.get("asn") or "")
                ):
                    added += 1
                    # 本地被动 DNS：同一个 IP 上还解析过谁
                    for sibling in self._dns.cache.reverse(str(ip)) if self._dns else []:
                        if sibling == value or self.lib.is_whitelisted(sibling):
                            continue
                        if self._ippool.observe(
                            str(ip), asset=value, reason=reason + "（同机反查）"
                        ):
                            pass
                        self._enqueue_ip_hit(sibling, str(ip), [value])
        if added:
            self._ippool.prune_dirty()
            log.info("IP 池更新：%d 个新 IP，池内 %d 条", added, len(self._ippool))
            emit("discover.ippool", added=added, size=len(self._ippool))
        self.stats.ip_pool = len(self._ippool)
        return added

    def _flush_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(2.0)
            self._flush()

    def _flush(self, force: bool = False) -> None:
        with self._pending_lock:
            if not self.pending:
                return
            if not force and len(self.pending) < 60 and (time.time() - self._last_flush) < 5:
                return
            batch = list(self.pending)
            self.pending.clear()
        self._last_flush = time.time()

        rows = batch
        try:
            with session_scope() as session:
                created = self._persist(session, rows)
            self.stats.queued += created
        except Exception as exc:  # noqa: BLE001
            self.stats.db_errors += 1
            log.warning("发现批写入失败（%d 条）：%s", len(rows), exc)
            # 失败不重排队：事件日志里已有流水，人工可回放
            emit("discover.flush_failed", count=len(rows), error=str(exc)[:200])

    def _cert_clusters(self, session, rows: list[tuple]) -> dict[str, str]:
        """同一张证书签过的可疑域名，按指纹索引。

        一次批量查，避免逐条 SELECT。只认「已经进过研判」的资产——
        两个都还在候选池、都还没取证的域名，谈不上团伙证据。
        """
        fps = {obs.fingerprint for obs, *_rest in rows if obs is not None and obs.fingerprint}
        if not fps:
            return {}
        out: dict[str, str] = {}
        for fp, normalized, tier, score in session.execute(
            select(Asset.fingerprint, Asset.normalized, Asset.tier, Asset.score).where(
                Asset.fingerprint.in_(fps),
                Asset.tier.in_((TIER_WATCH, TIER_CONFIRMED, TIER_CANDIDATE)),
            )
        ):
            if tier == TIER_CANDIDATE and (score or 0) < 20:
                continue
            out.setdefault(fp, normalized)
        return out

    def _persist(self, session, rows: list[tuple]) -> int:
        created = 0
        assets: list[dict[str, Any]] = []
        clusters = self._cert_clusters(session, rows)
        # 同一批里出现多个域名的证书：一次签发给整个站群，比「库里已有」
        # 更早能看到。诈骗团伙常常一次性签发 5~20 个域名再逐个启用。
        fp_counts: dict[str, int] = {}
        for obs, *_rest in rows:
            if obs is not None and obs.fingerprint:
                fp_counts[obs.fingerprint] = fp_counts.get(obs.fingerprint, 0) + 1
        for obs, kind, value, score, terms, host in rows:
            normalized = value
            existing = session.scalar(
                select(Asset.id).where(Asset.kind == kind, Asset.normalized == normalized)
            )
            if existing:
                # 只更新 last_seen 和发现原因，不动评分——评分由研判链路负责
                asset = session.get(Asset, existing)
                if asset is not None:
                    asset.last_seen = utcnow()
                    asset.enrich_count = (asset.enrich_count or 0) + 1
                    meta = dict(asset.meta or {})
                    changed = False
                    if score > meta.get("discover_hint", 0):
                        meta["discover_hint"] = round(score, 3)
                        changed = True
                        # 冷档资产被更强的发现信号命中：提回候选池，别让它沉底。
                        # 已被研判过的不动，避免覆盖评分与人工结论。
                        if (
                            asset.tier == TIER_COLD
                            and score >= COLD_THRESHOLD
                            and not meta.get("triaged")
                        ):
                            asset.tier = TIER_CANDIDATE
                            asset.discovery_reason = "、".join(terms[:6]) or asset.discovery_reason
                            self.stats.cold_promoted += 1
                    # 外部线索复现：不设 triaged 门槛。
                    # triaged 是域名级研判的产物，而外部线索的价值恰恰在「页面
                    # 已被看到」——用域名结论否定它，等于把这条线索作废。
                    if obs is not None and obs.source in EXTERNAL_SOURCES:
                        meta["await_capture"] = True
                        changed = True
                        if asset.tier == TIER_COLD and not asset.reviewed_by:
                            asset.tier = TIER_CANDIDATE
                            self.stats.cold_promoted += 1
                    hosts = meta.get("hosts") or []
                    if host and host not in hosts and len(hosts) < 30:
                        meta["hosts"] = hosts + [host]
                        changed = True
                    if changed:
                        asset.meta = meta
                    # 证书指纹是同一团伙最强的关联证据，第一次拿到就记住
                    if obs is not None and obs.fingerprint and not asset.fingerprint:
                        asset.fingerprint = obs.fingerprint[:64]
                session.add(
                    DiscoveryEvent(
                        source=obs.source if obs else "manual",
                        kind=kind,
                        value=value,
                        normalized=normalized,
                        matched_terms=terms[:12],
                        score_hint=round(score, 3),
                        asset_id=existing,
                        raw=obs.as_dict() if obs else {},
                    )
                )
                continue

            # 同一张证书签过的域名已在研判队列里：这张证书就是团伙证据，
            # 新域名即便自己一个词都没命中，也该进候选池看一眼。
            cluster_of = None
            if obs is not None and obs.fingerprint:
                cluster_of = clusters.get(obs.fingerprint)
                if cluster_of == normalized:
                    cluster_of = None

            # 同批多域名同证书：一次签发给整个站群，还没建站就该记下来
            batch_mates = 0
            if obs is not None and obs.fingerprint:
                batch_mates = max(0, fp_counts.get(obs.fingerprint, 1) - 1)

            meta: dict[str, Any] = {
                "discover_hint": round(score, 3),
                "hosts": [host] if host else [],
            }
            if obs is not None and (
                obs.source in EXTERNAL_SOURCES or score >= STRONG_HINT
            ):
                # 取证前不许被域名级研判降档，否则永远等不到取证。
                #
                # 不只外部线索：同 IP（0.78）、批量证书（0.58）、形态池命中
                # 都属于「已经拿到结构化证据」，它们的价值在于关联，而富化
                # 流程只看域名本身，会立刻算成 0 分压进冷存。线上实测：
                # 40 个同证书域名入池 8 秒内全被压成 cold，一个都没取到证。
                meta["await_capture"] = True
            reason = "、".join(terms[:6])
            note = (getattr(obs, "note", "") or "") if obs is not None else ""
            if note:
                reason = note + ("；" + reason if reason else "")
            if cluster_of:
                meta["cert_cluster"] = cluster_of
                reason = (reason + "；" if reason else "") + f"同证书：{cluster_of}"
                self.stats.cert_cluster += 1
            elif batch_mates:
                meta["cert_siblings"] = batch_mates
                reason = (reason + "；" if reason else "") + f"同批签发 {batch_mates + 1} 个域名"
                self.stats.cert_cluster += 1

            asset = Asset(
                kind=kind,
                value=value,
                normalized=normalized,
                tier=TIER_CANDIDATE
                if (score >= COLD_THRESHOLD or cluster_of or batch_mates)
                else TIER_COLD,
                discovery_source=obs.source if obs else "manual",
                discovery_reason=reason,
                score=0.0,
                verdict="insufficient",
                fingerprint=(obs.fingerprint[:64] if obs is not None else ""),
                meta=meta,
            )
            session.add(asset)
            session.flush()
            session.add(
                DiscoveryEvent(
                    source=obs.source if obs else "manual",
                    kind=kind,
                    value=value,
                    normalized=normalized,
                    matched_terms=terms[:12],
                    score_hint=round(score, 3),
                    asset_id=asset.id,
                    raw=obs.as_dict() if obs else {},
                )
            )
            assets.append(
                {
                    "id": asset.id,
                    "kind": kind,
                    "value": value,
                    "score": round(score, 3),
                    "terms": terms[:6],
                    "source": obs.source if obs else "manual",
                }
            )
            created += 1

            # 词库命中统计：用来淘汰永远误报的词
            for term in terms[:6]:
                if not term:
                    continue
                row = session.get(KeywordHit, term)
                if row:
                    row.hits += 1
                    row.last_hit = utcnow()
                else:
                    session.add(KeywordHit(term=term, hits=1))

        session.commit()

        for item in assets[:40]:
            bus.publish("discovery", item)
        if assets:
            emit("discover.batch", created=len(assets), sample=[a["value"] for a in assets[:5]])
        return created

    # ------------------------------------------------------------ 手动注入
    def inject(self, values: Iterable[str], *, source: str = "manual", note: str = "") -> dict[str, Any]:
        """人工/外部导入。用于举报线索、批量域名清单、已知样本附带的基础设施。"""
        added = 0
        skipped = 0
        with session_scope() as session:
            for raw in values:
                value = str(raw).strip().lower().rstrip(".")
                if not value or "." not in value:
                    skipped += 1
                    continue
                if self.lib.is_whitelisted(value):
                    skipped += 1
                    continue
                if not self.deduper.add(value):
                    skipped += 1
                    continue
                match = self.lib.match_domain(value)
                note_text = note or "人工导入"
                existing = session.scalar(
                    select(Asset.id).where(Asset.kind == "domain", Asset.normalized == value)
                )
                if existing:
                    skipped += 1
                    continue
                asset = Asset(
                    kind="domain", value=value, normalized=value,
                    tier=TIER_CANDIDATE, discovery_source=source,
                    discovery_reason=note_text + ("；命中：" + "、".join(match.terms[:5]) if match.terms else ""),
                    meta={"discover_hint": round(match.score, 3)},
                )
                session.add(asset)
                session.flush()
                session.add(
                    DiscoveryEvent(
                        source=source, kind="domain", value=value, normalized=value,
                        matched_terms=match.terms[:12], score_hint=round(match.score, 3),
                        asset_id=asset.id, raw={"note": note_text},
                    )
                )
                added += 1
            session.commit()
        bus.publish("discovery_injected", {"added": added, "skipped": skipped, "source": source})
        emit("discover.inject", added=added, skipped=skipped, source=source)
        return {"added": added, "skipped": skipped}

    def search_history(self, terms: list[str], limit_per_term: int = 60) -> dict[str, Any]:
        """按词根翻 crt.sh 历史。慢，只在需要补漏时手动触发。"""
        total = 0
        for term in terms[:20]:
            last = self._ct_sh_last.get(term, 0)
            if time.time() - last < 3600:      # 同一词根一小时最多查一次
                continue
            self._ct_sh_last[term] = time.time()
            observations = self._ct_sh.search(term, limit=limit_per_term)
            for obs in observations:
                domain = obs.domain.lower()
                if not domain or self.lib.is_whitelisted(domain):
                    continue
                match = self.lib.match_domain(domain)
                if match.score < COLD_THRESHOLD and not match.hits:
                    continue
                if not self.deduper.add(domain):
                    continue
                with self._pending_lock:
                    self.pending.append((obs, "domain", domain, match.score, match.terms))
                total += 1
            time.sleep(2)
        self._flush(force=True)
        return {"queued": total}

    # ------------------------------------------------------------ 状态
    def status(self) -> dict[str, Any]:
        followers = list(self._followers)
        return {
            "running": self._running,
            "stats": self.stats.as_dict(),
            "keyword_library": self.lib.stats(),
            "followers": [f.status() for f in followers],
            "followers_total_lag": sum(
                (f.status().get("lag") or 0) for f in followers if not getattr(f, "retired", False)
            ),
            "followers_frozen": sum(1 for f in followers if f.frozen),
            "stream": self._stream.status() if self._stream else None,
            "dns": self._dns.stats if self._dns else None,
            "seeds": self._seeds.stats() if self._seeds else None,
            "pending": len(self.pending),
            "crt_sh_error": self._ct_sh.last_error,
        }


_engine: DiscoveryEngine | None = None
_lock = threading.Lock()


def get_engine() -> DiscoveryEngine:
    global _engine
    if _engine is None:
        with _lock:
            if _engine is None:
                _engine = DiscoveryEngine()
    return _engine
