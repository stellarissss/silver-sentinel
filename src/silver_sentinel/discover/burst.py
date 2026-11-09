"""批量「单域名证书」识别（v1.16）。

为什么需要
----------
v1.15 的「批量证书主动扫描」判据是 `len(obs.all_domains) >= 8`：假设诈骗
团伙把几十个域名塞进**一张**证书的 SAN。上线一天实测 `bulk_assets = 0`，
现场 CT 轮询拿到的观测几乎都是：

    michaelsaschalau.com  ["en-gh.michaelsaschalau.com"]
    yl770.com             ["www.yl770.com", "yl770.com"]
    cctv-bet.vip          ["cctv-bet.vip"]

现代站群改用 **Let's Encrypt / Google Trust Services 单域名证书**，
但第一版（按「签发者 + 签名 + 证书签发 10 分钟桶」聚合）上线实测
`bursts = 0`：4000 条 CT 观测里只有 97 个形态达标域名，散在 50 个桶，
平均每桶不到 2 个。离线重放 8000 条生产 CT 事件找出了原因——

    yl8387.com  yl5837.com  yl2828.com  … 20 个，签发时间散布 8~9 月两个月
    05cctv.com  15cctv.com  cctv668.com … 7 个，冒充央视
    mz790.top   mz749.top   mz920.top   … 7 个

**这不是「一次性批量签发」，是同一个生成器长期运营**：固定字母前缀 +
变数字，域名一个一个注册、证书一张一张签。按签发时刻分桶从根上就错了。
线上反复出现的 `yl770.com`、`cctv-bet.vip`、`mz88` 正是这几族，系统一直
没把它们关联成一批。

判据（全程不依赖任何关键词）
----------------------------
主判据 **前缀族**：`yl8387.com` → 族 `yl|com`，`05cctv.com` → 族 `cctv|com`。
  - 只收「单域名证书」（all_domains <= 2，www + apex 算一个站点）
  - 只收形态分 >= 0.55 的注册域（比窗口判据宽 0.05 留余量；排除可读词、共享基础设施、白名单）
  - 同族累计 >= 5 个不同域名 → 判为一个站群，返回形态分最高的几个
  - 实测 8000 条 CT 事件 → 5 个族 / 50 个域名，全是明显站群，零正常站误入

补充判据 **同时段同签名**：证书签发时刻确实挤在 10 分钟内的（一次性批量
提交），仍按 (签发者, 命名签名, 时间桶) 聚合，阈值 8。两条独立冷却。

取舍
----
这一步只回答「值得花一次取证」，不回答「是不是诈骗」：采纳量受引擎日预算
封顶，进池后仍要走取证、涉老判定、人工复核。前缀族是**长期**信号，同一族
会持续冒出新域名，所以按「族 key + 采纳过的域名」双重去重；CT 补历史、
重启游标回退、日预算耗尽这三类情况下观测都**只累积不丢弃**，等能采纳时
第一批就补上——冷却只负责限频，不再承担防重放。

形态分闸门挡得住 `web2024.com` / `shop2025.com` 这类「可读前缀 + 年份」
（实测 0.36~0.44 < 0.55），但 `abc123.com`（0.74）这类短字母前缀会过闸；
要凑够 5 个同族才触发，且后面还有涉老判定与人工复核，误判成本可控。这里
刻意不加英文词白名单：那等于把「不依赖关键词」的设计换成一份要长期维护的
词表，换个后缀就失效。
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from typing import Any

from ..normalize import collapse_host, is_pivot_noise, is_shared_infra
from .morph import assess as morph_assess

FAMILY_MIN_SIZE = 5         # 前缀族至少几个不同域名（实测 5 个族 / 50 域名，零误入）
FAMILY_MIN_SCORE = 0.55     # 族已有「前缀模板 + 5 个同族」两道强约束，形态分只留余量（现场正例 0.64~0.92）
BURST_MIN_SIZE = 8          # 同时段同签名判据的阈值
BURST_MIN_SCORE = 0.60      # 同时段判据的形态分门槛
BURST_TTL = 1800.0          # 桶空闲多久后清理（秒）
# 原 3600s 是拿来防「CT 重放同一批」的；改由 _seen 域名级去重承担后，冷却
# 只需限频。600s 让历史追平的一个族当天就能分批采完，不必等一小时。
BURST_COOLDOWN = 600.0
BURST_MAX_BUCKETS = 512     # 桶上限，防止内存无界增长

_ISSUER_ORG = re.compile(r"(?:o|O)\s*=\s*([^,]+)")
_PREFIX_NUM = re.compile(r"([a-z]{2,5})\d{2,6}")
_NUM_PREFIX = re.compile(r"\d{1,3}([a-z]{3,6})\d{0,4}")


def issuer_key(issuer: str) -> str:
    """把 `CN=WE1,O=Let's Encrypt,C=US` 归一成稳定的签发者键。

    不按 CN 归一：WE1/WE2/YE2 是同一家 CA 轮换的中间证书，按 CN 会把
    同一批证书劈成几个桶，永远凑不满 8 个。
    """
    m = _ISSUER_ORG.search(issuer or "")
    raw = (m.group(1) if m else (issuer or "unknown")).strip().lower()
    return re.sub(r"\s+", " ", raw)[:64] or "unknown"


def name_signature(root: str) -> str:
    """命名签名：`oi6o45.cn` → `cn:3:mix`。同生成器产物签名一致。"""
    host = (root or "").lower().strip(".")
    parts = [p for p in host.split(".") if p]
    tld = parts[-1] if parts else ""
    # 取注册域最左标签（与 morph._apex_label 保持同一套口径）
    if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "gov", "edu", "co"):
        label = parts[-3]
    elif len(parts) >= 2:
        label = parts[-2]
    else:
        label = parts[0] if parts else ""
    n = len(label)
    digits = sum(1 for c in label if c.isdigit())
    if digits == 0:
        charset = "alpha"
    elif n and digits / n >= 0.5:
        charset = "digit"
    else:
        charset = "mix"
    return f"{tld}:{n // 2}:{charset}"


def family_key(root: str) -> str | None:
    """站群前缀族：`yl8387.com` → `yl|com`，`05cctv.com` → `cctv|com`。

    现场离线重放校准出来的判据。只认「固定字母前缀 + 变数字」这一种命名
    模板——正常站不会注册 20 个 `yl####.com`。纯字母域名、带连字符的、
    以及可读词（命中 morph 低分）都在进桶前被挡掉。
    """
    host = (root or "").lower().strip(".")
    parts = [p for p in host.split(".") if p]
    if not parts:
        return None
    tld = parts[-1]
    if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "gov", "edu", "co"):
        label = parts[-3]
    elif len(parts) >= 2:
        label = parts[-2]
    else:
        return None
    m = _PREFIX_NUM.fullmatch(label)
    if not m:
        m = _NUM_PREFIX.fullmatch(label)
    if not m:
        return None
    return f"{m.group(1)}|{tld}"


def time_bucket(not_before: str) -> str:
    """把证书签发时刻归到 10 分钟桶。

    用证书自己的 not_before 而不是进程收包时间：CT 追平时一次会并发读回
    几十页历史，收包时间会挤成几秒，反而把不相干的证书混成一批。
    """
    text = (not_before or "").strip()
    if len(text) >= 15 and text[4:5] == "-" and text[10:11] == "T":
        return text[:15] + "0"      # "2026-11-09T13:5" → "2026-11-09T13:50"
    return time.strftime("%Y-%m-%dT%H:%M")[:15] + "0"


class BurstDetector:
    """把 CT 观测流聚合成站群批次。

    两条独立判据，桶键加前缀防止串味：

    - `fam:<前缀|TLD>`：同生成器长期运营（主力，现场实测 5 族 / 50 域名）
    - `win:<签发者|签名|10分钟桶>`：一次性批量提交（补充）

    线程安全：CT 每个日志一个线程，都会调 `observe`。
    """

    def __init__(
        self,
        *,
        min_size: int = BURST_MIN_SIZE,
        min_score: float = BURST_MIN_SCORE,
        family_min_size: int = FAMILY_MIN_SIZE,
        family_min_score: float = FAMILY_MIN_SCORE,
        ttl: float = BURST_TTL,
        cooldown: float = BURST_COOLDOWN,
        max_buckets: int = BURST_MAX_BUCKETS,
    ) -> None:
        self.min_size = max(2, min_size)
        self.min_score = min_score
        self.family_min_size = max(2, family_min_size)
        self.family_min_score = family_min_score
        self.ttl = ttl
        self.cooldown = cooldown
        self.max_buckets = max_buckets
        self._buckets: dict[str, dict[str, float]] = {}
        self._touched: dict[str, float] = {}
        self._fired: dict[str, float] = {}
        # 每个桶键记住已采纳过的域名：CT 补历史 / 游标回退重放同一批时不再入池
        self._seen: dict[str, set[str]] = {}
        self._lock = threading.Lock()
        self.stats = {"seen": 0, "candidates": 0, "bursts": 0, "batches": 0,
                      "families": 0, "windows": 0}

    def observe(
        self,
        obs: Any,
        *,
        allowed: Callable[[str], bool] | None = None,
        limit: int = 12,
        adoptable: bool = True,
    ) -> list[tuple[str, float]]:
        """喂一条 CT 观测；凑成一批则返回 [(域名, 形态分)]，否则空列表。

        `allowed(root)` 由引擎传入（白名单等外部判据），保证本模块不依赖
        词库实例，单测可以直接跑。`adoptable=False` 表示引擎当日预算已满：
        观测照常入桶，但不触发、不清桶、不进冷却，预算恢复后第一条即补上。
        """
        self.stats["seen"] += 1
        domains = [d for d in (getattr(obs, "all_domains", None) or []) if d and "." in str(d)]
        # 多 SAN 证书交给 _adopt_bulk_cert：那边的判据是「一张证书挂一堆域名」，
        # 与这里「一批证书各挂一个域名」是两种物理形态，不要混在一起计数。
        if len(domains) > 2:
            return []

        host = str(getattr(obs, "domain", "") or "").lower().strip(".")
        if not host or "." not in host:
            return []
        try:
            root = collapse_host(host)
        except Exception:  # noqa: BLE001 collapse 故障不该拖垮发现层
            root = host
        if not root or "." not in root:
            return []
        if is_shared_infra(root) or is_pivot_noise(root):
            return []
        if allowed is not None and not allowed(root):
            return []

        try:
            score = morph_assess(root).score
        except Exception:  # noqa: BLE001
            return []
        # 两条判据门槛不同：前缀族允许略宽的形态分（前缀本身就是强约束）
        in_family = score >= self.family_min_score
        in_window = score >= self.min_score
        if not (in_family or in_window):
            return []

        fam = family_key(root) if in_family else None
        sig = name_signature(root)
        win_key = "|".join(
            (issuer_key(str(getattr(obs, "issuer", "") or "")), sig,
             time_bucket(str(getattr(obs, "not_before", "") or "")))
        )
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            # 前缀族优先：命中族的观测不再投进时间窗，避免一个域名在两条
            # 判据里被采纳两次（deduper 会挡住第二次，但白白占两个桶）。
            if fam:
                out = self._offer("fam:" + fam, root, score,
                                  self.family_min_size, limit, now,
                                  adoptable=adoptable)
                if out:
                    self.stats["families"] += 1
                return out
            out = self._offer("win:" + win_key, root, score,
                              self.min_size, limit, now, adoptable=adoptable)
            if out:
                self.stats["windows"] += 1
            return out

    def _offer(
        self, key: str, root: str, score: float, min_size: int,
        limit: int, now: float, *, adoptable: bool = True,
    ) -> list[tuple[str, float]]:
        """往一个桶里放一条；够了就取走形态分最高的一批。调用方持有 _lock。

        「桶没满 / 冷却中 / 预算耗尽」三条路径都只累积不丢弃。触发后仅移除
        已采纳的域名，其余留在桶里等下一批——历史追平时一个族会一次涌入
        几十个域名，被 limit 截断的那些不该就此消失。
        """
        seen = self._seen.setdefault(key, set())
        if root in seen:
            return []
        bucket = self._buckets.setdefault(key, {})
        bucket[root] = max(bucket.get(root, 0.0), score)
        self._touched[key] = now
        self.stats["candidates"] += 1
        if not adoptable or len(bucket) < min_size:
            return []
        if now - self._fired.get(key, 0.0) < self.cooldown:
            return []
        picked = sorted(bucket.items(), key=lambda kv: -kv[1])[:max(1, limit)]
        for domain, _ in picked:
            seen.add(domain)
            bucket.pop(domain, None)
        self._fired[key] = now
        if not bucket:
            self._buckets.pop(key, None)
            self._touched.pop(key, None)
        self.stats["bursts"] += 1
        self.stats["batches"] += 1
        return picked

    def _prune(self, now: float) -> None:
        for key, touched in list(self._touched.items()):
            if now - touched > self.ttl:
                self._buckets.pop(key, None)
                self._touched.pop(key, None)
                self._seen.pop(key, None)
        for key, fired in list(self._fired.items()):
            if now - fired > self.cooldown * 2:
                self._fired.pop(key, None)
                if key not in self._buckets:
                    self._seen.pop(key, None)
        # 极端情况下桶数仍超限：丢掉最久没动静的
        if len(self._buckets) > self.max_buckets:
            stale = sorted(self._touched.items(), key=lambda kv: kv[1])[
                : len(self._buckets) - self.max_buckets
            ]
            for key, _ in stale:
                self._buckets.pop(key, None)
                self._touched.pop(key, None)

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                **dict(self.stats),
                "open_buckets": len(self._buckets),
                "cooldowns": len(self._fired),
                "seen_domains": sum(len(v) for v in self._seen.values()),
            }
