"""证书透明度（CT）发现：三条腿走路。

1. **CT 日志直连**（RFC 6962）：最可靠，不依赖任何第三方聚合服务。
   只跟最新的尾部，落后太多就跳段——我们要的是「最近新注册的仿冒站」，
   不是把 30 亿条历史全啃一遍。
2. **certstream WebSocket**：如果自建了 certstream-server，配 URL 即可，
   延迟比轮询低。
3. **crt.sh 关键词检索**：慢但能回溯历史，用于按词根批量补漏。

三者都只做一件事：把「新出现的域名 + 证书元数据」吐给上层。
判定不在这里做。
"""

from __future__ import annotations

import base64
import json
import logging
import random
import threading
import time
import urllib.error
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

log = logging.getLogger(__name__)

# 默认日志集：优先 DigiCert / Cloudflare。Google 系在很多国内机房连不上
# （实测 12s 超时），所以放最后，失败也不影响前面几条。
# 注意日志会「冻结」——`nimbus2025` 这类年度日志在年底后被封存，tree_size 不再增长。
# 因此除了这份静态清单，运行时会去官方 log_list.json 拉当前 usable 日志（见 fetch_usable_logs）。
DEFAULT_LOGS = [
    "https://wyvern.ct.digicert.com/2026h2/",
    "https://sphinx.ct.digicert.com/2026h2/",
    "https://ct.cloudflare.com/logs/nimbus2026/",
    "https://elephant2026h2.ct.sectigo.com/",
    "https://ct.googleapis.com/logs/us1/argon2026h2/",
]

LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
# 这些运营商在国内机房通常可达；排序时优先
PREFERRED_OPERATORS = ("DigiCert", "Cloudflare", "Sectigo", "TrustAsia")

# UA 由 opsec 统一分配：同一目标稳定、跨目标不同，且不含任何项目标识


@dataclass(slots=True)
class CertObservation:
    """一张证书带来的观测。字段保持原始值，不做加工。"""

    domain: str
    all_domains: list[str]
    issuer: str
    not_before: str
    fingerprint: str
    log_url: str
    entry_index: int
    source: str = "ct_poll"
    # 非证书来源（形态/IP 池/外部线索）附加的一句话说明，落库时进 discovery_reason
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "all_domains": self.all_domains[:50],
            "issuer": self.issuer[:120],
            "not_before": self.not_before,
            "fingerprint": self.fingerprint,
            "log_url": self.log_url,
            "entry_index": self.entry_index,
            "source": self.source,
            "note": self.note[:200],
        }


def _json_payload(resp: Any) -> Any:
    """把响应体解成 JSON，能扛住「服务端压缩了但客户端没解」的情况。

    正常路径是 httpx 自己按 Content-Encoding 解压；但线上见过 gstatic 用 br
    回包、而运行环境没装 brotli 的情况，此时 `resp.json()` 会在 UTF-8 解码处
    抛 ValueError，报错信息是一串乱码字节。这里按魔数再兜一层。
    """
    try:
        return resp.json()
    except ValueError:
        pass

    raw: bytes = resp.content
    decoded: bytes | None = None
    if raw[:2] == b"\x1f\x8b":
        import gzip

        decoded = gzip.decompress(raw)
    elif raw[:1] == b"\x78":
        import zlib

        decoded = zlib.decompress(raw)
    else:
        try:  # brotli 没有魔数，只能试
            import brotli

            decoded = brotli.decompress(raw)
        except Exception:  # noqa: BLE001
            decoded = None

    if decoded is None:
        raise ValueError(f"无法解码响应体（{len(raw)} 字节，content-encoding="
                         f"{resp.headers.get('content-encoding') or '无'}）")
    return json.loads(decoded.decode("utf-8", "replace"))


def _http_json(url: str, timeout: float = 25.0) -> Any:
    """统一走 OPSEC 闸门：不自报身份、按策略选出口、失败转 OSError 便于降级。"""
    from ..opsec import EgressBlocked, get_guard

    guard = get_guard()
    try:
        guard.preflight(url)
    except EgressBlocked as exc:
        raise OSError(str(exc)) from exc
    kwargs: dict[str, Any] = {
        "timeout": timeout,
        "follow_redirects": True,
        "headers": guard.headers_for(url),
    }
    proxy = guard.proxy_for(url)
    if proxy:
        kwargs["proxy"] = proxy
    last: Exception | None = None
    for attempt in range(3):
        try:
            with httpx.Client(**kwargs) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    return _json_payload(resp)
                # 429/5xx 是 CT 日志的常态限流，退避后重试；4xx 其余直接失败
                if resp.status_code not in {429, 500, 502, 503, 504}:
                    raise OSError(f"HTTP {resp.status_code}")
                last = OSError(f"HTTP {resp.status_code}")
        except (httpx.HTTPError, ValueError) as exc:
            last = exc
        if attempt < 2:
            time.sleep(1.5 * (2**attempt) + random.uniform(0, 0.5))
    raise OSError(str(last or "请求失败"))


def fetch_usable_logs(limit: int = 6, timeout: float = 8.0) -> list[str]:
    """从官方 log_list.json 取当前 `usable` 的日志，按可达性探测后返回。

    为什么不自带一份写死的清单：CT 日志按半年度滚动，到期后**冻结**
    （tree_size 不再增长）。写死的清单最多撑半年就会全部指向冻死的日志，
    表现是「进程在跑、指标在涨、实际一条新证书都没进来」——最难发现的那种故障。
    """
    try:
        data = _http_json(LOG_LIST_URL, timeout=timeout + 4)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        log.warning("拉取 CT 日志清单失败，用内置清单：%s", exc)
        return list(DEFAULT_LOGS)[:limit]

    # (operator, url) —— 同一运营商会开多条日志（按季度/分片），
    # 全跟一家等于把鸡蛋放一个篮子：它限流或割接，采集中断就全停了。
    candidates: list[tuple[str, str]] = []
    for operator in data.get("operators", []) or []:
        name = str(operator.get("name", ""))
        for entry in operator.get("logs", []) or []:
            state = entry.get("state") or {}
            if not state.get("usable"):
                continue
            url = str(entry.get("url", "")).strip()
            if url.startswith("https://"):
                candidates.append((name, url))

    if not candidates:
        return list(DEFAULT_LOGS)[:limit]

    def rank(item: tuple[str, str]) -> int:
        name = item[0]
        for i, op in enumerate(PREFERRED_OPERATORS):
            if op.lower() == name.lower():
                return i
        return len(PREFERRED_OPERATORS)

    candidates.sort(key=rank)

    # 探测：拿到 tree_size，用来判断这条日志是否「成熟」（条目多 = 承载主流流量）。
    # 并行探测，否则 20 多条 × 8s 超时会让启动卡上几分钟。
    probed: dict[str, list[tuple[str, int]]] = {}
    targets = candidates[: limit * 6]

    def _probe(item: tuple[str, str]) -> tuple[str, str, int] | None:
        name, url = item
        try:
            sth = _http_json(url.rstrip("/") + "/ct/v1/get-sth", timeout=timeout)
            size = int(sth.get("tree_size", 0))
            return (name, url, size) if size > 0 else None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError):
            return None

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=8) as pool:
        for res in pool.map(_probe, targets):
            if res:
                name, url, size = res
                probed.setdefault(name, []).append((url, size))

    if not probed:
        log.warning("官方清单里的日志全部不可达，退回内置清单")
        return list(DEFAULT_LOGS)[:limit]

    # 每个运营商只取条目最多的一条（最可能是当前主力日志），再按偏好顺序铺开
    ordered = sorted(probed.items(), key=lambda kv: rank((kv[0], "")))
    alive: list[str] = []
    for _name, logs in ordered:
        logs.sort(key=lambda x: -x[1])
        alive.append(logs[0][0])
        if len(alive) >= limit:
            break
    # 运营商不够多时，用次多的日志补齐
    if len(alive) < limit:
        for _name, logs in ordered:
            for url, _size in logs[1:]:
                if len(alive) >= limit:
                    break
                alive.append(url)

    log.info("CT 日志清单：来自 %d 家运营商的 %d 条可用日志", len(probed), len(alive))
    return alive


def _parse_entry(entry: dict[str, Any]) -> tuple[list[str], str, str, str] | None:
    """从 CT entry 提取 (域名列表, issuer, not_before, 证书指纹)。

    两种 entry：x509_entry 直接是完整证书；precert_entry 是 TBSCertificate，
    需要从 extra_data 的证书链里取完整证书。后者占绝大多数（Let's Encrypt 等）。
    """
    try:
        leaf = base64.b64decode(entry["leaf_input"])
        entry_type = int.from_bytes(leaf[10:12], "big")
        timestamp = int.from_bytes(leaf[2:10], "big") / 1000.0

        cert = None
        if entry_type == 0:
            cert_len = int.from_bytes(leaf[12:15], "big")
            der = leaf[15 : 15 + cert_len]
            try:
                cert = x509.load_der_x509_certificate(der)
            except Exception:  # noqa: BLE001
                cert = None
        if cert is None:
            chain_raw = base64.b64decode(entry.get("extra_data", "") or "")
            # TLS 向量：<3 字节总长><3 字节证书长><DER>
            if len(chain_raw) > 6:
                cert_len = int.from_bytes(chain_raw[3:6], "big")
                try:
                    cert = x509.load_der_x509_certificate(chain_raw[6 : 6 + cert_len])
                except Exception:  # noqa: BLE001
                    return None
        if cert is None:
            return None

        try:
            san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            names = [n.lower().lstrip("*.") for n in san.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            names = [str(a.value).lower().lstrip("*.") for a in cn]

        not_before = cert.not_valid_before_utc.isoformat() if hasattr(cert, "not_valid_before_utc") else ""
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        issuer = cert.issuer.rfc4514_string()
        if not names and not not_before:
            return None
        return [n for n in dict.fromkeys(names) if n], issuer, not_before or str(timestamp), fingerprint
    except Exception:  # noqa: BLE001
        return None


class CTLogFollower:
    """跟随一个 CT 日志的尾部。

    游标持久化，进程重启后接着上次位置。

    「尾部」不等于「最后 N 条」：日志头部的条目录入后往往要过几秒才可完整取回
    （实测 Cloudflare nimbus 请求最后 256 条只返回 12 条）。所以追平后不是停在
    `size`，而是保留 max_lag 的窗口慢慢往前啃——既拿得到数据，又不会因为跳段
    把中间几千条新证书整段丢掉。落后超过 max_lag 时才真正跳段（宕机数小时之后
    补历史没有意义，我们要的是「正在发生的事」）。
    """

    def __init__(self, url: str, state_path: Path, *, batch: int = 256, max_lag: int = 8000) -> None:
        self.url = url.rstrip("/")
        self.state_path = state_path
        self.batch = batch
        # 单次请求的条目数。日志侧通常还会再截断（实测 DigiCert 固定给 100 条），
        # 所以这里取小一点，让并发页之间粒度更细、浪费更少。
        self.page = max(32, min(256, batch))
        # 读的位置比 tree_size 后退多少条：避开「刚录入但还取不到」的头部区域
        self.trail = 500
        self.max_lag = max_lag
        self.index = 0
        self.tree_size = 0
        self.last_ok = 0.0
        self._sth_at = 0.0
        self.last_error = ""
        self.total_seen = 0
        self.caught_up_calls = 0
        self.frozen = False
        self._last_size = 0
        self._same_size_polls = 0
        self._load()

    def _load(self) -> None:
        if self.state_path.is_file():
            try:
                st = json.loads(self.state_path.read_text(encoding="utf-8"))
                self.index = int(st.get("index", 0))
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

    def _save(self) -> None:
        try:
            self.state_path.write_text(json.dumps({"index": self.index, "url": self.url}), encoding="utf-8")
        except OSError:
            pass

    def poll(self) -> list[CertObservation]:
        """取一页（供外部单步调用）。批量场景请用 catch_up()。"""
        try:
            if not self._refresh_head():
                return []
            start = self._next_start()
            if start is None:
                return []
            base = start
            entries = self._fetch_page(start, min(start + self.page, self._horizon()) - 1)
            if not entries:
                return []
            self.index = base + len(entries)
            self._save()
            return self._to_observations(entries, base)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"[:200]
            return []

    # ------------------------------------------------------------ 内部
    def _horizon(self) -> int:
        # 日志头部刚录入的条目往往还没对外提供（实测最后 256 条只能取到 12 条）。
        # 所以读的位置比 tree_size 后退 trail 条，拿「已经落定」的数据。
        return max(0, self.tree_size - self.trail)

    def _refresh_head(self) -> bool:
        """刷新 tree_size。5 秒内复用，避免每翻一页都多打一次 get-sth。"""
        if self.tree_size and time.time() - self._sth_at < 5:
            return True
        sth = _http_json(f"{self.url}/ct/v1/get-sth", timeout=15)
        size = int(sth.get("tree_size", 0))
        self._sth_at = time.time()
        if size <= 0:
            return False
        self.tree_size = size

        # 冻结检测：年度日志到期后 tree_size 不再增长，索引照跑但永远拿不到新条目。
        # 这是最隐蔽的失效——不报错、指标照涨，只是「什么也没发现」。
        if size == self._last_size:
            self._same_size_polls += 1
            if self._same_size_polls == 8 and not self.frozen:
                self.frozen = True
                log.warning("CT 日志 %s 的 tree_size 连续 8 次未变化，疑似已冻结，建议换日志", self.url)
        else:
            self._same_size_polls = 0
            self._last_size = size
            self.frozen = False
        return True

    def _next_start(self) -> int | None:
        horizon = self._horizon()
        if self.index == 0 or self.index > self.tree_size:
            # 首次接入或游标异常：从窗口尾部起，不追历史
            self.index = max(0, horizon - self.page)
        if horizon - self.index > self.max_lag:
            log.info(
                "CT 日志 %s 落后 %d 条，只保留最近 %d 条", self.url, horizon - self.index, self.max_lag
            )
            self.index = max(0, horizon - self.max_lag)
        if self.index >= horizon:
            self.last_ok = time.time()
            self.caught_up_calls += 1
            return None
        return self.index

    def _fetch_page(self, start: int, end: int) -> list[dict]:
        if end < start:
            return []
        data = _http_json(f"{self.url}/ct/v1/get-entries?start={start}&end={end}", timeout=40)
        entries = data.get("entries", []) or []
        self.last_ok = time.time()
        self.last_error = ""
        return entries

    def _to_observations(self, entries: list[dict], base: int) -> list[CertObservation]:
        out: list[CertObservation] = []
        for offset, entry in enumerate(entries):
            parsed = _parse_entry(entry)
            if not parsed:
                continue
            names, issuer, not_before, fingerprint = parsed
            idx = base + offset
            for name in names:
                out.append(
                    CertObservation(
                        domain=name,
                        all_domains=names,
                        issuer=issuer,
                        not_before=not_before,
                        fingerprint=fingerprint,
                        log_url=self.url,
                        entry_index=idx,
                    )
                )
        self.total_seen += len(out)
        return out

    def status(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "index": self.index,
            "tree_size": self.tree_size,
            "lag": max(0, self.tree_size - self.index) if self.tree_size else None,
            "total_seen": self.total_seen,
            "frozen": self.frozen,
            "age_seconds": round(time.time() - self.last_ok, 1) if self.last_ok else None,
            "error": self.last_error,
        }

    def catch_up(self, emit: Callable[[list[CertObservation]], None], *,
                 max_batches: int = 60, budget: float = 20.0, parallel: int = 8) -> int:
        """在时间预算内连续取多页，把积压啃完。

        两个必须并行的地方：

        1. **多页并发**。单页请求的返回条数由日志侧决定（实测 DigiCert 一次给 100 条、
           耗时 10 秒），串行时一条日志的吞吐只有 600 条/分钟，而这类日志每分钟新增
           约 2000 条——永远追不上，中间的证书就被永久跳过。
        2. **多日志并发**。由 engine 每条日志起一个线程。

        游标只按「实际返回条数」推进；某一页返回不满就丢弃后面预取的页，
        下一轮从断点重来。宁可多打几次请求，也不能在游标上跳着走。
        """
        from concurrent.futures import ThreadPoolExecutor

        deadline = time.monotonic() + budget
        total = 0
        batches = 0
        with ThreadPoolExecutor(max_workers=max(1, parallel)) as pool:
            while batches < max_batches and time.monotonic() < deadline:
                try:
                    if not self._refresh_head():
                        break
                    start = self._next_start()
                    if start is None:
                        break
                except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
                    self.last_error = f"{type(exc).__name__}: {exc}"[:200]
                    break

                horizon = self._horizon()
                starts = [s for s in (start + i * self.page for i in range(parallel)) if s < horizon]
                futures = [
                    pool.submit(self._fetch_page, s, min(s + self.page, horizon) - 1) for s in starts
                ]

                base = start
                progressed = False
                for fut in futures:
                    try:
                        entries = fut.result()
                    except Exception:  # noqa: BLE001
                        entries = []
                    if not entries:
                        # 单页被限流/超时只跳过这一页，别把整轮追平也一起放弃
                        continue
                    obs = self._to_observations(entries, base)
                    self.index = base + len(entries)
                    self._save()
                    base = self.index
                    batches += 1
                    progressed = True
                    if obs:
                        emit(obs)
                        total += len(obs)
                    if len(entries) < self.page:
                        # 不满页 = 这一页之后未必连续，剩下的预取作废
                        break
                if not progressed:
                    break
        return total


class CertStreamClient:
    """certstream WebSocket 客户端。仅在自建 server 时启用。"""

    def __init__(self, url: str, on_batch: Callable[[list[CertObservation]], None]) -> None:
        self.url = url
        self.on_batch = on_batch
        self.connected = False
        self.last_error = ""
        self.total = 0
        self.failures = 0
        self._last_data_at = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="certstream", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        backoff = 2.0
        while not self._stop.is_set():
            try:
                from websockets.sync.client import connect

                with connect(self.url, open_timeout=15, close_timeout=5, max_size=2**23) as ws:
                    self.connected = True
                    backoff = 2.0
                    log.info("certstream 已连接：%s", self.url)
                    buffer: list[CertObservation] = []
                    last_flush = time.time()
                    while not self._stop.is_set():
                        # 公共实例经常「连上了但不推流」，超时给足 60s 再判死
                        raw = ws.recv(timeout=60)
                        msg = json.loads(raw)
                        if msg.get("message_type") != "certificate_update":
                            continue
                        leaf = msg.get("data", {}).get("leaf_cert", {})
                        names = [n.lower().lstrip("*.") for n in leaf.get("all_domains") or [] if n]
                        if not names:
                            continue
                        issuer = (leaf.get("issuer") or {}).get("O") or ""
                        fp = leaf.get("fingerprint") or ""
                        for n in dict.fromkeys(names):
                            buffer.append(
                                CertObservation(
                                    domain=n,
                                    all_domains=names,
                                    issuer=str(issuer),
                                    not_before=str(leaf.get("not_before") or ""),
                                    fingerprint=fp,
                                    log_url=self.url,
                                    entry_index=0,
                                    source="ct_stream",
                                )
                            )
                        self.total += len(names)
                        self._last_data_at = time.monotonic()
                        if len(buffer) >= 400 or (time.time() - last_flush) > 3:
                            self.on_batch(buffer)
                            buffer = []
                            last_flush = time.time()
            except Exception as exc:  # noqa: BLE001
                self.connected = False
                self.failures += 1
                self.last_error = f"{type(exc).__name__}: {exc}"[:160]
                # 前两次和之后每 5 次记一条；公共实例常年在「连上但不推流」的状态，
                # 每次都刷 warning 会把真正有用的日志埋掉。主路是 CT 轮询，这条只是补强。
                if self.failures <= 2 or self.failures % 5 == 0:
                    log.warning(
                        "certstream 第 %d 次断开（%s），%.0fs 后重连；主路 CT 轮询不受影响",
                        self.failures, self.last_error, backoff,
                    )
                    if self.failures == 3 and self.total == 0:
                        log.warning("certstream 公共实例未推送任何数据，已降级为「仅 CT 轮询」")
                self._stop.wait(backoff)
                backoff = min(backoff * 1.8, 120.0)
                # 熔断：公共实例常年「连得上但不推流」，每 60 秒超时一次。
                # 判据用「最近半小时有没有收到过数据」，而不是累计条数——
                # 一条流可能很久以前推过一条，`total>0` 会让它永远重连下去。
                idle = time.monotonic() - self._last_data_at if self._last_data_at else None
                if self.failures >= 6 and (idle is None or idle > 1800):
                    log.warning(
                        "certstream 连续 %d 次未推送数据（静默 %.0f 分钟），暂停 30 分钟后再试",
                        self.failures, (idle or 0) / 60,
                    )
                    self._stop.wait(1800)
                    self.failures = 0
                    backoff = 2.0

    def status(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "connected": self.connected,
            "total": self.total,
            "failures": self.failures,
            "idle_s": round(time.monotonic() - self._last_data_at, 1) if self._last_data_at else None,
            "error": self.last_error,
        }


class CtrlShSearch:
    """crt.sh 关键词检索。慢，但能按词根翻历史，补 CT 尾部跟不到的旧资产。"""

    BASE = "https://crt.sh/"

    def __init__(self, timeout: float = 90.0) -> None:
        self.timeout = timeout
        self.last_error = ""

    def search(self, term: str, limit: int = 500) -> list[CertObservation]:
        url = f"{self.BASE}?q={urllib.parse.quote(term)}&output=json"
        try:
            data = _http_json(url, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001
            self.last_error = f"{type(exc).__name__}: {exc}"[:160]
            return []
        if not isinstance(data, list):
            return []

        out: list[CertObservation] = []
        seen: set[str] = set()
        for row in data[:limit]:
            names = [n.strip().lower().lstrip("*.") for n in str(row.get("name_value", "")).splitlines() if n.strip()]
            common = str(row.get("common_name") or "").lower()
            if common and common not in names:
                names.append(common)
            fp = str(row.get("serial_number") or "")[:40]
            issuer = str(row.get("issuer_name") or "")[:120]
            nb = str(row.get("not_before") or "")
            for n in names:
                if n in seen or not n:
                    continue
                seen.add(n)
                out.append(
                    CertObservation(
                        domain=n,
                        all_domains=names,
                        issuer=issuer,
                        not_before=nb,
                        fingerprint=fp,
                        log_url="crt.sh",
                        entry_index=0,
                        source="crt_sh",
                    )
                )
        return out
