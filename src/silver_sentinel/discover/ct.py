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
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID

from ..config import settings

log = logging.getLogger(__name__)

# 默认日志集。按「国内可达性」排序——生产环境里 Google 系常常连不上，
# 但 Cloudflare / DigiCert / Sectigo 一般没问题。
DEFAULT_LOGS = [
    "https://ct.cloudflare.com/logs/nimbus2025",
    "https://nessie2025.ct.digicert.com/log",
    "https://yeti2025.ct.digicert.com/log",
    "https://oak.ct.letsencrypt.org/2025h2",
    "https://ct.googleapis.com/logs/us1/argon2025h2",
]

UA = "Mozilla/5.0 (compatible; silver-sentinel/1.0; +https://github.com/stellarissss/silver-sentinel)"


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
        }


def _http_json(url: str, timeout: float = 25.0) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"null")


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

    游标持久化，进程重启后接着上次位置。落后超过 max_lag 直接跳段，
    因为追历史没有意义——我们要的是「正在发生的事」。
    """

    def __init__(self, url: str, state_path: Path, *, batch: int = 256, max_lag: int = 20000) -> None:
        self.url = url.rstrip("/")
        self.state_path = state_path
        self.batch = batch
        self.max_lag = max_lag
        self.index = 0
        self.tree_size = 0
        self.last_ok = 0.0
        self.last_error = ""
        self.total_seen = 0
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
        try:
            sth = _http_json(f"{self.url}/ct/v1/get-sth", timeout=15)
            size = int(sth.get("tree_size", 0))
            if size <= 0:
                return []
            self.tree_size = size

            if self.index == 0:
                # 首次启动：从尾部回补一小段，建立基线
                start = max(0, size - self.batch)
            elif self.index > size:
                # 日志被重置或游标异常，重新对齐
                start = max(0, size - self.batch)
            elif self.index == size:
                # 已追平，等新条目。直接返回，别重复取尾部
                self.last_ok = time.time()
                return []
            else:
                start = self.index
                if size - start > self.max_lag:
                    log.info("CT 日志 %s 落后 %d 条，跳段到尾部", self.url, size - start)
                    start = size - self.batch

            end = min(start + self.batch, size) - 1
            if end < start:
                return []

            data = _http_json(f"{self.url}/ct/v1/get-entries?start={start}&end={end}", timeout=40)
            entries = data.get("entries", [])
            self.index = end + 1
            self._save()
            self.last_ok = time.time()
            self.last_error = ""

            out: list[CertObservation] = []
            for offset, entry in enumerate(entries):
                parsed = _parse_entry(entry)
                if not parsed:
                    continue
                names, issuer, not_before, fingerprint = parsed
                idx = start + offset
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
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"[:200]
            return []

    def status(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "index": self.index,
            "tree_size": self.tree_size,
            "lag": max(0, self.tree_size - self.index) if self.tree_size else None,
            "total_seen": self.total_seen,
            "age_seconds": round(time.time() - self.last_ok, 1) if self.last_ok else None,
            "error": self.last_error,
        }


class CertStreamClient:
    """certstream WebSocket 客户端。仅在自建 server 时启用。"""

    def __init__(self, url: str, on_batch: Callable[[list[CertObservation]], None]) -> None:
        self.url = url
        self.on_batch = on_batch
        self.connected = False
        self.last_error = ""
        self.total = 0
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
                        raw = ws.recv(timeout=30)
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
                        if len(buffer) >= 400 or (time.time() - last_flush) > 3:
                            self.on_batch(buffer)
                            buffer = []
                            last_flush = time.time()
            except Exception as exc:  # noqa: BLE001
                self.connected = False
                self.last_error = f"{type(exc).__name__}: {exc}"[:160]
                log.warning("certstream 断开（%s），%.0fs 后重连", self.last_error, backoff)
                self._stop.wait(backoff)
                backoff = min(backoff * 1.8, 120.0)

    def status(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "connected": self.connected,
            "total": self.total,
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
