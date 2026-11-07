"""出站暴露面控制（OPSEC）。

为什么单独一层
--------------
这套系统长期跑在一台固定服务器上，对面是会反制的黑产。任何一个出站请求都可能
把「谁在查我」直接送到对方手里：

- 目标站点日志里有我们的公网 IP，反查就是一台云主机、一个备案主体；
- User-Agent 里写着项目名和 GitHub 地址，等于自报家门；
- 沙箱浏览器不设代理，页面里的 WebRTC 还能把内网地址带出去；
- 举报材料里如果混进了采集机的路径、内网地址、运维标识，等于把基础设施
  一起交给对方。

因此本模块的原则是 **fail-closed**：判定为「可疑目标」而没配代理时，宁可不抓，
也不直连。抓不到只是少一条证据，暴露了就是整条链路被反制。

四道闸
------
1. **分类**：internal（自己的服务）/ intel（公开情报源）/ suspect（可疑目标）/
   blocked（政务、CA、监管、内网、云元数据——不碰）。
2. **出口**：suspect 必须走代理池；代理按失败率冷却、轮换；DNS 交给代理解析
   （socks5h），避免本地解析泄露。
3. **指纹**：UA 池按目标稳定分配（同一目标始终同一 UA，跨目标不同），
   补齐常规请求头，请求前加随机抖动，不出现机器级等间隔。
4. **回写**：所有对外产物（证据备注、举报材料、导出 JSON）过一遍脱敏，
   发现自身 IP / 主机名 / 数据目录 / 密钥立即报错，不允许「带着家底出门」。
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import random
import re
import socket
import threading
import time
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .config import settings

# ---------------------------------------------------------------- 异常


class EgressBlocked(RuntimeError):
    """按策略拒绝出站。调用方应把它当成「正常结果」，不是故障。"""

    def __init__(self, url: str, reason: str) -> None:
        super().__init__(f"出站被拒（{reason}）：{url}")
        self.url = url
        self.reason = reason


class InfraLeakError(RuntimeError):
    """待导出内容里发现了自身基础设施信息。"""

    def __init__(self, findings: list[dict[str, str]]) -> None:
        super().__init__(f"检出 {len(findings)} 处自身基础设施信息，已阻止导出")
        self.findings = findings


# ---------------------------------------------------------------- 常量

# 只宣告「本机真能解」的压缩格式。线上踩过：服务器 venv 没装 brotli，
# 但仍然对外宣告 br，gstatic 的 CT log_list.json 就用 br 回，
# httpx 解不开 → json 解析拿到 0xf1 之类的字节 → 退回内置清单。
# 内置清单会随 CT 日志冻结而过期，那正是最难发现的一类故障。
try:  # pragma: no cover - 取决于环境是否装了 brotli
    import brotli as _brotli  # noqa: F401

    ACCEPT_ENCODING = "gzip, deflate, br"
except ImportError:  # pragma: no cover
    ACCEPT_ENCODING = "gzip, deflate"

# 常见浏览器 UA。刻意不含任何项目标识——这是最容易犯的低级错误。
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; 2211133C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 QIHU 360SE",
]

# 公开情报源：直连也只是暴露给服务方，不暴露给对手。仍优先走代理。
INTEL_SUFFIXES = (
    # 证书透明度日志与清单：只读、公开、不针对具体受害者。CA 的 CT 端点必须在
    # 禁访清单之前判定，否则「不碰 CA」会把发现能力本身掐死。
    "crt.sh",
    "gstatic.com",
    "ct.googleapis.com",
    "letsencrypt.org",
    "digicert.com",
    "sectigo.com",
    "globalsign.com",
    "gdca.com.cn",
    "certum.pl",
    "harica.gr",
    "ct.cloudflare.com",
    # 公开情报与注册数据
    "rdap.org",
    "abuse.ch",
    "openphish.com",
    "phishtank.com",
    "virustotal.com",
    "ipinfo.io",
    "maxmind.com",
    "dns.google",
    "cloudflare-dns.com",
    "aliyun.com",
    "tencentcloudapi.com",
    "github.com",
    "githubusercontent.com",
    "pypi.org",
    "python.org",
)

# 不主动触碰：政务/监管/CA/基础平台。查询它们既无收益，又容易触发风控与投诉。
DEFAULT_DENY_SUFFIXES = (
    "gov.cn",
    "edu.cn",
    "mil.cn",
    "12377.cn",
    "12321.cn",
    "12315.cn",
    "miit.gov.cn",
    "cac.gov.cn",
    "mps.gov.cn",
    "court.gov.cn",
    "spp.gov.cn",
)

_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),   # AWS / 阿里云 / 腾讯云 metadata
    ipaddress.ip_address("100.100.100.200"),   # 阿里云 metadata
    ipaddress.ip_address("fd00:ec2::254"),
}

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT，云厂商内网常用
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


# ---------------------------------------------------------------- 代理池


@dataclass
class _Proxy:
    url: str
    failures: int = 0
    cooldown_until: float = 0.0
    used: int = 0

    @property
    def alive(self) -> bool:
        return time.monotonic() >= self.cooldown_until


class ProxyPool:
    """轮换 + 失败冷却。不做主动健康检查（探测代理本身也是暴露面）。"""

    def __init__(self, urls: Iterable[str]) -> None:
        self._items = [_Proxy(u.strip()) for u in urls if u and u.strip()]
        self._lock = threading.Lock()
        self._cursor = 0

    def __bool__(self) -> bool:
        return bool(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def pick(self) -> _Proxy | None:
        with self._lock:
            if not self._items:
                return None
            n = len(self._items)
            for offset in range(n):
                idx = (self._cursor + offset) % n
                proxy = self._items[idx]
                if proxy.alive:
                    self._cursor = (idx + 1) % n
                    proxy.used += 1
                    return proxy
            # 全都在冷却：退化为最短冷却的那个，宁可慢也别直连
            proxy = min(self._items, key=lambda p: p.cooldown_until)
            self._cursor = 0
            return proxy

    def report(self, proxy: _Proxy | None, ok: bool) -> None:
        if proxy is None:
            return
        with self._lock:
            if ok:
                proxy.failures = max(0, proxy.failures - 1)
                return
            proxy.failures += 1
            # 指数退避，最长 10 分钟
            proxy.cooldown_until = time.monotonic() + min(600, 20 * (2 ** min(5, proxy.failures)))

    def status(self) -> list[dict[str, Any]]:
        return [
            {
                "index": i,
                "scheme": urllib.parse.urlsplit(p.url).scheme,
                "host": urllib.parse.urlsplit(p.url).hostname,
                "used": p.used,
                "failures": p.failures,
                "cooling": not p.alive,
            }
            for i, p in enumerate(self._items)
        ]


# ---------------------------------------------------------------- 主体


@dataclass
class Guard:
    enabled: bool = True
    allow_direct: bool = False
    proxies: ProxyPool = field(default_factory=lambda: ProxyPool([]))
    deny_suffixes: tuple[str, ...] = DEFAULT_DENY_SUFFIXES
    own_hostnames: set[str] = field(default_factory=set)
    own_ips: set[str] = field(default_factory=set)
    extra_identifiers: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        # 没走运行时时用的出口模式：允许直连就是 auto，否则按「仅代理」fail-closed
        self._egress_mode = "auto" if self.allow_direct else "proxy"
        self._runtime_proxies: tuple[str, ...] | None = None

    @property
    def mode(self) -> str:
        return getattr(self, "_egress_mode", "proxy")

    # ------------------------------------------------------ 分类
    def _internal_hosts(self) -> set[str]:
        hosts = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
        for raw in (
            settings.icp_api_base,
            settings.llm_base_url,
            settings.mobsf_base_url,
            settings.neo4j_uri,
        ):
            host = urllib.parse.urlsplit(raw or "").hostname
            if host:
                hosts.add(host.lower())
        return hosts

    def classify(self, url: str) -> str:
        try:
            parts = urllib.parse.urlsplit(url)
        except ValueError:
            return "blocked"
        if parts.scheme not in {"http", "https", "ws", "wss"}:
            return "blocked"
        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            return "blocked"

        if host in self._internal_hosts():
            return "internal"

        # IP 字面量：内网 / 元数据一律拒绝
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None:
            if ip in _METADATA_IPS or any(ip in net for net in _PRIVATE_NETS):
                return "blocked"
            if str(ip) in self.own_ips:
                return "blocked"
            return "suspect"

        if host in self.own_hostnames:
            return "blocked"
        # 先认「只读基础设施」，再认禁访清单：CA 的 CT 端点与政务站不能混为一谈
        if self._suffix_hit(host, INTEL_SUFFIXES):
            return "intel"
        if self._suffix_hit(host, self.deny_suffixes):
            return "blocked"
        # 阿里云 / 腾讯云的对象存储接口属于基础设施，不是打击目标
        if self._suffix_hit(host, ("aliyuncs.com", "myqcloud.com", "tencentcloudapi.com")):
            return "intel"
        return "suspect"

    @staticmethod
    def _suffix_hit(host: str, suffixes: Iterable[str]) -> bool:
        return any(host == s or host.endswith("." + s) for s in suffixes)

    # ------------------------------------------------------ 出站
    def preflight(self, url: str) -> str:
        """返回分类；不允许出站时抛 EgressBlocked。"""
        self.sync_runtime()
        if not self.enabled:
            # 即便关掉 OPSEC，内网与元数据也必须拦——这是 SSRF 底线
            kind = self.classify(url)
            if kind == "blocked":
                raise EgressBlocked(url, "内网/元数据/策略禁用")
            return kind

        kind = self.classify(url)
        if kind == "blocked":
            raise EgressBlocked(url, "命中禁访清单或内网地址")
        if kind == "suspect":
            mode = self._egress_mode
            if mode == "off":
                raise EgressBlocked(url, "出口已关闭（设置里把出口模式改回 auto 或 direct）")
            if mode == "proxy" and not self.proxies:
                raise EgressBlocked(url, "出口模式为「仅代理」，但未配置可用代理")
            if not self.proxies and not self.allow_direct:
                raise EgressBlocked(url, "未配置出站代理，拒绝直连可疑目标")
        return kind

    def sync_runtime(self) -> None:
        """把前端改过的代理配置同步到进程内。

        每次出站前对一下配置指纹，变了就重建池子。这样保存设置后
        下一次取证立即生效，不需要重启进程。
        """
        try:
            from .runtime_settings import egress_config

            cfg = egress_config()
        except Exception:  # 数据库未就绪时保持原样
            return
        if not cfg.get("configured"):
            # 界面上没人选过出口模式：尊重构造时的配置（fail-closed 不能被默认值改掉）
            return
        urls = tuple(cfg["proxies"])
        if urls != getattr(self, "_runtime_proxies", None):
            self.proxies = ProxyPool(urls)
            self._runtime_proxies = urls
            self._proxy_cursor_reset()
        self._egress_mode = cfg["effective"]
        self.allow_direct = cfg["effective"] != "proxy"

    def _proxy_cursor_reset(self) -> None:
        # ProxyPool 已重建，游标自然归零；这里留钩子便于将来换实现
        return None

    def proxy_for(self, url: str) -> str | None:
        self.sync_runtime()
        kind = self.classify(url)
        if kind == "internal":
            return None
        if getattr(self, "_egress_mode", "auto") == "direct":
            return None
        if not self.proxies:
            return None
        proxy = self.proxies.pick()
        return proxy.url if proxy else None

    def headers_for(self, url: str, *, mobile: bool = False) -> dict[str, str]:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
        idx = int(hashlib.sha256(host.encode()).hexdigest()[:8], 16) % len(UA_POOL)
        ua = UA_POOL[idx]
        if mobile:
            ua = next((u for u in UA_POOL if "Mobile" in u or "iPhone" in u), ua)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
            "Accept-Encoding": ACCEPT_ENCODING,
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Upgrade-Insecure-Requests": "1",
            # 不发送 Referer、不发 X-Forwarded-For，避免任何可关联字段
        }

    def jitter(self, *, suspect: bool = True) -> None:
        if not self.enabled:
            return
        if suspect:
            time.sleep(random.uniform(0.08, 0.6))
        else:
            time.sleep(random.uniform(0.01, 0.12))

    def note_failure(self, url: str, ok: bool) -> None:
        if not self.proxies:
            return
        proxy_url = self.proxy_for(url)
        for item in self.proxies._items:  # noqa: SLF001 - 同模块内的轻量访问
            if item.url == proxy_url:
                self.proxies.report(item, ok)
                return

    # ------------------------------------------------------ 脱敏
    def refresh_identity(self) -> dict[str, Any]:
        """收集「不能出现在对外产物里」的自身标识。只做本地探测，不向外发请求。"""
        self.own_hostnames = {socket.gethostname().lower()}
        ips: set[str] = set()
        # 取本机出口网卡地址：UDP connect 不发包
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.3)
            sock.connect(("223.5.5.5", 53))
            ips.add(sock.getsockname()[0])
            sock.close()
        except OSError:
            pass
        ips.update(ip.strip() for ip in settings.opsec_own_ips.split(",") if ip.strip())
        self.own_ips = ips
        self.extra_identifiers = {
            x.strip() for x in settings.opsec_identifiers.split(",") if x.strip()
        }
        return {"hostnames": sorted(self.own_hostnames), "ips": sorted(self.own_ips)}

    def redact(self, text: str) -> str:
        if not text:
            return text
        out = text
        for ip in sorted(self.own_ips, key=len, reverse=True):
            out = out.replace(ip, "[ip-redacted]")
        for host in sorted(self.own_hostnames, key=len, reverse=True):
            if host and len(host) > 3:
                out = re.sub(re.escape(host), "[host-redacted]", out, flags=re.IGNORECASE)
        for ident in sorted(self.extra_identifiers, key=len, reverse=True):
            out = out.replace(ident, "[id-redacted]")
        # 本机绝对路径与数据目录
        for raw in {str(settings.data_dir), os.path.expanduser("~"), "/opt/silver", "/workspace"}:
            if raw and len(raw) > 3:
                out = out.replace(raw, "[path-redacted]")
        # 私网地址不可能是「对手的证据」，但会暴露内网拓扑
        def _mask_ip(match: re.Match[str]) -> str:
            ip = match.group(0)
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                return ip
            if any(parsed in net for net in _PRIVATE_NETS) or parsed in _METADATA_IPS:
                return "[internal-ip]"
            return ip

        return _IPV4.sub(_mask_ip, out)

    def find_leaks(self, obj: Any, path: str = "$") -> list[dict[str, str]]:
        """递归检查对象里是否残留自身标识。导出前必须为空。"""
        findings: list[dict[str, str]] = []
        if isinstance(obj, str):
            for token in list(self.own_ips) + list(self.own_hostnames) + list(self.extra_identifiers):
                if token and len(token) > 3 and token in obj:
                    findings.append({"path": path, "token": token})
            for raw in (str(settings.data_dir), os.path.expanduser("~"), "/opt/silver", "/workspace"):
                if raw and len(raw) > 3 and raw in obj:
                    findings.append({"path": path, "token": raw})
        elif isinstance(obj, dict):
            for key, value in obj.items():
                findings.extend(self.find_leaks(value, f"{path}.{key}"))
        elif isinstance(obj, (list, tuple, set)):
            for i, value in enumerate(obj):
                findings.extend(self.find_leaks(value, f"{path}[{i}]"))
        return findings

    def assert_clean(self, obj: Any) -> None:
        findings = self.find_leaks(obj)
        if findings:
            raise InfraLeakError(findings)

    # ------------------------------------------------------ 蜜罐
    def honeypot_check(self, text: str, *, canary: str = "", request_url: str = "") -> dict[str, Any]:
        """识别「对方在钓我们」的常见信号。

        不追求高召回（那会误伤大量正常站点），只把明确的自曝信号标出来：
        页面回显了我们的出口 IP、回显了只在本次请求里出现的探针串、
        或者把我们引向 metadata / 内网地址。
        """
        reasons: list[str] = []
        body = text or ""
        for ip in self.own_ips:
            if ip and ip in body:
                reasons.append("页面回显了采集端 IP")
        if canary and canary in body:
            reasons.append("页面回显了本次请求的一次性探针串（反射型蜜罐特征）")
        for token in ("169.254.169.254", "100.100.100.200", "metadata.tencentyun", "metadata.aliyun"):
            if token in body:
                reasons.append("页面诱导访问云元数据地址")
                break
        # 页面里出现「执法/取证/扫描」类自述，同时要求提供身份信息
        lowered = body.lower()
        if ("honeypot" in lowered or "scanner detected" in lowered) and "ip" in lowered:
            reasons.append("页面自述已识别扫描器")
        score = min(100, 40 * len(reasons))
        return {"suspected": bool(reasons), "score": score, "reasons": reasons}


# ---------------------------------------------------------------- 单例

_guard: Guard | None = None
_guard_lock = threading.Lock()


def get_guard() -> Guard:
    global _guard
    if _guard is None:
        with _guard_lock:
            if _guard is None:
                guard = Guard(
                    enabled=settings.opsec_enabled,
                    allow_direct=settings.opsec_allow_direct,
                    proxies=ProxyPool(settings.opsec_proxies.split(",")),
                    deny_suffixes=DEFAULT_DENY_SUFFIXES
                    + tuple(s.strip() for s in settings.opsec_deny_suffixes.split(",") if s.strip()),
                )
                guard.refresh_identity()
                _guard = guard
    return _guard


def redact(text: str) -> str:
    return get_guard().redact(text)


def redact_obj(obj: Any) -> Any:
    """递归脱敏，返回新对象。导出前统一走这里。"""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v) for v in obj)
    return obj


def assert_clean(obj: Any) -> None:
    get_guard().assert_clean(obj)


def status() -> dict[str, Any]:
    guard = get_guard()
    return {
        "enabled": guard.enabled,
        "fail_closed": not guard.allow_direct,
        "proxy_count": len(guard.proxies),
        "proxies": guard.proxies.status(),
        "own_ips_masked": len(guard.own_ips),
        "own_hostnames_masked": len(guard.own_hostnames),
        "deny_suffixes": len(guard.deny_suffixes),
    }
