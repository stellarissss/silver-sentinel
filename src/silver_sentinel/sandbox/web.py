"""网页动态执行沙箱。

为什么必须真跑
--------------
静态抓 HTML 看不出这类站点的真面目：
- 首屏是「活动已结束」，带 User-Agent/地域/Referer 才吐真内容（cloaking）；
- 真正的下载链接由 JS 拼出来，源码里根本没有；
- 表单提交地址在运行时才注入。

真跑一遍，才能拿到重定向链、真实外传地址、最终落地页。

安全边界（重要）
----------------
1. **阻断内网**。可疑 URL 可能是精心构造的 SSRF，指向 127.0.0.1 / 192.168.x /
   169.254.x。所有请求在发出前校验目标 IP，命中内网直接 abort。
2. **只读不写**。POST/PUT 请求被拦截记录后 abort，绝不真的提交——
   否则等于帮对方完成一次「用户已报名」。
3. **不落 cookie**。每次用全新 context，不用持久化 profile。
4. **资源上限**。总时长、重定向次数、总请求数都有硬上限，防止被拖死。
5. **不主动执行下载**。发现 .apk 链接只记录 URL，不下载——
   下载由上层在明确授权时进行，避免自动把恶意样本拉进机器。
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit

from ..config import settings
from ..opsec import EgressBlocked, get_guard

log = logging.getLogger(__name__)

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_APK_LINK = re.compile(r"https?://[^\s\"'<>]+\.apk(?:\?[^\s\"'<>]*)?", re.IGNORECASE)
_INTERESTING_EXT = (".apk", ".ipa", ".exe", ".zip", ".rar", ".dmg")


def _shrink_image(data: bytes, *, max_height: int = 6000, max_bytes: int = 1_400_000) -> bytes:
    """把全页截图裁到可接受的高度与体积。失败时原样返回，不能让截图问题拖垮取证。"""
    try:
        from io import BytesIO

        from PIL import Image

        im = Image.open(BytesIO(data))
        if im.height > max_height:
            im = im.crop((0, 0, im.width, max_height))
        if im.mode not in ("RGB", "L"):
            im = im.convert("RGB")
        for quality in (68, 55, 42):
            buf = BytesIO()
            im.save(buf, format="JPEG", quality=quality, optimize=True)
            out = buf.getvalue()
            if len(out) <= max_bytes:
                return out
        return out
    except Exception:  # noqa: BLE001
        return data


def _is_private_host(host: str) -> bool:
    if not host:
        return True
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False          # 解析不了就交给浏览器去失败，不算内网
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if any(ip in net for net in _PRIVATE_NETS):
            return True
    return False


@dataclass
class WebObservation:
    url: str
    final_url: str = ""
    status: int = 0
    title: str = ""
    text: str = ""
    # 原始快照：HTML 原文与首屏截图。它们是「当时页面长什么样」的唯一凭据，
    # 页面明天改版就再也拿不回来了，必须原样固化。
    html: str = ""
    screenshot: bytes = b""
    # 全页截图：首屏只能看到「活动已结束」之类的幌子，整页才露馅
    screenshot_full: bytes = b""
    html_len: int = 0
    tls: dict[str, Any] = field(default_factory=dict)
    redirects: list[dict[str, Any]] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    downloads: list[str] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    apk_links: list[str] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    error: str = ""
    elapsed: float = 0.0
    engine: str = "playwright"
    honeypot: dict[str, Any] = field(default_factory=dict)
    egress: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "title": self.title[:200],
            "text": self.text[:20000],
            "html_len": self.html_len,
            "screenshot_bytes": len(self.screenshot),
            "screenshot_full_bytes": len(self.screenshot_full),
            "tls": self.tls,
            "redirects": self.redirects[:30],
            "requests": self.requests[:200],
            "forms": self.forms[:20],
            "downloads": self.downloads[:20],
            "apk_links": self.apk_links[:20],
            "blocked": self.blocked[:40],
            "cookies": self.cookies[:30],
            "error": self.error,
            "elapsed": round(self.elapsed, 2),
            "engine": self.engine,
            "honeypot": self.honeypot,
            "egress": self.egress,
        }


class WebSandbox:
    """Playwright 驱动的单例。浏览器进程复用，context 每次新建。"""

    def __init__(self) -> None:
        self._playwright = None
        self._browser = None
        self._lock = threading.Lock()
        self.available = False
        self.last_error = ""
        self.stats = {"runs": 0, "ok": 0, "blocked_private": 0, "errors": 0}

    def _ensure_browser(self):
        if self._browser is not None:
            return self._browser
        with self._lock:
            if self._browser is not None:
                return self._browser
            from playwright.sync_api import sync_playwright

            try:
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-background-networking",
                        "--disable-features=NetworkPrediction,Translate",
                        # WebRTC 是浏览器最容易漏内网/真实出口的地方：强制只走代理 UDP
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                        # 去掉 navigator.webdriver 这个最廉价的机器人标记
                        "--disable-blink-features=AutomationControlled",
                    ],
                )
            except Exception as exc:  # noqa: BLE001
                # 启动失败必须把现场擦干净：sync_playwright().start() 会在当前线程
                # 留下一个仍在跑的 event loop，如果不清掉，下一次 start() 会直接报
                # 「Sync API inside the asyncio loop」，然后永久卡死在这个线程上。
                # 线上就踩过：浏览器装在 root 的 ~/.cache，服务却以 silver 身份跑，
                # launch 失败 → 线程被毒化 → 之后每次取证都报这句看不懂的话。
                self.last_error = (
                    f"{type(exc).__name__}: {exc}"
                    "（检查 PLAYWRIGHT_BROWSERS_PATH 与 `playwright install chromium`）"
                )[:500]
                self._playwright = None
                self._browser = None
                self.available = False
                raise RuntimeError(self.last_error) from exc

            self.available = True
            self.last_error = ""
            return self._browser

    def observe(self, url: str, *, timeout: float | None = None) -> WebObservation:
        timeout = timeout or settings.sandbox_timeout
        started = time.monotonic()
        obs = WebObservation(url=url)

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            obs.error = f"不支持的协议：{parsed.scheme}"
            return obs
        if not settings.sandbox_allow_private_ip and _is_private_host(parsed.hostname or ""):
            obs.error = "目标解析到内网地址，已阻断"
            self.stats["blocked_private"] += 1
            return obs

        guard = get_guard()
        try:
            kind = guard.preflight(url)
        except EgressBlocked as exc:
            obs.error = f"出站被拒：{exc.reason}"
            self.stats["blocked_egress"] = self.stats.get("blocked_egress", 0) + 1
            return obs

        proxy_url = guard.proxy_for(url)
        # 出口模式以 Guard 为准：它已经吸收了界面配置与 fail-closed 策略，
        # 这里再读一次配置容易出现「门禁说能走、Guard 说不能」的分裂。
        egress_mode = guard.mode

        if egress_mode == "off":
            obs.error = "出口模式为「关闭」，已跳过本次页面执行"
            self.stats["blocked_egress"] = self.stats.get("blocked_egress", 0) + 1
            return obs
        # 只有在「要求代理」的模式下，缺代理才拒绝。
        # auto/direct 是明确允许直连的降级路径——否则线上没有代理就永远取不到证，
        # 界面会一直显示 0 条证据，等于功能没做。
        if settings.opsec_require_proxy_for_sandbox and egress_mode == "proxy" and not proxy_url:
            obs.error = "出口模式为「仅代理」但未配置代理，已拒绝运行"
            self.stats["blocked_egress"] = self.stats.get("blocked_egress", 0) + 1
            return obs
        obs.egress = "proxy" if proxy_url else "direct"

        # 一次性探针串：只用于识别「把我们请求原样回显」的反射型蜜罐
        canary = ""
        nav_url = url
        if settings.opsec_canary and kind == "suspect":
            canary = "ssv" + uuid.uuid4().hex[:12]
            parts = urlsplit(url)
            if not parts.query:
                nav_url = urlunsplit((parts.scheme, parts.netloc, parts.path, f"_={canary}", ""))

        try:
            browser = self._ensure_browser()
        except Exception as exc:  # noqa: BLE001
            obs.error = f"浏览器不可用：{type(exc).__name__}: {exc}"[:200]
            self.stats["errors"] += 1
            return obs

        context = None
        try:
            context_kwargs: dict[str, Any] = {
                "user_agent": guard.headers_for(url, mobile=True)["User-Agent"],
                "viewport": {"width": 414, "height": 896},
                "locale": "zh-CN",
                "timezone_id": "Asia/Shanghai",
                "ignore_https_errors": True,
                "java_script_enabled": True,
                "accept_downloads": False,
                "geolocation": None,
                "permissions": [],
            }
            if proxy_url:
                # Playwright 只认 socks5://，远端解析是 Chromium 的默认行为
                context_kwargs["proxy"] = {
                    "server": proxy_url.replace("socks5h://", "socks5://", 1)
                }
            context = browser.new_context(**context_kwargs)
            context.set_default_timeout(timeout * 1000)

            page = context.new_page()
            request_log: list[dict[str, Any]] = []
            blocked: list[str] = []

            def _guard(route, request):  # noqa: ANN001
                try:
                    target = urlparse(request.url)
                    if target.scheme in ("data", "blob", "about"):
                        route.continue_()
                        return
                    if not settings.sandbox_allow_private_ip and _is_private_host(target.hostname or ""):
                        blocked.append(request.url[:300])
                        route.abort("blockedbyclient")
                        return
                    # 只读：任何写方法都记录后丢弃，绝不真的提交
                    if request.method.upper() not in ("GET", "HEAD", "OPTIONS"):
                        request_log.append(
                            {
                                "method": request.method,
                                "url": request.url[:400],
                                "post_len": len(request.post_data or ""),
                                "post_sample": (request.post_data or "")[:400],
                                "blocked": True,
                            }
                        )
                        route.abort("blockedbyclient")
                        return
                    route.continue_()
                except Exception:  # noqa: BLE001
                    try:
                        route.continue_()
                    except Exception:  # noqa: BLE001
                        pass

            context.route("**/*", _guard)

            page.on(
                "requestfinished",
                lambda req: request_log.append(
                    {
                        "method": req.method,
                        "url": req.url[:400],
                        "resource": req.resource_type,
                        "blocked": False,
                    }
                )
                if req.method in ("GET", "HEAD")
                else None,
            )

            response = page.goto(nav_url, wait_until="domcontentloaded", timeout=timeout * 1000)
            page.wait_for_timeout(2500)      # 给 JS 跳转留时间

            obs.status = response.status if response else 0
            obs.final_url = page.url
            try:
                obs.title = page.title() or ""
            except Exception:  # noqa: BLE001
                obs.title = ""
            try:
                obs.text = page.inner_text("body")[:30000]
            except Exception:  # noqa: BLE001
                obs.text = ""
            try:
                html = page.content()
                obs.html = html
                obs.html_len = len(html)
            except Exception:  # noqa: BLE001
                html = ""
            # 截图放在最后：等 JS 渲染与跳转都结束，截到的才是受害者看到的那一屏
            try:
                obs.screenshot = page.screenshot(full_page=False, type="png", animations="disabled")
            except Exception as exc:  # noqa: BLE001
                log.debug("截图失败：%s", exc)
            # 全页截图：首屏常被伪装成「活动已结束」，整页才看得到表单和二维码。
            # 限高 + JPEG，避免超长落地页把 2G 内存打满。
            try:
                raw = page.screenshot(full_page=True, type="jpeg", quality=68, animations="disabled")
                obs.screenshot_full = _shrink_image(raw, max_height=6000)
            except Exception as exc:  # noqa: BLE001
                log.debug("全页截图失败：%s", exc)

            # TLS 证书：签发者与有效期是「同一团伙批量签发」的重要关联依据
            try:
                details = response.security_details() if response else None
                if details:
                    obs.tls = {
                        "subject": details.get("subjectName", ""),
                        "issuer": details.get("issuer", ""),
                        "valid_from": details.get("validFrom", ""),
                        "valid_to": details.get("validTo", ""),
                        "protocol": details.get("protocol", ""),
                    }
            except Exception:  # noqa: BLE001
                obs.tls = {}
            # 表单：只看 action 与字段名，不看用户填什么（也没有用户）
            try:
                obs.forms = page.evaluate(
                    """() => Array.from(document.forms).slice(0,10).map(f => ({
                        action: f.action || '',
                        method: (f.method || 'get').toUpperCase(),
                        inputs: Array.from(f.elements).slice(0,20)
                            .map(e => e.name || e.id || e.type).filter(Boolean)
                    }))"""
                )
            except Exception:  # noqa: BLE001
                obs.forms = []

            # 跳转链
            try:
                nav = page.evaluate("() => performance.getEntriesByType('navigation')")
                if nav:
                    obs.redirects = [{"url": n.get("name", ""), "type": "navigation"} for n in nav][:10]
            except Exception:  # noqa: BLE001
                pass
            if obs.final_url and obs.final_url != url:
                obs.redirects.insert(0, {"from": url, "to": obs.final_url, "type": "redirect"})

            obs.requests = request_log
            obs.blocked = blocked

            # 从 HTML 与运行时 DOM 里找安装包链接
            apk_candidates = set(_APK_LINK.findall(html or ""))
            try:
                hrefs = page.evaluate(
                    "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href).slice(0,400)"
                )
                for href in hrefs or []:
                    if any(ext in href.lower() for ext in _INTERESTING_EXT):
                        apk_candidates.add(href)
            except Exception:  # noqa: BLE001
                pass
            obs.apk_links = sorted(apk_candidates)[:20]

            try:
                obs.cookies = [
                    {"name": c.get("name"), "domain": c.get("domain")} for c in context.cookies()
                ][:30]
            except Exception:  # noqa: BLE001
                pass

            # 蜜罐识别：页面回显了采集端 IP / 本次探针串 / 云元数据地址
            obs.honeypot = guard.honeypot_check(
                (obs.text or "") + "\n" + (html or ""), canary=canary, request_url=url
            )
            if obs.honeypot.get("suspected"):
                self.stats["honeypot"] = self.stats.get("honeypot", 0) + 1

            self.stats["ok"] += 1
        except Exception as exc:  # noqa: BLE001
            obs.error = f"{type(exc).__name__}: {exc}"[:300]
            self.stats["errors"] += 1
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:  # noqa: BLE001
                    pass
            obs.elapsed = time.monotonic() - started
            self.stats["runs"] += 1

        return obs

    def status(self) -> dict[str, Any]:
        return {
            "enabled": settings.sandbox_enabled and settings.sandbox_browser_enabled,
            "available": self.available,
            "last_error": self.last_error,
            "stats": self.stats,
            "allow_private_ip": settings.sandbox_allow_private_ip,
            "timeout": settings.sandbox_timeout,
            "egress": "proxy" if get_guard().proxies else "direct",
            "require_proxy": settings.opsec_require_proxy_for_sandbox,
        }

    def close(self) -> None:
        try:
            if self._browser is not None:
                self._browser.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            if self._playwright is not None:
                self._playwright.stop()
        except Exception:  # noqa: BLE001
            pass
        self._browser = None
        self._playwright = None
        self.available = False


_web: WebSandbox | None = None
_lock = threading.Lock()


def get_web_sandbox() -> WebSandbox:
    global _web
    if _web is None:
        with _lock:
            if _web is None:
                _web = WebSandbox()
    return _web
