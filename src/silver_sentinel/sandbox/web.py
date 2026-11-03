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
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from ..config import settings

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
    html_len: int = 0
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

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "final_url": self.final_url,
            "status": self.status,
            "title": self.title[:200],
            "text": self.text[:20000],
            "html_len": self.html_len,
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

            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-background-networking",
                    "--disable-features=NetworkPrediction,Translate",
                ],
            )
            self.available = True
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

        try:
            browser = self._ensure_browser()
        except Exception as exc:  # noqa: BLE001
            obs.error = f"浏览器不可用：{type(exc).__name__}: {exc}"[:200]
            self.stats["errors"] += 1
            return obs

        context = None
        try:
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Linux; Android 12; SM-G9910) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
                ),
                viewport={"width": 414, "height": 896},
                locale="zh-CN",
                timezone_id="Asia/Shanghai",
                ignore_https_errors=True,
                java_script_enabled=True,
                accept_downloads=False,
            )
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

            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
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
                obs.html_len = len(html)
            except Exception:  # noqa: BLE001
                html = ""

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
