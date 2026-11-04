"""统一 HTTP 客户端：超时、重试、限速、可关闭。

明确边界：本项目只访问「第三方情报服务」与「公开注册数据」，
不抓取可疑站点正文。理由有二 ——
1) 访问即给对方贡献 UV，还可能触发其反制（记录 IP、下发定向载荷）；
2) 静态证据已足够支撑判定，动态取证应由执法/平台侧在受控环境完成。

所有出站都经过 opsec 闸门：分类 → 选出口 → 换指纹 → 抖动 → 失败记账。
可疑目标在未配置代理且策略为 fail-closed 时会被直接拒绝（EgressBlocked），
调用方应把它当作「正常降级」，而不是异常。
"""

from __future__ import annotations

import json
import logging
import random
import threading
import time
import urllib.parse
from typing import Any

import httpx

from ..config import settings
from ..opsec import EgressBlocked, get_guard

log = logging.getLogger(__name__)


class NetworkDisabled(RuntimeError):
    """离线模式下发起网络请求。"""


class _RateLimiter:
    def __init__(self, rate_per_sec: float) -> None:
        self._interval = 1.0 / max(0.1, rate_per_sec)
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                time.sleep(self._next - now)
                now = self._next
            self._next = now + self._interval


# 限速按「目标站点」而不是全局：全局桶会把流水线卡死——实测 8 线程并发研判时，
# 全局 2 req/s 让每个目标都排在同一个队里，8 个目标串成 33 秒。
# 按 host 限速既不失礼（对单个站点仍然克制），又不会互相拖累。
_master = _RateLimiter(max(settings.rate_limit_per_sec * 4, 4.0))
_host_limiters: dict[str, _RateLimiter] = {}
_host_lock = threading.Lock()


def _host_of(url: str) -> str:
    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""


def wait_turn(url: str) -> None:
    """先过全局总闸，再过目标站点自己的闸。固定顺序，避免死锁。"""
    host = _host_of(url)
    with _host_lock:
        limiter = _host_limiters.get(host)
        if limiter is None:
            limiter = _RateLimiter(settings.rate_limit_per_sec)
            _host_limiters[host] = limiter
    _master.wait()
    limiter.wait()


class HttpClient:
    def __init__(self, *, timeout: float | None = None, retries: int | None = None) -> None:
        self.timeout = timeout or settings.http_timeout
        self.retries = retries if retries is not None else settings.http_retries

    def _client(self, url: str, headers: dict[str, str]) -> httpx.Client:
        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "follow_redirects": True,
            "headers": headers,
        }
        proxy = get_guard().proxy_for(url)
        if proxy:
            kwargs["proxy"] = proxy
        return httpx.Client(**kwargs)

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if not settings.allow_network:
            raise NetworkDisabled("离线模式（SILVER_ALLOW_NETWORK=0）下不允许网络请求")

        guard = get_guard()
        kind = guard.preflight(url)          # 可能抛 EgressBlocked
        headers = guard.headers_for(url)
        headers.update(kwargs.pop("headers", {}) or {})

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            wait_turn(url)
            guard.jitter(suspect=(kind == "suspect"))
            try:
                with self._client(url, headers) as client:
                    resp = client.request(method, url, **kwargs)
                guard.note_failure(url, True)
                if resp.status_code in {429, 500, 502, 503, 504} and attempt < self.retries:
                    time.sleep(min(8.0, 1.5 * (2**attempt)) + random.uniform(0, 0.4))
                    continue
                return resp
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                guard.note_failure(url, False)
                if attempt < self.retries:
                    time.sleep(min(8.0, 1.2 * (2**attempt)))
                    continue
        raise RuntimeError(f"请求失败：{url}") from last_error

    def get_json(self, url: str, **kwargs: Any) -> Any | None:
        try:
            resp = self._request("GET", url, **kwargs)
            if resp.status_code != 200:
                return None
            return resp.json()
        except (NetworkDisabled, EgressBlocked, RuntimeError, json.JSONDecodeError) as exc:
            log.debug("GET JSON 降级：%s（%s）", url, exc)
            return None

    def post_json(self, url: str, **kwargs: Any) -> Any | None:
        try:
            resp = self._request("POST", url, **kwargs)
            if resp.status_code != 200:
                return None
            return resp.json()
        except (NetworkDisabled, EgressBlocked, RuntimeError, json.JSONDecodeError) as exc:
            log.debug("POST JSON 降级：%s（%s）", url, exc)
            return None

    def get_text(self, url: str, **kwargs: Any) -> str | None:
        try:
            resp = self._request("GET", url, **kwargs)
            return resp.text if resp.status_code == 200 else None
        except (NetworkDisabled, EgressBlocked, RuntimeError) as exc:
            log.debug("GET TEXT 降级：%s（%s）", url, exc)
            return None


client = HttpClient()
