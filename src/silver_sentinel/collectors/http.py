"""统一 HTTP 客户端：超时、重试、限速、可关闭。

明确边界：本项目只访问「第三方情报服务」与「公开注册数据」，
不抓取可疑站点正文。理由有二 ——
1) 访问即给对方贡献 UV，还可能触发其反制（记录 IP、下发定向载荷）；
2) 静态证据已足够支撑判定，动态取证应由执法/平台侧在受控环境完成。
"""

from __future__ import annotations

import json
import random
import threading
import time
from typing import Any

import httpx

from ..config import settings

USER_AGENT = (
    "Mozilla/5.0 (compatible; SilverSentinel/0.1; +https://github.com/stellarissss/silver-sentinel) "
    "anti-fraud-research"
)


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


_limiter = _RateLimiter(settings.rate_limit_per_sec)


class HttpClient:
    def __init__(self, *, timeout: float | None = None, retries: int | None = None) -> None:
        self.timeout = timeout or settings.http_timeout
        self.retries = retries if retries is not None else settings.http_retries

    def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        if not settings.allow_network:
            raise NetworkDisabled("离线模式（SILVER_ALLOW_NETWORK=0）下不允许网络请求")

        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        headers.update(kwargs.pop("headers", {}) or {})

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            _limiter.wait()
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=True, headers=headers) as client:
                    resp = client.request(method, url, **kwargs)
                if resp.status_code in {429, 500, 502, 503, 504} and attempt < self.retries:
                    time.sleep(min(8.0, 1.5 * (2**attempt)) + random.uniform(0, 0.4))
                    continue
                return resp
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
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
        except (NetworkDisabled, RuntimeError, json.JSONDecodeError):
            return None

    def post_json(self, url: str, **kwargs: Any) -> Any | None:
        try:
            resp = self._request("POST", url, **kwargs)
            if resp.status_code != 200:
                return None
            return resp.json()
        except (NetworkDisabled, RuntimeError, json.JSONDecodeError):
            return None

    def get_text(self, url: str, **kwargs: Any) -> str | None:
        try:
            resp = self._request("GET", url, **kwargs)
            return resp.text if resp.status_code == 200 else None
        except (NetworkDisabled, RuntimeError):
            return None


client = HttpClient()
