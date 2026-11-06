"""控制台访问口令。

这套东西里全是涉诈线索与举报材料，不能裸奔在公网上。默认行为：

- 设了 ``SILVER_WEB_PASSWORD`` 就用它；
- 没设、但监听地址不是回环地址时，自动生成一个随机口令，写到
  ``<data>/web-password.txt``（0600），启动日志打印一次；
- 只监听回环地址时不做鉴权，保持本机开发不被打扰。

会话是一个 HMAC 签名的 cookie，密钥由口令派生——换口令等于让所有旧会话立即失效。
中间件按纯 ASGI 写，不套 ``BaseHTTPMiddleware``，否则 ``/api/stream`` 的 SSE 会被缓冲。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

logger = logging.getLogger(__name__)

COOKIE_NAME = "ss_session"
SESSION_TTL = 7 * 24 * 3600
LOGIN_PATH = "/login"
LOGIN_POST = "/auth/login"
LOGOUT_PATH = "/auth/logout"

# 静态资源无需鉴权：里面没有任何线索数据，且浏览器加载子资源时不会带自定义头
_PUBLIC_PREFIXES = ("/static/", "/favicon.ico", LOGIN_PATH, LOGIN_POST, LOGOUT_PATH)
_PUBLIC_EXACT = {"/api/ping"}

_FAIL_WINDOW = 600
_FAIL_LIMIT = 8
_fails: dict[str, list[float]] = {}


def _password_file() -> Path:
    from .config import settings

    return settings.data_dir / "web-password.txt"


def _read_password() -> str:
    from .config import settings

    pw = (settings.web_password or "").strip()
    if pw:
        return pw
    path = _password_file()
    try:
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return ""


def ensure_password(host: str = "") -> str:
    """拿到口令；需要时生成并落盘。

    只在「对外监听」时才生成，避免本机开发也被迫输密码。
    """
    pw = _read_password()
    if pw:
        return pw

    from .config import settings

    loopback = host in ("127.0.0.1", "localhost", "::1", "")
    if loopback and not settings.web_force_auth:
        return ""

    pw = "ss-" + secrets.token_urlsafe(12)
    path = _password_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pw + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    except OSError as exc:  # noqa: BLE001
        logger.warning("口令无法落盘（%s），本次仅打印到日志", exc)
    return pw


def auth_enabled() -> bool:
    return bool(_read_password())


def _secret() -> bytes:
    return hashlib.sha256(("silver-sentinel::" + _read_password()).encode()).digest()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue(ttl: int = SESSION_TTL) -> str:
    payload = _b64(json.dumps({"exp": int(time.time()) + ttl, "v": 1}, separators=(",", ":")).encode())
    sig = _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{sig}"


def verify(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    payload, _, sig = token.partition(".")
    try:
        expect = _b64(hmac.new(_secret(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expect):
            return False
        data = json.loads(_unb64(payload))
        return int(data.get("exp", 0)) > time.time()
    except (ValueError, binascii.Error, json.JSONDecodeError):
        return False


def check_password(given: str) -> bool:
    expect = _read_password()
    if not expect:
        return True
    # compare_digest 只吃 ASCII；中文口令必须先编码成 bytes
    return hmac.compare_digest((given or "").encode("utf-8"), expect.encode("utf-8"))


def client_key(scope: dict) -> str:
    client = scope.get("client") or ("?", 0)
    host = client[0] if isinstance(client, (tuple, list)) and client else "?"
    # 反代后面取真实来源，避免全站共用一个失败计数
    for k, v in scope.get("headers") or []:
        if k.lower() == b"x-forwarded-for":
            host = v.decode(errors="replace").split(",")[0].strip() or host
            break
    return host


def too_many_failures(key: str) -> bool:
    now = time.time()
    hits = [t for t in _fails.get(key, []) if now - t < _FAIL_WINDOW]
    _fails[key] = hits
    return len(hits) >= _FAIL_LIMIT


def note_failure(key: str) -> None:
    _fails.setdefault(key, []).append(time.time())


def clear_failures(key: str) -> None:
    _fails.pop(key, None)


def needs_auth(path: str) -> bool:
    if path in _PUBLIC_EXACT:
        return False
    return not any(path == p or path.startswith(p) for p in _PUBLIC_PREFIXES)


def _cookie_of(headers: dict[str, str]) -> str:
    raw = headers.get("cookie", "")
    for part in raw.split(";"):
        name, _, value = part.strip().partition("=")
        if name == COOKIE_NAME:
            return value
    return ""


def _query_token(scope: dict) -> str:
    qs = (scope.get("query_string") or b"").decode(errors="replace")
    for part in qs.split("&"):
        name, _, value = part.partition("=")
        if name == "token":
            from urllib.parse import unquote_plus

            return unquote_plus(value)
    return ""


def _wants_html(headers: dict[str, str]) -> bool:
    accept = headers.get("accept", "")
    if "text/html" in accept:
        return True
    return "text/event-stream" not in accept and not headers.get("x-requested-with")


def _authorized(headers: dict[str, str], scope: dict, path: str) -> bool:
    """会话 cookie 优先；脚本可以带 Bearer，也可以给 /api 加 ?token=。

    Bearer 与 ?token= 同时接受「口令本身」和「session token」——前者是为了让
    curl / 扩展少一步，后者是为了给已经登录过的客户端复用。
    """
    if verify(_cookie_of(headers)):
        return True

    auth = headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        return verify(token) or check_password(token)

    if path.startswith("/api/"):
        token = _query_token(scope)
        return verify(token) or check_password(token)

    return False


class AuthMiddleware:
    """纯 ASGI 中间件：不消费响应体，SSE 照常逐条下发。"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        if not auth_enabled() or not needs_auth(path):
            return await self.app(scope, receive, send)

        # 用 UTF-8 解码：口令可能是中文，curl -H 会原样发 UTF-8 字节；
        # cookie 与常规头都是 ASCII，解码结果一致。非法序列用 replace 兜住。
        headers = {
            k.decode("latin-1").lower(): v.decode("utf-8", "replace")
            for k, v in scope.get("headers") or []
        }

        if _authorized(headers, scope, path):
            return await self.app(scope, receive, send)

        if path.startswith("/api/") or not _wants_html(headers):
            body = json.dumps({"detail": "未登录或会话已过期"}, ensure_ascii=False).encode()
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                    (b"cache-control", b"no-store"),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        target = LOGIN_PATH
        if path not in ("/", ""):
            from urllib.parse import quote

            target = f"{LOGIN_PATH}?next={quote(path, safe='/')}"
        await send({
            "type": "http.response.start",
            "status": 302,
            "headers": [(b"location", target.encode()), (b"cache-control", b"no-store")],
        })
        await send({"type": "http.response.body", "body": b""})
