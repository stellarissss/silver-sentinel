"""运行时可改配置。

为什么需要这一层
----------------
密钥、代理、模型名这类东西，改一次就要登服务器改 .env、重启进程，
实际结果是「配一次就再也不动」。这里把它们放进数据库，前端改完即时生效。

安全边界
--------
- 接口只返回**掩码**（`sk-…3f2a`），永远不回传原文；
- 写入必须经过登录会话（中间件已经保证）；
- 值只落本地 SQLite，不进日志、不进证据包。

优先级：数据库 > 环境变量 > 缺省值。数据库为空时回落到 settings，
保证老部署不改任何东西也能跑。
"""

from __future__ import annotations

import threading
import time
from typing import Any

from sqlalchemy import select

from .models import AppSetting

# ---- key 常量，避免各处手写字符串
LLM_BASE_URL = "llm.base_url"
LLM_API_KEY = "llm.api_key"
LLM_MODEL = "llm.model"
LLM_ENABLED = "llm.enabled"
LLM_GRAY_LOW = "llm.gray_low"
LLM_GRAY_HIGH = "llm.gray_high"

EGRESS_PROXIES = "egress.proxies"
EGRESS_MODE = "egress.mode"          # auto | proxy | direct | off

CAPTURE_APK_MAX_MB = "capture.apk_max_mb"
CAPTURE_APK_DAILY_MB = "capture.apk_daily_mb"
CAPTURE_AUTO_APK_TIERS = "capture.apk_tiers"

DEFAULTS: dict[str, str] = {
    LLM_BASE_URL: "",
    LLM_API_KEY: "",
    LLM_MODEL: "deepseek-v4-flash",
    LLM_ENABLED: "1",
    LLM_GRAY_LOW: "25",
    LLM_GRAY_HIGH: "70",
    EGRESS_PROXIES: "",
    EGRESS_MODE: "auto",
    CAPTURE_APK_MAX_MB: "50",
    CAPTURE_APK_DAILY_MB: "300",
    CAPTURE_AUTO_APK_TIERS: "watch,confirmed",
}

_TTL = 5.0
_cache: dict[str, str] = {}
_cache_at = 0.0
# 哪些键是「人真的写过」的。DEFAULTS 里的值不算配置——
# 否则「出口模式默认 auto」会被当成用户选了自动，把 fail-closed 顶掉。
_explicit: set[str] = set()
_lock = threading.Lock()


def _load() -> dict[str, str]:
    global _cache, _cache_at, _explicit
    now = time.monotonic()
    if _cache and now - _cache_at < _TTL:
        return _cache
    with _lock:
        if _cache and now - _cache_at < _TTL:
            return _cache
        values = dict(DEFAULTS)
        explicit: set[str] = set()
        try:
            from .db import session_scope

            with session_scope() as s:
                for row in s.scalars(select(AppSetting)):
                    if row.value != "":
                        values[row.key] = row.value
                        explicit.add(row.key)
        except Exception:  # 数据库还没建好时不能让配置读取炸掉
            pass
        _cache = values
        _explicit = explicit
        _cache_at = now
        return values


def invalidate() -> None:
    global _cache_at
    with _lock:
        _cache_at = 0.0


def get(key: str, default: str = "") -> str:
    return _load().get(key, default)


def is_set(key: str) -> bool:
    """这个键是否被显式写过（区别于「取到了默认值」）。"""
    _load()
    return key in _explicit


def get_int(key: str, default: int) -> int:
    try:
        return int(float(_load().get(key, "") or default))
    except (TypeError, ValueError):
        return default


def get_float(key: str, default: float) -> float:
    try:
        return float(_load().get(key, "") or default)
    except (TypeError, ValueError):
        return default


def get_bool(key: str, default: bool) -> bool:
    return (_load().get(key, "1" if default else "0") or "").strip().lower() in {"1", "true", "yes", "on"}


def set_many(values: dict[str, str], *, by: str = "") -> None:
    from .db import session_scope
    from .domain import utcnow

    with session_scope() as s:
        for key, value in values.items():
            if key not in DEFAULTS:
                continue
            row = s.get(AppSetting, key)
            if row is None:
                s.add(AppSetting(key=key, value=str(value), updated_at=utcnow(), updated_by=by))
            else:
                row.value = str(value)
                row.updated_at = utcnow()
                row.updated_by = by
    invalidate()


def mask(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "•" * len(secret)
    return f"{secret[:4]}…{secret[-4:]}"


# ---------------------------------------------------------------- 组合视图


def llm_config() -> dict[str, Any]:
    """LLM 的实际生效配置：数据库优先，回落环境变量。"""
    from .config import settings

    base = (get(LLM_BASE_URL) or settings.llm_base_url or "").strip().rstrip("/")
    key = (get(LLM_API_KEY) or settings.llm_api_key or "").strip()
    model = (get(LLM_MODEL) or settings.llm_model or "deepseek-v4-flash").strip()
    enabled = get_bool(LLM_ENABLED, settings.llm_enabled)
    return {
        "base_url": base,
        "api_key": key,
        "model": model,
        "enabled": enabled,
        "ready": bool(enabled and base and key),
        "gray_low": get_float(LLM_GRAY_LOW, 25.0),
        "gray_high": get_float(LLM_GRAY_HIGH, 70.0),
    }


def egress_config() -> dict[str, Any]:
    from .config import settings

    proxies = get(EGRESS_PROXIES) or settings.opsec_proxies or ""
    proxy_list = [p.strip() for p in proxies.split(",") if p.strip()]
    raw_mode = (get(EGRESS_MODE) or "auto").strip().lower()
    if raw_mode not in {"auto", "proxy", "direct", "off"}:
        raw_mode = "auto"
    # configured=False 表示「没人在界面上选过」。这时候实例构造时的
    # fail-closed 设定必须保留，不能被这里的默认值悄悄改成直连。
    configured = is_set(EGRESS_MODE)
    mode = raw_mode
    # auto 的语义就是「有代理走代理，没有就本机直连」——这是用户拍板的降级路径
    effective = ("proxy" if proxy_list else "direct") if mode == "auto" else mode
    return {
        "mode": mode,
        "configured": configured,
        "proxies": proxy_list,
        "effective": effective,
        "isolated": effective == "proxy" and bool(proxy_list),
        "require_proxy": settings.opsec_require_proxy_for_sandbox,
    }


def llm_public() -> dict[str, Any]:
    """给前端看的版本：密钥掩码，代理掩码。"""
    cfg = llm_config()
    eg = egress_config()
    from .config import settings

    return {
        "llm": {
            "base_url": cfg["base_url"],
            "model": cfg["model"],
            "enabled": cfg["enabled"],
            "ready": cfg["ready"],
            "api_key_masked": mask(cfg["api_key"]),
            "has_key": bool(cfg["api_key"]),
            "gray_low": cfg["gray_low"],
            "gray_high": cfg["gray_high"],
            "presets": [
                {"label": "DeepSeek V4 Flash（推荐，快且便宜）", "model": "deepseek-v4-flash", "base_url": "https://api.deepseek.com"},
                {"label": "DeepSeek V4 Pro（更强，成本高）", "model": "deepseek-v4-pro", "base_url": "https://api.deepseek.com"},
            ],
        },
        "egress": {
            "mode": eg["mode"],
            "effective": eg["effective"],
            "isolated": eg["isolated"],
            "proxies_masked": [mask(p) for p in eg["proxies"]],
            "proxy_count": len(eg["proxies"]),
            "require_proxy": settings.opsec_require_proxy_for_sandbox,
        },
        "capture": {
            "apk_max_mb": get_int(CAPTURE_APK_MAX_MB, 50),
            "apk_daily_mb": get_int(CAPTURE_APK_DAILY_MB, 300),
            "apk_tiers": get(CAPTURE_AUTO_APK_TIERS, "watch,confirmed"),
        },
    }
