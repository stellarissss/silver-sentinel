"""外部信誉查询：URLhaus、OpenPhish、ICP 备案、官方通报清单。

所有查询都是「读取别人已经采集好的情报」，不触碰可疑站点本身。
无 key / 无网络时统一返回 None，由规则引擎按「未知」处理 —— 未知不等于安全，也不等于危险。
"""

from __future__ import annotations

import time
from pathlib import Path

import yaml

from ..config import settings
from ..normalize import normalize_domain, registrable_domain
from .http import client

_OPENPHISH_CACHE: tuple[float, set[str]] | None = None
_OPENPHISH_TTL = 6 * 3600

_PKG_WATCHLIST = Path(__file__).resolve().parent.parent / "data" / "official_watchlist.yaml"


def _watchlist_candidates() -> list[Path]:
    """优先用运行时数据目录（可由用户覆盖），其次用包内置清单。"""
    return [settings.data_dir / "official_watchlist.yaml", _PKG_WATCHLIST]


def urlhaus_lookup(host: str) -> dict | None:
    """abuse.ch URLhaus host 查询。2024 年后需要 Auth-Key，未配置则跳过。"""
    host = normalize_domain(host)
    if not host:
        return None
    headers = {}
    if settings.urlhaus_auth_key:
        headers["Auth-Key"] = settings.urlhaus_auth_key
    data = client.post_json(
        "https://urlhaus-api.abuse.ch/v1/host/",
        data={"host": host},
        headers=headers,
    )
    if not data or data.get("query_status") != "ok":
        return None
    urls = data.get("urls") or []
    return {
        "listed": True,
        "url_count": len(urls),
        "tags": sorted({t for u in urls for t in (u.get("tags") or []) if t}),
        "threat": data.get("threat") or "",
        "firstseen": min((u.get("date_added", "") for u in urls), default=""),
    }


def openphish_listed(url_or_host: str) -> bool | None:
    """OpenPhish 免费 feed，本地缓存 6 小时。返回 None 表示源不可用。"""
    global _OPENPHISH_CACHE

    text = client.get_text(settings.openphish_feed)
    if text is None:
        return None

    entries = {
        line.strip().lower().rstrip("/")
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }

    now = time.time()
    _OPENPHISH_CACHE = (now, entries)

    target = (url_or_host or "").strip().lower().rstrip("/")
    if target in entries:
        return True
    host = registrable_domain(normalize_domain(target))
    return any(host and host in e for e in entries)


def icp_lookup(domain: str) -> bool | None:
    """ICP 备案探测。

    境内备案数据没有稳定公开 API，直连工信部系统既不稳定也不合规。
    这里采用「可插拔」策略：配置了 SILVER_ICP_API 才查询，否则返回 None。
    None 会被规则引擎视为未知，不参与加分 —— 宁可少判，不可错判。
    """
    domain = normalize_domain(domain)
    if not domain:
        return None

    import os

    api = os.environ.get("SILVER_ICP_API", "").strip()
    if not api:
        return None

    url = api.format(domain=domain) if "{domain}" in api else f"{api}{domain}"
    data = client.get_json(url)
    if not data:
        return None
    if isinstance(data, dict):
        payload = data.get("data") or data
        if isinstance(payload, dict):
            for key in ("icp", "ICP", "license", "beian", "备案号"):
                if payload.get(key):
                    return True
        if data.get("success") is False:
            return None
    return False


# ---------------------------------------------------------------- 域名年龄


def rdap_age_days(domain: str) -> int | None:
    """通过 RDAP 查域名注册时间，返回距今天数。查不到返回 None。"""
    from datetime import datetime, timezone

    domain = registrable_domain(normalize_domain(domain))
    if not domain:
        return None

    data = client.get_json(f"https://rdap.org/domain/{domain}")
    if not isinstance(data, dict):
        return None

    for event in data.get("events") or []:
        if str(event.get("eventAction", "")).lower() != "registration":
            continue
        raw = str(event.get("eventDate", "")).replace("Z", "+00:00")
        try:
            registered = datetime.fromisoformat(raw)
        except ValueError:
            continue
        if registered.tzinfo is None:
            registered = registered.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - registered).days)
    return None


# ---------------------------------------------------------------- 官方通报清单


def load_watchlist(path: Path | None = None) -> list[dict]:
    candidates = [path] if path else _watchlist_candidates()
    for candidate in candidates:
        if candidate and candidate.is_file():
            try:
                data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                continue
            entries = list(data.get("entries") or [])
            if entries:
                return entries
    return []


def match_watchlist(names: list[str], path: Path | None = None) -> dict | None:
    """在公开通报清单里匹配名称。只做包含匹配，长度需 >= 3 防误命中。"""
    entries = load_watchlist(path)
    if not entries:
        return None

    haystack = " ".join(n for n in names if n)
    if not haystack:
        return None

    for entry in entries:
        alias = [entry.get("name", "")] + list(entry.get("aliases") or [])
        for a in alias:
            a = (a or "").strip()
            if len(a) >= 3 and a in haystack:
                return entry
    return None
