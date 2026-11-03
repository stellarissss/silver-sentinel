"""证书透明度日志（crt.sh）查询。

两个用途：
1. 发现：按品牌/关键词找新签发的相关域名（诈骗站群换域名很频繁）。
2. 归并：查某个域名证书的 SAN 列表，同一张证书上的其他域名基本同源。

数据来自公开 CT 日志，属于被动情报，不接触目标站点。
"""

from __future__ import annotations

from urllib.parse import quote

from ..normalize import normalize_domain
from .http import HttpClient

_CT = HttpClient(timeout=35.0, retries=1)


def _query(q: str, limit: int = 300) -> list[dict]:
    url = f"https://crt.sh/?q={quote(q)}&output=json"
    raw = _CT.get_json(url)
    if not isinstance(raw, list):
        return []

    seen: set[str] = set()
    out: list[dict] = []
    for row in raw[: limit * 3]:
        if not isinstance(row, dict):
            continue
        names = {
            n.strip().lower().lstrip("*.")
            for n in str(row.get("name_value", "")).splitlines()
            if n.strip()
        }
        for name in names:
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(
                {
                    "domain": name,
                    "issuer": row.get("issuer_name", ""),
                    "not_before": row.get("not_before", ""),
                    "not_after": row.get("not_after", ""),
                    "entry_timestamp": row.get("entry_timestamp", ""),
                    "serial": row.get("serial_number", ""),
                }
            )
        if len(out) >= limit:
            break
    return out


def search_keyword(keyword: str, limit: int = 200) -> list[dict]:
    """按关键词模糊搜索证书中的域名，用于发现新出现的仿冒站。"""
    keyword = (keyword or "").strip().lower()
    if len(keyword) < 3:
        return []
    return _query(f"%25{keyword}%25", limit=limit)


def siblings_of(domain: str, limit: int = 100) -> list[str]:
    """取同一张证书上的其他域名 —— 强同源证据。"""
    domain = normalize_domain(domain)
    if not domain:
        return []
    rows = _query(domain, limit=limit)
    found = {r["domain"] for r in rows if r["domain"] != domain}
    return sorted(found)[:limit]
