"""仿冒域名变体生成与存活探测。

只做 DNS 解析，不发 HTTP 请求 —— 能判断「是否存在」，又不给对方送流量。
"""

from __future__ import annotations

import socket

from ..normalize import registrable_domain

HOMOGLYPHS = {
    "o": ["0"],
    "l": ["1", "i"],
    "i": ["1", "l"],
    "e": ["3"],
    "a": ["4"],
    "s": ["5", "$"],
    "g": ["9"],
    "b": ["6"],
    "t": ["7"],
}

CN_SUFFIXES = ["cn", "china", "zg", "app", "vip", "official", "gw", "pt", "v"]


def _edits(word: str) -> set[str]:
    out: set[str] = set()
    for i in range(len(word)):
        out.add(word[:i] + word[i + 1 :])                      # 删除
        out.add(word[:i] + word[i] + word[i] + word[i + 1 :])  # 重复
        if i + 1 < len(word):
            out.add(word[:i] + word[i + 1] + word[i] + word[i + 2 :])  # 换位
        for sub in HOMOGLYPHS.get(word[i], []):
            out.add(word[:i] + sub + word[i + 1 :])            # 同形替换
    return out


def generate_variants(brand: str, max_variants: int = 220) -> list[str]:
    """生成可能的仿冒域名（不含 TLD）。"""
    brand = (brand or "").strip().lower().replace(" ", "")
    if len(brand) < 3:
        return []

    variants: set[str] = set(_edits(brand))
    for suffix in CN_SUFFIXES:
        variants.add(f"{brand}{suffix}")
        variants.add(f"{brand}-{suffix}")
        variants.add(f"{suffix}{brand}")
        variants.add(f"{suffix}-{brand}")
    variants.discard(brand)

    return sorted(v for v in variants if 3 <= len(v) <= 63)[:max_variants]


def resolve(domain: str, timeout: float = 2.5) -> list[str]:
    """返回解析到的 IP，空列表表示不存在或解析失败。"""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        return sorted({info[4][0] for info in infos})
    except (socket.gaierror, socket.herror, OSError, UnicodeError):
        return []
    finally:
        socket.setdefaulttimeout(old)


def probe(brand: str, tlds: tuple[str, ...] = ("com", "cn", "net", "top", "xyz"), limit: int = 60) -> list[dict]:
    """批量探测变体域名是否存在，返回存活列表。会触发 DNS 查询，注意调用频率。"""
    results: list[dict] = []
    for variant in generate_variants(brand)[:limit]:
        for tld in tlds:
            domain = f"{variant}.{tld}"
            ips = resolve(domain)
            if ips:
                results.append({"domain": domain, "registrable": registrable_domain(domain), "ips": ips})
    return results
