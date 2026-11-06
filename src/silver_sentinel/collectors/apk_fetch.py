"""APK 下载器：把落地页上的安装包原样取回来。

为什么单独一个模块
------------------
下载是最容易把服务器拖垮的一步：对方给一个 2GB 的「安装包」、一个永远不结束的
流、或者一个看起来是 APK 实际是 HTML 的 302 页。所以这里所有限制都是硬限制：
体积、时长、速度、魔数校验，任一不满足就中止并记录原因。

拿到之后只做静态分析，绝不执行、绝不安装。
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ..config import settings
from ..opsec import EgressBlocked, get_guard

log = logging.getLogger(__name__)

APK_MAGIC = b"PK\x03\x04"
CHUNK = 64 * 1024


@dataclass(slots=True)
class FetchResult:
    ok: bool
    url: str = ""
    path: str = ""
    sha256: str = ""
    size: int = 0
    reason: str = ""
    elapsed: float = 0.0
    content_type: str = ""
    final_url: str = ""

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "url": self.url[:300],
            "final_url": self.final_url[:300],
            "sha256": self.sha256,
            "size": self.size,
            "reason": self.reason,
            "elapsed": round(self.elapsed, 2),
            "content_type": self.content_type,
        }


def _proxy_url(url: str) -> str | None:
    guard = get_guard()
    try:
        guard.preflight(url)
    except EgressBlocked:
        raise
    raw = guard.proxy_for(url)
    if not raw:
        return None
    # httpx 只认 http:// 与 socks5://；socks5h 的远端解析语义在 httpx 里由 socks5 默认承担
    return raw.replace("socks5h://", "socks5://", 1)


def fetch(url: str, dest_dir: Path | str | None = None, *, max_bytes: int = 50 * 1024 * 1024,
          timeout: float = 75.0, referer: str = "") -> FetchResult:
    started = time.monotonic()
    out = FetchResult(ok=False, url=url)
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        out.reason = f"不支持的协议：{parsed.scheme}"
        return out

    try:
        proxy = _proxy_url(url)
    except EgressBlocked as exc:
        out.reason = f"出站被拒：{exc.reason}"
        return out

    headers = {
        "User-Agent": get_guard().headers_for(url, mobile=True)["User-Agent"],
        "Accept": "application/vnd.android.package-archive,application/octet-stream,*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
    }
    if referer:
        headers["Referer"] = referer[:400]

    dest_dir = Path(dest_dir or (settings.data_dir / "apk"))
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None

    try:
        kwargs: dict = {"follow_redirects": True, "timeout": httpx.Timeout(timeout, connect=15.0)}
        if proxy:
            kwargs["proxy"] = proxy
        with httpx.Client(**kwargs) as client:
            with client.stream("GET", url, headers=headers) as resp:
                out.content_type = resp.headers.get("content-type", "")[:120]
                out.final_url = str(resp.url)
                if resp.status_code >= 400:
                    out.reason = f"HTTP {resp.status_code}"
                    return out

                declared = resp.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > max_bytes:
                    out.reason = f"声明体积 {int(declared) // 1024 // 1024}MB 超过上限 {max_bytes // 1024 // 1024}MB"
                    return out

                fd, tmp_name = tempfile.mkstemp(prefix="dl-", suffix=".part", dir=str(dest_dir))
                tmp_path = Path(tmp_name)
                digest = hashlib.sha256()
                size = 0
                head = b""
                with os.fdopen(fd, "wb") as fh:
                    for chunk in resp.iter_bytes(CHUNK):
                        if not chunk:
                            continue
                        if not head:
                            head = chunk[:8]
                        size += len(chunk)
                        if size > max_bytes:
                            out.reason = f"实际体积超过上限 {max_bytes // 1024 // 1024}MB，已中止"
                            return out
                        if time.monotonic() - started > timeout:
                            out.reason = f"下载超过 {int(timeout)} 秒，已中止"
                            return out
                        digest.update(chunk)
                        fh.write(chunk)

        if size == 0:
            out.reason = "空文件"
            return out
        if not head.startswith(APK_MAGIC):
            # 伪装成 APK 的 HTML / 压缩包很常见，魔数不对就不是安装包
            out.reason = f"不是有效 APK（文件头 {head[:4]!r}）"
            return out

        sha = digest.hexdigest()
        target = dest_dir / f"{sha}.apk"
        if not target.exists():
            tmp_path.replace(target)
            tmp_path = None

        out.ok = True
        out.path = str(target)
        out.sha256 = sha
        out.size = size
        out.reason = ""
        return out
    except httpx.HTTPError as exc:
        out.reason = f"网络错误：{type(exc).__name__}: {exc}"[:200]
        return out
    except Exception as exc:  # noqa: BLE001
        out.reason = f"下载失败：{type(exc).__name__}: {exc}"[:200]
        return out
    finally:
        out.elapsed = time.monotonic() - started
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def candidate_links(links: list[str], page_url: str, *, limit: int = 3) -> list[str]:
    """从页面里挑出值得下载的链接：优先 .apk，其次下载页。"""
    out: list[str] = []
    for link in links:
        if not link or link.startswith(("data:", "javascript:")):
            continue
        low = link.lower()
        if ".apk" in low:
            out.append(link)
        elif any(k in low for k in ("download", "anzhuo", "android")):
            out.append(link)
    # 去重保序
    seen: set[str] = set()
    uniq = [x for x in out if not (x in seen or seen.add(x))]
    return uniq[:limit]
