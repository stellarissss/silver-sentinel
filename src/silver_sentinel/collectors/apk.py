"""APK 静态分析。

为什么以 APK 为核心：涉老诈骗的载体早已不是网页，而是「应用商店搜不到、
只能扫码装」的仿冒 App。网页可以下线，安装包会留在老人手机里继续跑。

实现要点：
- 自己解析二进制 AndroidManifest（AXML），不依赖 androguard，零重依赖；
- 解析失败时降级为正则扫字符串池 —— 权限名在 string pool 里是明文，几乎不会漏；
- 只读不执行，不联网，样本留在本地。
"""

from __future__ import annotations

import hashlib
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from ..normalize import extract_indicators, shingle_hash

MAX_SCAN_BYTES = 80 * 1024 * 1024

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.QUERY_ALL_PACKAGES",
}

PACKER_SIGNS = (
    "libjiagu", "libshell", "libmobisec", "libnesec", "libDexHelper",
    "libapp-protect", "libtup", "libkwscmm", "libsecexe", "libsecmain",
    "libexec.so", "libprotectClass", "libbaiduprotect", "libnqshield",
)

DANGEROUS_APIS = {
    "DexClassLoader": "动态加载 dex",
    "PathClassLoader": "动态加载 dex",
    "addJavascriptInterface": "WebView 暴露原生接口",
    "Runtime.exec": "执行系统命令",
    "getDeviceId": "读取设备标识",
    "getSubscriberId": "读取 SIM 卡标识",
    "SmsManager": "短信收发能力",
    "AccessibilityService": "无障碍服务",
    "setAccessibilityVolume": "无障碍服务",
    "MediaProjection": "屏幕录制",
    "requestScreenCapture": "屏幕录制",
    "ClipboardManager": "读取剪贴板",
}

_CN_RUN = re.compile(r"[\u4e00-\u9fff][\u4e00-\u9fff0-9A-Za-z，。！？、：；]{1,24}")
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{16,140}")
# 短的域名（guohui-vip.top 只有 14 字符）过不了 _ASCII_RUN 的 16 字符门槛，
# 而「App 指向哪个站」恰恰是最关键的一条关系。单独用域名形状捞一遍。
_DOMAINLIKE = re.compile(
    rb"(?<![a-zA-Z0-9.-])((?:[a-z0-9][a-z0-9-]{0,50}\.)+(?:top|xyz|cn|com|net|org|cc|vip|shop|site|online|club|icu|buzz|cyou|wang|xin|ltd|work|live|fun|info|me|io|co|app|link|tech|store|space|website|pro|ink|cloud|host|press|art|bar|rest|group|life|world|today|digital|studio|agency|solutions|services|systems|network|center|support|team|tools|works|zone|city|plus|one|run|dev|page|blog|wiki|media|news|video|music|photo|pics|design|email|chat|social|community|global|international|asia|mobi|tel|travel|jobs|careers|education|training|school|college|university|institute|academy|clinic|hospital|health|care|fitness|coffee|food|recipes|menu|bar|pub|beer|wine|shop|store|market|sale|deal|discount|coupon|gift|present|prize|award|win|bet|casino|poker|lottery|game|games|play|toys|kids|baby|family|home|house|property|estate|rent|lease|mortgage|loan|credit|finance|bank|money|cash|fund|invest|capital|trade|exchange|market|stock|bond|insurance|policy|claim|legal|law|attorney|lawyer|court|judge|police|security|guard|protect|safe|alarm|lock|key|door|window|roof|build|construction|repair|service|maintenance|clean|wash|laundry|dry|iron|sew|tailor|fashion|style|beauty|spa|massage|salon|hair|nail|makeup|skin|cosmetic|perfume|jewelry|watch|bag|shoe|cloth|wear|dress|shirt|pants|hat|cap|sock|glove|scarf|belt|tie|suit|coat|jacket|jean|short|skirt))(?![a-zA-Z0-9-])"
)
_URL = re.compile(rb"https?://[\x21-\x7e]{4,160}")
_PERM = re.compile(r"android\.permission\.[A-Z_0-9]{3,60}")


# ---------------------------------------------------------------- AXML


class _StringPool:
    def __init__(self, data: bytes, off: int, header_size: int) -> None:
        self.data = data
        self.utf8 = False
        self.strings: list[str] = []
        try:
            count, _style_count, flags, strings_start, _styles_start = struct.unpack_from("<IIIII", data, off + 8)
            self.utf8 = bool(flags & 0x100)
            offsets = struct.unpack_from(f"<{count}I", data, off + header_size)
            base = off + strings_start
            end = min(len(data), off + struct.unpack_from("<I", data, off + 4)[0])
            for idx in offsets:
                pos = base + idx
                if pos >= end:
                    self.strings.append("")
                    continue
                self.strings.append(self._read(pos, end))
        except (struct.error, IndexError, UnicodeDecodeError):
            self.strings = []

    def _read(self, pos: int, end: int) -> str:
        data = self.data
        if self.utf8:
            n = data[pos]
            pos += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[pos]
                pos += 1
            b = data[pos]
            pos += 1
            if b & 0x80:
                b = ((b & 0x7F) << 8) | data[pos]
                pos += 1
            return data[pos : min(pos + b, end)].decode("utf-8", "replace")
        n = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
            pos += 2
        return data[pos : min(pos + n * 2, end)].decode("utf-16-le", "replace")

    def get(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""


def parse_manifest(data: bytes) -> dict[str, Any]:
    """解析二进制 AndroidManifest.xml，取包名、权限、组件数。"""
    result: dict[str, Any] = {"package": "", "permissions": [], "components": 0, "ok": False}
    if len(data) < 16 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        return result

    pool: _StringPool | None = None
    off = 8
    total = len(data)
    permissions: list[str] = []
    components = 0
    depth = 0

    while off + 8 <= total:
        ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
        if csize < 8 or off + csize > total:
            break

        if ctype == 0x0001:
            pool = _StringPool(data, off, hsize)
        elif ctype == 0x0102 and pool is not None:
            try:
                p = off + 8
                _line, _comment = struct.unpack_from("<II", data, p)
                p += 8
                _ns, name_idx = struct.unpack_from("<II", data, p)
                p += 8
                attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, p)
                tag = pool.get(name_idx)
                # attributeStart 是相对「node 结束处（即 ns 字段）」的偏移，
                # node 本身 16 字节（8 头 + 4 行号 + 4 注释），所以基准是 off+16。
                attrs_off = off + 16 + attr_start
                if attr_size < 20:
                    attr_size = 20
                attrs: dict[str, Any] = {}
                for i in range(attr_count):
                    ap = attrs_off + i * (attr_size or 20)
                    if ap + 20 > total:
                        break
                    a_ns, a_name, a_raw, _a_size, _res0, a_type, a_data = struct.unpack_from("<IIIHBBI", data, ap)
                    key = pool.get(a_name)
                    if a_type == 0x03:
                        attrs[key] = pool.get(a_data)
                    elif a_type == 0x12:
                        attrs[key] = bool(a_data)
                    else:
                        attrs[key] = a_data

                if depth == 0 and tag == "manifest":
                    result["package"] = str(attrs.get("package", "") or "")
                elif tag == "uses-permission":
                    perm = str(attrs.get("name", "") or "")
                    if perm:
                        permissions.append(perm)
                elif tag in {"activity", "service", "receiver", "provider"}:
                    components += 1
                depth += 1
            except (struct.error, IndexError):
                pass
        elif ctype == 0x0103:
            depth = max(0, depth - 1)

        off += csize

    result["permissions"] = sorted(set(permissions))
    result["components"] = components
    result["ok"] = bool(result["package"] or permissions)
    return result


# ---------------------------------------------------------------- 证书


def _cert_info(zf: zipfile.ZipFile) -> dict[str, Any]:
    info: dict[str, Any] = {"cert_sha256": "", "debug_signed": False, "issuer": ""}
    certs = [n for n in zf.namelist() if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA", ".DSA", ".EC"))]
    if not certs:
        return info

    raw = zf.read(certs[0])
    info["cert_sha256"] = hashlib.sha256(raw).hexdigest()
    info["debug_signed"] = b"Android Debug" in raw or b"androiddebugkey" in raw

    try:  # 证书 DN 在 DER 中以 UTF8String/PrintableString 明文存在，直接捞
        text = raw.decode("latin-1")
        match = re.search(r"CN=([^,\x00-\x1f]{1,64})", text)
        if match:
            info["issuer"] = match.group(1)
    except Exception:
        pass
    return info


# ---------------------------------------------------------------- 主流程


def _scan_blobs(zf: zipfile.ZipFile) -> dict[str, Any]:
    urls: set[str] = set()
    _seen_domains: set[str] = set()
    cn_chunks: list[str] = []
    ascii_chunks: list[str] = []
    apis: set[str] = set()
    packers: set[str] = set()
    dex_count = 0
    total = 0
    html_parts: list[str] = []

    for item in zf.infolist():
        name = item.filename
        lower = name.lower()
        if item.file_size > 24 * 1024 * 1024:
            continue
        if not (
            lower.endswith(".dex")
            or lower.endswith(".so")
            or lower.endswith(".xml")
            or lower.endswith(".html")
            or lower.endswith(".js")
            or lower == "resources.arsc"
        ):
            continue
        if total > MAX_SCAN_BYTES:
            break

        try:
            blob = zf.read(name)
        except (KeyError, RuntimeError, OSError):
            continue
        total += len(blob)

        if lower.endswith(".dex"):
            dex_count += 1
        if lower.endswith(".so"):
            base = lower.rsplit("/", 1)[-1]
            if any(sign in base for sign in PACKER_SIGNS):
                packers.add(base)

        for match in _URL.findall(blob):
            urls.add(match.decode("latin-1", "ignore"))

        # dex 里的钱包地址、手机号、包名都是 ASCII，单独收集一段供指标抽取
        if lower.endswith(".dex"):
            if len(ascii_chunks) < 1200:
                for chunk in _ASCII_RUN.findall(blob)[:400]:
                    ascii_chunks.append(chunk.decode("latin-1", "ignore"))
            # 裸域名单独捞，不受 16 字符阈值影响
            for match in _DOMAINLIKE.findall(blob)[:600]:
                candidate = match.decode("latin-1", "ignore").lower()
                if len(candidate) >= 5 and candidate not in _seen_domains:
                    _seen_domains.add(candidate)
                    urls.add(candidate)

        if lower.endswith((".html", ".htm")):
            html_parts.append(blob.decode("utf-8", "ignore")[:20000])

        if lower.endswith(".dex"):
            for api, label in DANGEROUS_APIS.items():
                if api.encode() in blob:
                    apis.add(label)
            for chunk in _CN_RUN.findall(blob.decode("utf-8", "ignore")):
                if len(cn_chunks) < 4000:
                    cn_chunks.append(chunk)

    return {
        "urls": sorted(urls),
        "cn_chunks": cn_chunks,
        "ascii_chunks": ascii_chunks,
        "apis": apis,
        "packers": packers,
        "dex_count": dex_count,
        "html": "\n".join(html_parts),
    }


def _locate_manifest(zf: zipfile.ZipFile, names: list[str]) -> tuple[str, dict[str, Any], bool]:
    """找出真正的 AndroidManifest.xml，并判断这个包有没有在做「反分析」。

    返回 (选中的条目名, 解析结果, 是否对抗)。
    对抗特征（命中任一即 True）：
      - 存在名为 `AndroidManifest.xml/` 的目录（正常 APK 不会把 manifest 做成目录）
      - 根目录有大小写变体（ANDROIDMANIFEST.XML）当诱饵
      - 所有候选都解析不出包名
    """
    lowered = [n for n in names if n.lower() == "androidmanifest.xml"]
    dirs = [n for n in names if n.lower().startswith("androidmanifest.xml/")]
    decoys = [n for n in names if n.upper() == "ANDROIDMANIFEST.XML"]
    obfuscated = bool(dirs)

    # 候选按体积升序：真 manifest 很少超过 2MB，加密块和诱饵往往更大
    cands = [n for n in lowered if not n.endswith("/")]
    try:
        cands.sort(key=lambda n: zf.getinfo(n).file_size)
    except KeyError:
        pass

    for name in cands:
        try:
            info = zf.getinfo(name)
            if info.file_size > 8 * 1024 * 1024:  # 8MB 的 manifest 不可能是真的
                continue
            parsed = parse_manifest(zf.read(name))
        except Exception:  # noqa: BLE001 单个候选坏了就试下一个
            continue
        if parsed.get("ok") and parsed.get("package"):
            return name, parsed, obfuscated or bool(decoys)

    return (cands[0] if cands else ""), {}, True


def analyze(path: str | Path, extra_keywords: list[str] | None = None) -> dict[str, Any]:
    """返回 {facts, text, urls, keywords, template_hash, sha256}。"""
    path = Path(path)
    raw = path.read_bytes()
    file_sha = hashlib.sha256(raw).hexdigest()

    facts: dict[str, Any] = {
        "file_sha256": file_sha,
        "file_size": len(raw),
        "package_name": "",
        "permissions": [],
        "dangerous_permission_count": 0,
        "has_accessibility": False,
        "has_overlay": False,
        "has_dynamic_loading": False,
        "requests_install_packages": False,
        "wallet_addresses": [],
        "debug_signed": False,
        "has_js_bridge": False,
        "packer": "",
        "dex_count": 0,
        "apk_ok": False,
        # 反分析痕迹：manifest 被做成目录 / 换了大小写当诱饵 / 加密
        "manifest_obfuscated": False,
    }

    text_parts: list[str] = []
    urls: list[str] = []
    keywords: list[str] = []
    template_hash = ""

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            # `AndroidManifest.xml` 被做成目录、真 manifest 换成大写塞在别处——
            # 实测 26537.net 分发的 84MB 包就是这么干的：根目录有个 34KB 的
            # 加密 `ANDROIDMANIFEST.XML`，而 `AndroidManifest.xml/` 底下塞了
            # 几百个假 xml 当诱饵。按名字取第一个会拿到加密块，解析全空。
            manifest_name, manifest, obfuscated = _locate_manifest(zf, names)
            facts["manifest_obfuscated"] = obfuscated

            blob_info = _scan_blobs(zf)
            cert = _cert_info(zf)

            permissions = set(manifest.get("permissions") or [])
            if not permissions and manifest_name:  # 兜底：直接扫字符串池
                raw_manifest = zf.read(manifest_name)
                permissions = set(_PERM.findall(raw_manifest.decode("latin-1", "ignore")))

            danger = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
            apis = blob_info["apis"]

            facts.update(
                {
                    "package_name": manifest.get("package", "") or "",
                    "permissions": sorted(permissions),
                    "dangerous_permission_count": len(danger),
                    "has_accessibility": any("ACCESSIBILITY" in p for p in permissions) or "无障碍服务" in apis,
                    "has_overlay": "android.permission.SYSTEM_ALERT_WINDOW" in permissions,
                    "has_dynamic_loading": "动态加载 dex" in apis,
                    "requests_install_packages": "android.permission.REQUEST_INSTALL_PACKAGES" in permissions,
                    "debug_signed": cert["debug_signed"],
                    "has_js_bridge": "WebView 暴露原生接口" in apis,
                    "packer": ",".join(sorted(blob_info["packers"])),
                    "dex_count": blob_info["dex_count"],
                    "cert_sha256": cert["cert_sha256"],
                    "apk_ok": bool(manifest.get("ok")),
                }
            )

            urls = blob_info["urls"]
            text_parts.extend(urls[:300])
            text_parts.extend(blob_info["cn_chunks"][:1200])
            text_parts.extend(blob_info["ascii_chunks"][:1200])
            if blob_info["html"]:
                text_parts.append(blob_info["html"][:20000])

            combined = "\n".join(text_parts)
            indicators = extract_indicators(combined)
            facts["wallet_addresses"] = indicators["wallets"]

            for kw in extra_keywords or []:
                if kw and kw in combined:
                    keywords.append(kw)

            template_hash = shingle_hash(blob_info["html"] or combined[:5000])

    except (zipfile.BadZipFile, OSError):
        facts["apk_ok"] = False
        return {
            "facts": facts,
            "text": "",
            "urls": [],
            "keywords": [],
            "template_hash": "",
            "sha256": file_sha,
            "error": "不是有效的 APK/ZIP 文件",
        }

    return {
        "facts": facts,
        "text": "\n".join(text_parts)[:120_000],
        "urls": urls,
        "keywords": keywords,
        "template_hash": template_hash,
        "sha256": file_sha,
    }
