"""测试夹具与样本构造器。

这里的 AXML 构造器不是玩具：它按 ResourceTypes.h 的真实布局生成二进制 AndroidManifest，
用来验证解析器的字节偏移是否算对。没有它，解析器只能靠「跑真实样本不报错」来验证，
而那种验证证明不了正确性。
"""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest


def _string_pool(strings: list[str]) -> bytes:
    offsets: list[int] = []
    blob = b""
    for s in strings:
        raw = s.encode("utf-8")
        offsets.append(len(blob))
        # UTF-8 风格字符串池需要两个长度前缀：字符数 + 字节数
        blob += bytes([len(s)]) + bytes([len(raw)]) + raw + b"\x00"
    while len(blob) % 4:
        blob += b"\x00"

    count = len(strings)
    strings_start = 0x1C + 4 * count
    size = 0x1C + 4 * count + len(blob)
    header = struct.pack("<HHI", 0x0001, 0x001C, size)
    body = struct.pack("<IIIII", count, 0, 0x100, strings_start, 0)
    return header + body + struct.pack(f"<{count}I", *offsets) + blob


def _start_element(name_idx: int, attrs: list[tuple[int, int]], line: int = 1) -> bytes:
    n = len(attrs)
    size = 16 + 20 + 20 * n
    head = struct.pack("<HHI", 0x0102, 0x0010, size)
    node = struct.pack("<II", line, 0xFFFFFFFF)
    ext = struct.pack("<II", 0xFFFFFFFF, name_idx) + struct.pack("<HHHHHH", 20, 20, n, 0, 0, 0)
    body = b"".join(
        struct.pack("<IIIHBBI", 0xFFFFFFFF, an, 0xFFFFFFFF, 20, 0, 0x03, av) for an, av in attrs
    )
    return head + node + ext + body


def _end_element(name_idx: int, line: int = 1) -> bytes:
    return (
        struct.pack("<HHI", 0x0103, 0x0010, 24)
        + struct.pack("<II", line, 0xFFFFFFFF)
        + struct.pack("<II", 0xFFFFFFFF, name_idx)
    )


def build_manifest(package: str, permissions: list[str]) -> bytes:
    strings = ["manifest", "package", "uses-permission", "name", package, *permissions]
    index = {s: i for i, s in enumerate(strings)}

    chunks = _string_pool(strings)
    chunks += _start_element(index["manifest"], [(index["package"], index[package])])
    for perm in permissions:
        chunks += _start_element(index["uses-permission"], [(index["name"], index[perm])])
        chunks += _end_element(index["uses-permission"])
    chunks += _end_element(index["manifest"])

    return struct.pack("<HHI", 0x0003, 0x0008, 8 + len(chunks)) + chunks


def build_apk(
    path: Path,
    *,
    package: str = "com.example.yanglao",
    permissions: list[str] | None = None,
    dex_text: str = "",
    html: str = "",
) -> Path:
    permissions = permissions or [
        "android.permission.INTERNET",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ]

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", build_manifest(package, permissions))
        zf.writestr("classes.dex", b"dex\n035\x00" + dex_text.encode("utf-8"))
        zf.writestr("META-INF/CERT.RSA", b"\x30\x82" + b"CN=Android Debug,O=Android,C=US" + b"\x00" * 40)
        if html:
            zf.writestr("assets/index.html", html.encode("utf-8"))
    return path


@pytest.fixture
def fresh_db(tmp_path, monkeypatch):
    """每个用例一个独立数据库，避免相互污染。"""
    from silver_sentinel.config import settings
    from silver_sentinel.db import get_engine, reset_engine
    from silver_sentinel.models import Base

    evidence = tmp_path / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)

    settings.data_dir = tmp_path
    settings.db_url = f"sqlite:///{tmp_path / 'test.db'}"
    settings.allow_network = False
    settings.llm_enabled = False
    monkeypatch.setenv("SILVER_ALLOW_NETWORK", "0")

    reset_engine(settings.db_url)
    Base.metadata.create_all(get_engine())
    return tmp_path
