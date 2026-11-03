"""APK 静态分析：AXML 解析、权限提取、关键特征识别。"""

from __future__ import annotations

import pytest

from silver_sentinel.collectors.apk import analyze, parse_manifest
from tests.conftest import build_apk, build_manifest


def test_parse_manifest_reads_package_and_permissions():
    raw = build_manifest(
        "com.guohui.minsheng",
        ["android.permission.INTERNET", "android.permission.READ_SMS", "android.permission.RECORD_AUDIO"],
    )
    parsed = parse_manifest(raw)

    assert parsed["ok"] is True
    assert parsed["package"] == "com.guohui.minsheng"
    assert "android.permission.READ_SMS" in parsed["permissions"]
    assert "android.permission.RECORD_AUDIO" in parsed["permissions"]
    assert len(parsed["permissions"]) == 3


def test_parse_manifest_rejects_non_axml():
    assert parse_manifest(b"<manifest package='x'/>")["ok"] is False
    assert parse_manifest(b"")["ok"] is False


def test_analyze_flags_dangerous_permissions(tmp_path):
    apk = build_apk(tmp_path / "a.apk")
    result = analyze(apk)
    facts = result["facts"]

    assert facts["apk_ok"] is True
    assert facts["package_name"] == "com.example.yanglao"
    assert facts["has_accessibility"] is True
    assert facts["has_overlay"] is True
    assert facts["requests_install_packages"] is True
    assert facts["dangerous_permission_count"] >= 3
    assert facts["debug_signed"] is True
    assert facts["cert_sha256"]


def test_analyze_extracts_wallet_and_scam_language(tmp_path):
    dex = (
        "请使用 USDT-TRC20 充值，收款地址 TQn9Y2khEsLJW1ChVWFMSMeRDow5KcbLSE 。"
        "免费领鸡蛋，专家义诊，国家补贴发放。"
        "https://guohui-minsheng.top/reg?invite=1"
    )
    apk = build_apk(tmp_path / "b.apk", dex_text=dex)
    result = analyze(apk, extra_keywords=["免费领鸡蛋", "专家义诊"])

    assert "免费领鸡蛋" in result["keywords"]
    assert result["facts"]["wallet_addresses"], "应识别出 TRON 地址"
    assert any("guohui-minsheng.top" in u for u in result["urls"])


def test_analyze_handles_broken_zip(tmp_path):
    path = tmp_path / "broken.apk"
    path.write_bytes(b"PK\x03\x04not really a zip")
    result = analyze(path)
    assert result["facts"]["apk_ok"] is False
    assert "error" in result


def test_template_hash_stable_across_identical_pages(tmp_path):
    html = "<html><div>国家惠民补贴 领取养老补贴 下载注册</div></html>"
    a = analyze(build_apk(tmp_path / "c1.apk", html=html))
    b = analyze(build_apk(tmp_path / "c2.apk", html=html))
    assert a["template_hash"] == b["template_hash"]
    assert a["template_hash"] != ""
