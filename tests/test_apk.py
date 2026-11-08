"""APK 静态分析：AXML 解析、权限提取、关键特征识别。"""

from __future__ import annotations

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


def test_candidate_tier_allows_large_apk(monkeypatch, fresh_db):
    """候选档原来只让下 10MB，而真实涉老诈骗的包普遍 15~40MB。

    线上实测：nuanyang 的 16.5MB 包在 candidate 档被直接拒，
    「一个 APK 也没有」有一半来自这个阈值。
    """
    seen: dict[str, int] = {}

    class _R:
        ok = False
        reason = "stub（本用例只验证阈值）"
        url = "https://x/a.apk"

    def fake_fetch(url, max_bytes, referer=""):
        seen["max_bytes"] = max_bytes
        return _R()

    monkeypatch.setattr("silver_sentinel.capture.apk_fetch.fetch", fake_fetch)

    from silver_sentinel.capture import _download_apk_locked
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset

    with session_scope() as s:
        a = Asset(kind="domain", value="x.test", normalized="x.test", tier="candidate",
                  score=0.0, verdict="insufficient", meta={})
        s.add(a)
        s.flush()
        aid = a.id

    _download_apk_locked(aid, ["https://x/a.apk"], "https://x/", "candidate")
    assert seen["max_bytes"] >= 40 * 1024 * 1024, "16.5MB 的包必须放得下"


def test_dangerous_apk_promotes_asset(fresh_db):
    """带无障碍 + 装包权限的包能接管手机，不该还停在候选池等页面话术。

    线上实测：com.nuanyangcare.app 有 6 个危险权限和无障碍服务，
    但页面只写了「智慧养老服务平台」——光看页面，它像个普通宣传页。
    """
    from silver_sentinel.capture import _apply_apk_signal
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset

    with session_scope() as s:
        a = Asset(kind="domain", value="nuanyang.test", normalized="nuanyang.test",
                  tier="candidate", score=30.0, verdict="suspicious",
                  meta={"apk_analysis": {
                      "package_name": "com.nuanyangcare.app",
                      "dangerous_permission_count": 6,
                      "has_accessibility": True,
                      "permissions": ["android.permission.REQUEST_INSTALL_PACKAGES"],
                  }})
        s.add(a)
        s.flush()
        aid = a.id

    _apply_apk_signal(aid)

    with session_scope() as s:
        a = s.get(Asset, aid)
        assert (a.meta or {}).get("facts", {}).get("apk_danger") is True
        assert a.tier in ("watch", "candidate"), "至少不能掉档"
        assert a.tier == "watch", "高危安装包应当直接进盯防"
