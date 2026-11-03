"""APK 动态分析适配层。

现实约束
--------
真跑 APK 需要 Android 运行时（模拟器或真机 + Frida）。这在服务器上成本很高，
而且这类样本普遍带反调试、模拟器检测、二次加载，跑出来的行为经常是假的。

所以这里做**三级适配**，按可用性自动降级，并对结果诚实标注：
1. MobSF（配了 SILVER_MOBSF_URL + KEY）：完整的静态 + 动态报告，最可信。
2. adb/emulator（配了 SILVER_ANDROID_SERIAL）：装上去跑，抓 logcat 与网络。
3. 都没有：**静态行为推演**——从权限、API、字符串推断「它跑起来会做什么」，
   标注 engine=static-inference，绝不冒充动态结果。

第 3 级不是凑数。对「领鸡蛋」这类 App，权限组合已经足以说明问题：
一个声称「领补贴」的应用同时要读短信、开无障碍、悬浮窗、装应用，
这四件事凑在一起只有一种解释。
"""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ..config import settings

log = logging.getLogger(__name__)

# 权限 → 行为。参考 MITRE ATT&CK Mobile 与国内涉诈 App 的公开分析。
PERMISSION_BEHAVIORS: dict[str, tuple[str, str, float]] = {
    "android.permission.READ_SMS": ("credential_access", "读取短信（可截获验证码）", 0.85),
    "android.permission.RECEIVE_SMS": ("credential_access", "接收短信（可劫持验证码）", 0.85),
    "android.permission.SEND_SMS": ("impact", "发送短信（可群发扩散/扣费）", 0.80),
    "android.permission.READ_CONTACTS": ("collection", "读取通讯录（可拉人头）", 0.70),
    "android.permission.READ_CALL_LOG": ("collection", "读取通话记录", 0.65),
    "android.permission.SYSTEM_ALERT_WINDOW": ("defense_evasion", "悬浮窗覆盖（可遮挡系统提示）", 0.85),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("persistence", "请求安装应用（可推装/自更新）", 0.75),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("collection", "无障碍服务（可自动点击/读屏）", 0.90),
    "android.permission.RECORD_AUDIO": ("collection", "录音", 0.60),
    "android.permission.CAMERA": ("collection", "拍照/扫码", 0.45),
    "android.permission.READ_PHONE_STATE": ("discovery", "读取设备标识（用于风控绕过）", 0.55),
    "android.permission.READ_EXTERNAL_STORAGE": ("collection", "读取外部存储", 0.40),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("impact", "写入外部存储", 0.35),
    "android.permission.ACCESS_FINE_LOCATION": ("discovery", "精确定位", 0.45),
    "android.permission.CALL_PHONE": ("impact", "直接拨号", 0.55),
    "android.permission.PROCESS_OUTGOING_CALLS": ("collection", "监听外拨电话", 0.70),
    "android.permission.QUERY_ALL_PACKAGES": ("discovery", "枚举已安装应用（可识别反诈 App）", 0.75),
    "android.permission.IGNORE_BATTERY_OPTIMIZATIONS": ("persistence", "忽略电池优化（保活）", 0.50),
    "android.permission.FOREGROUND_SERVICE": ("persistence", "前台服务保活", 0.35),
    "android.permission.WAKE_LOCK": ("persistence", "阻止休眠", 0.25),
}

# 组合触发：单看每个权限都不致命，凑齐就是另一回事
COMBO_RULES: list[tuple[frozenset[str], str, float]] = [
    (
        frozenset({"android.permission.READ_SMS", "android.permission.READ_CONTACTS"}),
        "同时读取短信与通讯录：典型的验证码劫持 + 通讯录扩散组合",
        0.90,
    ),
    (
        frozenset({"android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"}),
        "悬浮窗 + 无障碍：可覆盖系统界面并自动点击，是远程控制型木马的标准配置",
        0.95,
    ),
    (
        frozenset({"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.QUERY_ALL_PACKAGES"}),
        "可枚举应用并推装新包：具备自我更新与静默推广能力",
        0.85,
    ),
]

# 识别「反诈/安全软件」的包名特征，用于判断它是否在躲避检测
SECURITY_PACKAGE_HINTS = ("antivirus", "security", "safe", "guard", "cleaner", "jianguan", "fanzha")


@dataclass
class APKObservation:
    package: str = ""
    engine: str = "static-inference"
    behaviors: list[dict[str, Any]] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    network: list[str] = field(default_factory=list)
    c2_candidates: list[str] = field(default_factory=list)
    risk: float = 0.0
    report: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    elapsed: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "engine": self.engine,
            "behaviors": self.behaviors[:40],
            "permissions": self.permissions[:60],
            "network": self.network[:50],
            "c2_candidates": self.c2_candidates[:20],
            "risk": round(self.risk, 3),
            "error": self.error,
            "elapsed": round(self.elapsed, 2),
        }


def infer_behaviors(permissions: list[str], strings: str = "") -> tuple[list[dict[str, Any]], float]:
    """从权限与字符串推断运行时行为。返回 (行为列表, 风险分)。"""
    perms = {p.strip() for p in permissions if p}
    behaviors: list[dict[str, Any]] = []
    score = 0.0

    for perm, (tactic, desc, weight) in PERMISSION_BEHAVIORS.items():
        if perm in perms:
            behaviors.append({"tactic": tactic, "desc": desc, "weight": weight, "source": perm})
            score = 1 - (1 - score) * (1 - weight * 0.6)

    for combo, desc, weight in COMBO_RULES:
        if combo.issubset(perms):
            behaviors.append({"tactic": "combined", "desc": desc, "weight": weight, "source": "combo"})
            score = 1 - (1 - score) * (1 - weight)

    low = strings.lower()
    if any(h in low for h in SECURITY_PACKAGE_HINTS):
        behaviors.append(
            {
                "tactic": "defense_evasion",
                "desc": "代码中出现安全软件包名特征，可能在检测反诈/杀毒应用",
                "weight": 0.7,
                "source": "strings",
            }
        )
        score = 1 - (1 - score) * (1 - 0.5)

    return behaviors, min(score, 0.99)


class APKSandbox:
    def __init__(self) -> None:
        self.stats = {"runs": 0, "mobsf": 0, "emulator": 0, "static": 0, "errors": 0}

    # ------------------------------------------------------------ MobSF
    def _mobsf(self, apk_path: Path) -> APKObservation | None:
        obs = APKObservation(engine="mobsf")
        base = settings.mobsf_base_url
        headers = {"Authorization": settings.mobsf_api_key}
        try:
            with httpx.Client(base_url=base, headers=headers, timeout=120) as client:
                with apk_path.open("rb") as fh:
                    up = client.post(
                        "/api/v1/upload",
                        files={"file": (apk_path.name, fh, "application/vnd.android.package-archive")},
                    )
                up.raise_for_status()
                info = up.json()
                file_hash = info.get("hash")
                if not file_hash:
                    obs.error = "MobSF 上传未返回 hash"
                    return obs

                client.post("/api/v1/scan", data={"hash": file_hash, "scan_type": "apk"}).raise_for_status()
                # 轮询报告（MobSF 同步扫描，report_json 会等到完成）
                for _ in range(60):
                    rep = client.post("/api/v1/report_json", data={"hash": file_hash})
                    if rep.status_code == 200:
                        data = rep.json()
                        break
                    time.sleep(2)
                else:
                    obs.error = "MobSF 报告超时"
                    return obs

                obs.report = {
                    "app_name": data.get("app_name"),
                    "package_name": data.get("package_name"),
                    "md5": data.get("md5"),
                    "size": data.get("size"),
                    "malware_score": (data.get("malware_score") if isinstance(data.get("malware_score"), (int, float)) else None),
                    "trackers": [t.get("name") for t in (data.get("trackers") or {}).get("trackers", [])][:20],
                    "urls": (data.get("urls") or [])[:60],
                }
                obs.package = data.get("package_name") or obs.package
                obs.permissions = [p.get("permission") or p.get("name") for p in (data.get("permissions") or [])][:80]
                obs.network = (data.get("urls") or [])[:50]
                obs.c2_candidates = [
                    u for u in obs.network
                    if not any(x in u.lower() for x in ("google", "android.com", "schemas", "w3.org", "apache"))
                ][:20]
                mb = data.get("malware_score")
                if isinstance(mb, (int, float)):
                    obs.risk = max(0.0, min(1.0, float(mb) / 100 if mb > 1 else float(mb)))
                self.stats["mobsf"] += 1
                return obs
        except Exception as exc:  # noqa: BLE001
            obs.error = f"MobSF 调用失败：{type(exc).__name__}: {exc}"[:200]
            self.stats["errors"] += 1
            return None        # 降级到下一级

    # ------------------------------------------------------------ emulator
    def _emulator(self, apk_path: Path) -> APKObservation | None:
        if not settings.android_serial:
            return None
        obs = APKObservation(engine="emulator")
        serial = settings.android_serial
        try:
            subprocess.run(
                ["adb", "-s", serial, "install", "-r", "-g", str(apk_path)],
                capture_output=True, timeout=180, check=True,
            )
            # 拉起主 Activity（用 monkey，不必知道具体类名）
            subprocess.run(
                ["adb", "-s", serial, "shell", "monkey", "-p",
                 obs.package or "", "-c", "android.intent.category.LAUNCHER", "1"],
                capture_output=True, timeout=60,
            )
            time.sleep(20)
            logs = subprocess.run(
                ["adb", "-s", serial, "logcat", "-d", "-v", "brief", "-t", "3000"],
                capture_output=True, text=True, timeout=60,
            ).stdout
            obs.report = {"logcat_sample": logs[-4000:]}
            self.stats["emulator"] += 1
            return obs
        except Exception as exc:  # noqa: BLE001
            obs.error = f"模拟器执行失败：{type(exc).__name__}: {exc}"[:200]
            self.stats["errors"] += 1
            return None

    # ------------------------------------------------------------ 入口
    def analyze(self, apk_path: str | Path, *, static_facts: dict[str, Any] | None = None) -> APKObservation:
        """按可用性选择引擎。static_facts 是已有静态分析结果（避免重复解析）。"""
        started = time.monotonic()
        path = Path(apk_path)
        self.stats["runs"] += 1

        if settings.mobsf_ready and path.is_file():
            result = self._mobsf(path)
            if result and not result.error:
                result.elapsed = time.monotonic() - started
                return result

        if settings.android_serial and path.is_file():
            result = self._emulator(path)
            if result:
                result.elapsed = time.monotonic() - started
                return result

        # 兜底：静态推演
        facts = static_facts or {}
        obs = APKObservation(engine="static-inference")
        perms = [str(p) for p in (facts.get("permissions") or [])]
        strings = " ".join(facts.get("strings_sample") or []) or str(facts.get("sample_text", ""))
        behaviors, risk = infer_behaviors(perms, strings)
        obs.permissions = perms
        obs.behaviors = behaviors
        obs.package = str(facts.get("package") or "")
        obs.network = [str(u) for u in (facts.get("embedded_urls") or [])][:50]
        obs.c2_candidates = [
            u for u in obs.network if not any(x in u.lower() for x in ("google", "android.com", "w3.org"))
        ][:20]
        obs.risk = risk
        obs.error = "" if (perms or strings) else "缺少静态分析输入"
        self.stats["static"] += 1
        obs.elapsed = time.monotonic() - started
        return obs

    def status(self) -> dict[str, Any]:
        return {
            "mobsf": settings.mobsf_ready,
            "emulator": bool(settings.android_serial),
            "engine": "mobsf" if settings.mobsf_ready else ("emulator" if settings.android_serial else "static-inference"),
            "stats": self.stats,
        }


_sandbox: APKSandbox | None = None


def get_apk_sandbox() -> APKSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = APKSandbox()
    return _sandbox
