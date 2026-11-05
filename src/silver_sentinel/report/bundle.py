"""证据包：把散落的证据固化成一份能直接交出去的材料。

产出三样东西，各有各的用处：

* ``<host>-证据包.pdf``  人读。监管人员打开就能看到「谁、做了什么、证据在哪」。
* ``<host>-证据包.zip``  机读兼归档。含 PDF、页面截图、HTML 原文、网络请求流水、manifest。
* ``manifest.json``      校验用。逐文件 SHA-256 + 证据链首尾哈希，换一个字节就对不上。

附件体积是硬约束：12377 单文件与总量都有限制，所以截图统一压到 1100px 宽、
HTML 超过 4MB 截断并在 manifest 里注明「truncated」——**宁可标注截断，也不静默丢数据**。
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..domain import CATEGORY_LABELS
from .narrative import Ctx, _fmt

KIND_LABELS = {
    "domain": "域名",
    "url": "网址",
    "apk": "安卓应用",
    "account": "网络账号",
    "wechat": "微信公众号",
    "qq": "QQ 账号",
    "phone": "电话号码",
    "wallet": "收款地址",
    "sample": "话术样本",
}

MAX_HTML_BYTES = 4 * 1024 * 1024
MAX_IMG_WIDTH = 1100


@dataclass
class Built:
    pdf: bytes
    zip_bytes: bytes
    manifest: dict[str, Any]
    pdf_name: str
    zip_name: str


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _shrink(path: Path) -> tuple[bytes, str]:
    """截图压缩；失败就原样返回，不因为压缩问题丢证据。"""
    raw = path.read_bytes()
    try:
        from PIL import Image

        img = Image.open(io.BytesIO(raw))
        if img.width > MAX_IMG_WIDTH:
            ratio = MAX_IMG_WIDTH / img.width
            img = img.resize((MAX_IMG_WIDTH, int(img.height * ratio)), Image.LANCZOS)
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=82, optimize=True)
        return buf.getvalue(), "image/jpeg"
    except Exception:  # noqa: BLE001 - 压缩是优化，不是必要条件
        return raw, "image/png"


def _css() -> str:
    return """
    @page { size: A4; margin: 18mm 16mm 16mm 16mm;
            @bottom-center { content: "第 " counter(page) " / " counter(pages) " 页"; font-size: 9px; color: #888; } }
    * { box-sizing: border-box; }
    body { font-family: "Noto Sans CJK SC", "Noto Sans SC", sans-serif; font-size: 10.5pt;
           color: #1a1a1a; line-height: 1.62; }
    h1 { font-size: 19pt; margin: 0 0 4px; letter-spacing: .5px; }
    .sub { color: #666; font-size: 9.5pt; margin-bottom: 18px; }
    .band { border-left: 4px solid #b3261e; padding: 10px 14px; background: #fdf6f5; margin: 14px 0 18px; }
    .band b { color: #b3261e; }
    h2 { font-size: 12.5pt; margin: 22px 0 8px; padding-bottom: 4px; border-bottom: 1px solid #e2e2e2; }
    table { width: 100%; border-collapse: collapse; font-size: 9.5pt; margin: 8px 0 4px; }
    th, td { border: 1px solid #dcdcdc; padding: 5px 8px; text-align: left; vertical-align: top; }
    th { background: #f4f4f4; font-weight: 600; width: 26%; }
    .mono { font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt; word-break: break-all; }
    .shot { margin: 10px 0 16px; page-break-inside: avoid; }
    .shot img { width: 100%; border: 1px solid #d8d8d8; }
    .cap { font-size: 8.5pt; color: #666; margin-top: 3px; }
    .body-text { white-space: pre-wrap; background: #fafafa; border: 1px solid #e8e8e8;
                 padding: 10px 12px; font-size: 10pt; }
    .foot { margin-top: 26px; padding-top: 10px; border-top: 1px dashed #ccc;
            font-size: 8.5pt; color: #777; }
    .seal { margin-top: 8px; font-size: 8.5pt; color: #444; }
    """


def pdf_html(ctx: Ctx, channel: Any, body: str, shots: list[tuple[str, bytes, str]], manifest: dict[str, Any]) -> str:
    import base64
    import html as _h

    a = ctx.asset
    e = _h.escape
    rows = [
        ("被举报标识", a.value),
        ("规范化标识", a.normalized or a.value),
        ("对象类型", KIND_LABELS.get(getattr(a, "kind", ""), getattr(a, "kind", ""))),
        ("首次发现", _fmt(getattr(a, "first_seen", None))),
        ("最近核查", _fmt(getattr(a, "last_seen", None))),
        ("系统研判", f"{getattr(a, 'verdict', '')}（风险分 {getattr(a, 'score', 0):.1f}，"
                     f"置信 {getattr(a, 'confidence', 0):.2f}）"),
        ("建议类别", ctx.harm.label if ctx.harm else "—"),
        ("拟提交渠道", channel.name),
        ("解析地址", ", ".join(str(i) for i in (ctx.facts.get("ips") or [])[:5]) or "未获取"),
        ("注册商", str(ctx.facts.get("registrar") or "未获取")),
        ("ICP 备案", {
            "none": "无备案记录",
            "ok": f"{getattr(a, 'icp_license', '') or '已备案'}（{getattr(a, 'icp_entity', '') or '—'}）",
            "unknown": "未查询到",
        }.get(getattr(a, "icp_status", "unknown"), "未查询到")),
        ("材料编号", manifest.get("bundle_id", "")),
        ("生成时间", manifest.get("generated_at", "")),
    ]
    tr = "\n".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in rows)

    ev_rows = []
    for i, ev in enumerate(ctx.evidence[:20], 1):
        ev_rows.append(
            "<tr>"
            f"<td>{i}</td><td>{e(str(getattr(ev, 'kind', '')))}</td>"
            f"<td>{e(_fmt(getattr(ev, 'captured_at', None)))}</td>"
            f"<td class='mono'>{e(ev.sha256)}</td>"
            f"<td>{e((getattr(ev, 'note', '') or '')[:70])}</td>"
            "</tr>"
        )
    ev_table = (
        "<table><tr><th style='width:5%'>#</th><th style='width:14%'>类型</th>"
        "<th style='width:16%'>采集时间</th><th style='width:38%'>SHA-256</th><th>说明</th></tr>"
        + "".join(ev_rows) + "</table>"
        if ev_rows else "<p>暂未归档证据。</p>"
    )

    shot_html = []
    for i, (name, data, mime) in enumerate(shots[:6], 1):
        b64 = base64.b64encode(data).decode()
        shot_html.append(
            f"<div class='shot'><img src='data:{mime};base64,{b64}'/>"
            f"<div class='cap'>图 {i}　页面首屏截图　（SHA-256 "
            f"{_h.escape(_sha(data)[:32])}…）</div></div>"
        )

    sig_rows = "".join(
        f"<tr><td>{e(getattr(s, 'title', ''))}</td>"
        f"<td>{e(CATEGORY_LABELS.get(getattr(s, 'category', ''), getattr(s, 'category', '')))}</td>"
        f"<td>{getattr(s, 'weight', 0):.0f}</td><td>{e((getattr(s, 'detail', '') or '')[:150])}</td></tr>"
        for s in ctx.signals[:12]
    )

    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<style>{_css()}</style></head><body>

<h1>涉网违法信息举报材料</h1>
<div class="sub">{e(channel.name)}　·　{_h.escape(manifest.get("bundle_id", ""))}　·　
{_h.escape(manifest.get("generated_at", ""))}</div>

<div class="band">
<b>材料说明</b>　本材料由举报人依据实际访问记录与公开查询结果整理，逐条可核查。
文中所述为线索与事实，不构成法律定性，最终认定以有权机关调查结果为准。
全部证据已按采集顺序做 SHA-256 固化，任一字节改动都会导致校验失败。
</div>

<h2>一、被举报对象</h2>
<table>{tr}</table>

<h2>二、举报正文（可直接粘贴到受理表单）</h2>
<div class="body-text">{e(body)}</div>

<h2>三、判定依据</h2>
<table>
<tr><th style="width:32%">特征</th><th style="width:14%">类别</th><th style="width:8%">权重</th><th>说明</th></tr>
{sig_rows or "<tr><td colspan='4'>未命中规则信号</td></tr>"}
</table>

<h2>四、证据清单</h2>
{ev_table}

<h2>五、页面存证</h2>
{"".join(shot_html) or "<p>本次材料未附截图，可在控制台对目标重新执行动态取证。</p>"}

<h2>六、校验方法</h2>
<p class="mono">sha256sum -c manifest.sha256</p>
<p>证据链首条：<span class="mono">{e(manifest.get("chain_head", "") or "—")}</span><br/>
证据链末条：<span class="mono">{e(manifest.get("chain_tail", "") or "—")}</span></p>

<div class="foot">
生成工具：银发哨兵（Silver Sentinel）本地取证模块。本文件不含举报人以外的任何第三方个人信息；
页面截图中如出现他人信息，系目标站点自行公开展示。
</div>
</body></html>"""


def build(
    ctx: Ctx,
    channel: Any,
    body: str,
    bundle_id: str,
    out_dir: Path,
    evidence_paths: dict[str, Path],
) -> Built:
    out_dir.mkdir(parents=True, exist_ok=True)
    host = (ctx.asset.normalized or ctx.asset.value).replace("/", "_").replace(":", "_")[:60] or "target"
    pdf_name = f"{host}-举报材料-{bundle_id}.pdf"
    zip_name = f"{host}-证据包-{bundle_id}.zip"

    # ---- 截图（PDF 内嵌用压缩版，zip 里也放压缩版，避免包过大）
    shots: list[tuple[str, bytes, str]] = []
    shot_files: list[tuple[str, bytes]] = []
    for ev in ctx.evidence:
        if getattr(ev, "kind", "") != "screenshot":
            continue
        p = evidence_paths.get(str(getattr(ev, "sha256", "")))
        if not p or not p.exists():
            continue
        data, mime = _shrink(p)
        label = f"{getattr(ev, 'captured_at', '')}_{str(ev.sha256)[:8]}.jpg"
        shots.append((label, data, mime))
        shot_files.append((label, data))
        if len(shots) >= 6:
            break

    manifest: dict[str, Any] = {
        "bundle_id": bundle_id,
        "generated_at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
        "channel": {"id": channel.id, "name": channel.name, "entry_url": channel.entry_url},
        "target": {
            "kind": ctx.asset.kind,
            "value": ctx.asset.value,
            "normalized": ctx.asset.normalized,
        },
        "harm": {
            "type": ctx.harm.harm if ctx.harm else "",
            "label": ctx.harm.label if ctx.harm else "",
            "big": ctx.harm.big if ctx.harm else "",
            "small": ctx.harm.small if ctx.harm else "",
            "reason": ctx.harm.reason if ctx.harm else "",
        },
        "evidence": [
            {
                "kind": getattr(ev, "kind", ""),
                "sha256": ev.sha256,
                "chain_hash": getattr(ev, "chain_hash", ""),
                "captured_at": getattr(ev, "captured_at", None).isoformat() if getattr(ev, "captured_at", None) else "",
                "size": getattr(ev, "size", 0),
                "note": getattr(ev, "note", ""),
            }
            for ev in ctx.evidence
        ],
        "chain_head": ctx.evidence[0].chain_hash if ctx.evidence else "",
        "chain_tail": ctx.evidence[-1].chain_hash if ctx.evidence else "",
        "files": [],
        "truncated": [],
    }

    html = pdf_html(ctx, channel, body, shots, manifest)
    try:
        from weasyprint import HTML

        pdf_bytes = HTML(string=html).write_pdf()
    except Exception:  # noqa: BLE001 - 无 weasyprint 时退化为纯文本，不阻断流程
        pdf_bytes = (body + "\n\n" + json.dumps(manifest, ensure_ascii=False, indent=2)).encode("utf-8")
        manifest["truncated"].append("pdf-fallback")

    # ---- zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        zf.writestr(pdf_name, pdf_bytes)
        manifest["files"].append({"name": pdf_name, "sha256": _sha(pdf_bytes), "size": len(pdf_bytes)})

        for name, data in shot_files:
            arc = f"evidence/{name}"
            zf.writestr(arc, data)
            manifest["files"].append({"name": arc, "sha256": _sha(data), "size": len(data)})

        for ev in ctx.evidence:
            kind = getattr(ev, "kind", "")
            if kind not in {"page_html", "page_text", "network"}:
                continue
            p = evidence_paths.get(str(getattr(ev, "sha256", "")))
            if not p or not p.exists():
                continue
            data = p.read_bytes()
            if len(data) > MAX_HTML_BYTES:
                data = data[:MAX_HTML_BYTES]
                manifest["truncated"].append(f"{kind}:{ev.sha256[:12]}")
            arc = f"evidence/{kind}-{str(ev.sha256)[:12]}{p.suffix or '.bin'}"
            zf.writestr(arc, data)
            manifest["files"].append(
                {"name": arc, "sha256": _sha(data), "size": len(data),
                 "source_sha256": ev.sha256, "truncated": len(data) >= MAX_HTML_BYTES}
            )

        readme = (
            "本压缩包为举报证据包，由「银发哨兵」本地取证模块生成。\n\n"
            f"材料编号：{bundle_id}\n生成时间：{manifest['generated_at']}\n"
            f"被举报对象：{ctx.asset.value}\n\n"
            "核验方法：sha256sum -c manifest.sha256\n"
            "manifest.json 记录每个文件的 SHA-256 与证据链首尾哈希。\n"
        ).encode("utf-8")
        zf.writestr("README.txt", readme)
        manifest["files"].append({"name": "README.txt", "sha256": _sha(readme), "size": len(readme)})

        mj = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
        zf.writestr("manifest.json", mj)
        manifest["files"].append({"name": "manifest.json", "sha256": _sha(mj), "size": len(mj)})

        sums = "\n".join(f"{f['sha256']}  {f['name']}" for f in manifest["files"]) + "\n"
        zf.writestr("manifest.sha256", sums.encode("utf-8"))

    zip_bytes = buf.getvalue()
    (out_dir / pdf_name).write_bytes(pdf_bytes)
    (out_dir / zip_name).write_bytes(zip_bytes)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return Built(
        pdf=pdf_bytes,
        zip_bytes=zip_bytes,
        manifest=manifest,
        pdf_name=pdf_name,
        zip_name=zip_name,
    )
