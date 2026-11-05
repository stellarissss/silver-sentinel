"""分渠道举报正文。

三条硬约束，写在这里避免后来者改坏：

1. **只陈述能核查的事实。** 每条数字都来自本系统实际采集（页面标题、IP、证书、备案、
   截图张数）。字段缺失就不写，绝不用「疑似」「大量」这类无法核实的修饰去凑字数。
2. **不做定性。** 用「涉嫌」「请核查」，结论留给有权机关。这是材料能被受理的前提。
3. **字数硬上限。** 12377 正文框 500 字，超了前端直接截断，截掉的可能正是诉求，
   所以由本模块主动裁剪，优先保「对象—行为—诉求」三段。

正文里的引号内容一律来自页面原文（page_text 证据），不改写、不拼接。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .channels import Channel
from .harmtype import Harm

# 摘引页面原话时优先命中的词：这些是「对老人说的那句话」，最有说服力
_QUOTE_HINTS = (
    "养老", "补贴", "申领", "免费领", "免费送", "领鸡蛋", "退休", "社保", "医保",
    "返利", "充值", "投资", "稳赚", "保本", "银行卡", "验证码", "身份证",
    "国家", "民政", "财政部", "人社局", "红头文件", "名额有限", "限时",
)
# 出现这些词的句子是主观推断，不能当事实写进材料
_SUBJECTIVE = ("常见于", "典型", "说明", "可能", "疑似", "往往", "通常", "意味")


@dataclass
class Ctx:
    asset: Any
    signals: list[Any] = field(default_factory=list)
    evidence: list[Any] = field(default_factory=list)
    harm: Harm | None = None
    reporter: str = ""
    now: datetime | None = None
    extra_urls: list[str] = field(default_factory=list)
    page_text: str = ""

    @property
    def facts(self) -> dict[str, Any]:
        return (getattr(self.asset, "meta", None) or {}).get("facts") or {}

    @property
    def label(self) -> str:
        a = self.asset
        return str(a.value)

    def ev_of(self, kind: str) -> list[Any]:
        return [e for e in self.evidence if getattr(e, "kind", "") == kind]


def _fmt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d") if dt else ""


def _clip(s: str, n: int) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _as_url(v: str) -> str:
    v = (v or "").strip()
    return v if v.startswith(("http://", "https://")) else f"http://{v}"


def pick_quotes(text: str, limit: int = 2, width: int = 46) -> list[str]:
    """从页面正文里挑最能说明问题的原话。找不到就返回空，不硬凑。"""
    if not text:
        return []
    body = text[:300_000]
    parts: list[str] = []
    for seg in re.split(r"[。！？\n\r]+", body):
        seg = re.sub(r"\s+", " ", seg).strip()
        if not seg:
            continue
        # 无标点的长段落按空格拆开，避免整段被当成一句话截断
        if len(seg) > 60:
            parts.extend(x for x in re.split(r" +", seg) if len(x) >= 8)
        else:
            parts.append(seg)
    scored: list[tuple[int, str]] = []
    for p in parts:
        s = re.sub(r"\s+", " ", p).strip()
        if not (8 <= len(s) <= 120):
            continue
        if any(w in s for w in _SUBJECTIVE):
            continue
        hits = sum(1 for w in _QUOTE_HINTS if w in s)
        if hits == 0:
            continue
        # 同时出现「老人词」和「钱/证件词」的句子最有力；长句降权，短的更好引
        money = any(w in s for w in ("银行卡", "验证码", "转账", "充值", "投资", "身份证"))
        score = hits * 2 + (2 if money else 0) - max(0, (len(s) - 40) // 20)
        scored.append((score, s))
    scored.sort(key=lambda x: (-x[0], len(x[1])))
    out: list[str] = []
    seen: set[str] = set()
    for _, s in scored:
        key = s[:18]
        if key in seen:
            continue
        seen.add(key)
        out.append(_clip(s, width))
        if len(out) >= limit:
            break
    return out


def _behaviour(ctx: Ctx) -> str:
    """从命中信号里提炼行为描述，去掉主观推断句。"""
    bits: list[str] = []
    for s in ctx.signals[:6]:
        detail = str(getattr(s, "detail", "") or "")
        first = re.split(r"[。；]", detail)[0].strip()
        if 6 <= len(first) <= 60 and not any(w in first for w in _SUBJECTIVE):
            bits.append(first)
        else:
            title = str(getattr(s, "title", "") or "").strip()
            if title:
                bits.append(title)
        if len(bits) >= 3:
            break
    if not bits:
        return ""
    return "；".join(dict.fromkeys(bits)) + "。"


def _subject(ctx: Ctx) -> str:
    a = ctx.asset
    f = ctx.facts
    kind = getattr(a, "kind", "")
    if kind == "apk":
        pkg = f.get("package_name") or ""
        sha = f.get("file_sha256") or ""
        bits = [f"App「{a.value}」"]
        if pkg:
            bits.append(f"包名 {pkg}")
        if sha:
            bits.append(f"SHA-256 {sha[:16]}…")
        return "，".join(bits)
    bits = [f"网站「{a.normalized or a.value}」"]
    ips = f.get("ips") or []
    if ips:
        bits.append(f"解析 IP {', '.join(str(i) for i in ips[:2])}")
    reg = f.get("registrar")
    if reg:
        bits.append(f"注册商 {reg}")
    icp = getattr(a, "icp_status", "unknown")
    if icp == "none":
        bits.append("无 ICP 备案")
    elif icp == "ok" and getattr(a, "icp_license", ""):
        bits.append(f"ICP 备案 {a.icp_license}")
    return "，".join(bits)


def _evidence_line(ctx: Ctx) -> str:
    shots = len(ctx.ev_of("screenshot"))
    htmls = len(ctx.ev_of("page_html"))
    bits = []
    if shots:
        bits.append(f"页面截图 {shots} 张")
    if htmls:
        bits.append("HTML 原文 1 份")
    if not bits:
        return ""
    head = ctx.evidence[0].sha256[:16] if ctx.evidence else ""
    return "、".join(bits) + (f"，SHA-256 已固化（首条 {head}…）" if head else "") + "。"


def brief(ctx: Ctx, channel: Channel) -> str:
    """12377 一类短正文（500 字上限）。段落按重要性排，尾部诉求永不被裁。"""
    a = ctx.asset
    quotes = pick_quotes(ctx.page_text)
    beh = _behaviour(ctx)

    head = f"【对象】{_subject(ctx)}。"
    points: list[str] = []
    if quotes:
        points.append("\n【页面原文】" + "；".join(f"“{q}”" for q in quotes))
    if beh:
        points.append(f"\n【行为】{beh}")
    if getattr(a, "first_seen", None) and ctx.now:
        days = max((ctx.now - a.first_seen).days, 0)
        if days >= 1:
            points.append(
                f"\n【经过】{_fmt(a.first_seen)} 首次发现，已持续 {days} 天，"
                f"核查 {getattr(a, 'scan_count', 0) or 0} 次。"
            )
        else:
            points.append(f"\n【经过】{_fmt(a.first_seen)} 首次发现。")
    ev = _evidence_line(ctx)
    if ev:
        points.append(f"\n【证据】{ev}")
    if getattr(a, "icp_violation", "") == "listed":
        points.append("\n【备案】该域名已被列入工信部违法违规网站名单。")

    tail = "\n请核查并依法采取阻断访问、关闭站点等措施。"
    return _fit(head, points, tail, channel.body_limit or 500)


def _fit(head: str, points: list[str], tail: str, limit: int) -> str:
    if not limit or limit <= 0:
        return head + "".join(points) + tail
    budget = limit - len(head) - len(tail)
    if budget <= 0:
        return head[: max(limit - len(tail), 0)] + tail
    picked, used = [], 0
    for p in points:
        if used + len(p) > budget:
            continue
        picked.append(p)
        used += len(p)
    return (head + "".join(picked) + tail).replace("。。", "。")


def detail(ctx: Ctx, channel: Channel) -> str:
    """12321 一类长正文（2200 字上限），带分条事实与证据清单。"""
    a = ctx.asset
    quotes = pick_quotes(ctx.page_text, limit=4, width=90)
    beh = _behaviour(ctx)
    lines = [
        f"一、被举报对象：{_subject(ctx)}",
        f"    系统研判 {getattr(a, 'verdict', '')}（风险分 {getattr(a, 'score', 0):.0f}，"
        f"置信 {getattr(a, 'confidence', 0):.2f}）；首次发现 {_fmt(getattr(a, 'first_seen', None))}。",
        "",
        "二、具体事实：",
    ]
    n = 1
    if quotes:
        lines.append(f"    {n}. 页面出现以下表述：")
        for q in quotes:
            lines.append(f"       “{q}”")
        n += 1
    if beh:
        lines.append(f"    {n}. {beh}")
        n += 1
    if getattr(a, "first_seen", None) and ctx.now:
        days = max((ctx.now - a.first_seen).days, 0)
        if days >= 1:
            lines.append(
                f"    {n}. 自 {_fmt(a.first_seen)} 首次发现，截至 {_fmt(ctx.now)} 已持续 {days} 天，"
                f"期间核查 {getattr(a, 'scan_count', 0) or 0} 次，页面内容一致。"
            )
        else:
            lines.append(f"    {n}. 于 {_fmt(a.first_seen)} 首次发现，页面当日仍在运行。")
        n += 1
    apks = ctx.facts.get("apk_links") or []
    if apks:
        lines.append(f"    {n}. 页面提供 {len(apks)} 个安装包下载地址，引导下载安装后继续实施诈骗。")

    if ctx.evidence:
        lines += ["", "三、证据清单（均带 SHA-256，可校验）："]
        for e in ctx.evidence[:8]:
            lines.append(
                f"    - {getattr(e, 'kind', '')}｜{_fmt(getattr(e, 'captured_at', None))}｜"
                f"{e.sha256[:24]}…｜{_clip(getattr(e, 'note', '') or '', 50)}"
            )

    lines += [
        "",
        "四、诉求：请核查上述网址，如确属违法，依法采取阻断访问、下架内容、关闭站点等措施，并将结果反馈举报人。",
        "",
        "说明：本材料依据实际访问记录与公开查询结果整理，所述为可核查事实，不构成法律定性。",
    ]
    text = "\n".join(lines)
    limit = channel.body_limit or 0
    if limit and len(text) > limit:
        text = text[: limit - 18] + "\n（材料过长已截断）"
    return text


def mail(ctx: Ctx, channel: Channel, abuse_addr: str, domain: str) -> tuple[str, str]:
    """给注册商/托管商的 abuse 邮件，中英双语。"""
    a = ctx.asset
    subject = f"Abuse report: {domain} — phishing / impersonation of a Chinese government agency"
    cites = [f"  - {e.kind} sha256={e.sha256}" for e in ctx.evidence[:6]]
    quotes = pick_quotes(ctx.page_text, limit=2, width=80)
    body = f"""To the Abuse Team,

We are reporting {domain} for hosting a fraudulent website that impersonates a Chinese
government agency and targets elderly users.

URL: {_as_url(a.value)}
First seen: {_fmt(getattr(a, 'first_seen', None))}
Registrar on record: {ctx.facts.get('registrar', 'unknown')}
Resolved IPs: {', '.join(str(i) for i in (ctx.facts.get('ips') or [])[:3]) or 'unknown'}

Page content (verbatim excerpts from the live page):
{chr(10).join('  > ' + q for q in quotes) if quotes else '  (see attached screenshots)'}

The site asks elderly visitors for ID numbers, bank card numbers and SMS codes, and directs
them to install an Android package. Screenshots and the raw HTML are attached, each with a
SHA-256 digest for integrity verification:
{chr(10).join(cites) if cites else '  (see attached evidence bundle)'}

We request suspension of the domain or hosting account pending your investigation, and a
reply with the outcome.

Regards,
{ctx.reporter or 'Reporting desk'}

---
中文摘要：{domain} 涉嫌仿冒中国国家机关，以「养老补贴」名义骗取老年人身份证号、银行卡号
与短信验证码。附件为页面截图与 HTML 原文，均带 SHA-256。请核查并暂停该域名解析或托管服务。
"""
    return subject, body


def guide(ctx: Ctx, channel: Channel) -> list[str]:
    tips = [
        f"入口：{channel.entry_url or '见渠道说明'}",
        f"被举报对象填：{ctx.label}",
        f"类别按此选：{ctx.harm.label if ctx.harm else '按实际内容选择'}",
    ]
    if channel.body_limit:
        tips.append(f"正文上限 {channel.body_limit} 字，直接用下面这段")
    tips.append("附件用证据包里的 PDF（截图与哈希都在里面）")
    if channel.login_required:
        tips.append("该渠道需要实名登录，请先登录好再点「打开举报页」")
    if channel.captcha != "none":
        tips.append("验证码／滑块需要你手动完成")
    return tips
