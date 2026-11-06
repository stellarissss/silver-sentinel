"""处置与举报材料生成。

原则：**不替用户做定性，只把事实、证据、法条摆成监管能直接受理的形状。**
所以每份材料都遵循同一结构 —— 被举报对象 / 事实经过 / 证据清单 / 涉嫌违反的规定 / 诉求。
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .domain import VERDICT_LABELS, utcnow
from .models import Asset, Evidence, ReportDraft, SignalRow
from .opsec import redact_obj

# 渠道元数据。url 为官方入口，字段说明用于指导人工填报。
CHANNELS: dict[str, dict[str, Any]] = {
    "12321": {
        "name": "12321 网络不良与垃圾信息举报受理中心",
        "url": "https://www.12321.cn",
        "entry": "网站举报 / 不良 App 举报（可用「12321 举报助手」App 截图举报）",
        "best_for": "涉诈网址、无法在应用商店上架的仿冒 App",
        "fields": ["被举报网址或 App 名称", "诈骗类型", "详细描述", "截图证据"],
    },
    "12377": {
        "name": "中央网信办违法和不良信息举报中心",
        "url": "https://www.12377.cn",
        "entry": "网络诈骗类举报",
        "best_for": "传播虚假信息、冒充国家机关的网页与账号",
        "fields": ["信息网址", "样本截图", "举报说明"],
    },
    "cyberpolice": {
        "name": "公安部网络违法犯罪举报网站",
        "url": "https://www.cyberpolice.cn",
        "entry": "注册登录后提交线索，可查询处置进度",
        "best_for": "已造成实际损失的诈骗案件线索",
        "fields": ["线索描述", "涉案网址/账号", "转账凭证", "证据材料"],
    },
    "12315": {
        "name": "全国 12315 平台（市场监督管理）",
        "url": "https://www.12315.cn",
        "entry": "我要投诉 / 我要举报",
        "best_for": "保健品、食品宣称疗效，会销虚假宣传，价格欺诈",
        "fields": ["被举报主体", "消费金额", "宣传材料", "发票或收据"],
    },
    "96110": {
        "name": "反诈专线 96110 / 报警 110",
        "url": "tel:96110",
        "entry": "电话直拨",
        "best_for": "正在转账、已转账、老人被深度洗脑需要上门劝阻",
        "fields": ["当事人姓名与位置", "对方账号", "转账时间与金额"],
    },
    "registrar": {
        "name": "域名注册商 / 托管商滥用举报",
        "url": "",
        "entry": "向 whois 中的 abuse 邮箱发送举报信",
        "best_for": "要求关停仿冒域名",
        "fields": ["域名", "滥用类型", "证据链接"],
    },
}

LEGAL_BASIS: list[tuple[str, str]] = [
    ("《中华人民共和国刑法》第二百六十六条", "诈骗公私财物，数额较大的构成诈骗罪。"),
    ("《中华人民共和国反电信网络诈骗法》第三十八条", "任何单位和个人不得非法制造、买卖、提供或者使用用于实施电信网络诈骗等违法犯罪的设备、软件。"),
    ("《中华人民共和国广告法》第十七条", "除医疗、药品、医疗器械广告外，禁止其他任何广告涉及疾病治疗功能。"),
    ("《中华人民共和国食品安全法》第七十三条", "食品广告不得含有虚假内容，不得涉及疾病预防、治疗功能。"),
    ("《禁止传销条例》第七条", "以发展人员数量或者销售业绩为依据计酬、要求交纳费用取得加入资格等，属传销行为。"),
]

ADVICE = {
    "confirmed": [
        "立即停止一切转账，不要再向对方提供任何验证码、人脸或银行卡信息。",
        "保留聊天记录、转账凭证、App 安装包与宣传材料，不要卸载、不要删除聊天。",
        "拨打 96110 或 110 报警，同时联系开户行申请紧急止付。",
        "卸载涉诈 App，关闭其无障碍、悬浮窗、短信读取权限；修改银行卡与支付密码。",
    ],
    "high_risk": [
        "不要扫码、不要点击对方发来的链接、不要安装应用商店搜不到的 App。",
        "已安装的，先在「设置—应用管理」中确认权限，关闭无障碍与短信读取，再卸载。",
        "把本篇材料转给家里老人看，重点讲「免费领鸡蛋」之后一定会转到买东西或投钱。",
        "如已转账，立即拨 96110。",
    ],
    "suspicious": [
        "先不着急下结论，但暂停一切付款与实名认证。",
        "用官方渠道反向核实：打 12345 或到街道办问是否有该「补贴项目」。",
        "任何要求「先交钱才能领钱」的，一律视为诈骗。",
    ],
    "insufficient": [
        "目前证据不足，建议补充：完整聊天记录、下载链接、安装包、收款账户信息。",
    ],
    "low": [
        "暂未发现明显涉诈特征，但仍需警惕后续以「领礼品」为名的转化话术。",
    ],
    "benign": ["已人工排除，无需处置。"],
}


def _fmt(dt: datetime | None) -> str:
    if not dt:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M")


def _signals(session: Session, asset_id: int) -> list[SignalRow]:
    return list(
        session.scalars(
            select(SignalRow).where(SignalRow.asset_id == asset_id).order_by(SignalRow.weight.desc())
        )
    )


def _evidence_lines(rows: list[Evidence]) -> list[str]:
    if not rows:
        return ["（暂无归档证据，建议补充截图或安装包）"]
    return [
        f"- `{r.kind}` · {_fmt(r.captured_at)} · SHA-256 `{r.sha256[:24]}…` · {r.size} 字节 · {r.note or '—'}"
        for r in rows
    ]


def render_markdown(
    asset: Asset,
    signals: list[SignalRow],
    evidence: list[Evidence],
    channel: str,
    *,
    reporter: str = "",
) -> str:
    ch = CHANNELS.get(channel, CHANNELS["12321"])
    verdict_label = VERDICT_LABELS.get(asset.verdict, asset.verdict)

    signal_lines = [
        f"{i}. **{s.title}**（{s.category}，权重 {s.weight:.0f}，置信 {s.confidence:.2f}）\n   {s.detail}"
        for i, s in enumerate(signals[:12], 1)
    ] or ["（未命中规则信号）"]

    legal = "\n".join(f"- {law}：{text}" for law, text in LEGAL_BASIS)

    return f"""# 涉老诈骗线索举报材料

**拟提交渠道**：{ch['name']}
**渠道入口**：{ch['url']}（{ch['entry']}）
**生成时间**：{_fmt(utcnow())}
**举报人**：{reporter or '（请填写）'}

---

## 一、被举报对象

| 项目 | 内容 |
| --- | --- |
| 类型 | {asset.kind} |
| 标识 | `{asset.value}` |
| 规范化标识 | `{asset.normalized}` |
| 首次发现 | {_fmt(asset.first_seen)} |
| 最近发现 | {_fmt(asset.last_seen)} |
| 系统研判 | {verdict_label}（风险分 {asset.score:.1f}／置信度 {asset.confidence:.2f}） |
| 关联团伙 | {asset.campaign_id or '未归并'} |

## 二、事实经过

{_narrative(asset, signals)}

## 三、判定依据

{chr(10).join(signal_lines)}

## 四、证据清单

{chr(10).join(_evidence_lines(evidence))}

> 上述证据已按采集顺序做哈希链固化，任何一条被修改都会导致链校验失败。
> 校验命令：`silver-sentinel verify-chain --asset {asset.id}`

## 五、涉嫌违反的规定

{legal}

## 六、诉求

1. 对上述{ '网址' if asset.kind in {'url','domain'} else '应用/账号' }进行核查，如确属涉诈，依法采取阻断访问、下架、关停等措施；
2. 对关联收款账户、推广账号开展溯源；
3. 将处理结果反馈举报人。

---

**说明**：本材料由「银发哨兵」根据公开情报与被动采集证据自动生成，所述内容为线索而非定性结论，
最终认定以有权机关调查结果为准。
"""


def _narrative(asset: Asset, signals: list[SignalRow]) -> str:
    """用命中信号拼一段人能读的事实描述，不做无根据的扩写。"""
    if not signals:
        return "该对象暂未命中任何已知特征规则，现有材料不足以描述其行为模式。"

    cats: dict[str, list[str]] = {}
    for s in signals:
        cats.setdefault(s.category, []).append(s.title)

    parts = []
    if "distribution" in cats:
        parts.append("在分发环节，" + "、".join(cats["distribution"][:3]) + "。")
    if "impersonation" in cats:
        parts.append("在身份包装上，" + "、".join(cats["impersonation"][:3]) + "。")
    if "financial" in cats:
        parts.append("在资金环节，" + "、".join(cats["financial"][:3]) + "。")
    if "persuasion" in cats:
        parts.append("在话术上，" + "、".join(cats["persuasion"][:3]) + "。")
    if "technical" in cats:
        parts.append("从技术特征看，" + "、".join(cats["technical"][:3]) + "。")
    if "reputation" in cats:
        parts.append("外部信誉方面，" + "、".join(cats["reputation"][:3]) + "。")

    return "".join(parts) + "\n\n上述特征组合与已知的「免费礼品引流 → 洗脑 → 收割」类涉老骗局高度一致。"


def build(session: Session, asset_id: int, channel: str = "12321", *, reporter: str = "") -> ReportDraft:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError(f"资产不存在：{asset_id}")

    channel = channel if channel in CHANNELS else "12321"
    signals = _signals(session, asset_id)
    evidence = list(session.scalars(select(Evidence).where(Evidence.asset_id == asset_id).order_by(Evidence.id)))

    body = redact_obj(render_markdown(asset, signals, evidence, channel, reporter=reporter))
    payload = {
        "channel": channel,
        "channel_name": CHANNELS[channel]["name"],
        "channel_url": CHANNELS[channel]["url"],
        "required_fields": CHANNELS[channel]["fields"],
        "target": {"kind": asset.kind, "value": asset.value},
        "score": asset.score,
        "verdict": asset.verdict,
        "signal_count": len(signals),
        "evidence_count": len(evidence),
        "evidence_hashes": [e.sha256 for e in evidence],
    }
    payload = redact_obj(payload)          # 导出前抹掉采集端标识，避免把基础设施写进举报材料

    draft = ReportDraft(asset_id=asset_id, channel=channel, payload=payload, body=body)
    session.add(draft)
    session.flush()
    return draft


def advise(verdict: str) -> list[str]:
    return ADVICE.get(verdict, ADVICE["insufficient"])


def one_pager(session: Session, asset_id: int) -> dict[str, Any]:
    """给家属/社区工作者的一页纸：是什么、为什么危险、现在做什么。"""
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError(f"资产不存在：{asset_id}")
    signals = _signals(session, asset_id)
    llm = (asset.meta or {}).get("llm") or {}

    return {
        "title": f"{VERDICT_LABELS.get(asset.verdict, asset.verdict)}：{asset.value[:40]}",
        "score": asset.score,
        "verdict": asset.verdict,
        "why": llm.get("reasoning") or _narrative(asset, signals),
        "tactics": llm.get("tactics") or [s.title for s in signals[:6]],
        "stage": llm.get("stage", ""),
        "actions": advise(asset.verdict),
        "hotlines": [
            {"name": "反诈专线", "number": "96110"},
            {"name": "报警", "number": "110"},
            {"name": "消费投诉", "number": "12315"},
            {"name": "网络不良信息举报", "number": "12321"},
        ],
    }


def export_bundle(session: Session, asset_id: int, channels: list[str] | None = None) -> dict[str, Any]:
    channels = channels or ["12321", "12377", "cyberpolice", "12315"]
    drafts = [build(session, asset_id, c) for c in channels]
    bundle = {
        "asset_id": asset_id,
        "generated_at": utcnow().isoformat(),
        "reports": [
            {"channel": d.channel, "body": d.body, "payload": d.payload} for d in drafts
        ],
        "one_pager": one_pager(session, asset_id),
    }
    return redact_obj(bundle)


def to_json(bundle: dict[str, Any]) -> str:
    return json.dumps(bundle, ensure_ascii=False, indent=2)
