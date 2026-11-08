"""分级：把评分翻译成「下一步做什么」。

为什么需要独立于评分
--------------------
评分回答「像不像诈骗」，分级回答「值不值得花资源」。这两件事经常不一致：
- 一个刚注册 3 天、含「国惠」的域名，证据很少（分数不高），但必须马上盯住；
- 一个老域名偶尔被提及，分数中等，但没有时效性，可以慢慢看。

所以分级规则单独写，输入是「评分 + 事实 + 历史」，输出是 tier 与理由。
每条理由都落库，方便日后回答「当初为什么把它列进来」。

四档语义
--------
confirmed  已确认。只能来自官方通报或人工复核——机器不给这个档。
watch      高度可疑。进入高频监控。
candidate  候选。发现即收，低频轮转。**这是「宁可错杀」的落点**。
cold       冷存。记着，但不主动看。出现新证据会被自动激活。
dismissed  已排除。人工确认无害，保留记录防止重复收。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .domain import utcnow
from .models import (
    TIER_CANDIDATE,
    TIER_COLD,
    TIER_CONFIRMED,
    TIER_DISMISSED,
    TIER_WATCH,
    Asset,
)

log = logging.getLogger(__name__)

# 分级阈值。与 scoring 的 verdict 阈值刻意不同：
# watch 的门槛低于 high_risk，因为我们宁可多看几个。
WATCH_SCORE = 50.0
WATCH_SCORE_WITH_URGENCY = 32.0     # 有强时效信号时放宽
# 「冒充 × 施压/诱导」双维度覆盖时的放宽门槛。
# 这是涉老诈骗的最小充分结构：冒用机构名义（KW-001）＋ 用福利或恐吓
# 推动老人行动（PER/CT 类）。加权分会因换词掉到门槛下，结构不会。
WATCH_SCORE_COMPOSITE = 45.0
# 「机构级伪装」：一次伪造多个身份元素（部委名 + 公文格式 + 证件样式）。
# 这类站往往正文特征稀疏、加权分上不去，但伪装本身已经足够定性。
IMPERSONATION_WATCH = 3
CANDIDATE_SCORE = 12.0
COLD_AFTER_DAYS = 45                # 长期无新证据的候选降为冷存


@dataclass(slots=True)
class TriageDecision:
    tier: str
    reasons: list[str] = field(default_factory=list)
    urgent: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"tier": self.tier, "reasons": self.reasons, "urgent": self.urgent}


def _urgency(facts: dict[str, Any], asset: Asset) -> tuple[bool, list[str]]:
    """时效性信号：说明「现在是活的、正在扩散」。"""
    reasons: list[str] = []
    urgent = False

    age = facts.get("domain_age_days")
    if isinstance(age, (int, float)):
        if age <= 7:
            reasons.append(f"域名注册仅 {int(age)} 天")
            urgent = True
        elif age <= 30:
            reasons.append(f"域名注册 {int(age)} 天，属新起站点")
            urgent = True
        elif age <= 90:
            reasons.append(f"域名注册 {int(age)} 天")

    if facts.get("forces_apk_download"):
        reasons.append("强制下载安装包")
        urgent = True
    if facts.get("distribution_channel") in ("sideload", "qr"):
        reasons.append("非应用商店分发")
        urgent = True
    if facts.get("urlhaus_listed") or facts.get("openphish_listed"):
        reasons.append("命中公开钓鱼情报源")
        urgent = True
    if facts.get("official_listed"):
        reasons.append("命中官方涉诈通报")
        urgent = True

    # 模型结论作为「时效性」信号，不单独定性：它读到了页面原文，
    # 对「现在还在拉人」比任何域名特征都敏感。只在置信度足够时计入。
    llm_class = str(facts.get("llm_classification") or "")
    try:
        llm_conf = float(facts.get("llm_confidence") or 0)
    except (TypeError, ValueError):
        llm_conf = 0.0
    if llm_class in ("elderly_scam", "likely_scam") and llm_conf >= 0.7:
        reasons.append(f"模型研判：{llm_class}（{llm_conf:.2f}）")
        urgent = True

    if (asset.scan_count or 0) >= 3 and (asset.last_seen - asset.first_seen).days <= 3:
        reasons.append("短期内被多次独立发现")
        urgent = True

    return urgent, reasons


def _hard_evidence(facts: dict[str, Any], score: float, verdict: str) -> list[str]:
    """「硬证据」清单：不是加权词，而是可核查的事实。"""
    out: list[str] = []
    if facts.get("official_listed"):
        out.append("官方通报")
    if facts.get("linked_confirmed_campaign"):
        out.append("与已确认团伙共用基础设施")
    if score >= 70 and verdict in ("high_risk", "confirmed"):
        out.append(f"评分 {score:.0f}，多项强特征同时成立")
    if facts.get("shared_wallet"):
        out.append("共用收款地址")
    if facts.get("shared_certificate"):
        out.append("共用签名证书")
    # 模型判到「就是这类骗局」且引用被核对过，才算一条硬证据；
    # 「unclear」永远不进这个清单。
    if str(facts.get("llm_classification") or "") == "elderly_scam":
        try:
            if float(facts.get("llm_confidence") or 0) >= 0.85:
                out.append("模型研判与规则一致（引用已核对）")
        except (TypeError, ValueError):
            pass
    return out


def _composite(asset: Asset, facts: dict[str, Any] | None = None) -> list[str]:
    """结构性组合兜底：分数差一点点时，看维度而不是看加权和。

    线上实测：一条「民政局/高龄津贴/免费领鸡蛋/专家讲座」的站，命中
    KW-001 + PER-001 + CT-008 + 未备案，分数 49.7，差 0.3 分卡在 watch
    门外。这类漏报没法靠调权重解决——同一套话术换几个词，加权分就掉下来了。

    两条判据：

    - 冒充 + 说服各自成立（最通用，覆盖大部分引流话术）；
    - 冒充强度 ≥3 且分数 ≥45（冒充退役军人事务部这类「机构级」伪装，
      往往同时伪造多个身份元素：部委名、公文格式、证件样式）。
    """
    coverage = (facts or {}).get("coverage")
    if not isinstance(coverage, dict):
        coverage = ((asset.meta or {}).get("scoring") or {}).get("coverage") or {}
    try:
        impersonation = int(coverage.get("impersonation") or 0)
        persuasion = int(coverage.get("persuasion") or 0)
    except (TypeError, ValueError, AttributeError):
        return []
    if impersonation >= 1 and persuasion >= 1:
        return ["同时具备身份冒充与说服施压两类特征"]
    if impersonation >= IMPERSONATION_WATCH and float(asset.score or 0) >= WATCH_SCORE_COMPOSITE:
        return [f"冒充特征命中 {impersonation} 项，机构级伪装"]
    return []


def decide(asset: Asset, *, facts: dict[str, Any] | None = None, verdict: str | None = None) -> TriageDecision:
    facts = facts or (asset.meta or {}).get("facts", {}) or {}
    verdict = verdict or asset.verdict or "insufficient"
    score = float(asset.score or 0.0)

    # 人工结论优先级最高，且不被后续自动流程覆盖
    if asset.reviewed_by and asset.tier == TIER_DISMISSED:
        return TriageDecision(TIER_DISMISSED, ["人工复核排除"])
    if asset.reviewed_by and asset.tier == TIER_CONFIRMED:
        return TriageDecision(TIER_CONFIRMED, ["人工复核确认"])

    if facts.get("official_listed") or verdict == "confirmed":
        return TriageDecision(TIER_CONFIRMED, ["命中官方涉诈通报"])

    # 自称/冒充：词库看「用了什么词」，这里看「说自己是哪个机构」。
    # 后者可核验——部委的官方域名只有一个，对不上就是冒充。
    claim = facts.get("claim")
    claim = claim if isinstance(claim, dict) else {}
    claim_verdict = str(claim.get("verdict") or "")
    if claim_verdict in ("fake_site_id", "fake_icp"):
        reason = (
            f"伪造政府网站标识码 {claim.get('site_id') or ''}（该码只发给 .gov.cn），需人工确认"
            if claim_verdict == "fake_site_id"
            else "；".join((claim.get("reasons") or ["页面备案号与域名不一致"])[:1])
        )
        return TriageDecision(TIER_WATCH, [reason], urgent=True)
    if claim_verdict == "fake_site_id":
        return TriageDecision(
            TIER_WATCH,
            [f"伪造政府网站标识码 {claim.get('site_id') or ''}（该码只发给 .gov.cn），需人工确认"],
            urgent=True,
        )
    if claim_verdict == "impersonation":
        who = (claim.get("agencies") or [""])[0]
        domains = (claim.get("official_domains") or {}).get(who) or [""]
        return TriageDecision(
            TIER_WATCH,
            [f"冒充「{who}」，该机构官方域名为 {domains[0]}"],
            urgent=True,
        )
    if claim_verdict == "fabricated_agency":
        return TriageDecision(TIER_CANDIDATE, ["自称政府库中不存在的国家机构"])
    if claim_verdict == "legit" and score < 80:
        # 白名单命中：政府站/正规媒体不该占据待处理队列前排。
        # 不删除——记录留着，改版或域名易主后可复查。
        return TriageDecision(TIER_COLD, ["命中政府/媒体白名单"])

    urgent, urgency_reasons = _urgency(facts, asset)
    hard = _hard_evidence(facts, score, verdict)

    # 备案状态：查到备案是「减分项」，但绝不等于清白——
    # 黑产也会买壳公司备案。所以只降一档，不直接排除。
    icp_registered = asset.icp_status == "registered"
    icp_note = f"备案主体：{asset.icp_entity}" if icp_registered and asset.icp_entity else ""

    composite = _composite(asset, facts)
    if score >= WATCH_SCORE or (urgent and score >= WATCH_SCORE_WITH_URGENCY) or len(hard) >= 2:
        reasons = hard + urgency_reasons
        if icp_registered and score < 80:
            reasons.append(icp_note + "（已备案，降为候选）")
            return TriageDecision(TIER_CANDIDATE, reasons, urgent)
        return TriageDecision(TIER_WATCH, reasons or ["综合评分较高"], urgent)

    if composite and score >= WATCH_SCORE_COMPOSITE:
        reasons = composite + hard + urgency_reasons
        if icp_registered and score < 80:
            reasons.append(icp_note + "（已备案，降为候选）")
            return TriageDecision(TIER_CANDIDATE, reasons, urgent)
        return TriageDecision(TIER_WATCH, reasons, urgent)

    if score >= CANDIDATE_SCORE or urgent or hard:
        reasons = hard + urgency_reasons
        if not reasons:
            reasons = [f"评分 {score:.0f}，进入候选池"]
        return TriageDecision(TIER_CANDIDATE, reasons, urgent)

    # 分数很低：进冷存。仍保留记录——这是「宁可错杀」的成本上限。
    if (asset.meta or {}).get("discover_hint", 0) >= 0.3:
        return TriageDecision(TIER_COLD, ["发现阶段命中弱特征，暂无其他证据"])

    return TriageDecision(TIER_COLD, ["证据不足"])


def apply(
    asset: Asset, *, facts: dict[str, Any] | None = None, allow_downgrade: bool = False
) -> TriageDecision:
    """算出分级并写回资产。返回决策供调用方记录。

    allow_downgrade 只给「规则口径变更后的重新定级」用：评分逻辑改了，
    原先按旧口径升上去的档必须能落回来，否则一次误判会永久留在 watch。
    """
    decision = decide(asset, facts=facts)
    previous = asset.tier
    meta = dict(asset.meta or {})
    # 「首次分级」可以自由落档——但已确认的目标除外：
    # 它们可能来自官方通报导入，尚无 triaged 标记，不能被一次自动评估刷掉。
    first_time = (not meta.get("triaged")) and previous != TIER_CONFIRMED

    # 首次分级可以自由落档；之后只允许「升级」自动发生。
    # 降级必须经过 decay 或人工，否则一次采集失败就能把确认过的目标刷回候选。
    rank = {TIER_CONFIRMED: 4, TIER_WATCH: 3, TIER_CANDIDATE: 2, TIER_COLD: 1, TIER_DISMISSED: 0}
    if allow_downgrade and previous != TIER_CONFIRMED and not asset.reviewed_by:
        asset.tier = decision.tier
    elif first_time or rank.get(decision.tier, 0) >= rank.get(previous, 0) or previous in (None, ""):
        asset.tier = decision.tier
    elif previous == TIER_CONFIRMED and decision.tier != TIER_CONFIRMED:
        # 已确认的不会自动降级
        asset.tier = TIER_CONFIRMED
        decision.tier = TIER_CONFIRMED
        decision.reasons.append("已确认目标不自动降级")

    if previous and previous != asset.tier:
        log.info("分级变更 %s: %s -> %s (%s)", asset.value[:40], previous, asset.tier, "；".join(decision.reasons[:2]))

    asset.discovery_reason = "；".join(decision.reasons)[:500]
    meta["triaged"] = True
    meta["triaged_at"] = utcnow().isoformat()
    asset.meta = meta
    return decision


def decay(stale_days: int = COLD_AFTER_DAYS, limit: int = 2000) -> dict[str, Any]:
    """把长期没有任何变化的候选降为冷存。

    做这件事的原因很实际：候选池会随时间无限膨胀，如果不做衰减，
    监控队列会被几万个「三个月前看过一眼」的域名堵死。
    冷存不等于删除——出现新证据时 activate() 会把它捞回来。
    """
    from sqlalchemy import select

    from .db import session_scope

    cutoff = utcnow() - timedelta(days=stale_days)
    moved = 0
    with session_scope() as session:
        rows = list(
            session.scalars(
                select(Asset)
                .where(
                    Asset.tier == TIER_CANDIDATE,
                    Asset.last_seen < cutoff,
                    Asset.score < CANDIDATE_SCORE,
                    Asset.reviewed_by == "",
                )
                .limit(limit)
            )
        )
        for asset in rows:
            asset.tier = TIER_COLD
            asset.dismiss_reason = f"超过 {stale_days} 天无新证据，自动降为冷存"
            moved += 1
        session.commit()
    return {"moved": moved, "cutoff_days": stale_days}


def activate(asset_id: int, reason: str) -> bool:
    """冷存资产出现新证据时重新激活。"""
    from .db import session_scope

    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            return False
        if asset.tier in (TIER_COLD, TIER_DISMISSED):
            asset.tier = TIER_CANDIDATE
            asset.dismiss_reason = ""
            asset.discovery_reason = f"重新激活：{reason}"[:500]
            session.commit()
            return True
    return False
