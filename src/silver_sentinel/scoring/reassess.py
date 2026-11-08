"""用「完整证据」重算评分。

原来的链路断在这里
------------------
发现层落库时 `score=0`，研判走的是 `scan(quick=True)`——quick 只跳过 crt.sh，
但真正的问题是取证拿到的页面正文从来没进入过评分：

1. 取证把 page_text 写进证据仓，随后明文被脱敏；
2. 下一轮 `_scan_one` 用 `Path(row.path).read_text()` 读正文，读到空串；
3. 评分只剩域名特征，上限 38.8，永远够不到 watch 的 50。

于是「抓了 145 个站、2378 条证据」，分数却全部 <40。

这个模块把「拿到新证据 → 重算 → 回写」做成一件原子的事，供三处调用：
- 取证成功后（capture）；
- 人工补判 / 批量重评（CLI 与接口）；
- 定时巡检发现内容变了的资产。

只做规则评分。LLM 是独立的一步（analysis.llm_judge），因为它慢且要计费，
不能让取证线程等它。
"""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import settings
from ..domain import Assessment, utcnow
from ..models import Asset, SignalRow
from ..normalize import extract_indicators, normalize_domain
from .engine import assess, get_ruleset

log = logging.getLogger(__name__)

SCORING_VERSION = 2


def _keyword_facts(asset: Asset, corpus: str) -> dict[str, Any]:
    """把词库命中写回事实。

    取证后的正文往往包含「民族资产解冻」「每日返利」这类原句，
    词库本来就是为它们准备的，不匹配一次等于白抓。

    主题无关的页面（体育直播、影视站群）只按域名匹配——那些站群的
    域名里常带「weixin/qq」之类的品牌词，按正文匹配会把整类站点
    误判成「冒充微信」。
    """
    from .engine import detect_off_topic

    try:
        from ..discover.keywords import get_library

        host = ""
        if asset.kind in ("domain", "url"):
            host = normalize_domain(asset.value)
        body = "" if detect_off_topic(corpus) else f"{asset.value} {corpus[:4000]}"
        match = get_library().match_any(host, body)
    except Exception as exc:  # noqa: BLE001 词库坏了不能影响主判定
        log.debug("词库匹配失败：%s", exc)
        return {}
    if not match.hits:
        return {}
    return {
        "keyword_hint": round(match.score, 3),
        "keyword_terms": match.terms[:8],
        "keyword_clusters": sorted(match.clusters),
        # 命中条数：单个品牌词（尤其是站群域名里的 weixin/qq）不足以定性，
        # KW-001 要求「高分 + 至少两个独立命中」才算强主题词根。
        "keyword_hits": len(match.hits),
    }


def _claim_signals(merged: dict[str, Any]) -> list[Any]:
    """把「自称与冒充」转成信号。

    为什么不写成 YAML 规则：claim 是结构化事实（谁自称、官方域名是谁），
    不是关键词条件；而且权重必须压倒词库——伪造政府网站标识码这一条，
    比命中一百个「补贴」都硬。
    """
    from ..domain import Signal

    claim = merged.get("claim") or {}
    if not isinstance(claim, dict):
        return []
    verdict = str(claim.get("verdict") or "")
    site_id = claim.get("site_id") or ""
    agencies = claim.get("agencies") or []
    domains = claim.get("official_domains") or {}
    who = agencies[0] if agencies else ""
    official = (domains.get(who) or [""])[0] if who else ""

    if verdict in ("fake_site_id", "fake_icp"):
        return [
            Signal(
                rule_id="IMP-001" if verdict == "fake_site_id" else "IMP-004",
                category="impersonation",
                title="伪造政府网站标识码" if verdict == "fake_site_id" else "伪造备案号",
                weight=96.0,
                confidence=0.99 if verdict == "fake_site_id" else 0.9,
                detail=(f"非政府域名标注 {site_id}（该码只发给 .gov.cn）"
                        if verdict == "fake_site_id"
                        else "；".join((claim.get("reasons") or [])[:1])[:200]),
                source="claim",
            )
        ]
    if verdict == "impersonation":
        return [
            Signal(
                rule_id="IMP-002",
                category="impersonation",
                title="冒充政府机构",
                weight=78.0,
                confidence=0.9,
                detail=f"自称「{who}」，该机构官方域名为 {official}",
                source="claim",
            )
        ]
    if verdict == "fabricated_agency":
        return [
            Signal(
                rule_id="IMP-003",
                category="impersonation",
                title="自称不存在的国家机构",
                weight=62.0,
                confidence=0.62,
                detail="；".join((claim.get("reasons") or [])[:2])[:200],
                source="claim",
            )
        ]
    return []


def _apply_claim(assessment: Any, merged: dict[str, Any], thresholds: dict[str, float]) -> None:
    """把冒充结论叠加到评分上。

    claim 不给 confirmed——「机器不给 confirmed」是既有约束（那条档要进举报链）。
    伪造标识码给 95 分 + high_risk，triage 会把它顶进 watch 并标 urgent，
    人工一眼确认即可。
    """
    claim = merged.get("claim") or {}
    if not isinstance(claim, dict):
        return
    verdict = str(claim.get("verdict") or "")
    signals = _claim_signals(merged)
    if signals:
        assessment.signals.extend(signals)
    if verdict in ("fake_site_id", "fake_icp"):
        assessment.score = max(float(assessment.score or 0), 95.0)
        assessment.verdict = "high_risk"
        assessment.confidence = max(float(assessment.confidence or 0), 0.95)
        assessment.notes.append("伪造政府网站标识码，按最高优先级处置")
    elif verdict == "impersonation":
        assessment.score = max(float(assessment.score or 0), 70.0)
        if assessment.verdict in ("insufficient", "low"):
            assessment.verdict = "high_risk"
        assessment.confidence = max(float(assessment.confidence or 0), 0.85)
        assessment.notes.append("冒充政府机构，优先人工核验")
    elif verdict == "fabricated_agency":
        assessment.score = max(float(assessment.score or 0), 55.0)
        assessment.confidence = max(float(assessment.confidence or 0), 0.7)
    elif verdict == "legit":
        # 政府/媒体白名单命中：不是「无罪」，是「不值得排在前面」。
        # 保留分数上限 20，让它落回冷存，但记录仍在，改版后可复查。
        assessment.score = min(float(assessment.score or 0), 20.0)
        assessment.notes.append("命中政府/媒体白名单")


def _claim_from_evidence(session: Session, asset: Asset) -> dict[str, Any] | None:
    """从已存的 page_html 补一次自称抽取。

    只在重评时调用（离线、批量），不进入取证热路径。
    """
    if asset.kind not in ("domain", "url"):
        return None
    try:
        from ..claim import analyze_html
        from ..evidence import latest_text_row, read_text
        from ..normalize import registrable_domain

        row = latest_text_row(session, asset.id, kind="page_html")
        if row is None:
            return None
        html = read_text(row, limit=400_000)
        if not html:
            return None
        host = registrable_domain(asset.normalized or asset.value)
        # 证据的 note 里带了最终 URL（可能被跳转过），有就用它，没有就用资产域名
        note = str(getattr(row, "note", "") or "")
        m = re.search(r"https?://([^/\s]+)", note)
        if m:
            host = m.group(1).lower()
        return analyze_html(html, host).as_dict()
    except Exception as exc:  # noqa: BLE001 补算失败按无自称处理
        log.debug("从证据补算自称失败 %s：%s", asset.id, exc)
        return None


def assess_now(
    asset: Asset,
    *,
    facts: dict[str, Any] | None = None,
    text: str = "",
) -> tuple[Assessment, dict[str, Any]]:
    """纯计算：不碰数据库，返回 (评估结果, 合并后的 facts)。"""
    merged: dict[str, Any] = dict((asset.meta or {}).get("facts") or {})
    if facts:
        merged.update({k: v for k, v in facts.items() if v is not None})
    if text:
        try:
            prev_len = int(merged.get("page_text_len") or 0)
        except (TypeError, ValueError):
            prev_len = 0
        merged["page_text_len"] = max(prev_len, len(text))
        # 正文里的电话/域名/钱包地址是「同一团伙」的关联线索，顺手提出来
        indicators = extract_indicators(text)
        if indicators.get("phones"):
            merged.setdefault("page_phones", indicators["phones"][:10])
        if indicators.get("wallets"):
            merged.setdefault("page_wallets", indicators["wallets"][:10])
        if indicators.get("domains"):
            merged.setdefault("page_mentions", indicators["domains"][:20])
    else:
        indicators = extract_indicators(f"{asset.value} {asset.normalized}")
    # 没有正文时也要按域名匹配一次词库：那是发现阶段唯一的语义信号
    merged.update(_keyword_facts(asset, text))

    ruleset = get_ruleset()
    assessment = assess(
        merged,
        text=text,
        indicators=indicators,
        ruleset=ruleset,
        official=bool(merged.get("official_listed")),
        reviewed=bool(asset.reviewed_by),
        min_signals=settings.min_signals_for_verdict,
    )
    # 维度覆盖写进 facts：triage 要据此判断「冒充 × 说服」的结构组合，
    # 纯计算入口（不落库）也必须能拿到，否则测试与线上走两套逻辑。
    merged["coverage"] = dict(assessment.coverage)
    # 自称/冒充是结构化事实，不走 YAML 规则，直接叠加到评分上。
    _apply_claim(assessment, merged, ruleset.thresholds)
    merged["coverage"] = dict(assessment.coverage)
    return assessment, merged


def apply_assessment(session: Session, asset: Asset, assessment: Assessment) -> int:
    """把评估结果写回资产与信号表，返回写入的信号条数。"""
    asset.score = assessment.score
    asset.confidence = assessment.confidence
    asset.verdict = assessment.verdict

    session.execute(delete(SignalRow).where(SignalRow.asset_id == asset.id))
    written = 0
    for sig in assessment.top_signals:
        session.add(
            SignalRow(
                asset_id=asset.id,
                rule_id=sig.rule_id,
                category=sig.category,
                title=sig.title,
                weight=sig.weight,
                confidence=sig.confidence,
                detail=sig.detail,
                source=sig.source,
                evidence=sig.evidence,
            )
        )
        written += 1
    return written


def rescore(
    session: Session,
    asset: Asset,
    *,
    facts: dict[str, Any] | None = None,
    text: str | None = None,
    trigger: str = "rescore",
    allow_downgrade: bool = False,
) -> dict[str, Any]:
    """重算一个资产。`text=None` 时自动去证据仓取最新正文（含解密）。"""
    from .. import triage
    from ..evidence import latest_text_row, read_text

    evidence_id = 0
    if text is None:
        row = latest_text_row(session, asset.id)
        body = read_text(row)
        evidence_id = row.id if row is not None else 0
    else:
        body = text
    before = {"score": float(asset.score or 0.0), "verdict": asset.verdict, "tier": asset.tier}

    # 历史资产没跑过「自称」抽取（本轮才上线）。重评时顺手从 page_html 补一次，
    # 否则要等 24 小时复访才生效，批量重评等于白跑。
    facts = dict(facts or {})
    existing = ((asset.meta or {}).get("facts") or {}).get("claim")
    if "claim" not in facts and not existing:
        html_claim = _claim_from_evidence(session, asset)
        if html_claim:
            facts["claim"] = html_claim

    assessment, merged = assess_now(asset, facts=facts or None, text=body)
    written = apply_assessment(session, asset, assessment)

    meta = dict(asset.meta or {})
    meta["facts"] = merged
    meta["scored_at"] = utcnow().isoformat()
    meta["scoring"] = {
        "version": SCORING_VERSION,
        "trigger": trigger,
        "text_len": len(body or ""),
        "signals": written,
        # 维度覆盖：triage 靠「冒充 × 施压」的组合结构判定最小充分条件，
        # 这种结构比加权分稳——加权分同一套话术换几个词就掉到门槛下。
        "coverage": dict(assessment.coverage),
        # 幂等键：正文证据的 id。下次只在这条证据变了（新取证）时才重评，
        # 否则流水线会每小时把同一批资产无限重算。
        "evidence_id": evidence_id,
    }
    asset.meta = meta

    decision = triage.apply(asset, facts=merged, allow_downgrade=allow_downgrade)
    session.flush()

    changed = abs(float(asset.score or 0) - before["score"]) >= 0.05 or asset.tier != before["tier"]
    if changed:
        log.info(
            "重评 %s：%.1f→%.1f（%s→%s，正文 %d 字，%d 条信号）",
            asset.value[:48], before["score"], float(asset.score or 0),
            before["tier"], asset.tier, len(body or ""), written,
        )
    return {
        "asset_id": asset.id,
        "before": before,
        "after": {"score": float(asset.score or 0), "verdict": asset.verdict, "tier": asset.tier},
        "signals": written,
        "text_len": len(body or ""),
        "reasons": decision.reasons[:5],
        "changed": changed,
    }


def rescore_by_id(asset_id: int, *, trigger: str = "rescore") -> dict[str, Any]:
    from ..db import session_scope

    with session_scope() as session:
        asset = session.get(Asset, asset_id)
        if asset is None:
            return {"ok": False, "asset_id": asset_id, "error": "资产不存在"}
        result = rescore(session, asset, trigger=trigger)

    _ensure_watch(result)
    return {"ok": True, **result}


def _ensure_watch(result: dict[str, Any]) -> None:
    """升级到 watch/confirmed 后纳入监控。

    必须在事务提交之后做：ensure_watch 自己要开一个写事务，
    在持有写锁的时候再开一个，SQLite 会直接 `database is locked`。
    """
    tier = (result.get("after") or {}).get("tier")
    if tier not in ("watch", "confirmed"):
        return
    if (result.get("before") or {}).get("tier") == tier:
        return
    try:
        from ..capture import ensure_watch

        ensure_watch(int(result["asset_id"]))
    except Exception as exc:  # noqa: BLE001
        log.debug("自动纳管失败 %s: %s", result.get("asset_id"), exc)


def rescore_many(
    *,
    limit: int = 200,
    only_with_text: bool = True,
    min_score: float = 0.0,
    retier: bool = False,
) -> dict[str, Any]:
    """批量重评。部署后跑一次，把历史上「只按域名打过分」的资产捞回来。

    retier=True 允许降档：规则口径改过之后（比如修掉一类误报），
    原先被推上 watch 的必须能落回候选，否则误判会永久留在监控队列里。
    """
    from ..db import session_scope
    from ..models import TIER_CANDIDATE, TIER_WATCH, Evidence

    with session_scope() as session:
        stmt = select(Asset.id).where(Asset.reviewed_by == "", Asset.score >= min_score)
        if retier:
            stmt = stmt.where(Asset.tier.in_((TIER_CANDIDATE, TIER_WATCH)))
        if only_with_text:
            stmt = stmt.where(
                Asset.id.in_(
                    select(Evidence.asset_id).where(
                        Evidence.kind == "page_text", Evidence.deleted_at.is_(None)
                    )
                )
            )
        ids = [r[0] for r in session.execute(stmt.order_by(Asset.score.desc()).limit(limit)).all()]

    bumped = 0
    upgraded = 0
    downgraded = 0
    errors = 0
    detail: list[dict[str, Any]] = []
    for asset_id in ids:
        try:
            with session_scope() as session:
                asset = session.get(Asset, asset_id)
                if asset is None:
                    continue
                res = rescore(session, asset, trigger="bulk", allow_downgrade=retier)
            if not res.get("changed"):
                continue
            _ensure_watch(res)
            bumped += 1
            before, after = res["before"], res["after"]
            if after["tier"] in ("watch", "confirmed") and before["tier"] not in ("watch", "confirmed"):
                upgraded += 1
            elif before["tier"] in ("watch", "confirmed") and after["tier"] not in ("watch", "confirmed"):
                downgraded += 1
            if len(detail) < 30:
                detail.append({"asset_id": asset_id, **res})
        except Exception as exc:  # noqa: BLE001 单条失败不影响整批
            errors += 1
            log.debug("批量重评失败 %s: %s", asset_id, exc)

    pruned = 0
    if retier:
        try:
            from ..capture import prune_watch

            pruned = prune_watch()
        except Exception as exc:  # noqa: BLE001
            log.debug("清理自动盯防失败：%s", exc)
    return {
        "ok": True,
        "scanned": len(ids),
        "changed": bumped,
        "upgraded": upgraded,
        "downgraded": downgraded,
        "watch_pruned": pruned,
        "errors": errors,
        "sample": detail,
    }
