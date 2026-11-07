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
    """
    try:
        from ..discover.keywords import get_library

        host = ""
        if asset.kind in ("domain", "url"):
            host = normalize_domain(asset.value)
        match = get_library().match_any(host, f"{asset.value} {corpus[:4000]}")
    except Exception as exc:  # noqa: BLE001 词库坏了不能影响主判定
        log.debug("词库匹配失败：%s", exc)
        return {}
    if not match.hits:
        return {}
    return {
        "keyword_hint": round(match.score, 3),
        "keyword_terms": match.terms[:8],
        "keyword_clusters": sorted(match.clusters),
    }


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
        merged.update(_keyword_facts(asset, text))
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

    assessment, merged = assess_now(asset, facts=facts, text=body)
    written = apply_assessment(session, asset, assessment)

    meta = dict(asset.meta or {})
    meta["facts"] = merged
    meta["scored_at"] = utcnow().isoformat()
    meta["scoring"] = {
        "version": SCORING_VERSION,
        "trigger": trigger,
        "text_len": len(body or ""),
        "signals": written,
        # 幂等键：正文证据的 id。下次只在这条证据变了（新取证）时才重评，
        # 否则流水线会每小时把同一批资产无限重算。
        "evidence_id": evidence_id,
    }
    asset.meta = meta

    decision = triage.apply(asset, facts=merged)
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
) -> dict[str, Any]:
    """批量重评。部署后跑一次，把历史上「只按域名打过分」的资产捞回来。"""
    from ..db import session_scope
    from ..models import Evidence

    with session_scope() as session:
        stmt = select(Asset.id).where(Asset.reviewed_by == "", Asset.score >= min_score)
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
    errors = 0
    detail: list[dict[str, Any]] = []
    for asset_id in ids:
        try:
            res = rescore_by_id(asset_id, trigger="bulk")
            if not res.get("ok"):
                errors += 1
                continue
            if res["changed"]:
                bumped += 1
            if res["after"]["tier"] in ("watch", "confirmed") and res["before"]["tier"] not in (
                "watch",
                "confirmed",
            ):
                upgraded += 1
            if res["changed"] and len(detail) < 30:
                detail.append(res)
        except Exception as exc:  # noqa: BLE001 单条失败不影响整批
            errors += 1
            log.debug("批量重评失败 %s: %s", asset_id, exc)
    return {
        "ok": True,
        "scanned": len(ids),
        "changed": bumped,
        "upgraded": upgraded,
        "errors": errors,
        "sample": detail,
    }
