"""扫描编排：一次研判从输入到落库的完整链路。

流程：规范化 → 被动情报采集 → 规则评分 → （可选）LLM 研判 → 落库 → 证据链 → 归并。
任何一步失败都不应让整次扫描崩溃：情报源是「尽力而为」，规则是「确定的」，二者分开记账。
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import triage
from .analyzers import llm as llm_analyzer
from .analyzers.cluster import cluster
from .collectors import apk as apk_collector
from .collectors import crtsh, reputation, typosquat
from .config import settings
from .db import session_scope
from .discover.keywords import get_library
from .domain import Assessment, AssetKind, Signal, utcnow
from .enrich.icp import get_icp
from .evidence import append as append_evidence
from .evidence import append_file
from .models import Asset, SignalRow
from .normalize import (
    CHEAP_TLDS,
    brand_lookalike,
    extract_indicators,
    is_free_hosting,
    is_shortener,
    normalize_domain,
    normalize_text,
    normalize_url,
    registrable_domain,
    tld_of,
)
from .scoring.engine import assess, load_ruleset, priority_of

log = logging.getLogger(__name__)

DOWNLOAD_HINTS = ("下载", "安装", "apk", "客户端", "点击安装", "扫码安装", "浏览器打开")


@dataclass(slots=True)
class ScanResult:
    asset_id: int
    created: bool
    assessment: Assessment
    asset: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset,
            "assessment": self.assessment.as_dict(),
            "priority": priority_of(self.assessment),
            "created": self.created,
        }


def _canonical(kind: str, value: str) -> tuple[str, str]:
    """返回 (用于展示的 value, 唯一键 normalized)。"""
    value = normalize_text(value)
    if kind == AssetKind.DOMAIN.value:
        host = normalize_domain(value)
        return host, host
    if kind == AssetKind.URL.value:
        url, host = normalize_url(value)
        return url or value, url or value
    if kind == AssetKind.APK.value:
        return value, value
    if kind == AssetKind.TEXT.value:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
        return value[:2000], f"text:{digest}"
    return value[:200], value.lower()


def _collect_url_facts(
    url: str, host: str, ruleset, manual: dict[str, Any], *, quick: bool = False
) -> tuple[dict[str, Any], dict[str, Any]]:
    """采集判定所需的被动情报。

    quick=True 用于批量流水线：跳过 crt.sh（实测单次最长 70 秒），
    因为发现层已经从 CT 日志拿到了证书与同源域名，不需要再查一遍。
    单条人工研判仍走完整路径。
    """
    facts: dict[str, Any] = {}
    meta: dict[str, Any] = {"host": host, "registrable": registrable_domain(host)}

    domain = registrable_domain(host)
    facts["is_shortener"] = is_shortener(host)
    facts["is_free_hosting"] = is_free_hosting(host)
    facts["cheap_tld"] = tld_of(host).lstrip(".").lower() in CHEAP_TLDS

    lookalike = brand_lookalike(host, set(ruleset.brands))
    if lookalike:
        facts["brand_lookalike"] = lookalike[1]
        meta["impersonated_brand"] = lookalike[0]

    if manual.get("icp_registered") is not None:
        facts["icp_registered"] = bool(manual["icp_registered"])

    if not settings.allow_network:
        return facts, meta

    # 每个情报源单独兜底：代理挂了、接口限流、DNS 超时，都不能让整次研判失败。
    # 情报是「尽力而为」，规则才是「确定的」。
    try:
        age = reputation.rdap_age_days(domain)
        if age is not None:
            facts["domain_age_days"] = age
            meta["domain_age_days"] = age
    except Exception:  # noqa: BLE001
        log.debug("RDAP 查询失败", exc_info=True)

    try:
        ip_list = typosquat.resolve(host)
        if ip_list:
            meta["ips"] = ip_list
    except Exception:  # noqa: BLE001
        log.debug("DNS 解析失败", exc_info=True)

    try:
        uh = reputation.urlhaus_lookup(host)
        facts["urlhaus_listed"] = bool(uh and uh.get("listed"))
        if uh:
            meta["urlhaus"] = uh
    except Exception:  # noqa: BLE001
        log.debug("URLhaus 查询失败", exc_info=True)

    try:
        phish = reputation.openphish_listed(url)
        if phish is not None:
            facts["openphish_listed"] = phish
    except Exception:  # noqa: BLE001
        log.debug("OpenPhish 查询失败", exc_info=True)

    if not quick:
        try:
            siblings = crtsh.siblings_of(domain)
            if siblings:
                meta["cert_siblings"] = siblings[:30]
        except Exception:  # CT 日志偶发超时，不影响主流程
            log.debug("crt.sh 查询失败", exc_info=True)

    return facts, meta


def _collect_apk_facts(path: str, ruleset) -> tuple[dict[str, Any], dict[str, Any], str]:
    keywords = list(ruleset.asset_unfreeze_terms) + list(ruleset.therapeutic_terms)
    result = apk_collector.analyze(path, extra_keywords=keywords)

    facts = dict(result["facts"])
    facts["distribution_channel"] = "sideload"

    apk_text = result.get("text", "") or ""
    raw_urls = list(result.get("urls") or [])
    # collector 会把裸域名也塞进 urls（为了让短域名不漏），这里拆开：
    # 带协议头的才是 URL 节点，裸域名归到 domains
    urls = [u for u in raw_urls if "://" in u]
    bare_domains = [u for u in raw_urls if "://" not in u]
    # 内嵌域名是「App 指向哪个站」的唯一线索，必须同时从 URL 和裸字符串里捞。
    # 骗子经常在代码里只写域名不写协议头，只靠 URL 正则会全漏。
    indicators = extract_indicators(apk_text) if apk_text else {}
    embedded: list[str] = []
    for u in urls + bare_domains:
        host = normalize_domain(u)
        if host and "." in host and host not in embedded:
            embedded.append(host)
    for d in indicators.get("domains", []):
        if d not in embedded:
            embedded.append(d)
    embedded = [d for d in embedded if not d.endswith((".apk", ".png", ".jpg", ".gif", ".svg"))]

    meta = {
        "apk": {
            "sha256": result["sha256"],
            "package_name": facts.get("package_name", ""),
            "cert_sha256": facts.get("cert_sha256", ""),
            "permissions": facts.get("permissions", []),
            "packer": facts.get("packer", ""),
            "dex_count": facts.get("dex_count", 0),
        },
        "cert_sha256": facts.get("cert_sha256", ""),
        "package_name": facts.get("package_name", ""),
        "wallet_addresses": facts.get("wallet_addresses", []),
        "template_hash": result.get("template_hash", ""),
        "urls": urls[:30],
        "domains": embedded[:40],
        "keywords": result.get("keywords", [])[:30],
        "strings_sample": (result.get("text", "") or "")[:4000],
    }
    facts["embedded_domains"] = embedded[:40]
    facts["embedded_urls"] = urls[:30]
    return facts, meta, apk_text


def scan(
    kind: str,
    value: str,
    *,
    text: str | None = None,
    meta: dict[str, Any] | None = None,
    file_path: str | None = None,
    run_llm: bool = True,
    do_cluster: bool = True,
    trigger: str = "manual",
    quick: bool = False,
    session: Session | None = None,
) -> ScanResult:
    if session is None:
        with session_scope() as own:
            return scan(
                kind,
                value,
                text=text,
                meta=meta,
                file_path=file_path,
                run_llm=run_llm,
                do_cluster=do_cluster,
                trigger=trigger,
                quick=quick,
                session=own,
            )

    kind = (kind or "unknown").strip().lower()
    manual = dict(meta or {})
    ruleset = load_ruleset()

    display_value, normalized = _canonical(kind, value)
    facts: dict[str, Any] = {}
    extra_meta: dict[str, Any] = {}
    # 名称本身通常就带关键信息（「惠民补贴申领中心」），必须并入语料
    corpus = normalize_text(f"{value}\n{text or ''}")[:120_000]
    stored_kind = kind

    # ---- 采集
    if kind in {AssetKind.URL.value, AssetKind.DOMAIN.value}:
        url = display_value
        host = normalize_domain(url)
        facts, extra_meta = _collect_url_facts(url, host, ruleset, manual, quick=quick)

        if any(h in corpus for h in DOWNLOAD_HINTS) or ".apk" in url.lower():
            facts["forces_apk_download"] = True
        if manual.get("distribution_channel"):
            facts["distribution_channel"] = manual["distribution_channel"]
        elif is_shortener(host):
            facts["distribution_channel"] = "link"

    elif kind == AssetKind.APK.value:
        path = file_path or display_value
        try:
            facts, extra_meta, corpus_apk = _collect_apk_facts(path, ruleset)
            corpus = (corpus + "\n" + corpus_apk)[:120_000]
        except FileNotFoundError:
            extra_meta = {"error": "安装包文件不存在"}

    elif kind == AssetKind.TEXT.value:
        facts["distribution_channel"] = manual.get("distribution_channel", "unknown")
        # 文本类资产的 value 往往只是标题，必须和补充正文合并后再判定
        corpus = normalize_text(f"{display_value}\n{text or ''}")[:120_000]

    else:  # miniapp / account / unknown
        facts["distribution_channel"] = manual.get("distribution_channel", "unknown")

    if manual.get("internal_risk") is True:
        facts["linked_confirmed_campaign"] = True

    indicators = extract_indicators(corpus) if corpus else {}

    # ---- 词库匹配：把「发现层看见的词」变成可计分的信号。
    # 没有这一步，发现引擎挑出来的候选到了研判环节会因为「规则库没这条」而被打回冷存，
    # 形成「发现得越多、判得越少」的倒挂。
    kw_host = ""
    if kind in {AssetKind.URL.value, AssetKind.DOMAIN.value}:
        kw_host = normalize_domain(display_value)
    # 体育/影视站群不该按正文匹配词库：那些域名常带 weixin/qq，整类会误判
    from .scoring.engine import detect_off_topic

    vertical = detect_off_topic(corpus)
    kw_text = "" if vertical else f"{display_value} {corpus[:4000]}"
    if vertical:
        facts["off_topic"] = vertical
    kw_match = get_library().match_any(kw_host, kw_text)
    if kw_match.hits:
        facts["keyword_hint"] = round(kw_match.score, 3)
        facts["keyword_terms"] = kw_match.terms[:8]
        facts["keyword_clusters"] = sorted(kw_match.clusters)
        facts["keyword_hits"] = len(kw_match.hits)

    # ---- 官方通报匹配（名称类命中直接可给高权重）
    haystack_names = [
        display_value,
        extra_meta.get("package_name", "") or "",
        " ".join(extra_meta.get("keywords", []) or []),
    ]
    hit = reputation.match_watchlist(haystack_names)
    if not hit and corpus:
        hit = reputation.match_watchlist([corpus[:4000]])
    if hit:
        facts["official_listed"] = True
        extra_meta["official_entry"] = {
            "name": hit.get("name", ""),
            "source": hit.get("source", ""),
            "source_type": hit.get("source_type", ""),
            "category": hit.get("category", ""),
        }

    # ---- 规则评分
    assessment = assess(
        facts,
        text=corpus,
        indicators=indicators,
        ruleset=ruleset,
        official=bool(facts.get("official_listed")),
        reviewed=bool(manual.get("reviewed")),
        min_signals=settings.min_signals_for_verdict,
    )

    if extra_meta.get("official_entry"):
        entry = extra_meta["official_entry"]
        existing = next((s for s in assessment.signals if s.rule_id == "REP-003"), None)
        if existing is not None:
            existing.detail = f"公开通报名称：{entry['name']}（{entry['source']}）"
            existing.evidence = entry["source"]
        else:  # 理论上不会走到，保留兜底以免规则被外部覆盖后丢失信号
            assessment.signals.append(
                Signal(
                    rule_id="REP-003",
                    category="reputation",
                    title="命中官方涉诈通报",
                    weight=45,
                    confidence=0.98,
                    detail=f"公开通报名称：{entry['name']}（{entry['source']}）",
                    source="watchlist",
                    evidence=entry["source"],
                )
            )
        assessment.notes.append(f"匹配到公开通报条目：{entry['name']}，须人工核对包名/域名后再定性")

    # ---- LLM：只做灰区，不做全量
    # 全量调用既慢又贵，而高分（≥70）和低分（<25）本来就不需要模型：
    # 前者证据已经足够，后者连证据都没有，问了也只能得到「不确定」。
    from . import runtime_settings

    llm_cfg = runtime_settings.llm_config()
    if llm_cfg["ready"]:
        in_gray = llm_cfg["gray_low"] <= assessment.score <= llm_cfg["gray_high"]
        has_content = bool(facts.get("page_text_len")) or len(corpus) > 600
        forced = bool(manual.get("force_llm"))
        if forced or (in_gray and has_content):
            payload = {
                "asset": {"kind": kind, "value": display_value[:300]},
                "facts": {k: v for k, v in facts.items() if v not in (None, "", [], 0)},
                "signals": [
                    {"id": s.rule_id, "title": s.title, "weight": s.weight, "detail": s.detail}
                    for s in assessment.top_signals[:12]
                ],
                "rule_score": assessment.score,
                "rule_verdict": assessment.verdict,
                "text_excerpt": corpus[:6000],
                "note": "reasoning 中请用 [E:证据编号] 标注引用；无编号视为未引用。",
            }
            assessment.llm = llm_analyzer.analyze(payload)

    # ---- 富化：ICP 备案（只对值得查的目标，接口有严格频率限制）
    icp_result = None
    if stored_kind in ("domain", "url") and assessment.score >= 12:
        probe_host = extra_meta.get("host") or registrable_domain(display_value)
        probe_domain = registrable_domain(probe_host) if probe_host else ""
        if probe_domain:
            try:
                icp_result = get_icp().lookup(probe_domain)
                if icp_result.status == "registered":
                    facts["icp_registered"] = True
                    facts["icp_entity"] = icp_result.entity
                elif icp_result.status == "unregistered":
                    facts["icp_registered"] = False
            except Exception:  # noqa: BLE001
                log.debug("ICP 查询失败", exc_info=True)

    # ---- 落库
    now = utcnow()
    asset = session.scalar(select(Asset).where(Asset.kind == stored_kind, Asset.normalized == normalized))
    created = asset is None
    if asset is None:
        asset = Asset(kind=stored_kind, value=display_value, normalized=normalized, first_seen=now, last_seen=now)
        session.add(asset)
        session.flush()

    asset.value = display_value
    asset.last_seen = now
    asset.scan_count = (asset.scan_count or 0) + 1
    asset.score = assessment.score
    asset.confidence = assessment.confidence
    asset.verdict = assessment.verdict
    asset.meta = {**(asset.meta or {}), **extra_meta, "last_trigger": trigger, "facts": facts}

    if icp_result is not None:
        asset.icp_status = icp_result.status
        asset.icp_license = icp_result.license
        asset.icp_entity = icp_result.entity
        asset.icp_checked_at = now

    # ---- 分级：把评分翻译成「下一步做什么」
    decision = triage.apply(asset, facts=facts)

    if assessment.llm:
        asset.meta = {**asset.meta, "llm": assessment.llm}

    session.execute(delete(SignalRow).where(SignalRow.asset_id == asset.id))
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

    # ---- 证据
    if kind == AssetKind.APK.value and file_path:
        try:
            append_file(session, asset.id, "apk", file_path, note="原始安装包")
        except OSError:
            log.warning("安装包入库失败：%s", file_path)
    elif kind in {AssetKind.TEXT.value, AssetKind.MINIAPP.value, AssetKind.ACCOUNT.value}:
        append_evidence(session, asset.id, "text", display_value.encode("utf-8"), note="原始文本/名称", extension=".txt")

    snapshot = {
        "kind": kind,
        "value": display_value,
        "facts": facts,
        "signals": [s.as_dict() for s in assessment.signals],
        "score": assessment.score,
        "verdict": assessment.verdict,
        "captured_at": now.isoformat(),
    }
    append_evidence(
        session,
        asset.id,
        "assessment",
        json.dumps(snapshot, ensure_ascii=False, indent=2).encode("utf-8"),
        note="本次研判快照",
        extension=".json",
    )

    session.flush()

    # ---- 自动纳管：分级到 watch/confirmed 就该进监控队列。
    # 以前 WatchTarget 只能手动建，所以「监控」页永远是空的。
    if asset.tier in ("watch", "confirmed"):
        try:
            from .capture import ensure_watch

            ensure_watch(asset.id)
        except Exception:  # noqa: BLE001
            log.debug("自动纳管失败", exc_info=True)

    if do_cluster:
        try:
            cluster(session)
        except Exception:
            log.warning("聚类失败，不影响本次研判", exc_info=True)

    session.refresh(asset)
    asset_payload = {
        "id": asset.id,
        "kind": asset.kind,
        "value": asset.value,
        "normalized": asset.normalized,
        "score": asset.score,
        "confidence": asset.confidence,
        "verdict": asset.verdict,
        "campaign_id": asset.campaign_id,
        "first_seen": asset.first_seen.isoformat(),
        "last_seen": asset.last_seen.isoformat(),
        "scan_count": asset.scan_count,
        "meta": asset.meta,
    }
    asset_payload["tier"] = asset.tier
    asset_payload["triage_reasons"] = decision.reasons[:6]
    return ScanResult(asset_id=asset.id, created=created, assessment=assessment, asset=asset_payload)
