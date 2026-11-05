"""从资产构建关系图。

图的原料全部来自已经固化的证据，不引入新的采集：
- 域名资产 → RDAP 注册商、ICP 主体、DNS 解析 IP
- APK 资产 → 包名、签名证书、内嵌域名、钱包地址、联系方式、模板指纹
- 文本资产 → 从语料里抽出的指标

设计取舍：**宁多勿少**。多余的边只是让图看起来乱一点，漏掉的边会让两个
本该归为一伙的资产永远分开。所以 MENTIONS 这类弱关系也全建，只是不参与聚类。
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from sqlalchemy import select

from ..db import session_scope
from ..models import Asset, Evidence
from ..normalize import extract_indicators, is_shared_infra
from .schema import CLUSTER_RELATIONS, node_key
from .store import GraphStore, get_graph

log = logging.getLogger(__name__)


def _as_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return []


class GraphBuilder:
    def __init__(self, store: GraphStore | None = None) -> None:
        self.store = store or get_graph()
        self.stats = {"assets": 0, "nodes": 0, "edges": 0, "errors": 0}

    def _link(self, src: tuple[str, str], dst: tuple[str, str], rel: str, **kw: Any) -> None:
        try:
            self.store.link(src, dst, rel, **kw)
            self.stats["edges"] += 1
        except Exception as exc:  # noqa: BLE001
            self.stats["errors"] += 1
            log.debug("建边失败 %s -%s-> %s: %s", src, rel, dst, exc)

    # ------------------------------------------------------------ 单资产
    def build_asset(self, asset: Asset, *, evidence_texts: Iterable[str] = ()) -> None:
        self.stats["assets"] += 1
        meta = asset.meta or {}
        facts = meta.get("facts") or {}
        value = asset.value
        kind = asset.kind
        label = value[:120]

        if kind == "domain":
            self._build_domain(asset, value, facts, meta, label)
        elif kind == "url":
            self._build_url(asset, value, facts, meta, label)
        elif kind == "apk":
            self._build_apk(asset, value, facts, meta, label)
        else:
            # 文本 / 小程序 / 话术：只抽指标
            fallback = self.store.upsert_node("keyword" if kind == "text" else kind, value, label)
            self._attach_indicators(fallback, value)

        if evidence_texts:
            anchor = node_key(kind, value)
            self._attach_indicators(anchor, "\n".join(t for t in evidence_texts if t))

    def _build_domain(self, asset: Asset, value: str, facts: dict, meta: dict, label: str) -> None:
        dkey = self.store.upsert_node("domain", value, label, {"tier": asset.tier, "score": asset.score})
        # 共享基础设施（*.snowflake.com / *.amazonaws.com / *.vercel.app …）下，
        # 证书与 IP 是平台分配的，拿来当「同伙」证据会把整朵云的客户判成一伙。
        infra = is_shared_infra(value)

        for ip in ([] if infra else _as_list(facts.get("ips")) + _as_list(facts.get("a_records"))):
            self._link(("domain", value), ("ip", ip), "RESOLVES_TO")
        for ns in _as_list(facts.get("nameservers")):
            self._link(("domain", value), ("asn", ns), "HOSTED_ON")

        # 证书指纹是同一团伙最强的关联证据：一张证书签过的域名，几乎必然同源。
        # 优先读资产列（CT 发现时写入），再退回 meta/facts 里的旧字段。
        cert_fp = asset.fingerprint or facts.get("cert_fingerprint") or meta.get("cert_fingerprint")
        if cert_fp and not infra:
            self._link(("domain", value), ("cert", cert_fp), "HAS_CERT")

        registrar = facts.get("registrar") or meta.get("registrar")
        if registrar:
            self._link(("domain", value), ("registrar", registrar), "REGISTERED_BY")

        if asset.icp_entity:
            self._link(("domain", value), ("entity", asset.icp_entity), "ICP_ENTITY")

        brand = facts.get("brand_lookalike")
        if brand:
            self._link(("domain", value), ("brand", str(brand)), "IMPERSONATES")

        # 域名里出现的联系方式/钱包（少见但存在，如 pay.xxx.top/qq12345）
        self._attach_indicators(dkey, value)

    def _build_url(self, asset: Asset, value: str, facts: dict, meta: dict, label: str) -> None:
        ukey = self.store.upsert_node("url", value, label, {"tier": asset.tier})
        host = facts.get("host") or meta.get("host")
        if host:
            self._link(("url", value), ("domain", host), "RESOLVES_TO")
            self._link(("domain", host), ("url", value), "MENTIONS")
        self._attach_indicators(ukey, value)

    def _build_apk(self, asset: Asset, value: str, facts: dict, meta: dict, label: str) -> None:
        # APK 的元数据在 intake 里是扁平写入 meta 的（package_name / cert_sha256 /
        # template_hash / wallet_addresses / urls），另有一份嵌套在 meta.apk。
        # 两处都取，谁有值用谁。
        nested = meta.get("apk") or {}
        package = (
            meta.get("package_name")
            or nested.get("package_name")
            or facts.get("package")
            or value
        )
        akey = self.store.upsert_node(
            "apk", package, label,
            {"sha256": facts.get("sha256", ""), "tier": asset.tier, "score": asset.score},
        )

        certs = (
            _as_list(meta.get("cert_sha256"))
            or _as_list(nested.get("cert_sha256"))
            or _as_list(facts.get("signing_certs"))
            or _as_list(meta.get("signing_certs"))
        )
        for fp in certs:
            self._link(("apk", package), ("cert", fp), "SIGNED_WITH")

        template = meta.get("template_hash") or nested.get("template_hash") or facts.get("template_fingerprint")
        if template:
            self._link(("apk", package), ("template", template), "SAME_TEMPLATE")

        for domain in (
            _as_list(facts.get("embedded_domains"))
            + _as_list(meta.get("embedded_domains"))
            + _as_list(meta.get("domains"))
        ):
            self._link(("apk", package), ("domain", domain), "EMBEDS")
        for url in _as_list(meta.get("urls")) + _as_list(facts.get("embedded_urls")):
            self._link(("apk", package), ("url", url), "EMBEDS")

        for wallet in _as_list(meta.get("wallet_addresses")) + _as_list(facts.get("wallets")):
            self._link(("apk", package), ("wallet", wallet), "USES_WALLET")
        for phone in _as_list(facts.get("phones")):
            self._link(("apk", package), ("phone", phone), "USES_PHONE")
        for qq in _as_list(facts.get("qq")):
            self._link(("apk", package), ("qq", qq), "USES_PHONE")
        for wx in _as_list(facts.get("wechat")):
            self._link(("apk", package), ("wechat", wx), "USES_PHONE")

        blob = " ".join(
            _as_list(facts.get("strings_sample")) + _as_list(meta.get("strings_sample"))
        )
        if blob:
            self._attach_indicators(akey, blob)

    # ------------------------------------------------------------ 指标挂载
    def _attach_indicators(self, anchor: str, text: str) -> None:
        if not text or len(text) < 4:
            return
        try:
            ind = extract_indicators(text[:200_000])
        except Exception:  # noqa: BLE001
            return

        node_type, node_value = anchor.split(":", 1)
        src = (node_type, node_value)

        for d in ind.get("domains", [])[:80]:
            if d == node_value:
                continue
            self._link(src, ("domain", d), "EMBEDS" if node_type == "apk" else "MENTIONS")
        for w in ind.get("wallets", [])[:20]:
            self._link(src, ("wallet", w), "USES_WALLET")
        for p in ind.get("phones", [])[:20]:
            self._link(src, ("phone", p), "USES_PHONE")
        for p in ind.get("landlines", [])[:10]:
            self._link(src, ("landline", p), "USES_PHONE")
        for q in ind.get("qq", [])[:10]:
            self._link(src, ("qq", q), "USES_PHONE")
        for wx in ind.get("wechat", [])[:10]:
            self._link(src, ("wechat", wx), "USES_PHONE")
        for c in ind.get("bank_cards", [])[:10]:
            self._link(src, ("bank_card", c), "USES_WALLET")
        for pkg in ind.get("apk_packages", [])[:10]:
            self._link(src, ("apk", pkg), "EMBEDS")

    # ------------------------------------------------------------ 批量
    def build_all(self, limit: int = 5000, tiers: tuple[str, ...] = ("confirmed", "watch", "candidate")) -> dict:
        """全量重建。资产多时按分级优先，先保证重要的进图。"""
        with session_scope() as s:
            rows = list(
                s.scalars(
                    select(Asset)
                    .where(Asset.tier.in_(tiers))
                    .order_by(Asset.score.desc(), Asset.last_seen.desc())
                    .limit(limit)
                )
            )
            # 预取证据文本，避免 N+1
            evidence_map: dict[int, list[str]] = {}
            for ev in s.scalars(
                select(Evidence).where(Evidence.asset_id.in_([r.id for r in rows] or [-1]))
            ):
                if ev.kind in ("page_text", "apk_strings", "chat_text"):
                    evidence_map.setdefault(ev.asset_id, []).append(ev.note or "")

            for asset in rows:
                try:
                    self.build_asset(asset, evidence_texts=evidence_map.get(asset.id, []))
                except Exception as exc:  # noqa: BLE001
                    self.stats["errors"] += 1
                    log.debug("构建资产 %s 失败：%s", asset.id, exc)

        # 把 Campaign 关系也写进图
        self._link_campaigns()
        # 节点数取图库真实值：builder 只负责建边，自己数是数不准的
        try:
            self.stats["nodes"] = int(self.store.stats().get("nodes", 0))
        except Exception:  # noqa: BLE001
            pass
        return self.stats

    def _link_campaigns(self) -> None:
        from ..models import Campaign

        with session_scope() as s:
            campaigns = list(s.scalars(select(Campaign)))
            for c in campaigns:
                self.store.upsert_node("campaign", c.key, c.name, {"status": c.status})
                for asset in c.assets or []:
                    if asset.kind == "apk":
                        pkg = (asset.meta or {}).get("package_name") or (asset.meta or {}).get("apk", {}).get("package_name")
                        node_value = pkg or asset.normalized
                    else:
                        node_value = asset.normalized
                    self._link((asset.kind, node_value), ("campaign", c.key), "PART_OF")


def build_graph(limit: int = 5000) -> dict:
    return GraphBuilder().build_all(limit=limit)
