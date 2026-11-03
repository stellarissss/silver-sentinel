"""团伙归并与聚类。

单个域名/安装包只是一片叶子，处置需要打掉根。归并依据是「共享的不可伪装物」：
签名证书、页面模板指纹、收款钱包、包名前缀、解析 IP。
这些都是换域名、换马甲包时很难全部改掉的东西。
"""

from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..domain import stable_key, utcnow
from ..models import Asset, Campaign

log = logging.getLogger(__name__)

# 这些前缀属于通用第三方，不能作为归并依据
_GENERIC_PREFIXES = {
    "com.android", "com.google", "com.microsoft", "com.tencent.sdk",
    "androidx", "com.facebook", "com.umeng", "com.alipay.sdk",
}


class UnionFind:
    def __init__(self) -> None:
        self._parent: dict[int, int] = {}

    def add(self, x: int) -> None:
        self._parent.setdefault(x, x)

    def find(self, x: int) -> int:
        self.add(x)
        root = x
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[x] != root:
            self._parent[x], x = root, self._parent[x]
        return root

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[rb] = ra

    def groups(self) -> dict[int, list[int]]:
        out: dict[int, list[int]] = defaultdict(list)
        for x in self._parent:
            out[self.find(x)].append(x)
        return out


def link_keys(asset: Asset) -> list[str]:
    meta = asset.meta or {}
    keys: list[str] = []

    if meta.get("cert_sha256"):
        keys.append(f"cert:{meta['cert_sha256']}")

    if meta.get("template_hash"):
        keys.append(f"tpl:{meta['template_hash']}")

    for wallet in meta.get("wallet_addresses") or []:
        if wallet:
            keys.append(f"wallet:{str(wallet).lower()}")

    package = str(meta.get("package_name") or "")
    if package.count(".") >= 2:
        prefix = ".".join(package.split(".")[:2])
        if prefix not in _GENERIC_PREFIXES and len(prefix.split(".")[-1]) >= 3:
            keys.append(f"pkg:{prefix}")

    for ip in meta.get("ips") or []:
        if ip and not str(ip).startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.")):
            keys.append(f"ip:{ip}")

    return keys


def _representative_name(assets: list[Asset]) -> str:
    apks = [a for a in assets if a.kind == "apk"]
    if apks:
        pkg = (apks[0].meta or {}).get("package_name") or ""
        if pkg:
            return f"团伙 · {pkg}"
        return f"团伙 · {apks[0].value[:48]}"
    domains = [a for a in assets if a.kind in {"domain", "url"}]
    if domains:
        return f"团伙 · {domains[0].value[:48]}"
    return f"团伙 · {assets[0].value[:48]}"


def cluster(session: Session) -> dict[str, int]:
    """全量重算归并关系。幂等：同一批资产重复运行结果一致。"""
    assets = list(session.scalars(select(Asset)))
    if not assets:
        return {"assets": 0, "clusters": 0, "created": 0, "linked": 0}

    uf = UnionFind()
    index: dict[str, list[int]] = defaultdict(list)

    for asset in assets:
        uf.add(asset.id)
        for key in link_keys(asset):
            index[key].append(asset.id)

    for ids in index.values():
        for other in ids[1:]:
            uf.union(ids[0], other)

    by_id = {a.id: a for a in assets}
    existing = list(session.scalars(select(Campaign)))
    by_key = {c.key: c for c in existing}

    created = 0
    linked = 0
    groups = uf.groups()

    for members in groups.values():
        if len(members) < 2:
            continue

        group_assets = [by_id[i] for i in members]
        anchor = min(a.normalized for a in group_assets)
        key = stable_key("cluster", anchor)
        campaign = by_key.get(key)

        if campaign is None:
            campaign = Campaign(
                key=key,
                name=_representative_name(sorted(group_assets, key=lambda a: a.first_seen)),
                first_seen=min(a.first_seen for a in group_assets),
                last_seen=max(a.last_seen for a in group_assets),
                summary=f"由 {len(group_assets)} 个资产归并，共享证书/模板/收款地址之一。",
                meta={"link_keys": sorted({k for a in group_assets for k in link_keys(a)})[:20]},
            )
            session.add(campaign)
            session.flush()
            by_key[key] = campaign
            created += 1

        campaign.last_seen = max(campaign.last_seen or utcnow(), *(a.last_seen for a in group_assets))
        for asset in group_assets:
            if asset.campaign_id != campaign.id:
                asset.campaign_id = campaign.id
                linked += 1

    session.flush()
    log.info("聚类完成：assets=%s clusters=%s created=%s linked=%s", len(assets), len(groups), created, linked)
    return {"assets": len(assets), "clusters": len(groups), "created": created, "linked": linked}
