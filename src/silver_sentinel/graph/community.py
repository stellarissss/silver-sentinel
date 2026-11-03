"""社区发现：把图上的连通块变成「团伙」。

为什么不是简单的连通分量
------------------------
连通分量会把「都用了同一家 CDN」的半个互联网连成一坨。
Louvain 用边权做模块度优化，天然抵抗这种弱连接的粘连——这正是我们要的：
共用签名证书（权重 0.9）比共用 IP（0.35）更能说明「同一伙人」。

产出的是什么
------------
不是「确认的犯罪团伙」，是**候选活动簇（Campaign candidate）**。
名字由簇内最具区分度的节点生成，摘要列出把大家连起来的那几条边。
所有结论都带 evidence 引用，供人工复核——这一步不能自动化。
"""

from __future__ import annotations

import hashlib
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

import networkx as nx
from sqlalchemy import select

from ..config import settings
from ..db import session_scope
from ..models import TIER_CONFIRMED, TIER_WATCH, Asset, Campaign
from ..domain import utcnow
from .schema import CLUSTER_RELATIONS, parse_key
from .store import GraphStore, get_graph

log = logging.getLogger(__name__)


@dataclass
class Community:
    node_keys: list[str]
    weight: float = 0.0
    by_type: dict[str, int] = field(default_factory=dict)
    anchor: str = ""
    reasons: list[dict[str, Any]] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.node_keys)


class CommunityFinder:
    def __init__(self, store: GraphStore | None = None) -> None:
        self.store = store or get_graph()

    def _graph(self) -> nx.Graph:
        g = nx.Graph()
        for src, dst, rel, weight in self.store.cluster_edges():
            if src == dst:
                continue
            if g.has_edge(src, dst):
                g[src][dst]["weight"] = max(g[src][dst]["weight"], float(weight))
                g[src][dst]["count"] += 1
                g[src][dst]["rels"].add(rel)
            else:
                g.add_edge(src, dst, weight=max(0.05, float(weight)), count=1, rels={rel})
        return g

    def find(self, min_size: int | None = None) -> list[Community]:
        min_size = max(2, min_size or settings.graph_min_community)
        g = self._graph()
        if g.number_of_edges() == 0:
            return []

        # 小图直接取连通分量：Louvain 的模块度在几十个节点上不稳定，
        # 容易把明明连着的一组切碎。上千节点时它才真正发挥作用。
        if g.number_of_nodes() <= 50:
            groups = list(nx.connected_components(g))
        else:
            try:
                groups = nx.algorithms.community.louvain_communities(g, weight="weight", seed=42)
            except Exception as exc:  # noqa: BLE001
                log.warning("Louvain 失败（%s），退回连通分量", exc)
                groups = list(nx.connected_components(g))

        out: list[Community] = []
        for group in groups:
            nodes = list(group)
            if len(nodes) < min_size:
                continue
            sub = g.subgraph(nodes)
            total_weight = sum(d.get("weight", 0.0) for _, _, d in sub.edges(data=True))
            by_type = Counter(parse_key(k)[0] for k in nodes)

            # 选一个「锚」：优先域名，其次 APK，用来给人看
            anchor = ""
            for preferred in ("domain", "apk", "url", "entity", "phone"):
                candidates = [k for k in nodes if k.startswith(preferred + ":")]
                if candidates:
                    candidates.sort(key=lambda k: -sum(
                        d.get("weight", 0) for _, _, d in g.edges(k, data=True)
                    ))
                    anchor = candidates[0]
                    break

            reasons = []
            for a, b, d in sorted(sub.edges(data=True), key=lambda x: -x[2].get("weight", 0))[:10]:
                reasons.append(
                    {
                        "src": a,
                        "dst": b,
                        "rels": sorted(d.get("rels") or []),
                        "weight": round(d.get("weight", 0), 3),
                        "count": d.get("count", 1),
                    }
                )

            out.append(
                Community(
                    node_keys=nodes,
                    weight=round(total_weight, 2),
                    by_type=dict(by_type),
                    anchor=anchor,
                    reasons=reasons,
                )
            )

        out.sort(key=lambda c: (-c.size, -c.weight))
        return out


def _community_key(asset_ids: list[int]) -> str:
    """稳定 key：由成员资产 id 决定。

    不用节点集合做 key —— 图会不断新增边（比如某天补上一张证书），
    节点集一变 key 就变，团伙名单里会冒出大量「同名的另一个人」。
    资产集合相对稳定，更适合做身份。
    """
    digest = hashlib.sha256("|".join(str(i) for i in sorted(asset_ids)).encode()).hexdigest()[:16]
    return f"cmp-{digest}"


def _build_asset_index(session) -> dict[str, list[Asset]]:
    """建立「图节点 key -> 资产」的多路索引。

    为什么需要多路：APK 资产的 normalized 是文件名（上传时的名字），
    而图节点用的是包名。只按 normalized 查会全部落空，
    表现为「图建好了但一个团伙都聚不出来」。
    """
    index: dict[str, list[Asset]] = {}
    for asset in session.scalars(select(Asset)):
        keys = {f"{asset.kind}:{asset.normalized}"}
        meta = asset.meta or {}
        if asset.kind == "apk":
            pkg = meta.get("package_name") or (meta.get("apk") or {}).get("package_name")
            if pkg:
                keys.add(f"apk:{pkg}")
            keys.add(f"apk:{asset.value}")
        else:
            keys.add(f"{asset.kind}:{asset.value}")
        for k in keys:
            index.setdefault(k.lower(), []).append(asset)
    return index


def _community_name(comm: Community) -> str:
    domain = next((k.split(":", 1)[1] for k in comm.node_keys if k.startswith("domain:")), "")
    apk = next((k.split(":", 1)[1] for k in comm.node_keys if k.startswith("apk:")), "")
    if domain:
        return domain[:60]
    if apk:
        return apk[:60]
    if comm.anchor:
        return comm.anchor.split(":", 1)[1][:60]
    return "未命名活动簇"


def sync_campaigns(store: GraphStore | None = None, min_size: int | None = None) -> dict[str, Any]:
    """把社区写回 campaigns 表，并建立资产与团伙的关联。

    只对「包含可疑资产」的社区建团伙——纯基础设施节点（比如一堆共用同一注册商的
    正常域名）不该被当成团伙。
    """
    finder = CommunityFinder(store)
    communities = finder.find(min_size=min_size)
    created = 0
    updated = 0
    linked = 0
    skipped = 0

    with session_scope() as session:
        index = _build_asset_index(session)
        for comm in communities:
            # 找出社区里的资产节点
            asset_nodes: list[Asset] = []
            seen_ids: set[int] = set()
            for key in comm.node_keys:
                for found in index.get(key.lower(), []):
                    if found.id not in seen_ids:
                        seen_ids.add(found.id)
                        asset_nodes.append(found)

            suspicious = [
                a for a in asset_nodes
                if a.tier in (TIER_CONFIRMED, TIER_WATCH) or a.score >= 35
            ]
            # 单点不成团：只有 1 个可疑资产时，它就是个孤立样本，
            # 建「团伙」只会让名单虚胖。已确认的除外。
            confirmed = [a for a in asset_nodes if a.tier == TIER_CONFIRMED]
            if len(suspicious) < 2 and not confirmed:
                skipped += 1
                continue

            key = _community_key([a.id for a in asset_nodes])
            campaign = session.scalar(select(Campaign).where(Campaign.key == key))
            summary = _summarize(comm, asset_nodes)

            if campaign is None:
                campaign = Campaign(
                    key=key,
                    name=_community_name(comm),
                    status="active",
                    summary=summary,
                    meta={
                        "size": comm.size,
                        "weight": comm.weight,
                        "by_type": comm.by_type,
                        "reasons": comm.reasons,
                    },
                    first_seen=utcnow(),
                    last_seen=utcnow(),
                )
                session.add(campaign)
                session.flush()
                created += 1
            else:
                campaign.summary = summary
                campaign.last_seen = utcnow()
                campaign.meta = {
                    "size": comm.size,
                    "weight": comm.weight,
                    "by_type": comm.by_type,
                    "reasons": comm.reasons,
                }
                updated += 1

            for asset in asset_nodes:
                if asset.campaign_id != campaign.id:
                    asset.campaign_id = campaign.id
                    linked += 1
        session.commit()

    log.info(
        "社区发现：%d 个簇，新建 %d，更新 %d，跳过 %d，关联资产 %d",
        len(communities), created, updated, skipped, linked,
    )
    return {
        "communities": len(communities),
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "linked": linked,
    }


def _summarize(comm: Community, assets: list[Asset]) -> str:
    """用「什么把大家连起来」写摘要。不吹哨，只陈述边。"""
    edge_desc = {
        "SHARES_CERT": "共用签名证书",
        "SIGNED_WITH": "同一证书签名",
        "USES_WALLET": "共用收款地址",
        "USES_PHONE": "共用联系方式",
        "ICP_ENTITY": "同一备案主体",
        "SAME_TEMPLATE": "同页面模板",
        "EMBEDS": "互相内嵌",
    }
    parts: list[str] = []
    counter: Counter[str] = Counter()
    for reason in comm.reasons:
        for rel in reason.get("rels") or []:
            desc = edge_desc.get(rel)
            if desc:
                counter[desc] += 1

    for desc, n in counter.most_common(3):
        parts.append(f"{n} 处{desc}")

    kinds = Counter(a.kind for a in assets)
    kind_desc = "、".join(f"{k} {v}" for k, v in kinds.most_common())
    high = [a for a in assets if a.score >= 70]

    head = f"含 {comm.size} 个关联节点（{kind_desc}）" if kind_desc else f"含 {comm.size} 个关联节点"
    if parts:
        head += "；" + "，".join(parts)
    if high:
        head += f"；其中 {len(high)} 项高度可疑"
    return head[:500]
