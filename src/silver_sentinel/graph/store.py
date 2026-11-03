"""图存储：内置引擎 + Neo4j 双后端。

为什么不一上来就用 Neo4j
-------------------------
Neo4j 是好轮子，但它是个需要运维的进程。这套系统的第一原则是「零配置能跑」，
所以默认用 SQLite 存图——节点和边各一张表，两级索引，几万节点毫秒级邻域查询。
配了 SILVER_NEO4J_URI 就自动切到 Neo4j，享受 Cypher 和可视化生态。

两个后端暴露同一组方法，上层不感知差异。切换只改环境变量。

一致性
------
图不是真相源，SQLite 里的 Asset / Evidence 才是。图可以随时从资产重建。
所以这里不做事务补偿——写失败就记日志，下次重建补上。
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

from sqlalchemy import func, or_, select

from ..config import settings
from ..db import session_scope
from ..domain import utcnow
from ..models import GraphEdge, GraphNode
from .schema import CLUSTER_RELATIONS, edge_weight, node_key, parse_key

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Node:
    key: str
    type: str
    label: str
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Edge:
    src: str
    dst: str
    rel: str
    weight: float = 1.0
    props: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Subgraph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": n.key, "type": n.type, "label": n.label, "props": n.props} for n in self.nodes
            ],
            "edges": [
                {"source": e.src, "target": e.dst, "rel": e.rel, "weight": e.weight}
                for e in self.edges
            ],
        }


class GraphStore:
    """接口定义。"""

    def upsert_node(self, node_type: str, value: str, label: str = "", props: dict | None = None) -> str:
        raise NotImplementedError

    def upsert_edge(self, src_key: str, dst_key: str, rel: str, weight: float | None = None) -> None:
        raise NotImplementedError

    def link(self, src: tuple[str, str], dst: tuple[str, str], rel: str, weight: float | None = None,
             src_label: str = "", dst_label: str = "") -> None:
        a = self.upsert_node(src[0], src[1], src_label)
        b = self.upsert_node(dst[0], dst[1], dst_label)
        self.upsert_edge(a, b, rel, weight)

    def neighbors(self, key: str, depth: int = 1) -> Subgraph:
        raise NotImplementedError

    def stats(self) -> dict[str, Any]:
        raise NotImplementedError

    def clear(self) -> None:
        raise NotImplementedError


class BuiltinGraphStore(GraphStore):
    """SQLite 实现。BFS 逐层扩展，每层一次 IN 查询。"""

    def upsert_node(self, node_type: str, value: str, label: str = "", props: dict | None = None) -> str:
        key = node_key(node_type, value)
        with session_scope() as s:
            row = s.scalar(select(GraphNode).where(GraphNode.key == key))
            if row:
                row.last_seen = utcnow()
                if label and not row.label:
                    row.label = label[:300]
                if props:
                    merged = dict(row.props or {})
                    merged.update(props)
                    row.props = merged
            else:
                s.add(
                    GraphNode(
                        key=key,
                        type=node_type,
                        label=(label or value)[:300],
                        props=props or {},
                    )
                )
        return key

    def upsert_edge(self, src_key: str, dst_key: str, rel: str, weight: float | None = None) -> None:
        if src_key == dst_key:
            return
        w = edge_weight(rel) if weight is None else weight
        with session_scope() as s:
            row = s.scalar(
                select(GraphEdge).where(
                    GraphEdge.src == src_key, GraphEdge.dst == dst_key, GraphEdge.rel == rel
                )
            )
            if row:
                row.count += 1
                row.weight = round(min(1.0, row.weight + w * 0.15), 4)
                row.last_seen = utcnow()
            else:
                s.add(GraphEdge(src=src_key, dst=dst_key, rel=rel, weight=round(w, 4)))

    def _fetch_nodes(self, keys: Iterable[str]) -> list[GraphNode]:
        keys = list(keys)
        if not keys:
            return []
        out: list[GraphNode] = []
        with session_scope() as s:
            for i in range(0, len(keys), 500):
                chunk = keys[i : i + 500]
                out.extend(s.scalars(select(GraphNode).where(GraphNode.key.in_(chunk))))
        return out

    def neighbors(self, key: str, depth: int = 1, *, limit_nodes: int = 600) -> Subgraph:
        visited: dict[str, GraphNode] = {}
        edges: dict[tuple[str, str, str], GraphEdge] = {}
        frontier = {key}
        depth = max(1, min(depth, 3))

        for _ in range(depth):
            if not frontier or len(visited) >= limit_nodes:
                break
            with session_scope() as s:
                rows = list(
                    s.scalars(
                        select(GraphEdge).where(
                            or_(GraphEdge.src.in_(list(frontier)), GraphEdge.dst.in_(list(frontier)))
                        ).limit(4000)
                    )
                )
            next_frontier: set[str] = set()
            for e in rows:
                edges[(e.src, e.dst, e.rel)] = e
                for k in (e.src, e.dst):
                    if k not in visited:
                        next_frontier.add(k)
            for node in self._fetch_nodes(next_frontier - set(visited)):
                visited[node.key] = node
                if len(visited) >= limit_nodes:
                    break
            frontier = next_frontier

        # 补上起点本身
        if key not in visited:
            for node in self._fetch_nodes([key]):
                visited[node.key] = node

        return Subgraph(
            nodes=[
                Node(n.key, n.type, n.label, n.props or {}) for n in visited.values()
            ],
            edges=[
                Edge(e.src, e.dst, e.rel, e.weight, e.props or {}) for e in edges.values()
            ],
        )

    def cluster_edges(self) -> list[tuple[str, str, str, float]]:
        """取出参与聚类的边 (src, dst, rel, weight)，给社区发现用。

        RESOLVES_TO 只在 url -> domain 方向计入：这是「归属」，不是「同源」。
        domain -> ip 方向必须排除，否则所有走同一 CDN 的网站会被连成一团。
        """
        rels = list(CLUSTER_RELATIONS)
        out: list[tuple[str, str, str, float]] = []
        with session_scope() as s:
            for e in s.scalars(select(GraphEdge).where(GraphEdge.rel.in_(rels))):
                if e.rel == "RESOLVES_TO":
                    src_type = e.src.split(":", 1)[0]
                    dst_type = e.dst.split(":", 1)[0]
                    if not (src_type in ("url", "domain") and dst_type == "domain"):
                        continue
                out.append((e.src, e.dst, e.rel, float(e.weight)))
        return out

    def stats(self) -> dict[str, Any]:
        with session_scope() as s:
            by_type = dict(
                s.execute(select(GraphNode.type, func.count(GraphNode.id)).group_by(GraphNode.type)).all()
            )
            by_rel = dict(
                s.execute(select(GraphEdge.rel, func.count(GraphEdge.id)).group_by(GraphEdge.rel)).all()
            )
            return {
                "backend": "builtin",
                "nodes": s.scalar(select(func.count(GraphNode.id))) or 0,
                "edges": s.scalar(select(func.count(GraphEdge.id))) or 0,
                "by_type": by_type,
                "by_rel": by_rel,
            }

    def clear(self) -> None:
        with session_scope() as s:
            s.query(GraphEdge).delete()
            s.query(GraphNode).delete()


class Neo4jGraphStore(GraphStore):
    """Neo4j 实现。用官方 driver，Cypher 直接映射。

    注意：Neo4j 里 label 不能参数化，所以节点标签用固定白名单拼接，
    值一律走参数，避免注入。
    """

    _VALID = {
        "domain", "url", "ip", "asn", "cert", "apk", "wallet", "phone", "landline",
        "qq", "wechat", "email", "bank_card", "entity", "registrar", "template",
        "brand", "campaign", "actor", "keyword",
    }

    def __init__(self) -> None:
        from neo4j import GraphDatabase

        self.driver = GraphDatabase.driver(
            settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password)
        )
        self._lock = threading.Lock()
        self._ensure_constraints()

    def _ensure_constraints(self) -> None:
        try:
            with self.driver.session(database=settings.neo4j_database) as s:
                s.run("CREATE CONSTRAINT entity_key IF NOT EXISTS FOR (n:Entity) REQUIRE n.key IS UNIQUE")
        except Exception as exc:  # noqa: BLE001
            log.warning("Neo4j 约束创建失败：%s", exc)

    def upsert_node(self, node_type: str, value: str, label: str = "", props: dict | None = None) -> str:
        key = node_key(node_type, value)
        lab = node_type if node_type in self._VALID else "Entity"
        with self.driver.session(database=settings.neo4j_database) as s:
            s.run(
                f"MERGE (n:{lab} {{key:$key}}) "
                "SET n.label = coalesce(nullif(n.label,''), $label), n.type=$type, "
                "n.value=$value, n.last_seen=datetime(), n += $props",
                key=key, label=(label or value)[:300], type=node_type, value=value[:200],
                props={k: str(v)[:500] for k, v in (props or {}).items()},
            )
        return key

    def upsert_edge(self, src_key: str, dst_key: str, rel: str, weight: float | None = None) -> None:
        if src_key == dst_key:
            return
        w = edge_weight(rel) if weight is None else weight
        safe_rel = "".join(ch for ch in rel.upper() if ch.isalnum() or ch == "_") or "RELATED"
        with self.driver.session(database=settings.neo4j_database) as s:
            s.run(
                f"MATCH (a {{key:$a}}), (b {{key:$b}}) "
                f"MERGE (a)-[r:{safe_rel}]->(b) "
                "ON CREATE SET r.weight=$w, r.count=1, r.first_seen=datetime() "
                "ON MATCH SET r.count = coalesce(r.count,1)+1, r.last_seen=datetime()",
                a=src_key, b=dst_key, w=round(w, 4),
            )

    def neighbors(self, key: str, depth: int = 1, *, limit_nodes: int = 600) -> Subgraph:
        depth = max(1, min(depth, 3))
        with self.driver.session(database=settings.neo4j_database) as s:
            res = s.run(
                f"MATCH path=(n {{key:$key}})-[*1..{depth}]-(m) "
                f"RETURN path LIMIT {int(limit_nodes)}",
                key=key,
            )
            nodes: dict[str, Node] = {}
            edges: dict[tuple[str, str, str], Edge] = {}
            for record in res:
                path = record["path"]
                for n in path.nodes:
                    k = n.get("key")
                    if k:
                        nodes[k] = Node(k, n.get("type", "entity"), n.get("label", k),
                                        dict(n.items()))
                for r in path.relationships:
                    a = r.start_node.get("key")
                    b = r.end_node.get("key")
                    if a and b:
                        edges[(a, b, r.type)] = Edge(a, b, r.type, float(r.get("weight", 0.3)))
            return Subgraph(list(nodes.values()), list(edges.values()))

    def cluster_edges(self) -> list[tuple[str, str, str, float]]:
        rels = "|".join(CLUSTER_RELATIONS)
        out: list[tuple[str, str, str, float]] = []
        with self.driver.session(database=settings.neo4j_database) as s:
            res = s.run(
                f"MATCH (a)-[r:{rels}]->(b) "
                "RETURN a.key AS a, b.key AS b, type(r) AS rel, r.weight AS w, "
                "labels(a)[0] AS ta, labels(b)[0] AS tb LIMIT 200000"
            )
            for rec in res:
                if rec["rel"] == "RESOLVES_TO" and not (
                    rec["ta"] in ("url", "domain") and rec["tb"] == "domain"
                ):
                    continue
                out.append((rec["a"], rec["b"], rec["rel"], float(rec["w"] or 0.5)))
        return out

    def stats(self) -> dict[str, Any]:
        with self.driver.session(database=settings.neo4j_database) as s:
            nodes = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
            edges = s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
            by_type = {r["t"]: r["c"] for r in s.run("MATCH (n) RETURN n.type AS t, count(*) AS c")}
        return {"backend": "neo4j", "nodes": nodes, "edges": edges, "by_type": by_type, "by_rel": {}}

    def clear(self) -> None:
        with self.driver.session(database=settings.neo4j_database) as s:
            s.run("MATCH (n) DETACH DELETE n")


_store: GraphStore | None = None
_lock = threading.Lock()


def get_graph() -> GraphStore:
    global _store
    if _store is None:
        with _lock:
            if _store is None:
                if settings.neo4j_ready:
                    try:
                        _store = Neo4jGraphStore()
                        log.info("图后端：Neo4j (%s)", settings.neo4j_uri)
                    except Exception as exc:  # noqa: BLE001
                        log.warning("Neo4j 连接失败（%s），回退到内置图引擎", exc)
                        _store = BuiltinGraphStore()
                else:
                    _store = BuiltinGraphStore()
                    log.info("图后端：内置 SQLite")
    return _store


def reset_graph() -> None:
    """测试用。"""
    global _store
    _store = None
