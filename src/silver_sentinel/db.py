"""数据库会话、轻量迁移与证据链校验。"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Base, Evidence

log = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        is_sqlite = settings.db_url.startswith("sqlite")
        _engine = create_engine(
            settings.db_url,
            echo=False,
            future=True,
            connect_args={"check_same_thread": False, "timeout": 30} if is_sqlite else {},
            pool_pre_ping=True,
        )
        if is_sqlite:

            @event.listens_for(_engine, "connect")
            def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                # WAL + NORMAL 已能保证崩溃后数据库不损坏，只会丢最近若干事务。
                # 真正的「一条不丢」由 events.jsonl 的 fsync 兜底（见 core/eventlog.py），
                # 那里是顺序追加，代价远低于让每次 UPDATE 都 fsync。
                cur.execute("PRAGMA synchronous=NORMAL")
                cur.execute("PRAGMA busy_timeout=30000")
                cur.execute("PRAGMA foreign_keys=ON")
                cur.close()

    return _engine


def get_session_factory() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)
    return _SessionLocal


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# 老库升级：create_all 不会给已存在的表补列，这里显式处理。
# 只做「加列 / 加索引」这两种安全操作，不动已有数据。
_ADDED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "assets": [
        ("tier", "VARCHAR(16) DEFAULT 'candidate'"),
        ("discovery_source", "VARCHAR(32) DEFAULT 'manual'"),
        ("discovery_reason", "TEXT DEFAULT ''"),
        ("dismiss_reason", "TEXT DEFAULT ''"),
        ("icp_status", "VARCHAR(24) DEFAULT 'unknown'"),
        ("icp_license", "VARCHAR(80) DEFAULT ''"),
        ("icp_entity", "VARCHAR(200) DEFAULT ''"),
        ("icp_violation", "VARCHAR(16) DEFAULT 'unknown'"),
        ("icp_violation_title", "VARCHAR(200) DEFAULT ''"),
        ("icp_checked_at", "DATETIME"),
        ("enrich_count", "INTEGER DEFAULT 0"),
        ("last_capture_at", "DATETIME"),
        ("capture_state", "VARCHAR(16) DEFAULT 'pending'"),
        ("capture_error", "TEXT DEFAULT ''"),
        ("capture_retry_at", "DATETIME"),
    ],
    "icp_cache": [
        ("violation", "VARCHAR(16) DEFAULT 'unknown'"),
        ("violation_title", "VARCHAR(200) DEFAULT ''"),
    ],
    "evidence": [
        ("mime", "VARCHAR(80) DEFAULT ''"),
        ("deleted_at", "DATETIME"),
        ("deleted_by", "VARCHAR(80) DEFAULT ''"),
        ("delete_reason", "TEXT DEFAULT ''"),
    ],
    "watch_targets": [
        ("asset_id", "INTEGER"),
        ("auto", "BOOLEAN DEFAULT 0"),
        ("fail_count", "INTEGER DEFAULT 0"),
        ("change_count", "INTEGER DEFAULT 0"),
        ("last_change_at", "DATETIME"),
    ],
}

_ADDED_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS ix_assets_tier ON assets (tier)",
    "CREATE INDEX IF NOT EXISTS ix_assets_discovery_source ON assets (discovery_source)",
    "CREATE INDEX IF NOT EXISTS ix_assets_tier_score ON assets (tier, score)",
    "CREATE INDEX IF NOT EXISTS ix_assets_capture_state ON assets (capture_state)",
    "CREATE INDEX IF NOT EXISTS ix_discovery_events_normalized ON discovery_events (normalized)",
    "CREATE INDEX IF NOT EXISTS ix_discovery_events_asset_id ON discovery_events (asset_id)",
    "CREATE INDEX IF NOT EXISTS ix_graph_edges_src ON graph_edges (src)",
    "CREATE INDEX IF NOT EXISTS ix_graph_edges_dst ON graph_edges (dst)",
    "CREATE INDEX IF NOT EXISTS ix_graph_edges_rel ON graph_edges (rel)",
    "CREATE INDEX IF NOT EXISTS ix_graph_nodes_type ON graph_nodes (type)",
    "CREATE INDEX IF NOT EXISTS ix_evidence_deleted_at ON evidence (deleted_at)",
    "CREATE INDEX IF NOT EXISTS ix_watch_targets_asset_id ON watch_targets (asset_id)",
]


def init_db() -> None:
    engine = get_engine()
    Base.metadata.create_all(engine)
    if engine.dialect.name != "sqlite":
        return

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, columns in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue
            present = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in columns:
                if name in present:
                    continue
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                log.info("迁移：%s 增加列 %s", table, name)
        for ddl in _ADDED_INDEXES:
            try:
                conn.execute(text(ddl))
            except Exception:  # 索引失败不该阻断启动
                log.debug("索引创建跳过：%s", ddl)


def reset_engine(db_url: str | None = None) -> None:
    """测试用：切换数据库后重建引擎。"""
    global _engine, _SessionLocal
    if db_url:
        settings.db_url = db_url
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


# ---------------------------------------------------------------- 证据链


def compute_chain_hash(prev_hash: str, sha256: str, captured_at_iso: str) -> str:
    return hashlib.sha256(f"{prev_hash}|{sha256}|{captured_at_iso}".encode()).hexdigest()


def verify_chain(session: Session, asset_id: int | None = None) -> dict:
    """逐条重算链式哈希，返回第一个断点。"""
    stmt = select(Evidence).order_by(Evidence.id)
    if asset_id is not None:
        stmt = stmt.where(Evidence.asset_id == asset_id)

    prev = ""
    checked = 0
    for row in session.scalars(stmt):
        expected = compute_chain_hash(prev, row.sha256, row.captured_at.isoformat())
        if row.prev_hash != prev or row.chain_hash != expected:
            # 区分「被改过」和「压根没写过链」：早期手工导入的数据链是空的，
            # 直接报「断点」会让人以为有人动过证据。
            reason = (
                "该条证据没有链哈希（早期导入或人工写入）"
                if not row.chain_hash
                else "链哈希不匹配，内容可能被改动"
            )
            return {
                "ok": False,
                "checked": checked,
                "broken_at": row.id,
                "reason": reason,
                "expected_prev": prev,
                "actual_prev": row.prev_hash,
            }
        prev = row.chain_hash
        checked += 1
    return {"ok": True, "checked": checked, "head": prev}


def db_stats() -> dict:
    """运维页用的粗粒度统计，避免把大表全扫一遍。"""
    from .models import Asset, DiscoveryEvent, Evidence, GraphEdge, GraphNode

    with session_scope() as s:
        from sqlalchemy import func

        return {
            "assets": s.scalar(select(func.count(Asset.id))) or 0,
            "evidence": s.scalar(select(func.count(Evidence.id))) or 0,
            "discovery_events": s.scalar(select(func.count(DiscoveryEvent.id))) or 0,
            "graph_nodes": s.scalar(select(func.count(GraphNode.id))) or 0,
            "graph_edges": s.scalar(select(func.count(GraphEdge.id))) or 0,
        }
