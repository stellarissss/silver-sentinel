"""数据库会话、轻量迁移与证据链校验。"""

from __future__ import annotations

import fcntl
import hashlib
import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Base, ChainAnchor, Evidence

log = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None

# 写证据链必须串行：chain_tip() 读到链尾、算出 prev_hash、flush 落行，
# 这三步中间只要插进另一个写事务，链就会分叉。取证虽已单线程，但
# intake / replay / CLI 也会写 evidence，跨进程还要靠文件锁。
_CHAIN_THREAD_LOCK = threading.RLock()
_CHAIN_LOCK_DEPTH = threading.local()  # 同线程/同进程嵌套调用不再抢第二个 flock fd
_LOCK_BUSY_TIMEOUT = 30.0
_LOCK_POLL = 0.02


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
        # autoflush=False：WAL 下 SELECT 触发的自动 flush 会去抢写锁，
        # 线上每小时几十次 "Query-invoked autoflush ... database is locked"
        # 都来自这里。所有需要提前落行的地方都显式 flush()（append/rescore
        # 本来就有），关掉隐式 flush 不改变语义，只去掉撞锁的机会。
        _SessionLocal = sessionmaker(
            bind=get_engine(), expire_on_commit=False, future=True, autoflush=False
        )
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


@contextmanager
def _chain_file_lock() -> Iterator[None]:
    """跨进程排他锁，包住整个「读链尾 → 写证据 → 提交」事务。

    锁的粒度必须是事务级：只在 append() 内部加锁没用，事务提交发生在
    with 退出时，另一个进程拿到锁后仍可能读到尚未提交的旧链尾。

    flock 绑在打开的文件描述符上：同一进程若嵌套进来再开一个 fd 抢
    LOCK_EX，会和外层持有的锁互相顶死、白等 30 秒。用线程内深度计数
    让嵌套调用直接放行，只在最外层真正加/解文件锁。
    """
    depth = getattr(_CHAIN_LOCK_DEPTH, "value", 0)
    if depth:
        _CHAIN_LOCK_DEPTH.value = depth + 1
        try:
            yield
            return
        finally:
            _CHAIN_LOCK_DEPTH.value = depth

    with _CHAIN_THREAD_LOCK:
        lock_path = Path(settings.data_dir) / "evidence.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fh = lock_path.open("w")
        deadline = time.monotonic() + _LOCK_BUSY_TIMEOUT
        try:
            while True:
                try:
                    fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("等待证据链写锁超时（30s）") from None
                    time.sleep(_LOCK_POLL)
            _CHAIN_LOCK_DEPTH.value = 1
            try:
                yield
            finally:
                _CHAIN_LOCK_DEPTH.value = 0
                fcntl.flock(fh, fcntl.LOCK_UN)
        finally:
            fh.close()


@contextmanager
def chain_write_scope() -> Iterator[Session]:
    """写证据用的会话：整段事务串行。

    所有会 INSERT evidence 的入口都应该走这里，而不是裸 session_scope()。
    重试不能放在 @contextmanager 里——yield 之后再重试会二次 yield，
    生成器会直接抛 RuntimeError；需要重试的调用方用 run_chain_write()。
    """
    with _chain_file_lock(), session_scope() as session:
        yield session


def run_chain_write(fn, /):
    """把一段写库逻辑放进串行写链事务，撞 SQLite 锁时整体重跑。

    fn 必须是幂等的：证据按 sha256 内容寻址、同内容去重，
    信号表是先 delete 再 insert，重跑不会产生重复行。
    """
    for attempt in range(3):
        try:
            with chain_write_scope() as session:
                return fn(session)
        except OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 2:
                raise
            time.sleep(0.2 * (2**attempt))
            log.warning("写证据撞 SQLite 锁，整体重试 %d/3", attempt + 1)


def add_chain_anchor(session: Session, evidence_id: int, reason: str, created_by: str = "") -> dict:
    """登记一处受控断点。幂等：重复登记只更新说明。"""
    if session.get(Evidence, evidence_id) is None:
        raise ValueError(f"证据 {evidence_id} 不存在")
    row = session.get(ChainAnchor, evidence_id)
    if row is None:
        row = ChainAnchor(evidence_id=evidence_id, reason=reason, created_by=created_by)
        session.add(row)
    else:
        row.reason = reason
        row.created_by = created_by or row.created_by
    session.flush()
    return {"evidence_id": evidence_id, "reason": reason, "created_by": row.created_by}


def list_chain_anchors(session: Session) -> list[dict]:
    rows = session.scalars(select(ChainAnchor).order_by(ChainAnchor.evidence_id)).all()
    return [
        {
            "evidence_id": r.evidence_id,
            "reason": r.reason,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else "",
        }
        for r in rows
    ]


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
        ("group_key", "VARCHAR(96) DEFAULT ''"),
        ("group_kind", "VARCHAR(16) DEFAULT ''"),
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
        ("storage", "VARCHAR(8) DEFAULT ''"),
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
    "CREATE INDEX IF NOT EXISTS ix_assets_group_key ON assets (group_key)",
    "CREATE INDEX IF NOT EXISTS ix_discovery_events_normalized ON discovery_events (normalized)",
    "CREATE INDEX IF NOT EXISTS ix_discovery_events_asset_id ON discovery_events (asset_id)",
    "CREATE INDEX IF NOT EXISTS ix_graph_edges_src ON graph_edges (src)",
    "CREATE INDEX IF NOT EXISTS ix_graph_edges_dst ON graph_edges (dst)",
    "CREATE INDEX IF NOT EXISTS ix_graph_edges_rel ON graph_edges (rel)",
    "CREATE INDEX IF NOT EXISTS ix_graph_nodes_type ON graph_nodes (type)",
    "CREATE INDEX IF NOT EXISTS ix_evidence_deleted_at ON evidence (deleted_at)",
    # 去重查询按 (asset, kind, sha) 走：同一份内容重复取证时不该再插一行
    "CREATE INDEX IF NOT EXISTS ix_evidence_asset_kind_sha ON evidence (asset_id, kind, sha256)",
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
    """逐条重算链式哈希，返回第一个断点。

    受控锚点（chain_anchors）把链分成若干段：锚点那一行的 prev_hash
    保持历史原样，校验从它这里另起一段。这样既能如实反映「这里分过叉」，
    又不用改写历史哈希，健康检查也不会把并发写入误报成证据被篡改。
    """
    all_rows = list(session.scalars(select(Evidence).order_by(Evidence.id)))
    anchors = {r.evidence_id: r.reason for r in session.scalars(select(ChainAnchor))}

    # 链是全局的：每条证据的 prev_hash 指向「全库上一条」的 chain_hash，
    # 那条证据可能属于另一个资产。按资产过滤时若还从 prev="" 起算，
    # 只要该资产不是全库第一条就会必然误报断点（GET /api/verify-chain
    # ?asset_id=N 一直不可用就是这么来的）。这里先建 id→前一条链尾的映射。
    prev_by_id: dict[int, str] = {}
    head = ""
    for r in all_rows:
        prev_by_id[r.id] = head
        head = r.chain_hash

    target = [r for r in all_rows if asset_id is None or r.asset_id == asset_id]
    checked = 0
    breaks: list[dict] = []
    for row in target:
        if row.id in anchors:
            # 受控锚点：这里另起一段，不要求接上前一条，但哈希本身仍要自洽。
            breaks.append({"evidence_id": row.id, "reason": anchors[row.id]})
            expected_prev = row.prev_hash
        else:
            expected_prev = prev_by_id.get(row.id, "")
        expected = compute_chain_hash(row.prev_hash, row.sha256, row.captured_at.isoformat())
        if row.prev_hash != expected_prev or row.chain_hash != expected:
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
                "expected_prev": expected_prev,
                "actual_prev": row.prev_hash,
                "anchors": breaks,
            }
        checked += 1
    return {"ok": True, "checked": checked, "head": head, "anchors": breaks}


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
