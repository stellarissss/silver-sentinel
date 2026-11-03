"""数据库会话与证据链校验。"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings
from .models import Base, Evidence

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


def init_db() -> None:
    Base.metadata.create_all(get_engine())


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
            return {
                "ok": False,
                "checked": checked,
                "broken_at": row.id,
                "expected_prev": prev,
                "actual_prev": row.prev_hash,
            }
        prev = row.chain_hash
        checked += 1
    return {"ok": True, "checked": checked, "head": prev}
