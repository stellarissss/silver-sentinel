"""v1.16.6 证据链回归：受控锚点、写链串行、关闭隐式 autoflush。

线上 id=15535 那处断裂是并发写入造成的：两个事务各自按旧链尾算
prev_hash。这几条用例把「断点可查」「并发不再分叉」「SELECT 不抢写锁」
三件事钉死。
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select

from silver_sentinel.db import (
    add_chain_anchor,
    chain_write_scope,
    compute_chain_hash,
    get_session_factory,
    list_chain_anchors,
    session_scope,
    verify_chain,
)
from silver_sentinel.domain import utcnow
from silver_sentinel.evidence import append
from silver_sentinel.models import Asset, Evidence


def _asset(session, value: str) -> Asset:
    row = Asset(kind="domain", value=value, normalized=value)
    session.add(row)
    session.flush()
    return row


def _evidence(session, asset_id: int, prev: str, payload: bytes) -> Evidence:
    ts = utcnow()
    sha = hashlib.sha256(payload).hexdigest()
    row = Evidence(
        asset_id=asset_id,
        kind="page_text",
        sha256=sha,
        prev_hash=prev,
        chain_hash=compute_chain_hash(prev, sha, ts.isoformat()),
        size=len(payload),
        captured_at=ts,
        path="",
    )
    session.add(row)
    session.flush()
    return row


def test_autoflush_is_off(fresh_db):
    """SELECT 不再触发隐式 flush —— 线上 'Query-invoked autoflush' 撞锁的根因。"""
    assert get_session_factory().kw["autoflush"] is False
    with session_scope() as s:
        s.add(Asset(kind="domain", value="pending.example", normalized="pending.example"))
        # 未显式 flush 的对象不该被 SELECT 偷偷写进去
        assert s.scalar(select(func.count(Asset.id))) == 0


def test_chain_break_detected_without_anchor(fresh_db):
    with session_scope() as s:
        a = _asset(s, "a.example")
        e1 = _evidence(s, a.id, "", b"first")
        e2 = _evidence(s, a.id, "wrong-prev", b"second")  # 模拟并发分叉
        _evidence(s, a.id, e2.chain_hash, b"third")
        result = verify_chain(s)
    assert result["ok"] is False
    assert result["broken_at"] == e2.id
    assert result["expected_prev"] == e1.chain_hash


def test_anchor_splits_chain_without_rewriting_history(fresh_db):
    with session_scope() as s:
        a = _asset(s, "a.example")
        e1 = _evidence(s, a.id, "", b"first")
        e2 = _evidence(s, a.id, "wrong-prev", b"second")
        before = (e2.prev_hash, e2.chain_hash, e2.sha256)
        _evidence(s, a.id, e2.chain_hash, b"third")
        add_chain_anchor(s, e2.id, "并发写入导致的已知分叉", "test")
        result = verify_chain(s)
        after = (e2.prev_hash, e2.chain_hash, e2.sha256)
        assert e1.chain_hash  # 原链尾仍在
    assert result["ok"] is True
    assert result["checked"] == 3
    assert result["anchors"] == [
        {"evidence_id": e2.id, "reason": "并发写入导致的已知分叉"}
    ]
    assert before == after  # 一行历史哈希都没改写


def test_anchor_is_idempotent_and_validates_evidence(fresh_db):
    with session_scope() as s:
        a = _asset(s, "a.example")
        e = _evidence(s, a.id, "", b"only")
        add_chain_anchor(s, e.id, "原因一", "tester")
        add_chain_anchor(s, e.id, "原因二", "tester")
        rows = list_chain_anchors(s)
    assert len(rows) == 1
    assert rows[0]["reason"] == "原因二"
    with session_scope() as s, pytest.raises(ValueError):
        add_chain_anchor(s, 999999, "不存在的证据", "tester")


def test_nested_chain_write_scope_does_not_deadlock(fresh_db):
    """嵌套的写链作用域不能各开一个 flock fd 互相顶死。"""
    from silver_sentinel.db import chain_write_scope

    with chain_write_scope() as outer:
        assert outer is not None
        with chain_write_scope() as inner:
            # 内层复用同一把锁，不实际写库，只验证不会自旋等锁
            assert inner is not None
    # 能走到这里就说明没有各开一个 flock fd 互相顶死


def test_concurrent_chain_writes_stay_continuous(fresh_db):
    """8 个并发写事务后链必须连续 —— 修复前这里会分叉或撞 database is locked。"""
    with session_scope() as s:
        aid = _asset(s, "concurrent.example").id

    def write(i: int) -> None:
        with chain_write_scope() as s:
            append(s, aid, "page_text", f"payload-{i}".encode(), extension=".txt")

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(write, range(8)))

    with session_scope() as s:
        assert s.scalar(select(func.count(Evidence.id))) == 8
        result = verify_chain(s)
    assert result["ok"] is True, result
    assert result["checked"] == 8
    assert result["anchors"] == []
