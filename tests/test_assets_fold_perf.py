"""折叠列表的 evidence_count 加载方式（防性能回归）。

生产事故（v1.16.7）：为了消掉「列表 50 行各查一次证据」的 N+1，给查询
无条件加了 `selectinload(Asset.evidence)`。但折叠视图会取**全量**资产来
分组，于是线上 4637 个资产对应的 57592 条 Evidence 被整体 ORM 化（53s+），
叠加 campaign 懒加载，/api/assets 直接挂死 150s。非折叠视图只取 limit
行，反而没事——这种「一个分支正常、另一个分支挂死」的差异很容易漏测。

这里锁死两条不变量：
1. 折叠视图只用一次聚合拿计数，绝不加载 Evidence ORM 实例；
2. 计数结果与 relationship 的软删过滤（`deleted_at IS NULL`）完全一致，
   折叠 / 非折叠两条路径给出同一个数。
"""

from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

from silver_sentinel.api import app
from silver_sentinel.db import session_scope
from silver_sentinel.models import Asset, Evidence


def _seed(*, evidence_total: int = 4, soft_deleted: int = 1) -> None:
    with session_scope() as s:
        # 独立行：evidence_count 好断言
        solo = Asset(
            kind="domain", value="solo.example", normalized="solo.example",
            score=92.0, confidence=0.92, verdict="high_risk", tier="watch",
            capture_state="captured",
        )
        s.add(solo)
        s.flush()
        for i in range(evidence_total):
            s.add(
                Evidence(
                    asset_id=solo.id,
                    kind="page_text",
                    sha256=f"{i:064x}",
                    deleted_at=datetime(2026, 1, 1) if i < soft_deleted else None,
                )
            )
        # 三条同证书：确保折叠路径真的走进分组分支，不只测独立行
        for i in range(3):
            s.add(
                Asset(
                    kind="domain", value=f"peer{i}.example",
                    normalized=f"peer{i}.example",
                    score=80.0 - i, confidence=0.8, verdict="high_risk",
                    tier="watch", capture_state="captured",
                    group_key="cert:deadbeef", group_kind="cert",
                    meta={"group_label": "同证书 deadbeef"},
                )
            )


def _solo_count(data: dict) -> int | None:
    for item in data["items"]:
        if item["value"] == "solo.example":
            return item["evidence_count"]
    return None


def test_fold_and_non_fold_agree_on_evidence_count(fresh_db):
    """软删 tombstone 不计入；折叠 / 非折叠两条路径数出来必须一样。"""
    _seed()
    with TestClient(app) as c:
        folded = c.get("/api/assets", params={"collapse": "1"}).json()
        plain = c.get("/api/assets", params={"collapse": "0"}).json()

    assert folded["collapsed"] is True
    assert _solo_count(folded) == 3  # 4 条里 1 条软删
    assert _solo_count(plain) == 3
    assert folded["total"] == 2  # 独立行 1 + 同证书组 1


def test_fold_never_loads_evidence_orm(fresh_db):
    """核心防回归：把 selectinload(Asset.evidence) 加回全量查询就会失败。

    证据数量刻意放大到 300 条，模拟线上「每个资产挂一批历史证据」的形态。
    折叠视图只允许做一次聚合查询，不允许把任何一个 Evidence 行变成 ORM 实例。
    """
    _seed(evidence_total=300, soft_deleted=0)

    loaded: list[str] = []

    def on_load(session: Session, instance: object) -> None:
        loaded.append(type(instance).__name__)

    event.listen(Session, "loaded_as_persistent", on_load)
    try:
        with TestClient(app) as c:
            data = c.get("/api/assets", params={"collapse": "1"}).json()
    finally:
        event.remove(Session, "loaded_as_persistent", on_load)

    assert "Asset" in loaded, "监听器没生效，这条防回归会变成假阳性"
    assert "Evidence" not in loaded, "折叠视图又把 Evidence 整体 ORM 化了"
    assert len(data["items"]) == 2
    assert _solo_count(data) == 300, "聚合计数必须覆盖全部有效证据"
    assert data["total"] == 2


def test_fold_offline_large_group_still_counts(fresh_db):
    """失联大组走同一条计数路径，成员截断不应把 evidence_count 弄丢。"""
    _seed(evidence_total=2, soft_deleted=0)
    with session_scope() as s:
        for i in range(6):
            s.add(
                Asset(
                    kind="domain", value=f"lost-site-{i}.cn",
                    normalized=f"lost-site-{i}.cn",
                    score=10.0, confidence=0.5, verdict="suspicious",
                    tier="candidate", capture_state="dead",
                )
            )
    with TestClient(app) as c:
        data = c.get("/api/assets", params={"collapse": "1"}).json()
    assert data["offline_count"] >= 6
    assert _solo_count(data) == 2
