"""展示层前缀族折叠：取证失败、没有 group_key 的站群域名也要能折起来。

线上实测：清理死站后活跃档仍有 199 条无组资产，其中 164 条来自 ct_poll，
样例 mz479.top / gdcr8378.com 都是「固定前缀 + 变数字」的长期运营族。
它们没有取证正文，grouping.compute() 拿不到 cert/backend/template 依据，
但前缀族本身就是发现期已有的基础设施指纹。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from silver_sentinel.api import app
from silver_sentinel.db import session_scope
from silver_sentinel.models import Asset


def _client() -> TestClient:
    return TestClient(app)


def _add(value: str, *, score: float = 40.0, state: str = "failed") -> None:
    with session_scope() as s:
        s.add(Asset(
            kind="domain", value=value, normalized=value,
            tier="candidate", capture_state=state, score=score,
            discovery_source="ct_poll",
        ))


def test_prefix_family_folds_without_group_key(fresh_db):
    for v in ("mz479.top", "mz749.top", "mz920.top", "mz88.top"):
        _add(v)
    _add("yl8387.com", score=39.0)                  # 另一个族，只有 1 个 → 不折
    _add("normal-example.com", score=38.0, state="captured")  # 带连字符 → 无族

    with _client() as c:
        data = c.get("/api/assets?tier=all&collapse=1&limit=50").json()
    items = data["items"]
    folded = [x for x in items if (x.get("group") or {}).get("collapsed")]
    assert len(folded) == 1
    group = folded[0]["group"]
    assert group["kind"] == "family"
    assert group["size"] == 4
    assert "mz|top" in group["label"]
    assert group["collapsed"] is True
    # 异族与正常域名仍逐条显示，不被误并
    plain = [x["value"] for x in items if not (x.get("group") or {}).get("collapsed")]
    assert "yl8387.com" in plain
    assert "normal-example.com" in plain
    assert data["raw_total"] > data["total"]


def test_family_fold_is_view_only_and_toggleable(fresh_db):
    """不写库：折叠只影响响应，资产表里 group_key 仍为空。"""
    for v in ("zk881.cc", "zk234.cc", "zk7788.cc"):
        _add(v)

    with _client() as c:
        folded = c.get("/api/assets?tier=all&collapse=1").json()
        expanded = c.get("/api/assets?tier=all&collapse=0").json()
    assert folded["collapsed"] is True
    assert expanded["collapsed"] is False
    assert expanded["total"] == expanded["raw_total"] == 3
    assert any(
        (x.get("group") or {}).get("kind") == "family" for x in folded["items"]
    )

    with session_scope() as s:
        rows = list(s.query(Asset).all())
    assert len(rows) == 3
    assert all((r.group_key or "") == "" for r in rows)


def test_existing_group_key_wins_over_family_fallback(fresh_db):
    """已有硬证据（同证书）的分组优先，不能被前缀族覆盖。"""
    with session_scope() as s:
        for v in ("yl8387.com", "yl5837.com", "yl2828.com"):
            s.add(Asset(
                kind="domain", value=v, normalized=v, tier="candidate",
                capture_state="failed", score=40.0, discovery_source="ct_poll",
                group_key="cert:deadbeef", group_kind="cert",
            ))
    with _client() as c:
        items = c.get("/api/assets?tier=all&collapse=1").json()["items"]
    folded = [x for x in items if (x.get("group") or {}).get("collapsed")]
    assert len(folded) == 1
    assert folded[0]["group"]["kind"] == "cert"
    assert folded[0]["group"]["key"] == "cert:deadbeef"
