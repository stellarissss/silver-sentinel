"""失联站点折叠：把已下线 / 取证失败的老站沉到列表末尾，别霸占首屏。

线上症状：用户举报过的 95 分站群全部 dead，按分数排序时首页前 60 行
100% 是站点失联，新发现（0 分、还没取证）被压到几十页之后，看起来
像「系统很久没有新发现」。

两条边界：
- 折叠只影响展示，不改 verdict / tier / capture_state，不删资产；
- **不能吞掉同源依据**：同证书 80 个站、同前缀族仍各自成组，
  只是整组沉底。团伙证据是人工研判的关键，折叠不能让它消失。
  只有连同源依据都没有的失联散站，才合成一个「失联站点」大组。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from silver_sentinel.api import app
from silver_sentinel.db import session_scope
from silver_sentinel.domain import utcnow
from silver_sentinel.models import Asset


def _asset(
    s,
    value: str,
    *,
    score: float,
    verdict: str = "insufficient",
    tier: str = "candidate",
    capture_state: str = "pending",
    group_key: str = "",
    group_kind: str = "",
    reviewed_by: str = "",
):
    a = Asset(
        kind="domain",
        value=value,
        normalized=value,
        score=score,
        verdict=verdict,
        tier=tier,
        capture_state=capture_state,
        group_key=group_key,
        group_kind=group_kind,
        reviewed_by=reviewed_by,
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    s.add(a)
    return a


def _seed(s):
    # 已举报过的失联站群：高分、confirmed、同证书（团伙证据必须保留）
    for i in range(4):
        _asset(
            s, f"dead{i}.cn", score=95.0, verdict="confirmed", tier="watch",
            capture_state="dead", group_key="cert:deadgroup", group_kind="cert",
            reviewed_by="人工审批·CDP浏览器",
        )
    # 一条取证失败、已复核的高分站（无同源依据）
    _asset(s, "failed-old.cn", score=72.0, verdict="confirmed", tier="watch",
           capture_state="failed", reviewed_by="人工审批·CDP浏览器")
    # 三条活跃、有内容的新线索
    _asset(s, "fresh-one.cn", score=41.0, verdict="suspicious", capture_state="captured")
    _asset(s, "fresh-two.cn", score=30.0, verdict="suspicious", capture_state="captured")
    _asset(s, "fresh-three.cn", score=20.0, verdict="insufficient", capture_state="pending")


def test_offline_groups_sink_to_the_end_but_keep_same_cert_evidence(fresh_db):
    with session_scope() as s:
        _seed(s)
    with TestClient(app) as c:
        data = c.get("/api/assets", params={"tier": "all"}).json()

    assert data["collapsed"] is True
    assert data["offline_count"] == 5          # 4 dead + 1 failed
    assert data["raw_total"] == 8
    # 4 条同证书折 1 项 + failed 逐条 1 项 + 3 条活跃 = 5 项
    assert data["total"] == 5

    items = data["items"]
    # 首屏是活跃线索，按分数排序
    assert [i["value"] for i in items[:3]] == [
        "fresh-one.cn", "fresh-two.cn", "fresh-three.cn",
    ]
    # 同证书组必须保留 cert 依据，只是整组沉底并标记 offline
    cert_group = next(i for i in items if (i.get("group") or {}).get("kind") == "cert")
    assert cert_group["group"]["key"] == "cert:deadgroup"
    assert cert_group["group"]["size"] == 4
    assert cert_group["group"]["collapsed"] is True
    assert cert_group["group"]["offline"] is True
    assert items.index(cert_group) >= 3


def test_offline_loose_sites_form_one_capped_group(fresh_db):
    """无同源依据的失联散站才合成大组，且成员不能全塞进 JSON。"""
    from silver_sentinel.grouping import OFFLINE_MEMBER_CAP

    with session_scope() as s:
        # 带连字符的域名不会被前缀族正则识别，才是真正的「无同源依据散站」
        for i in range(OFFLINE_MEMBER_CAP + 7):
            _asset(s, f"lost-site-{i}.cn", score=50.0 + i, capture_state="dead")
        _asset(s, "alive.cn", score=10.0, capture_state="captured")
    with TestClient(app) as c:
        data = c.get("/api/assets", params={"tier": "all"}).json()

    last = data["items"][-1]
    assert last["group"]["kind"] == "offline"
    assert last["group"]["size"] == OFFLINE_MEMBER_CAP + 7
    assert len(last["group"]["members"]) == OFFLINE_MEMBER_CAP
    assert last["group"]["members_truncated"] is True
    assert last["group"]["offline"] is True
    # 代表行取分数最高的那条，max_score 覆盖全量而非被截断的那批
    assert last["group"]["max_score"] == 50.0 + OFFLINE_MEMBER_CAP + 6
    assert data["items"][0]["value"] == "alive.cn"


def test_mixed_group_stays_in_front(fresh_db):
    """组里还有活站就不沉底——那批人还在运营，不该被藏起来。"""
    with session_scope() as s:
        for v, state in (("mix-a.cn", "captured"), ("mix-b.cn", "dead"), ("mix-c.cn", "dead")):
            _asset(s, v, score=60.0, capture_state=state,
                   group_key="cert:mixed", group_kind="cert")
    with TestClient(app) as c:
        items = c.get("/api/assets", params={"tier": "all"}).json()["items"]
    head = items[0]
    assert head["group"]["kind"] == "cert"
    assert head["group"]["size"] == 3
    assert head["group"].get("offline") is None


def test_offline_fold_can_be_turned_off(fresh_db):
    with session_scope() as s:
        _seed(s)
    with TestClient(app) as c:
        off = c.get("/api/assets", params={"tier": "all", "fold_offline": "0"}).json()
        noc = c.get("/api/assets", params={"tier": "all", "collapse": "0"}).json()

    assert off["offline_count"] == 0
    assert off["total"] == 5
    assert all((i.get("group") or {}).get("offline") is not True for i in off["items"])
    # collapse=0 时不折叠任何东西，失联站逐条可见
    assert noc["collapsed"] is False
    assert noc["total"] == 8
    assert noc["offline_count"] == 0


def test_stats_top_assets_exclude_offline_but_report_count(fresh_db):
    with session_scope() as s:
        _seed(s)
    with TestClient(app) as c:
        data = c.get("/api/stats").json()

    assert data["offline_assets"] == 5
    values = [a["value"] for a in data["top_assets"]]
    assert not any(v.startswith("dead") or v.startswith("failed") for v in values)
    assert "fresh-one.cn" in values


def test_offline_fold_does_not_mutate_assets(fresh_db):
    """折叠只是展示层：库里的判定、档位、取证状态一个都不许改。"""
    with session_scope() as s:
        _seed(s)
    with TestClient(app) as c:
        c.get("/api/assets", params={"tier": "all"}).json()
        c.get("/api/stats").json()
    with session_scope() as s:
        dead = s.query(Asset).filter(Asset.value == "dead0.cn").one()
        assert dead.capture_state == "dead"
        assert dead.verdict == "confirmed"
        assert dead.tier == "watch"
        assert dead.group_key == "cert:deadgroup"
        assert dead.reviewed_by
