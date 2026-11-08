"""折叠视图的接口行为。

这里测的是「折叠之后还能不能找到东西」，不是「折叠的算法对不对」——
后者在 test_grouping.py。接口这一层的风险是分页与代表行：

- 折叠后 `total` 是**视图条目数**，`raw_total` 才是原始条数。少给一个，
  用户就会以为折叠把线索弄丢了。
- 分组必须保持排序位置：一个高分组不能被低分成员拖到后面去。
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from silver_sentinel.api import app
from silver_sentinel.db import session_scope
from silver_sentinel.models import Asset


def _seed() -> None:
    with session_scope() as s:
        rows = [
            # 一批同模板：标题只差年份
            ("https://aa001.cn/", "2026年个人财政补贴申领", 96.0, "watch", "template:t1"),
            ("https://aa002.cn/", "2027年个人财政补贴申领", 93.0, "watch", "template:t1"),
            ("https://aa003.cn/", "2025年个人财政补贴申领", 90.0, "candidate", "template:t1"),
            # 一条独立资产，分数最低，但必须仍然可见
            ("https://bb999.cn/", "某地养老服务信息网", 41.0, "candidate", "template:t2"),
        ]
        for value, title, score, tier, key in rows:
            s.add(
                Asset(
                    kind="url",
                    value=value,
                    normalized=value,
                    score=score,
                    verdict="high_risk" if score >= 90 else "suspicious",
                    tier=tier,
                    capture_state="captured",
                    group_key=key,
                    group_kind="template",
                    meta={
                        "web_observation": {"title": title},
                        "group_label": f"同模板「{title}」",
                    },
                )
            )


def test_collapse_folds_same_template(fresh_db):
    _seed()
    with TestClient(app) as c:
        data = c.get("/api/assets", params={"collapse": "1"}).json()
    assert data["collapsed"] is True
    assert data["raw_total"] == 4
    # 3 条同模板折成 1 项，加 1 条独立 = 2 项
    assert data["total"] == 2
    assert data["group_count"] == 1

    group = next(i for i in data["items"] if i.get("group", {}).get("size", 0) > 1)
    assert group["group"]["size"] == 3
    assert group["value"] == "https://aa001.cn/"      # 代表行取分数最高的
    assert len(group["group"]["members"]) == 3
    assert group["group"]["max_score"] == 96.0


def test_collapse_off_returns_every_row(fresh_db):
    _seed()
    with TestClient(app) as c:
        data = c.get("/api/assets", params={"collapse": "0"}).json()
    assert data["collapsed"] is False
    assert data["total"] == 4
    assert len(data["items"]) == 4


def test_single_member_group_is_rendered_as_plain_row(fresh_db):
    """组里只有自己：不占折叠位，但保留 group 字段说明「它本来有关联对象」。"""
    _seed()
    with TestClient(app) as c:
        data = c.get("/api/assets", params={"collapse": "1"}).json()
    solo = next(i for i in data["items"] if i["value"] == "https://bb999.cn/")
    assert solo["group"]["size"] == 1
    assert solo["group"]["members"] == []


def test_decoy_marker_is_exposed_on_row(fresh_db):
    """诱饵标记必须出现在列表数据里——藏到详情页就没人看得见了。"""
    with session_scope() as s:
        s.add(
            Asset(
                kind="url",
                value="https://decoy.cn/",
                normalized="https://decoy.cn/",
                score=30.0,
                verdict="insufficient",
                tier="candidate",
                capture_state="captured",
                meta={
                    "facts": {
                        "decoy": {
                            "is_decoy": True,
                            "kind": "security_check",
                            "reason": "核验诱饵页，真实内容在下一跳",
                            "weight": 3,
                            "downstream": ["https://d7k2m.cn/submit.php"],
                            "honeypot": False,
                            "blocked_by": "",
                        }
                    }
                },
            )
        )
    with TestClient(app) as c:
        data = c.get("/api/assets", params={"collapse": "0"}).json()
    row = data["items"][0]
    assert row["decoy"]["is_decoy"] is True
    assert row["decoy"]["kind"] == "security_check"
    assert "d7k2m.cn" in row["decoy"]["downstream"][0]


def test_two_member_group_is_not_collapsed(fresh_db):
    """2 条的组不折：省一行却多一个徽标和一次点击，净收益是负的。

    线上 46 组里 30 组是「×2 同证书」（同一张证书覆盖两个子域），
    全折起来反而让列表更吵。关联信息用「+1 同源」标出来，不占折叠位。
    """
    with session_scope() as s:
        for i, v in enumerate(("https://s1.cn/", "https://s2.cn/")):
            s.add(
                Asset(
                    kind="domain", value=v, normalized=v, score=60.0 - i,
                    verdict="suspicious", tier="candidate", capture_state="captured",
                    group_key="cert:abc", group_kind="cert",
                    meta={"group_label": "同证书（2 域名）"},
                )
            )
    with TestClient(app) as c:
        data = c.get("/api/assets", params={"collapse": "1"}).json()
    assert data["total"] == 2
    row = next(i for i in data["items"] if i["value"] == "https://s1.cn/")
    assert row["group"]["size"] == 2
    assert row["group"]["collapsed"] is False
    assert len(row["group"]["members"]) == 1
