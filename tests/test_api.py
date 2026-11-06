"""HTTP 接口：扫描、统计、详情、举报。"""

from __future__ import annotations

from fastapi.testclient import TestClient

from silver_sentinel.api import app


def _client() -> TestClient:
    return TestClient(app)


def test_health_reports_engine_state(fresh_db):
    with _client() as c:
        data = c.get("/api/health").json()
    assert data["status"] == "ok"
    assert data["rules"]["count"] >= 30
    assert data["network"] is False


def test_index_page_renders(fresh_db):
    """首页必须真的能渲染。

    这条用例是为一个真实事故补的：Starlette 0.29 改了 TemplateResponse 的签名，
    旧写法 ("index.html", {...}) 会把 dict 当模板名，线上表现为首页 500，
    而 API 全部正常——只看接口健康检查是发现不了的。
    """
    with _client() as c:
        resp = c.get("/")
    assert resp.status_code == 200
    assert "银发哨兵" in resp.text


def test_scan_endpoint_returns_explainable_result(fresh_db):
    with _client() as c:
        resp = c.post(
            "/api/scan",
            json={
                "kind": "text",
                "value": "免费领鸡蛋 国家补贴",
                "text": "免费领鸡蛋，签到领补贴，下载 App 继续安装，邀请好友拿奖励，USDT 充值。",
                "run_llm": False,
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["assessment"]["score"] > 0
    assert data["assessment"]["signals"]
    assert data["advice"]
    assert data["priority"].startswith("P")


def test_asset_detail_and_report_flow(fresh_db):
    with _client() as c:
        scan_resp = c.post(
            "/api/scan",
            json={"kind": "url", "value": "http://kuaishou-yinfa.top/reg", "run_llm": False},
        ).json()
        asset_id = scan_resp["asset"]["id"]

        detail = c.get(f"/api/assets/{asset_id}").json()
        assert detail["id"] == asset_id
        assert "evidence" in detail and detail["evidence"]

        report = c.post(f"/api/assets/{asset_id}/report?channel=12377").json()
        assert "12377" in report["body"]
        assert report["payload"]["channel"] == "12377"

        stats = c.get("/api/stats").json()
        assert stats["total_assets"] >= 1
        assert stats["reports"] >= 1


def test_assets_listing_and_filter(fresh_db):
    with _client() as c:
        c.post("/api/scan", json={"kind": "text", "value": "老年人健康体检", "run_llm": False})
        c.post(
            "/api/scan",
            json={"kind": "text", "value": "民族资产解冻", "text": "民族资产解冻 追梦人 云数贸", "run_llm": False},
        )
        # 默认只回有效线索（已确认/观察中/候选），误报与冷存单独看
        active = c.get("/api/assets").json()
        assert active["tier"] == "active"
        assert all(a["tier"] in ("confirmed", "watch", "candidate") for a in active["items"])

        everything = c.get("/api/assets?tier=all").json()
        assert len(everything["items"]) >= 2
        assert everything["total"] >= 2

        confirmed = c.get("/api/assets?verdict=confirmed").json()["items"]
        assert all(a["verdict"] == "confirmed" for a in confirmed)


def test_watch_crud(fresh_db):
    with _client() as c:
        created = c.post("/api/watch", json={"kind": "keyword", "value": "领鸡蛋", "interval_minutes": 60}).json()
        assert created["ok"] is True

        items = c.get("/api/watch").json()["items"]
        assert any(i["value"] == "领鸡蛋" for i in items)

        assert c.delete(f"/api/watch/{created['id']}").json()["ok"] is True
        assert not c.get("/api/watch").json()["items"]


def test_scan_rejects_apk_via_json(fresh_db):
    with _client() as c:
        resp = c.post("/api/scan", json={"kind": "apk", "value": "x.apk"})
    assert resp.status_code == 400


def test_rules_and_channels_endpoints(fresh_db):
    with _client() as c:
        rules = c.get("/api/rules").json()
        assert rules["count"] >= 30
        assert all("weight" in r for r in rules["items"])

        channels = c.get("/api/channels").json()["items"]
        assert any(ch["key"] == "12321" for ch in channels)
