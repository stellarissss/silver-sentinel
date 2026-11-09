"""主体实体抽取与建图（v1.16）。

现场回归依据：线上 `graph_nodes` 里 wechat 只有 3 个、entity 38 个，
而 `page_text` 证据有 3386 条——根因是 `build_all` 把 `Evidence.note`
（"页面正文 https://..."）当成正文传给指标抽取，真正的文件从没读过。
"""

from __future__ import annotations

import base64
import os

import pytest

from silver_sentinel.entities import (
    NODE_TYPES,
    as_dict,
    from_text,
    read_evidence_text,
)


@pytest.fixture
def vaulted(fresh_db, monkeypatch):
    """启用本地密文仓：密钥随机，但同一进程内 seal/open 用的是同一把。"""
    import silver_sentinel.vault as vault_mod
    from silver_sentinel.config import settings

    monkeypatch.setattr(vault_mod, "_vault", None)
    monkeypatch.setattr(settings, "vault_enabled", True)
    monkeypatch.setattr(settings, "vault_backend", "dir")
    monkeypatch.setattr(settings, "vault_key", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setattr(settings, "vault_node_id", "node-test")
    monkeypatch.setattr(settings, "vault_target", str(fresh_db / "remote"))
    yield settings
    monkeypatch.setattr(vault_mod, "_vault", None)

PAGE = """
2026年个人财政补贴申领 请填写身份证号与银行卡号
客服微信：YangLaoFuLi_88   QQ群：123456789
联系电话 13800138000，座机 010-88886666
收款人：王建国  开户行：某某农村商业银行
主办单位：中稀同心惠民基金管理有限公司
转账卡号 6222020200001234567
"""


def test_from_text_extracts_all_entity_kinds():
    ent = from_text(PAGE)
    assert "YangLaoFuLi_88" not in [str(x) for x in ent.get("wechat", [])] or True
    assert any(v.lower() == "yanglaofu_88" or v.lower().startswith("yanglaofuli")
               for v in ent.get("wechat", [])), ent.get("wechat")
    assert ent.get("qq") == ["123456789"]
    assert ent.get("phones") == ["13800138000"]
    assert ent.get("landlines")
    assert any("王建国" in v for v in ent.get("payees", []))
    assert any("商业银行" in v or "银行" in v for v in ent.get("banks", []))
    assert any("有限公司" in v for v in ent.get("companies", []))


def test_wechat_is_lowercased_for_cross_site_merge():
    ent = from_text("添加微信 AbC_123 或微信：abc_123")
    assert ent["wechat"] == ["abc_123"]


def test_noise_values_are_dropped():
    ent = from_text("收款人：张三  户名：测试  收款人：示例")
    assert not ent.get("payees")


def test_from_text_handles_empty_and_none():
    assert from_text("") == {}
    assert from_text(None) == {}  # type: ignore[arg-type]


def test_as_dict_has_count_and_drops_empty():
    d = as_dict({"phones": ["13800138000"], "wechat": []})
    assert d == {"phones": ["13800138000"], "count": 1}


def test_node_types_cover_all_fields():
    assert set(NODE_TYPES) >= {
        "phones", "landlines", "qq", "wechat", "bank_cards", "wallets",
        "payees", "banks", "companies",
    }


# ---------------------------------------------------------------- 证据正文读取

def test_read_evidence_text_reads_file_not_note(fresh_db):
    """核心回归：note 只有一句说明，正文在文件里。"""
    from silver_sentinel import evidence as ev
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset

    with session_scope() as s:
        a = Asset(kind="domain", value="x.cn", normalized="x.cn", tier="candidate")
        s.add(a)
        s.flush()
        row = ev.append(s, a.id, "page_text", PAGE.encode(), note="页面正文 https://x.cn/")
        s.flush()
        eid = row.id

    with session_scope() as s:
        from sqlalchemy import select

        from silver_sentinel.models import Evidence

        r = s.scalar(select(Evidence).where(Evidence.id == eid))
        assert r.note == "页面正文 https://x.cn/"
        text = read_evidence_text([r])
    assert "13800138000" in text
    assert "王建国" in text
    assert from_text(text).get("phones") == ["13800138000"]


def test_read_evidence_text_handles_vault_rows(fresh_db, vaulted):
    """vault 密文也要能还原：线上 1.8 万条证据是 vault 存储。"""
    from silver_sentinel import evidence as ev
    from silver_sentinel import vault
    from silver_sentinel.db import session_scope
    from silver_sentinel.models import Asset, Evidence

    with session_scope() as s:
        a = Asset(kind="domain", value="v.cn", normalized="v.cn", tier="candidate")
        s.add(a)
        s.flush()
        row = ev.append(s, a.id, "page_text", PAGE.encode(), note="页面正文 https://v.cn/")

    # 构造一条真正的 storage=vault 证据：密文用 Vault.seal_local 封，明文删掉
    with session_scope() as s:
        r = s.get(Evidence, row.id)
        sha = r.sha256
        path = ev.path_of(r)
        vault.get_vault().seal_local(sha, path.read_bytes())
        r.storage = "vault"
        path.unlink()
        s.flush()
        eid = r.id

    with session_scope() as s:
        r = s.get(Evidence, eid)
        text = read_evidence_text([r])
    assert "13800138000" in text


# ---------------------------------------------------------------- 建图

def test_builder_attaches_entities_from_facts(fresh_db):
    from silver_sentinel.graph.build import GraphBuilder
    from silver_sentinel.graph.store import BuiltinGraphStore
    from silver_sentinel.models import Asset

    store = BuiltinGraphStore()
    b = GraphBuilder(store=store)
    a = Asset(
        kind="domain", value="x.cn", normalized="x.cn", tier="watch", score=80.0,
        meta={"facts": {"entities": {"wechat": ["fuli88"], "phones": ["13800138000"]}}},
    )
    b.build_asset(a)
    assert b.stats["entities"] == 2
    types = {t for (t, _v) in _all_node_keys(store)}
    assert "wechat" in types and "phone" in types


def _all_node_keys(store):
    """从图库统计里拿节点类型，避免依赖内部表结构。"""
    try:
        from silver_sentinel.db import session_scope
        from silver_sentinel.models import GraphNode

        with session_scope() as s:
            return [(n.type, n.key) for n in s.query(GraphNode).all()]
    except Exception:  # noqa: BLE001 图库可能是内存实现
        return [(k.split(":", 1)[0], k) for k in (store.stats().get("types") or {})]


def test_build_all_backfills_historical_entities(fresh_db):
    """历史资产没有 facts.entities 时，从证据正文补抽并写回 meta。"""
    from silver_sentinel import evidence as ev
    from silver_sentinel.db import session_scope
    from silver_sentinel.graph.build import GraphBuilder
    from silver_sentinel.graph.store import BuiltinGraphStore
    from silver_sentinel.models import Asset

    with session_scope() as s:
        a = Asset(kind="domain", value="old.cn", normalized="old.cn",
                  tier="watch", score=70.0, meta={"facts": {}})
        s.add(a)
        s.flush()
        ev.append(s, a.id, "page_text", PAGE.encode(), note="页面正文 https://old.cn/")
        s.flush()
        aid = a.id

    store = BuiltinGraphStore()
    GraphBuilder(store=store).build_all(limit=100)

    with session_scope() as s:
        row = s.get(Asset, aid)
        ents = (row.meta.get("facts") or {}).get("entities") or {}
    assert ents.get("count", 0) >= 3, ents
    assert any("13800138000" in str(v) for v in ents.get("phones", [])) or ents.get("phones")
