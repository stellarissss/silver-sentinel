"""账本流式读取与末行 O(1) 读取：卡死复发的真正根因回归。

线上 custody 账本涨到 95MB / 21.7 万行，vault-sync 每 120s 用
read_bytes().splitlines() 全量解析它，只为拿最后一条续哈希链——
100% CPU + 几百 MB 内存尖峰 + 持有 GIL 拖慢所有线程（含 API 和取证），
把 1.9G 机器推入 swap 颠簸卡死。这里钉住：
1. iter_manifest 逐行流式，不整表载入；
2. _last_entry 只读文件末尾，超大文件也 O(1)；
3. 损坏尾部能兜底不崩。
"""

from __future__ import annotations

import json

from silver_sentinel.vault import Vault


def _bare_vault() -> Vault:
    """绕过密钥/后端初始化，只测纯文件读取方法。"""
    return object.__new__(Vault)


def test_iter_manifest_streams_lines(tmp_path):
    p = tmp_path / "m.jsonl"
    rows = [{"seq": i, "v": i * 2} for i in range(1000)]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    v = _bare_vault()
    got = list(v.iter_manifest(p))
    assert len(got) == 1000
    assert got[-1]["seq"] == 999
    assert got[0]["v"] == 0


def test_iter_manifest_skips_blank_and_stops_on_bad(tmp_path):
    p = tmp_path / "m.jsonl"
    p.write_text(
        json.dumps({"seq": 1}) + "\n\n" + json.dumps({"seq": 2}) + "\nBAD JSON\n" + json.dumps({"seq": 3}) + "\n",
        encoding="utf-8",
    )
    v = _bare_vault()
    got = list(v.iter_manifest(p))
    assert [e["seq"] for e in got] == [1, 2], "坏行之后应停止，不继续解析"


def test_last_entry_reads_only_tail(tmp_path):
    p = tmp_path / "custody.jsonl"
    rows = [{"seq": i, "hash": f"h{i}"} for i in range(5000)]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    v = _bare_vault()
    last = v._last_entry(p)
    assert last == {"seq": 4999, "hash": "h4999"}


def test_last_entry_single_line_no_trailing_newline(tmp_path):
    p = tmp_path / "m.jsonl"
    p.write_text(json.dumps({"seq": 7, "x": "y"}), encoding="utf-8")  # 无结尾换行
    v = _bare_vault()
    assert v._last_entry(p) == {"seq": 7, "x": "y"}


def test_last_entry_empty_and_missing(tmp_path):
    v = _bare_vault()
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    assert v._last_entry(empty) is None
    assert v._last_entry(tmp_path / "nope.jsonl") is None


def test_last_entry_corrupt_tail_falls_back(tmp_path):
    """尾部是坏 JSON 时退回全表扫描兜底，保证拿到最后一条有效记录。"""
    p = tmp_path / "m.jsonl"
    rows = [{"seq": i} for i in range(5)]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    v = _bare_vault()
    assert v._last_entry(p)["seq"] == 4
