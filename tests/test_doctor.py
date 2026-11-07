"""看门狗自检：区分「进程活着」和「进程在干活」。

HTTP 探活只能证明 Web 还能回包。调度线程卡在一次没有超时的请求上时，
`/api/ping` 依然是 200，界面依然转圈，只有心跳文件会停更。
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace


def _write_heartbeat(tmp_path, age_s: float, **extra):
    payload = {
        "pid": 1234,
        "version": "test",
        "ts": time.time() - age_s,
        "threads": {"capture": True},
        **extra,
    }
    (tmp_path / "heartbeat.json").write_text(json.dumps(payload), encoding="utf-8")


def test_doctor_ok_when_heartbeat_is_fresh(fresh_db):
    from silver_sentinel.cli import cmd_doctor

    _write_heartbeat(fresh_db, 5)
    assert cmd_doctor(SimpleNamespace(max_age=300, quiet=True)) == 0


def test_doctor_fails_when_heartbeat_is_stale(fresh_db, capsys):
    from silver_sentinel.cli import cmd_doctor

    _write_heartbeat(fresh_db, 900)
    assert cmd_doctor(SimpleNamespace(max_age=300, quiet=False)) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert any("心跳文件" in p for p in out["problems"])


def test_doctor_fails_without_heartbeat_file(fresh_db):
    from silver_sentinel.cli import cmd_doctor

    assert cmd_doctor(SimpleNamespace(max_age=300, quiet=True)) == 1
