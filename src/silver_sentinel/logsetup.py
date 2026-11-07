"""日志初始化。

为什么单独一个模块
------------------
项目里所有模块都用 `logging.getLogger(__name__)`，但从来没有 `basicConfig`。
结果是：INFO 级别的「周期完成 / 取证成功」全部消失在黑洞里，只有 WARNING
以上才被 `logging.lastResort` 打到 stderr。线上排查时看到的日志只有
「certstream 断开」和 Traceback，看不出系统到底跑没跑。

这里做三件事：
1. 控制台 + 滚动文件双通道，文件留在 `<data>/logs/silver.log`，重启不丢；
2. 第三方库降噪（httpx/httpcore/urllib3/asyncio 只在 WARNING 以上说话）；
3. 幂等——重复调用不会叠出多份 handler（uvicorn reload、测试都会重复调）。
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from typing import Any

from .config import settings

_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"
_NOISY = ("httpx", "httpcore", "urllib3", "asyncio", "multipart", "watchfiles", "PIL")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, _DATEFMT),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: str | None = None) -> None:
    root = logging.getLogger()
    if getattr(root, "_silver_configured", False):
        return

    lvl = getattr(logging, (level or settings.log_level or "INFO").upper(), logging.INFO)
    root.setLevel(lvl)

    formatter: logging.Formatter = JsonFormatter() if settings.log_json else logging.Formatter(_FORMAT, _DATEFMT)

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    # 文件日志是排障主力：systemd 的 journal 会被轮转/限长，翻不了几天。
    try:
        settings.log_dir.mkdir(parents=True, exist_ok=True)
        path = settings.log_dir / "silver.log"
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=20 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:  # 磁盘只读/权限不足时不要因为日志起不来
        root.warning("文件日志不可用：%s", exc)

    for name in _NOISY:
        logging.getLogger(name).setLevel(logging.WARNING)

    root._silver_configured = True  # type: ignore[attr-defined]
    logging.getLogger(__name__).info(
        "日志已就绪：level=%s file=%s", logging.getLevelName(lvl), settings.log_dir / "silver.log"
    )
