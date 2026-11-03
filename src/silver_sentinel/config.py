"""运行配置。

所有可调项走环境变量，便于容器化与长期部署；缺省值保证「零配置可跑」。
敏感值只从环境或 .env 读取，不落日志。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    """极简 .env 解析：只补全尚未存在的变量，不覆盖真实环境。"""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, "1" if default else "0").strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(slots=True)
class Settings:
    # 存储
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("SILVER_DATA_DIR", "data")))
    db_url: str = ""

    # 网络
    allow_network: bool = True
    http_timeout: float = 12.0
    http_retries: int = 2
    rate_limit_per_sec: float = 2.0

    # LLM（OpenAI 兼容：DeepSeek / 通义 / Moonshot / vLLM 均可）
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_timeout: float = 45.0
    llm_enabled: bool = True

    # 外部情报（可选）
    urlhaus_auth_key: str = ""
    openphish_feed: str = "https://openphish.com/feed.txt"

    # 评分策略
    confirm_requires_official: bool = True  # 「确认诈骗」必须有人工复核或官方通报
    min_signals_for_verdict: int = 2

    # 调度
    monitor_tick_seconds: int = 60
    default_watch_interval_minutes: int = 360

    def __post_init__(self) -> None:
        _load_dotenv(PROJECT_ROOT / ".env")
        self.data_dir = Path(os.environ.get("SILVER_DATA_DIR", str(self.data_dir))).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "evidence").mkdir(exist_ok=True)

        if not self.db_url:
            self.db_url = os.environ.get("SILVER_DB_URL", f"sqlite:///{self.data_dir / 'sentinel.db'}")

        self.allow_network = _bool("SILVER_ALLOW_NETWORK", True)
        self.http_timeout = _float("SILVER_HTTP_TIMEOUT", self.http_timeout)
        self.http_retries = _int("SILVER_HTTP_RETRIES", self.http_retries)
        self.rate_limit_per_sec = _float("SILVER_RATE_LIMIT", self.rate_limit_per_sec)

        self.llm_base_url = os.environ.get("SILVER_LLM_BASE_URL", "").rstrip("/")
        self.llm_api_key = os.environ.get("SILVER_LLM_API_KEY", "")
        self.llm_model = os.environ.get("SILVER_LLM_MODEL", self.llm_model)
        self.llm_timeout = _float("SILVER_LLM_TIMEOUT", self.llm_timeout)
        self.llm_enabled = _bool("SILVER_LLM_ENABLED", True)

        self.urlhaus_auth_key = os.environ.get("URLHAUS_AUTH_KEY", "")
        self.openphish_feed = os.environ.get("OPENPHISH_FEED", self.openphish_feed)

        self.confirm_requires_official = _bool("SILVER_CONFIRM_REQUIRES_OFFICIAL", True)
        self.monitor_tick_seconds = _int("SILVER_MONITOR_TICK", self.monitor_tick_seconds)

    @property
    def llm_ready(self) -> bool:
        return bool(self.llm_enabled and self.llm_base_url and self.llm_api_key)

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"


settings = Settings()
