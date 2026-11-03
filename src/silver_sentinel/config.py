"""运行配置。

所有可调项走环境变量，便于容器化与长期部署；缺省值保证「零配置可跑」。
敏感值只从环境或 .env 读取，不落日志。

分组原则：每个可选能力都必须有「关掉它系统仍能工作」的默认值。
这是长期无人值守运行的前提——外部依赖随时会挂，挂了不能停摆。
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


def _str(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass(slots=True)
class Settings:
    # ---------------------------------------------------------------- 存储
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("SILVER_DATA_DIR", "data")))
    db_url: str = ""

    # ---------------------------------------------------------------- 网络
    allow_network: bool = True
    http_timeout: float = 12.0
    http_retries: int = 2
    rate_limit_per_sec: float = 2.0
    user_agent: str = ""

    # ---------------------------------------------------------------- LLM
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_timeout: float = 45.0
    llm_enabled: bool = True

    # ---------------------------------------------------------------- 外部情报
    urlhaus_auth_key: str = ""
    openphish_feed: str = "https://openphish.com/feed.txt"

    # ---------------------------------------------------------------- 发现
    discover_enabled: bool = True
    # certstream 公共 WebSocket；可指向自建 certstream-server-go
    ct_stream_url: str = "wss://certstream.calidog.io/"
    ct_stream_enabled: bool = True
    # 流断了之后的兜底：直接轮询 CT log 的 get-entries
    ct_poll_logs: str = ""           # 逗号分隔；空则自动拉官方 log_list 里可用且可达的日志
    ct_poll_logs_limit: int = 3      # 自动挑选时最多跟几条日志（每条一个线程）
    ct_poll_interval: int = 60
    ct_poll_batch: int = 256
    # 发现即入库的准入线。宁可错杀，命中一个词就进候选池
    discover_min_keyword_hits: int = 1
    # 单个域名被判定为「明显无关」时进入冷存，但仍保留记录
    discover_cold_retention_days: int = 180
    # 每轮发现最多入队多少条待研判（防止一次 CT 风暴打爆队列）
    discover_queue_capacity: int = 50000

    # ---------------------------------------------------------------- ICP 备案
    icp_enabled: bool = True
    # ICP_Query / ICP_Query_lite 本地服务，形如 http://127.0.0.1:16181
    icp_api_base: str = ""
    icp_timeout: float = 20.0
    # 每分钟最多查询次数。工信部接口对频率敏感，无节制会触发封禁
    icp_rate_per_minute: int = 10
    icp_cache_days: int = 30
    # 只对这些分级的目标查询备案，避免无差别扫描
    icp_tiers: str = "candidate,watch,confirmed"

    # ---------------------------------------------------------------- 图
    graph_enabled: bool = True
    # 留空则用内置图引擎；填 bolt://... 则写 Neo4j
    neo4j_uri: str = ""
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""
    neo4j_database: str = "neo4j"
    # 社区发现的最小团规模
    graph_min_community: int = 2

    # ---------------------------------------------------------------- 沙箱
    sandbox_enabled: bool = True
    sandbox_browser_enabled: bool = True
    sandbox_timeout: float = 45.0
    sandbox_max_redirects: int = 12
    sandbox_allow_private_ip: bool = False
    # MobSF REST（可选）。留空则 APK 走静态行为推演
    mobsf_base_url: str = ""
    mobsf_api_key: str = ""
    # adb/emulator 设备串号（可选）
    android_serial: str = ""

    # ---------------------------------------------------------------- 副本
    replica_enabled: bool = False
    replica_backend: str = "dir"      # dir | s3 | webdav
    replica_target: str = ""
    replica_interval: int = 300        # 秒
    replica_access_key: str = ""
    replica_secret_key: str = ""
    replica_bucket: str = "silver-sentinel"
    replica_verify: bool = True

    # ---------------------------------------------------------------- 评分
    confirm_requires_official: bool = True
    min_signals_for_verdict: int = 2

    # ---------------------------------------------------------------- 调度
    monitor_tick_seconds: int = 60
    default_watch_interval_minutes: int = 360
    # 每轮监控的预算：最多重扫多少目标，防止一轮跑几小时
    monitor_batch_size: int = 40
    # 全局并发（采集器是 IO 密集，但目标站点要温柔）
    worker_concurrency: int = 8
    # 发现任务与监控任务是否在 API 进程内跑
    scheduler_in_process: bool = True

    # ---------------------------------------------------------------- 运维
    log_level: str = "INFO"
    log_json: bool = False
    metrics_enabled: bool = True
    # SSE 推送的心跳
    stream_heartbeat: int = 15

    def __post_init__(self) -> None:
        _load_dotenv(PROJECT_ROOT / ".env")
        self.data_dir = Path(os.environ.get("SILVER_DATA_DIR", str(self.data_dir))).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "evidence").mkdir(exist_ok=True)
        (self.data_dir / "logs").mkdir(exist_ok=True)

        if not self.db_url:
            self.db_url = os.environ.get("SILVER_DB_URL", f"sqlite:///{self.data_dir / 'sentinel.db'}")

        self.allow_network = _bool("SILVER_ALLOW_NETWORK", True)
        self.http_timeout = _float("SILVER_HTTP_TIMEOUT", self.http_timeout)
        self.http_retries = _int("SILVER_HTTP_RETRIES", self.http_retries)
        self.rate_limit_per_sec = _float("SILVER_RATE_LIMIT", self.rate_limit_per_sec)
        self.user_agent = _str("SILVER_USER_AGENT", self.user_agent)

        self.llm_base_url = _str("SILVER_LLM_BASE_URL", "").rstrip("/")
        self.llm_api_key = _str("SILVER_LLM_API_KEY", "")
        self.llm_model = _str("SILVER_LLM_MODEL", self.llm_model)
        self.llm_timeout = _float("SILVER_LLM_TIMEOUT", self.llm_timeout)
        self.llm_enabled = _bool("SILVER_LLM_ENABLED", True)

        self.urlhaus_auth_key = _str("URLHAUS_AUTH_KEY", "")
        self.openphish_feed = _str("OPENPHISH_FEED", self.openphish_feed)

        self.discover_enabled = _bool("SILVER_DISCOVER_ENABLED", True)
        self.ct_stream_url = _str("SILVER_CT_STREAM_URL", self.ct_stream_url)
        self.ct_stream_enabled = _bool("SILVER_CT_STREAM_ENABLED", True)
        self.ct_poll_logs = _str("SILVER_CT_POLL_LOGS", "")
        self.ct_poll_logs_limit = max(1, _int("SILVER_CT_POLL_LOGS_LIMIT", self.ct_poll_logs_limit))
        self.ct_poll_interval = _int("SILVER_CT_POLL_INTERVAL", self.ct_poll_interval)
        self.ct_poll_batch = _int("SILVER_CT_POLL_BATCH", self.ct_poll_batch)
        self.discover_min_keyword_hits = _int("SILVER_DISCOVER_MIN_HITS", self.discover_min_keyword_hits)
        self.discover_cold_retention_days = _int("SILVER_COLD_RETENTION_DAYS", self.discover_cold_retention_days)
        self.discover_queue_capacity = _int("SILVER_DISCOVER_QUEUE", self.discover_queue_capacity)

        self.icp_enabled = _bool("SILVER_ICP_ENABLED", True)
        self.icp_api_base = _str("SILVER_ICP_API", "").rstrip("/")
        self.icp_timeout = _float("SILVER_ICP_TIMEOUT", self.icp_timeout)
        self.icp_rate_per_minute = _int("SILVER_ICP_RPM", self.icp_rate_per_minute)
        self.icp_cache_days = _int("SILVER_ICP_CACHE_DAYS", self.icp_cache_days)
        self.icp_tiers = _str("SILVER_ICP_TIERS", self.icp_tiers)

        self.graph_enabled = _bool("SILVER_GRAPH_ENABLED", True)
        self.neo4j_uri = _str("SILVER_NEO4J_URI", "")
        self.neo4j_user = _str("SILVER_NEO4J_USER", self.neo4j_user)
        self.neo4j_password = _str("SILVER_NEO4J_PASSWORD", "")
        self.neo4j_database = _str("SILVER_NEO4J_DATABASE", self.neo4j_database)
        self.graph_min_community = _int("SILVER_GRAPH_MIN_COMMUNITY", self.graph_min_community)

        self.sandbox_enabled = _bool("SILVER_SANDBOX_ENABLED", True)
        self.sandbox_browser_enabled = _bool("SILVER_SANDBOX_BROWSER", True)
        self.sandbox_timeout = _float("SILVER_SANDBOX_TIMEOUT", self.sandbox_timeout)
        self.sandbox_max_redirects = _int("SILVER_SANDBOX_MAX_REDIRECTS", self.sandbox_max_redirects)
        self.sandbox_allow_private_ip = _bool("SILVER_SANDBOX_ALLOW_PRIVATE", False)
        self.mobsf_base_url = _str("SILVER_MOBSF_URL", "").rstrip("/")
        self.mobsf_api_key = _str("SILVER_MOBSF_KEY", "")
        self.android_serial = _str("SILVER_ANDROID_SERIAL", "")

        self.replica_enabled = _bool("SILVER_REPLICA_ENABLED", False)
        self.replica_backend = _str("SILVER_REPLICA_BACKEND", self.replica_backend).lower()
        self.replica_target = _str("SILVER_REPLICA_TARGET", "")
        self.replica_interval = _int("SILVER_REPLICA_INTERVAL", self.replica_interval)
        self.replica_access_key = _str("SILVER_REPLICA_ACCESS_KEY", "")
        self.replica_secret_key = _str("SILVER_REPLICA_SECRET_KEY", "")
        self.replica_bucket = _str("SILVER_REPLICA_BUCKET", self.replica_bucket)
        self.replica_verify = _bool("SILVER_REPLICA_VERIFY", True)

        self.confirm_requires_official = _bool("SILVER_CONFIRM_REQUIRES_OFFICIAL", True)
        self.min_signals_for_verdict = _int("SILVER_MIN_SIGNALS", self.min_signals_for_verdict)

        self.monitor_tick_seconds = _int("SILVER_MONITOR_TICK", self.monitor_tick_seconds)
        self.default_watch_interval_minutes = _int("SILVER_WATCH_INTERVAL", self.default_watch_interval_minutes)
        self.monitor_batch_size = _int("SILVER_MONITOR_BATCH", self.monitor_batch_size)
        self.worker_concurrency = _int("SILVER_WORKERS", self.worker_concurrency)
        self.scheduler_in_process = _bool("SILVER_SCHEDULER_IN_PROCESS", True)

        self.log_level = _str("SILVER_LOG_LEVEL", self.log_level).upper()
        self.log_json = _bool("SILVER_LOG_JSON", False)
        self.metrics_enabled = _bool("SILVER_METRICS_ENABLED", True)
        self.stream_heartbeat = _int("SILVER_STREAM_HEARTBEAT", self.stream_heartbeat)

    # ------------------------------------------------------------ 派生属性
    @property
    def llm_ready(self) -> bool:
        return bool(self.llm_enabled and self.llm_base_url and self.llm_api_key)

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def eventlog_path(self) -> Path:
        return self.data_dir / "events.jsonl"

    @property
    def graph_ready(self) -> bool:
        return bool(self.graph_enabled)

    @property
    def neo4j_ready(self) -> bool:
        return bool(self.neo4j_uri and self.neo4j_password)

    @property
    def icp_ready(self) -> bool:
        return bool(self.icp_enabled and self.icp_api_base)

    @property
    def mobsf_ready(self) -> bool:
        return bool(self.mobsf_base_url and self.mobsf_api_key)

    @property
    def icp_tier_set(self) -> set[str]:
        return {t.strip() for t in self.icp_tiers.split(",") if t.strip()}

    def capability_report(self) -> dict[str, bool | str]:
        """给运维页面看的「哪些能力真的开着」。坦承降级比假装可用重要。"""
        return {
            "network": self.allow_network,
            "ct_stream": self.ct_stream_enabled and self.allow_network,
            "icp": self.icp_ready,
            "graph": "neo4j" if self.neo4j_ready else ("builtin" if self.graph_enabled else "off"),
            "sandbox_web": self.sandbox_enabled and self.sandbox_browser_enabled,
            "sandbox_apk": "mobsf" if self.mobsf_ready else ("emulator" if self.android_serial else "static-only"),
            "replica": self.replica_backend if self.replica_enabled else "off",
            "llm": "ready" if self.llm_ready else "off",
        }


settings = Settings()
