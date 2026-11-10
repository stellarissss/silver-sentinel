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
    """极简 .env 解析：只补全尚未存在的变量，不覆盖真实环境。

    注意：进程的工作目录可能不可读（例如以 silver 用户从 /root 启动），
    这里必须吞掉 OSError，否则一个无关文件就能让整个进程起不来。
    """
    try:
        if not path.is_file():
            return
        text = path.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
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
    # 每轮补判几条。模型调用要几秒到几十秒，宁可每轮少判两条也不要拖住主循环
    llm_batch: int = 2

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
    # 每条日志一个线程。3 条时实测覆盖不到全球新增证书的 5%，
    # 大量站群在别的日志里签发，永远轮不到。5 条是 2 核机器的平衡点。
    ct_poll_logs_limit: int = 5
    # 轮询不是定时任务，而是「预算内尽量追平」；间隔只决定两轮之间歇多久。
    ct_poll_interval: int = 30
    ct_poll_batch: int = 384
    # 发现即入库的准入线。宁可错杀，命中一个词就进候选池
    discover_min_keyword_hits: int = 1
    # 单个域名被判定为「明显无关」时进入冷存，但仍保留记录
    discover_cold_retention_days: int = 180
    # 每轮发现最多入队多少条待研判（防止一次 CT 风暴打爆队列）
    discover_queue_capacity: int = 50000
    # 同一注册域下的多主机是否归并成一个资产（主机清单留在 meta.hosts）
    discover_collapse_subdomains: bool = True
    # 外部线索发现（urlscan 标题检索）：CT 只认域名里写了什么，这条路认标题
    harvest_enabled: bool = True
    harvest_interval_seconds: int = 3600
    harvest_queries_per_round: int = 4

    # ---------------------------------------------------------------- ICP 备案
    icp_enabled: bool = True
    # ICP_Query / ICP_Query_lite 本地服务，形如 http://127.0.0.1:16181
    icp_api_base: str = ""
    icp_timeout: float = 20.0
    # 每分钟最多查询次数。工信部接口对频率敏感，无节制会触发封禁
    # 工信部实测：40/分钟跑十几条就 403。默认压到 5，用缓存换速度。
    icp_rate_per_minute: int = 5
    icp_cache_days: int = 30
    # 是否同时查工信部「违法违规域名」名单（多一次请求，但换来官方定性信号）
    icp_violation_check: bool = True
    # 连续失败多少次判定为「被风控」，以及冷却时长
    icp_max_failures: int = 4
    icp_cooldown_seconds: float = 900.0
    # 只对这些分级的目标查询备案，避免无差别扫描
    icp_tiers: str = "candidate,watch,confirmed"
    # 取证默认移动 UA。目标受众是手机用户，很多落地页对桌面 UA 直接返回
    # 「访问受限」——实测 np4w53.cn 桌面 26 字、移动 423 字。
    http_mobile_ua: bool = True

    # ---------------------------------------------------------------- 用途分类
    # 词库保广、用途保细：用途只影响排序，不产生风险分，也不删除资产。
    purpose_enabled: bool = True
    # 关闭后只记录用途、不降级——灰度或线上异常时的一键回退开关。
    purpose_suppress: bool = True
    # 用途模型路径（默认包内 data/purpose_model.joblib）。缺失自动退回规则。
    purpose_model: str = ""

    # ---------------------------------------------------------------- 图
    graph_enabled: bool = True
    # 建图间隔（分钟）。图结构变化远慢于取证，每轮全量重建纯属空转。
    graph_rebuild_minutes: int = 10
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

    # ---------------------------------------------------------------- 取证队列
    # 取证已从主周期拆成独立常驻线程（见 worker.py）：
    # 抓到一条就接着抓下一条，队列空了才退避。批次保持 1，因为 Chromium
    # 在这台机器上只能开一个；「连续」比「一次抓多条」更重要。
    capture_enabled: bool = True
    capture_batch: int = 1
    # 每轮补多少条「有效但没取过证」的资产进队列
    capture_backfill_limit: int = 8
    # 空闲时的轮询间隔；有活时会立即接上，不等这个值
    capture_interval_seconds: int = 15
    # 已取证资产的复访周期：超过这个小时数就重新排队，抓页面变化。
    # 24 小时是「还在不在骗人」的最小可信间隔，也让已知活跃目标的复访
    # 稳定贡献证据流，不必依赖冷档填谷抽到活站点。
    capture_refresh_hours: int = 24
    # 「判死」冷却：同一资产连续 3 次取证失败后，先关这么久再试。
    # 没有这道闸，死域名会永远占着队列水位，把新线索挤出去。
    capture_retry_cooldown_hours: int = 6
    # 永久性失败（NXDOMAIN / 端口拒连 / 不可达）不必按分钟重试：每次拉起
    # Chromium 要二三十秒，一天白烧几十分钟只换来同一句 ERR_NAME_NOT_RESOLVED。
    # 线上 181 条失败里 64 条是 NXDOMAIN、51 条是 SSL 握手失败，全在按 6 小时
    # 循环重试。这两类改成「隔天再看一眼」，把容量留给活着的目标。
    # 新签发的域名常常要过一两天才建站。72 小时太久，等于判了死刑；
    # 24 小时能覆盖绝大多数「签了还没部署」的情况，代价是每条多一次连接尝试。
    capture_dead_retry_hours: int = 48
    # 被 WAF / 证书 / 空响应挡住的目标：可能只是临时封锁，给 24 小时
    capture_blocked_retry_hours: int = 24
    # 空闲时用冷档资产「填谷」：队列没有到期任务时，每隔这么多秒取一条
    # 冷档待取证资产跑一遍。设 0 关闭。作用是让浏览器在发现层供给不足时
    # 仍在产出证据，也顺带用页面正文复核一遍当初被判冷的线索。
    capture_cold_fill_seconds: int = 90

    # ---------------------------------------------------------------- 出站防护（OPSEC）
    # 默认开启：拦内网/元数据、去标识 UA、导出脱敏。是否需要代理才允许访问可疑目标，
    # 由 allow_direct 控制；生产环境应设为 0（fail-closed）。
    opsec_enabled: bool = True
    opsec_allow_direct: bool = True
    # 逗号分隔，支持 socks5h://（远端解析，避免 DNS 泄露）/ http://
    opsec_proxies: str = ""
    # 本机对外 IP，多个用逗号分隔；留空则自动探测网卡地址
    opsec_own_ips: str = ""
    # 额外需要从产物中抹除的标识（机构名、邮箱、内网域名）
    opsec_identifiers: str = ""
    # 追加的禁访后缀（默认已含政务/监管/CA）
    opsec_deny_suffixes: str = ""
    # 沙箱浏览器没有隔离出口时是否直接拒绝运行
    opsec_require_proxy_for_sandbox: bool = True
    # 探针串：用于识别反射型蜜罐
    opsec_canary: bool = True

    # ---------------------------------------------------------------- 加密证据仓
    # 原始证据以 AES-256-GCM 加密后存放；仓库侧只留 SHA-256、哈希链与保管链。
    vault_enabled: bool = False
    vault_backend: str = "dir"          # dir | s3 | webdav | ipfs
    vault_target: str = ""
    vault_node_id: str = ""             # 留空自动生成并持久化
    vault_interval: int = 120           # 自动 pull+push 的间隔（秒）
    vault_key: str = ""                 # base64 32 字节；优先级最高
    vault_key_file: str = ""            # 默认 <data>/vault.key
    vault_passphrase: str = ""          # 无 key 时用口令派生（scrypt）
    vault_access_key: str = ""
    vault_secret_key: str = ""
    vault_bucket: str = "silver-sentinel-vault"
    vault_remove_plaintext: bool = False  # 上传并校验后删除本地明文
    # 「远端」是 dir 且与数据目录同盘时，push 只是把同一份密文再写一遍：
    # 既不是备份（盘坏一起坏），又白占一倍空间。打开后不再复制。
    vault_skip_same_device_copy: bool = False
    vault_verify_blobs: bool = True

    # ---------------------------------------------------------------- 副本
    replica_enabled: bool = False
    replica_backend: str = "dir"      # dir | s3 | webdav
    replica_target: str = ""
    replica_interval: int = 300        # 秒
    # 数据库快照保留份数。每 20 轮（约 100 分钟）一份，50G 盘上不清理
    # 一年就是 5000 份、几十 GB——磁盘满后取证会先降级再停摆。
    replica_db_keep: int = 3
    replica_access_key: str = ""
    replica_secret_key: str = ""
    replica_bucket: str = "silver-sentinel"
    replica_verify: bool = True

    # ---------------------------------------------------------------- 评分
    confirm_requires_official: bool = True
    min_signals_for_verdict: int = 2

    # ---------------------------------------------------------------- 半自动举报
    # 举报人档案：12377 会自动带出登录账号的实名信息，这里主要是给 12321／邮件
    # 用的署名与回执邮箱。留空则材料里写「举报人（请填写）」。
    report_reporter: str = ""
    report_email: str = ""
    report_phone: str = ""
    # 浏览器扩展访问本服务的令牌；留空表示仅允许本机回环地址取数。
    report_extension_token: str = ""
    # 扩展与前端打开举报页时用的服务地址（部署在服务器上时填对外地址）
    report_api_base: str = ""
    # 证据包里最多带几张截图（12377 附件有总量限制）
    report_max_shots: int = 6

    # ---------------------------------------------------------------- 控制台
    # 访问口令。留空且只监听回环地址时不鉴权；对外监听时自动生成并落盘。
    web_password: str = ""
    # 即使只监听本机也强制要口令（本机多人共用一台时开）
    web_force_auth: bool = False
    # 绑定地址与端口。默认只给本机，对外提供服务时改成 0.0.0.0 并务必设口令。
    web_host: str = "127.0.0.1"
    web_port: int = 18700

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
        # 加载顺序：显式指定的文件 → 当前工作目录 → 源码根目录。
        # 已存在的环境变量一律不覆盖，systemd/容器的优先级最高。
        candidates = [PROJECT_ROOT / ".env", Path.cwd() / ".env"]
        explicit = os.environ.get("SILVER_ENV_FILE", "").strip()
        if explicit:
            candidates.insert(0, Path(explicit))
        for candidate in candidates:
            _load_dotenv(candidate)
        self.data_dir = Path(os.environ.get("SILVER_DATA_DIR", str(self.data_dir))).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "evidence").mkdir(exist_ok=True)
        (self.data_dir / "logs").mkdir(exist_ok=True)

        if not self.db_url:
            self.db_url = os.environ.get("SILVER_DB_URL", f"sqlite:///{self.data_dir / 'sentinel.db'}")

        self.allow_network = _bool("SILVER_ALLOW_NETWORK", True)
        self.web_password = _str("SILVER_WEB_PASSWORD", "")
        self.web_force_auth = _bool("SILVER_WEB_FORCE_AUTH", False)
        self.web_host = _str("SILVER_WEB_HOST", "127.0.0.1")
        self.web_port = _int("SILVER_WEB_PORT", 18700)
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
        self.discover_collapse_subdomains = _bool(
            "SILVER_DISCOVER_COLLAPSE_SUBDOMAINS", self.discover_collapse_subdomains
        )
        self.harvest_enabled = _bool("SILVER_HARVEST_ENABLED", True)
        self.harvest_interval_seconds = _int(
            "SILVER_HARVEST_INTERVAL", self.harvest_interval_seconds
        )
        self.harvest_queries_per_round = _int(
            "SILVER_HARVEST_QUERIES", self.harvest_queries_per_round
        )

        self.icp_enabled = _bool("SILVER_ICP_ENABLED", True)
        self.icp_api_base = _str("SILVER_ICP_API", "").rstrip("/")
        self.icp_timeout = _float("SILVER_ICP_TIMEOUT", self.icp_timeout)
        self.icp_rate_per_minute = _int("SILVER_ICP_RPM", self.icp_rate_per_minute)
        self.icp_cache_days = _int("SILVER_ICP_CACHE_DAYS", self.icp_cache_days)
        self.icp_violation_check = _bool("SILVER_ICP_VIOLATION", self.icp_violation_check)
        self.icp_max_failures = _int("SILVER_ICP_MAX_FAILURES", self.icp_max_failures)
        self.icp_cooldown_seconds = _float("SILVER_ICP_COOLDOWN", self.icp_cooldown_seconds)
        self.icp_tiers = _str("SILVER_ICP_TIERS", self.icp_tiers)
        self.http_mobile_ua = _bool("SILVER_HTTP_MOBILE_UA", self.http_mobile_ua)
        self.purpose_enabled = _bool("SILVER_PURPOSE_ENABLED", self.purpose_enabled)
        self.purpose_suppress = _bool("SILVER_PURPOSE_SUPPRESS", self.purpose_suppress)
        self.purpose_model = _str("SILVER_PURPOSE_MODEL", self.purpose_model)

        self.graph_enabled = _bool("SILVER_GRAPH_ENABLED", True)
        self.graph_rebuild_minutes = max(
            1, _int("SILVER_GRAPH_REBUILD_MINUTES", self.graph_rebuild_minutes)
        )
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

        self.capture_enabled = _bool("SILVER_CAPTURE_ENABLED", True)
        self.capture_batch = max(1, _int("SILVER_CAPTURE_BATCH", self.capture_batch))
        self.capture_backfill_limit = max(0, _int("SILVER_CAPTURE_BACKFILL", self.capture_backfill_limit))
        self.capture_interval_seconds = max(5, _int("SILVER_CAPTURE_INTERVAL", self.capture_interval_seconds))
        self.capture_refresh_hours = max(1, _int("SILVER_CAPTURE_REFRESH_HOURS", self.capture_refresh_hours))
        self.capture_retry_cooldown_hours = max(
            1, _int("SILVER_CAPTURE_RETRY_COOLDOWN_HOURS", self.capture_retry_cooldown_hours)
        )
        self.capture_dead_retry_hours = max(
            1, _int("SILVER_CAPTURE_DEAD_RETRY_HOURS", self.capture_dead_retry_hours)
        )
        self.capture_blocked_retry_hours = max(
            1, _int("SILVER_CAPTURE_BLOCKED_RETRY_HOURS", self.capture_blocked_retry_hours)
        )
        self.capture_cold_fill_seconds = max(
            0, _int("SILVER_CAPTURE_COLD_FILL_SECONDS", self.capture_cold_fill_seconds)
        )
        self.llm_batch = max(0, _int("SILVER_LLM_BATCH", self.llm_batch))

        self.opsec_enabled = _bool("SILVER_OPSEC_ENABLED", True)
        self.opsec_allow_direct = _bool("SILVER_OPSEC_ALLOW_DIRECT", True)
        self.opsec_proxies = _str("SILVER_OPSEC_PROXIES", "")
        self.opsec_own_ips = _str("SILVER_OPSEC_OWN_IPS", "")
        self.opsec_identifiers = _str("SILVER_OPSEC_IDENTIFIERS", "")
        self.opsec_deny_suffixes = _str("SILVER_OPSEC_DENY_SUFFIXES", "")
        self.opsec_require_proxy_for_sandbox = _bool("SILVER_OPSEC_REQUIRE_PROXY_SANDBOX", True)
        self.opsec_canary = _bool("SILVER_OPSEC_CANARY", True)

        self.vault_enabled = _bool("SILVER_VAULT_ENABLED", False)
        self.vault_backend = _str("SILVER_VAULT_BACKEND", "dir").lower()
        self.vault_target = _str("SILVER_VAULT_TARGET", "")
        self.vault_node_id = _str("SILVER_VAULT_NODE_ID", "")
        self.vault_interval = _int("SILVER_VAULT_INTERVAL", 120)
        self.vault_key = _str("SILVER_VAULT_KEY", "")
        self.vault_key_file = _str("SILVER_VAULT_KEY_FILE", "")
        self.vault_passphrase = _str("SILVER_VAULT_PASSPHRASE", "")
        self.vault_access_key = _str("SILVER_VAULT_ACCESS_KEY", "")
        self.vault_secret_key = _str("SILVER_VAULT_SECRET_KEY", "")
        self.vault_bucket = _str("SILVER_VAULT_BUCKET", "silver-sentinel-vault")
        self.vault_remove_plaintext = _bool("SILVER_VAULT_REMOVE_PLAINTEXT", False)
        self.vault_skip_same_device_copy = _bool("SILVER_VAULT_SKIP_SAME_DEVICE_COPY", False)
        self.vault_verify_blobs = _bool("SILVER_VAULT_VERIFY", True)

        self.replica_enabled = _bool("SILVER_REPLICA_ENABLED", False)
        self.replica_backend = _str("SILVER_REPLICA_BACKEND", self.replica_backend).lower()
        self.replica_target = _str("SILVER_REPLICA_TARGET", "")
        self.replica_interval = _int("SILVER_REPLICA_INTERVAL", self.replica_interval)
        self.replica_db_keep = max(2, _int("SILVER_REPLICA_DB_KEEP", self.replica_db_keep))
        self.replica_access_key = _str("SILVER_REPLICA_ACCESS_KEY", "")
        self.replica_secret_key = _str("SILVER_REPLICA_SECRET_KEY", "")
        self.replica_bucket = _str("SILVER_REPLICA_BUCKET", self.replica_bucket)
        self.replica_verify = _bool("SILVER_REPLICA_VERIFY", True)

        self.confirm_requires_official = _bool("SILVER_CONFIRM_REQUIRES_OFFICIAL", True)
        self.min_signals_for_verdict = _int("SILVER_MIN_SIGNALS", self.min_signals_for_verdict)

        # 半自动举报配置：.env.example 与 docs/13 都要求能配，但以前字段只有
        # dataclass 默认值，__post_init__ 从没读过环境变量，扩展令牌静默失效。
        self.report_reporter = _str("SILVER_REPORT_REPORTER", self.report_reporter)
        self.report_email = _str("SILVER_REPORT_EMAIL", self.report_email)
        self.report_phone = _str("SILVER_REPORT_PHONE", self.report_phone)
        self.report_extension_token = _str("SILVER_REPORT_EXTENSION_TOKEN", self.report_extension_token)
        self.report_api_base = _str("SILVER_REPORT_API_BASE", self.report_api_base).rstrip("/")
        self.report_max_shots = _int("SILVER_REPORT_MAX_SHOTS", self.report_max_shots)

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
    def report_dir(self) -> Path:
        d = self.data_dir / "report_bundles"
        d.mkdir(parents=True, exist_ok=True)
        return d

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

    @property
    def vault_ready(self) -> bool:
        return bool(self.vault_enabled and self.vault_target)

    @property
    def egress_isolated(self) -> bool:
        return bool(self.opsec_proxies.strip())

    def capability_report(self) -> dict[str, bool | str]:
        """给运维页面看的「哪些能力真的开着」。坦承降级比假装可用重要。"""
        # 运行时配置（前端可改）优先。这里不能顶层 import，会循环。
        try:
            from .runtime_settings import egress_config, llm_config

            egress = egress_config()
            llm_cfg = llm_config()
        except Exception:  # noqa: BLE001
            egress = {
                "effective": "proxy" if self.opsec_proxies.strip() else "direct",
                "isolated": bool(self.opsec_proxies.strip()),
                "mode": "auto",
            }
            llm_cfg = {"ready": self.llm_ready, "model": self.llm_model}

        egress_ok = egress["effective"] != "off" and (
            egress["isolated"] or egress["effective"] == "direct"
        )
        return {
            "network": self.allow_network,
            "ct_stream": self.ct_stream_enabled and self.allow_network,
            "icp": self.icp_ready,
            "graph": "neo4j" if self.neo4j_ready else ("builtin" if self.graph_enabled else "off"),
            # 有浏览器但出口被关掉，实际一次也跑不起来。报 true 就是自欺。
            "sandbox_web": bool(self.sandbox_enabled and self.sandbox_browser_enabled and egress_ok),
            "sandbox_web_blocked_by": (
                "" if egress_ok else ("egress-off" if egress["effective"] == "off" else "no-proxy")
            )
            if (self.sandbox_enabled and self.sandbox_browser_enabled)
            else "",
            "sandbox_apk": "mobsf" if self.mobsf_ready else ("emulator" if self.android_serial else "static-only"),
            "replica": self.replica_backend if self.replica_enabled else "off",
            "vault": "off" if not self.vault_enabled else (self.vault_backend if self.vault_target else "unconfigured"),
            "egress": (
                "off"
                if not self.opsec_enabled
                else (
                    "proxy" if egress["isolated"]
                    else ("blocked" if egress["effective"] == "off" else "direct-degraded")
                )
            ),
            "llm": "ready" if llm_cfg["ready"] else "off",
            "llm_model": llm_cfg.get("model", ""),
            # 举报是「服务端备料 + 浏览器代填」，本机随时可生成材料；
            # 能不能一步跳到表单，取决于用户浏览器里装没装扩展。
            "report": "material+fill" if self.report_extension_token else "material+fill-local",
        }


settings = Settings()
