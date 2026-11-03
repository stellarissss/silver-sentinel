FROM python:3.11-slim

# WITH_SANDBOX=1 会一并装 playwright + chromium 及其系统依赖，用于真实网页取证。
# 默认 0：镜像小、构建快，沙箱能力自动降级为「不执行页面」，运维页会明示。
ARG WITH_SANDBOX=0

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SILVER_DATA_DIR=/var/lib/silver-sentinel

WORKDIR /app

# 系统依赖：证书链（CT / RDAP 走 HTTPS）、时区、以及排查用的基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tzdata curl \
    && rm -rf /var/lib/apt/lists/*

# 依赖层单独缓存：先拷元数据、装依赖，再拷源码
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && \
    if [ "$WITH_SANDBOX" = "1" ]; then \
        pip install ".[sandbox,stream,s3]"; \
        python -m playwright install --with-deps chromium; \
    else \
        pip install ".[stream,s3]"; \
    fi

RUN useradd --system --uid 10001 --create-home sentinel && \
    mkdir -p /var/lib/silver-sentinel/evidence /var/lib/silver-sentinel/logs && \
    chown -R sentinel:sentinel /var/lib/silver-sentinel /app

USER sentinel
VOLUME ["/var/lib/silver-sentinel"]
EXPOSE 8000

# 存活探针只打 /api/health（不查外部依赖），避免外部源抖动把容器反复重启
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)"

# 默认单进程：发现引擎 + 周期调度 + Web 控制台同进程。
# 要拆多进程请分别跑 `silver-sentinel discover run` 与 `silver-sentinel serve`，
# 且共用数据卷时 SQLite 写锁会冲突——那种规模应改 Postgres。
CMD ["silver-sentinel", "serve", "--host", "0.0.0.0", "--port", "8000"]
