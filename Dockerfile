FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SILVER_DATA_DIR=/var/lib/silver-sentinel

WORKDIR /app

# 依赖层单独缓存
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

RUN useradd --system --uid 10001 --create-home sentinel && \
    mkdir -p /var/lib/silver-sentinel && \
    chown -R sentinel:sentinel /var/lib/silver-sentinel /app

USER sentinel
VOLUME ["/var/lib/silver-sentinel"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status==200 else 1)"

CMD ["silver-sentinel", "serve", "--host", "0.0.0.0", "--port", "8000"]
