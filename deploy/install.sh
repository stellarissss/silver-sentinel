#!/usr/bin/env bash
# 银发哨兵 · 服务器侧安装 / 升级脚本
#
#   bash install.sh /tmp/ss-deploy/silver_sentinel-1.4.0-py3-none-any.whl
#
# 幂等：反复执行只会覆盖程序，不动数据目录，也不覆盖已有口令。
# 只碰自己的路径（/opt/silver-sentinel、/var/lib/silver-sentinel、systemd 同名单元），
# 不会去改 nginx 或服务器上别的站点。

set -euo pipefail

APP_NAME="silver-sentinel"
APP_USER="${APP_USER:-sentinel}"
APP_DIR="${APP_DIR:-/opt/silver-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/silver-sentinel}"
SERVICE="${SERVICE:-silver-sentinel}"
WEB_HOST="${WEB_HOST:-0.0.0.0}"
WEB_PORT="${WEB_PORT:-18700}"
OPEN_FIREWALL="${OPEN_FIREWALL:-1}"

WHEEL="${1:-}"

log()  { printf '\033[2m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[32m  ok\033[0m %s\n' "$*"; }
warn() { printf '\033[33m  !!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m  xx\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 既有部署探测
# 早期版本可能是手工装的：账号不叫 sentinel、环境文件在 /etc、数据在 /var/lib/.../data。
# 按默认值重装会在旁边另起一套空目录，启动后界面上就是「数据全没了」。
# 所以先看现有 unit 怎么写的，认它的账号、环境文件与数据目录。
UNIT_FILE="/etc/systemd/system/${SERVICE}.service"
ENV_FILE=""
ADOPTED=0
if [ -f "$UNIT_FILE" ]; then
  _user="$(sed -n 's/^User=//p' "$UNIT_FILE" | head -1)"
  _env="$(sed -n 's/^EnvironmentFile=//p' "$UNIT_FILE" | head -1)"
  _env="${_env#-}"
  [ -n "$_user" ] && APP_USER="$_user"
  [ -n "$_env" ] && ENV_FILE="$_env"
  ADOPTED=1
fi
[ -n "$ENV_FILE" ] || ENV_FILE="$APP_DIR/.env"
if [ -f "$ENV_FILE" ]; then
  _data="$(sed -n 's/^SILVER_DATA_DIR=//p' "$ENV_FILE" | head -1 | tr -d "\"'" )"
  [ -n "$_data" ] && DATA_DIR="$_data"
fi

# 老部署的虚拟环境可能叫 venv 而不是 .venv，别在同一个目录里再建一个
VENV_DIR="$APP_DIR/.venv"
[ -x "$APP_DIR/venv/bin/python" ] && VENV_DIR="$APP_DIR/venv"

if [ "$ADOPTED" = "1" ]; then
  log "检测到既有部署，沿用：账号 $APP_USER / 环境文件 $ENV_FILE / 数据目录 $DATA_DIR / 虚拟环境 $VENV_DIR"
fi

# ---------------------------------------------------------------- 前置检查
[ "$(id -u)" -eq 0 ] || die "需要 root（用 sudo bash install.sh ...）"
[ -n "$WHEEL" ] || die "用法: install.sh <wheel 文件路径>"
[ -f "$WHEEL" ] || die "找不到 wheel: $WHEEL"
WHEEL="$(cd "$(dirname "$WHEEL")" && pwd)/$(basename "$WHEEL")"

for bin in curl systemctl; do
  command -v "$bin" >/dev/null 2>&1 || die "缺少 $bin，先装好基础系统工具"
done

# ---------------------------------------------------------------- Python
# 挑解释器：版本够 + venv/ensurepip 可用。后者在 Debian 系常常是单独的包，
# 只看版本会挑到一个建不出 venv 的 python，装到一半才炸。
pick_python() {
  local c fallback=""
  for c in python3.13 python3.12 python3.11 python3; do
    command -v "$c" >/dev/null 2>&1 || continue
    "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null || continue
    if "$c" -c 'import venv, ensurepip' 2>/dev/null; then
      printf '%s\n' "$c"; return 0
    fi
    [ -n "$fallback" ] || fallback="$c"
  done
  [ -n "$fallback" ] && { printf '%s\n' "$fallback"; return 0; }
  return 1
}

PY="$(pick_python)" || die "需要 Python 3.11+（Debian/Ubuntu: apt install python3 python3-venv；RHEL 系: dnf install python3.11）"
log "Python: $PY ($("$PY" -V 2>&1))"

# venv 在 Debian 系是独立包（python3.12-venv），缺了 `python -m venv` 会失败；
# 这里失败就补装再重试一次，别让用户对着 ensurepip 的报错自己猜。
make_venv() {
  rm -rf "$VENV_DIR"
  if "$PY" -m venv "$VENV_DIR" >/dev/null 2>&1; then return 0; fi

  log "venv 创建失败，补装 venv 组件后重试 ..."
  local vp
  vp="$("$PY" -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "python${vp}-venv" python3-venv >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "python${vp}" python3-pip >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "python${vp}" python3-pip >/dev/null 2>&1 || true
  fi
  rm -rf "$VENV_DIR"
  "$PY" -m venv "$VENV_DIR" >/dev/null 2>&1
}

# ---------------------------------------------------------------- 账号与目录
if ! id "$APP_USER" >/dev/null 2>&1; then
  log "创建系统账号 $APP_USER"
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER" 2>/dev/null \
    || useradd -r -d "$APP_DIR" -s /sbin/nologin "$APP_USER"
fi

install -d -m 0755 "$APP_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR"
install -d -m 0750 -o "$APP_USER" -g "$APP_USER" "$DATA_DIR/evidence" "$DATA_DIR/logs"

# ---------------------------------------------------------------- 口令
# 已有 .env 就不动它；只补缺失项，避免升级把口令重置、把人挡在外面
NEW_PASSWORD=""
if [ ! -f "$ENV_FILE" ]; then
  NEW_PASSWORD="$("$PY" - <<'EOF'
import secrets, string
alphabet = string.ascii_letters + string.digits
print("".join(secrets.choice(alphabet) for _ in range(24)))
EOF
)"
  umask 077
  cat > "$ENV_FILE" <<EOF
# 由 deploy/install.sh 生成于 $(date -Iseconds)
# 改动后需 systemctl restart $SERVICE
SILVER_WEB_HOST=$WEB_HOST
SILVER_WEB_PORT=$WEB_PORT
SILVER_WEB_PASSWORD=$NEW_PASSWORD
SILVER_DATA_DIR=$DATA_DIR
SILVER_AUTOSTART_MONITOR=1
SILVER_LOG_LEVEL=INFO
# 证据包里抹掉采集机 IP，避免把自身信息带进举报材料
SILVER_OPSEC_ENABLED=1
SILVER_OPSEC_ALLOW_DIRECT=1
EOF
  ok "已生成 $ENV_FILE"
else
  log "保留已有 $ENV_FILE（不覆盖口令）"
fi
chmod 0600 "$ENV_FILE"; chown root:root "$ENV_FILE"

# 老版本升级上来的 .env 可能缺新键，缺什么补什么
ensure_env() {
  local key="$1" val="$2"
  grep -qE "^${key}=" "$ENV_FILE" || printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
}
ensure_env SILVER_WEB_HOST "$WEB_HOST"
ensure_env SILVER_WEB_PORT "$WEB_PORT"
ensure_env SILVER_DATA_DIR "$DATA_DIR"

PASSWORD="$(sed -n 's/^SILVER_WEB_PASSWORD=//p' "$ENV_FILE" | head -1)"
if [ -z "$PASSWORD" ]; then
  PASSWORD="$NEW_PASSWORD"
  [ -n "$PASSWORD" ] || die "SILVER_WEB_PASSWORD 为空。监听非回环地址时必须设口令，请手动编辑 $ENV_FILE"
  ensure_env SILVER_WEB_PASSWORD "$PASSWORD"
fi

# ---------------------------------------------------------------- 虚拟环境与安装
if [ ! -x "$VENV_DIR/bin/python" ] || ! "$VENV_DIR/bin/python" -c 'import sys' >/dev/null 2>&1; then
  log "创建虚拟环境 $VENV_DIR"
  make_venv || die "虚拟环境创建失败（$PY）。Debian/Ubuntu 先装 python3-venv，RHEL 系装 python3-pip"
fi

log "安装 $(basename "$WHEEL") ..."
"$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip setuptools wheel
# --force-reinstall 保证同名同版本也能覆盖（重打 wheel 调试时常见）
"$VENV_DIR/bin/python" -m pip install --quiet --no-cache-dir --force-reinstall "$WHEEL" \
  || die "pip install 失败"

VER="$("$VENV_DIR/bin/python" -c 'import silver_sentinel as s; print(s.__version__)' 2>/dev/null || echo '?')"
ok "已安装 silver-sentinel $VER"

# 导入自检：pip 装完不等于能用。线上踩过一次 pillow 没进依赖、
# capture 模块 import 就炸，导致 /api/capture/queue 直接 500。
log "导入自检 ..."
"$VENV_DIR/bin/python" - <<'PYEOF' || die "导入自检失败（缺依赖？看上面的 ModuleNotFoundError）"
import importlib
mods = [
    "silver_sentinel.capture",
    "silver_sentinel.api_extra",
    "silver_sentinel.pipeline",
    "silver_sentinel.monitor",
    "silver_sentinel.worker",
    "silver_sentinel.logsetup",
    "silver_sentinel.scoring.reassess",
    "silver_sentinel.risk",
    "silver_sentinel.runtime_settings",
    "silver_sentinel.report.bundle",
    "silver_sentinel.discover.engine",
]
for m in mods:
    importlib.import_module(m)
print(f"  ok {len(mods)} 个核心模块可导入")
PYEOF

# ---------------------------------------------------------------- 浏览器
# Playwright 的 chromium 默认装进「执行安装的那个用户」的 ~/.cache。
# 服务是以 $APP_USER 身份跑的，单元又开了 ProtectHome=true ——
# 浏览器留在 root 家目录时服务永远找不到，取证会一路失败，
# 而报错只是「浏览器不可用」，不说为什么。所以固定装到应用目录下。
PW_PATH="$APP_DIR/ms-playwright"
ensure_env PLAYWRIGHT_BROWSERS_PATH "$PW_PATH"
install -d -m 0755 "$PW_PATH"
if [ -n "$(ls -A "$PW_PATH" 2>/dev/null || true)" ]; then
  ok "chromium 已就位（$PW_PATH）"
elif "$VENV_DIR/bin/python" -c 'import playwright' >/dev/null 2>&1; then
  log "安装 chromium（约 150MB，只需一次）"
  if PLAYWRIGHT_BROWSERS_PATH="$PW_PATH" "$VENV_DIR/bin/python" -m playwright install chromium >/dev/null 2>&1; then
    ok "chromium 已安装"
  else
    warn "chromium 安装失败：网页取证会退化为「无截图」，可稍后重试"
  fi
else
  warn "未安装 playwright（可选依赖）：网页取证不可用，pip install '.[sandbox]' 后重跑本脚本"
fi
chown -R "$APP_USER:$APP_USER" "$PW_PATH" 2>/dev/null || true

# ---------------------------------------------------------------- systemd
UNIT="/etc/systemd/system/${SERVICE}.service"
log "写入 $UNIT"

# 只给数据目录写权限，但副本目录 / 证据仓可能配在数据目录之外
# （线上就是 /var/lib/silver-sentinel/replica）。漏了它们，副本同步会静默失败。
RW_PATHS="$DATA_DIR"
for _key in SILVER_REPLICA_TARGET SILVER_VAULT_TARGET SILVER_VAULT_DIR; do
  _val="$(sed -n "s/^${_key}=//p" "$ENV_FILE" 2>/dev/null | head -1 | tr -d "\"'")"
  case "$_val" in
    /*) case " $RW_PATHS " in *" $_val "*) ;; *) RW_PATHS="$RW_PATHS $_val" ;; esac ;;
  esac
done
cat > "$UNIT" <<EOF
[Unit]
Description=Silver Sentinel console ($APP_NAME)
Documentation=https://github.com/stellarissss/silver-sentinel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$VENV_DIR/bin/silver-sentinel serve --host \${SILVER_WEB_HOST} --port \${SILVER_WEB_PORT}
Restart=always
RestartSec=5
TimeoutStopSec=20
# 只允许写数据目录，其余一律只读
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$RW_PATHS
ReadOnlyPaths=$APP_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"

# ---------------------------------------------------------------- 看门狗
# Restart=always 只覆盖「进程退出」。进程活着但线程卡死时，服务一直是
# active、Web 也一直 200，只有 heartbeat.json 会停更。这条 timer 每 2 分钟
# 读一次心跳，超时就重启，并做频率熔断。
WATCHDOG_SRC="$(dirname "$0")/watchdog.sh"
if [ -f "$WATCHDOG_SRC" ]; then
  install -m 0755 "$WATCHDOG_SRC" "$APP_DIR/watchdog.sh"
  log "写入 ${SERVICE}-watchdog 单元"
  cat > "/etc/systemd/system/${SERVICE}-watchdog.service" <<EOF
[Unit]
Description=Silver Sentinel watchdog（心跳停更则重启主服务）
After=${SERVICE}.service

[Service]
Type=oneshot
EnvironmentFile=$ENV_FILE
Environment=APP_DIR=$APP_DIR VENV=$VENV_DIR SERVICE=$SERVICE DATA_DIR=$DATA_DIR
ExecStart=$APP_DIR/watchdog.sh
EOF
  cat > "/etc/systemd/system/${SERVICE}-watchdog.timer" <<EOF
[Unit]
Description=Silver Sentinel watchdog timer

[Timer]
# 用 OnActiveSec 而不是 OnBootSec：后者是相对「系统启动」算的，
# 在一台已经跑了几个月的机器上启用 timer 会立刻触发一次，
# 撞上服务刚重启、心跳还没落盘的那几秒，白白多重启一次。
OnActiveSec=2min
OnUnitActiveSec=2min
AccuracySec=15s
Unit=${SERVICE}-watchdog.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now "${SERVICE}-watchdog.timer" >/dev/null 2>&1 \
    && ok "看门狗 timer 已启用（每 2 分钟检查一次心跳）" \
    || warn "看门狗 timer 启用失败，可手动 systemctl enable --now ${SERVICE}-watchdog.timer"
else
  warn "没找到 deploy/watchdog.sh，跳过看门狗安装"
fi

# ---------------------------------------------------------------- 自检
log "等待服务就绪 ..."
for i in $(seq 1 30); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${WEB_PORT}/api/ping" >/dev/null 2>&1; then
    ok "健康检查通过（/api/ping）"
    break
  fi
  if [ "$i" -eq 30 ]; then
    printf '\n'
    journalctl -u "$SERVICE" -n 40 --no-pager 2>/dev/null || true
    die "服务没起来，日志见上"
  fi
  sleep 1
done

# ---------------------------------------------------------------- 防火墙
if [ "$OPEN_FIREWALL" = "1" ]; then
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
    ufw allow "${WEB_PORT}/tcp" >/dev/null 2>&1 && ok "ufw 放行 ${WEB_PORT}/tcp"
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${WEB_PORT}/tcp" >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1 && ok "firewalld 放行 ${WEB_PORT}/tcp"
  else
    warn "没检测到 ufw/firewalld，若启用的是 iptables 需自行放行 ${WEB_PORT}/tcp"
  fi
fi

# ---------------------------------------------------------------- 汇总
# 公网地址：多个来源依次尝试，全是内网地址时如实标注，别骗用户
detect_ip() {
  local ip
  for url in https://api.ipify.org https://ifconfig.me/ip https://ipinfo.io/ip; do
    ip="$(curl -fsS --max-time 4 "$url" 2>/dev/null | tr -d '[:space:]')"
    case "$ip" in
      ''|*[!0-9.]*) continue ;;
    esac
    printf '%s\n' "$ip"; return 0
  done
  hostname -I 2>/dev/null | awk '{print $1}'
}

IP="$(detect_ip)"
case "$IP" in
  10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) EXTERNAL_HINT="（内网地址，外网请用公网 IP 或域名）" ;;
  *) EXTERNAL_HINT="" ;;
esac

cat <<EOF

────────────────────────────────────────────────────────
 银发哨兵 $VER 已就绪
────────────────────────────────────────────────────────
 本机访问   http://127.0.0.1:${WEB_PORT}/
 外网访问   http://${IP}:${WEB_PORT}/ ${EXTERNAL_HINT}
 访问口令   ${PASSWORD}
 数据目录   ${DATA_DIR}
 服务管理   systemctl status|restart ${SERVICE}
 实时日志   journalctl -u ${SERVICE} -f

 还要做一步：云厂商安全组 / 防火墙需放行 TCP ${WEB_PORT}，
 否则浏览器会卡在「连接超时」而不是 404。
 口令已写入 ${ENV_FILE}（0600），改口令后记得 restart。
────────────────────────────────────────────────────────
EOF
