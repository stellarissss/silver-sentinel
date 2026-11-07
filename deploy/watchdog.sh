#!/usr/bin/env bash
# 银发哨兵 · 进程级看门狗
#
# systemd 的 Restart=always 只能救「进程退出」。真正难发现的是另一种：
# 进程还在、Web 还能回包、界面照常转圈，但调度线程卡在一次没有超时的请求上，
# 或者取证线程死锁——services 显示 active，实际已经几个小时没干活。
#
# 这条脚本由 systemd timer 每 2 分钟拉起一次，读服务自己写的 heartbeat.json：
# 5 分钟没更新就地重启。重启有频率上限，避免「起不来 → 无限重启」把日志刷爆。
#
# 退出码：0 = 健康或有活干；1 = 已重启；2 = 判定异常但拒绝再重启（熔断）。

set -uo pipefail

APP_DIR="${APP_DIR:-/opt/silver-sentinel}"
VENV="${VENV:-$APP_DIR/venv}"
SERVICE="${SERVICE:-silver-sentinel}"
DATA_DIR="${DATA_DIR:-/var/lib/silver-sentinel/data}"
MAX_AGE="${MAX_AGE:-300}"
MAX_RESTARTS="${MAX_RESTARTS:-3}"
WINDOW=$((60 * 60))                     # 一小时内最多重启 3 次
STATE="${STATE:-/var/lib/silver-sentinel/watchdog.state}"
LOG_FILE="${LOG_FILE:-$DATA_DIR/logs/watchdog.log}"

log() {
  local line
  line="$(date -Iseconds) $*"
  printf '%s\n' "$line"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
  printf '%s\n' "$line" >>"$LOG_FILE" 2>/dev/null || true
}

# ---- 0. 重启宽限期：服务刚起不久时心跳还没落盘，别急着重启
# ActiveEnterTimestampMonotonic 是微秒；取不到就当作老服务，继续往下查。
START_US="$(systemctl show -p ActiveEnterTimestampMonotonic --value "$SERVICE" 2>/dev/null || echo "")"
if [ -n "$START_US" ] && [ "$START_US" != "0" ]; then
  NOW_US="$(awk '{printf "%.0f", $1 * 1000000}' /proc/uptime)"
  UP_S=$(( (NOW_US - START_US) / 1000000 ))
  if [ "$UP_S" -lt 300 ]; then
    exit 0
  fi
fi

# ---- 1. 自检。doctor 自己会判断心跳年龄与队列 starvation
OUT="$("$VENV/bin/silver-sentinel" doctor --max-age "$MAX_AGE" 2>&1)"
RC=$?
if [ $RC -eq 0 ]; then
  exit 0
fi

# ---- 2. 频率熔断：一小时内已经重启 N 次，就不再重启，改成大声报错
mkdir -p "$(dirname "$STATE")" 2>/dev/null
touch "$STATE" 2>/dev/null || true
NOW="$(date +%s)"
# 只保留窗口内的重启时间戳
RECENT="$(awk -v now="$NOW" -v win="$WINDOW" '$1 ~ /^[0-9]+$/ && now - $1 < win' "$STATE" 2>/dev/null || true)"
COUNT="$(printf '%s\n' "$RECENT" | grep -c '[0-9]' || true)"

log "自检未通过（退出码 $RC），准备重启 $SERVICE；近一小时内已重启 ${COUNT}/${MAX_RESTARTS} 次"
printf '%s\n' "$OUT" | tail -20 | while IFS= read -r l; do log "  $l"; done

if [ "${COUNT:-0}" -ge "$MAX_RESTARTS" ]; then
  log "已达重启上限：不再自动重启，需要人工介入（查看 journalctl -u $SERVICE）"
  exit 2
fi

printf '%s\n' "$RECENT" "$NOW" | grep '[0-9]' >"$STATE"

systemctl restart "$SERVICE"
log "已执行 systemctl restart $SERVICE"
exit 1
