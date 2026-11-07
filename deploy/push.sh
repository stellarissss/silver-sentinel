#!/usr/bin/env bash
# 银发哨兵 · 从本机推送到服务器
#
#   bash deploy/push.sh root@119.45.14.187
#   bash deploy/push.sh root@119.45.14.187 -p 2222 -i ~/.ssh/id_ed25519
#
# 做的事：取/构建 wheel → tar 流式传到 /tmp/ss-deploy → 远端执行 install.sh。
# 不依赖服务器上有 git / pipx / 公网访问 PyPI（wheel 里已带全部静态资源）。

set -euo pipefail

TARGET="${1:-}"
[ -n "$TARGET" ] || {
  cat >&2 <<'EOF'
用法: bash deploy/push.sh <user@host> [ssh 参数...]

例:
  bash deploy/push.sh root@119.45.14.187
  bash deploy/push.sh root@119.45.14.187 -p 2222
EOF
  exit 1
}
shift

SSH_ARGS=("$@")
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE_DIR="/tmp/ss-deploy"

# 服务器只开了密码认证时：DEPLOY_PASSWORD=xxx bash deploy/push.sh root@host
# 用 SSH_ASKPASS 而不是 echo 口令 | ssh，也不需要装 sshpass：
# OpenSSH 8.4+ 的 SSH_ASKPASS_REQUIRE=force 会强制走这个助手取口令。
if [ -n "${DEPLOY_PASSWORD:-}" ]; then
  ASKPASS_HELPER="$(mktemp /tmp/ss-askpass-XXXXXX)"
  printf '#!/bin/sh\nprintf "%%s\\n" "$DEPLOY_PASSWORD"\n' > "$ASKPASS_HELPER"
  chmod 700 "$ASKPASS_HELPER"
  export DEPLOY_PASSWORD SSH_ASKPASS="$ASKPASS_HELPER" SSH_ASKPASS_REQUIRE=force
  export DISPLAY="${DISPLAY:-:0}"
  trap 'rm -f "$ASKPASS_HELPER"' EXIT
  SSH_ARGS+=(-o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no)
fi

log()  { printf '\033[2m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
die()  { printf '\033[31m  xx\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 1. 取 wheel
WHEEL="$(ls -t "$ROOT"/dist/silver_sentinel-*.whl 2>/dev/null | head -1 || true)"
if [ -z "$WHEEL" ]; then
  log "dist/ 里没有 wheel，开始构建"
  ( cd "$ROOT" && python -m build --wheel >/dev/null )
  WHEEL="$(ls -t "$ROOT"/dist/silver_sentinel-*.whl | head -1)"
fi
log "使用 $(basename "$WHEEL") ($(du -h "$WHEEL" | cut -f1))"

# 冒烟：本地先确认这个 wheel 装得起来、静态资源齐全
python - "$WHEEL" <<'EOF' || die "wheel 自检失败"
import sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
names = set(z.namelist())
need = ["web/static/style.css", "web/static/ui.js", "web/templates/login.html"]
for n in need:
    assert any(x.endswith(n) for x in names), f"wheel 缺少 {n}"
EOF

# ---------------------------------------------------------------- 2. 传输
log "连接 $TARGET ..."
ssh "${SSH_ARGS[@]}" -o ConnectTimeout=12 "$TARGET" "mkdir -p $REMOTE_DIR" \
  || die "SSH 连不上 $TARGET（检查地址、端口、密钥或安全组）"

log "传输安装包"
tar czf - -C "$ROOT/deploy" install.sh watchdog.sh -C "$(dirname "$WHEEL")" "$(basename "$WHEEL")" \
  | ssh "${SSH_ARGS[@]}" "$TARGET" "tar xzf - -C $REMOTE_DIR" \
  || die "传输失败"

# ---------------------------------------------------------------- 3. 远端安装
log "执行远端安装（需要 sudo 权限）"
ssh "${SSH_ARGS[@]}" -t "$TARGET" \
  "cd $REMOTE_DIR && (id -u | grep -qx 0 && bash install.sh $REMOTE_DIR/$(basename "$WHEEL") || sudo bash install.sh $REMOTE_DIR/$(basename "$WHEEL"))"

log "完成"
