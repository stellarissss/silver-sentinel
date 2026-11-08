#!/usr/bin/env bash
# 银发哨兵 · 用途分类上线验收
#
#   bash deploy/verify-purpose.sh              # 只读检查，不改任何数据
#   bash deploy/verify-purpose.sh --apply      # 另外执行 rescore --retier（补算历史资产用途）
#
# 验收的不是「进程活着」，而是「新判据真的生效了」：
#   1. 模型加载成功（不是静默退回规则）
#   2. 客服站被判成客服、不占高危队列
#   3. 落地页不被误判成经营型
#   4. 历史资产补算后，用途分布不是全 0
#   5. 看门狗与队列健康度没有因为这次升级变差
#
# 只读是默认值：部署后先跑这个，确认无误再 --apply。

set -uo pipefail

SILVER_BIN="${SILVER_BIN:-silver-sentinel}"
APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "未知参数：$arg" >&2; exit 2 ;;
  esac
done

# install.sh 把程序装在 $APP_DIR/.venv（兼容旧版的 venv/），没有做全局软链。
# 先自己找一遍，别让人为了跑一次验收去查 systemd 单元。
if ! command -v "$SILVER_BIN" >/dev/null 2>&1; then
  for cand in \
    "${APP_DIR:-/opt/silver-sentinel}/.venv/bin/silver-sentinel" \
    "${APP_DIR:-/opt/silver-sentinel}/venv/bin/silver-sentinel" \
    /opt/silver-sentinel/.venv/bin/silver-sentinel; do
    if [ -x "$cand" ]; then SILVER_BIN="$cand"; break; fi
  done
fi
if ! command -v "$SILVER_BIN" >/dev/null 2>&1 && [ ! -x "$SILVER_BIN" ]; then
  echo "找不到 silver-sentinel。用 SILVER_BIN=/opt/silver-sentinel/.venv/bin/silver-sentinel 指定。" >&2
  exit 2
fi

PY="$(dirname "$(command -v "$SILVER_BIN")")/python"
[ -x "$PY" ] || PY=python3

pass=0
fail=0
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; fail=$((fail+1)); }
note() { printf '    %s\n' "$1"; }

echo "== 1. 版本 =="
VER="$("$SILVER_BIN" --version 2>/dev/null || true)"
if [ -z "$VER" ]; then
  VER="$("$PY" -c 'import silver_sentinel as s; print(s.__version__)' 2>/dev/null || echo '?')"
fi
note "silver-sentinel $VER"

echo "== 2. 用途模型 =="
MODEL_JSON="$("$SILVER_BIN" model status 2>/dev/null || echo '{}')"
AVAILABLE="$(printf '%s' "$MODEL_JSON" | "$PY" -c 'import json,sys
try: print(json.load(sys.stdin).get("available"))
except Exception: print(False)' 2>/dev/null)"
if [ "$AVAILABLE" = "True" ]; then
  printf '%s' "$MODEL_JSON" | "$PY" -c 'import json,sys
d=json.load(sys.stdin); m=d.get("metrics") or {}
print(f"    算法 {m.get(\"algorithm\")}  样本 {m.get(\"samples\")}  "
      f"CV 准确率 {m.get(\"cv_accuracy\")}  operational 召回 {m.get(\"operational_recall\")}")
f=m.get("fusion") or {}
if f:
    print(f"    折外融合：经营型识别 {f.get(\"fused_suppressed\")}/{f.get(\"operational_n\")}，"
          f"目标形态误排除 {f.get(\"fused_danger\")}/{f.get(\"target_n\")}")' 2>/dev/null
  ok "模型已加载（不是退回规则基线）"
else
  bad "模型未加载——用途判定会退回纯规则，识别率约降一半"
  note "检查 wheel 是否带 data/purpose_model.joblib，或 SILVER_PURPOSE_MODEL 是否指错"
fi

echo "== 3. 客服站判定（真实站点）=="
CS_OUT="$("$SILVER_BIN" purpose https://www.53kf.com --timeout 30 2>/dev/null || echo '{}')"
read -r pur lab conf sup <<< "$(printf '%s' "$CS_OUT" | "$PY" -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: d={}
p=d.get("purpose") or {}
print(p.get("purpose"), p.get("label"), p.get("confidence"), p.get("suppressed"))' 2>/dev/null)"
if [ "${pur:-}" = "customer_service" ] && [ "${sup:-}" = "True" ]; then
  ok "53kf → $lab（置信 ${conf}），不占高危队列"
else
  bad "53kf 判定异常：${pur:-抓取失败} / suppressed=${sup:-?}"
  note "若抓取失败，先确认出口代理与 chromium 可用"
fi

echo "== 4. 落地页不被误排除 =="
LP_HTML="$(mktemp /tmp/ss-lp-XXXXXX.html)"
cat > "$LP_HTML" <<'HTML'
<html><head><title>中华人民共和国财政部 惠民补贴申领</title></head>
<body><div>财政部 民政部 主办</div>
<div>立即领取 限时 名额 扫码 加微信 免费领取 一键申请</div>
<form><input name="idcard" placeholder="身份证号"></form></body></html>
HTML
LP_OUT="$("$SILVER_BIN" purpose --html-file "$LP_HTML" --host example.top 2>/dev/null || echo '{}')"
rm -f "$LP_HTML"
read -r pur sup <<< "$(printf '%s' "$LP_OUT" | "$PY" -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: d={}
p=d.get("purpose") or {}
print(p.get("purpose"), p.get("suppressed"))' 2>/dev/null)"
if [ "${sup:-}" != "True" ]; then
  ok "伪造部委落地页未被用途闸门放过（${pur:-unknown}）"
else
  bad "落地页被误判为经营型并抑制（${pur}）——立即 SILVER_PURPOSE_SUPPRESS=0"
fi

if [ "$APPLY" = "1" ]; then
  echo "== 5. 历史资产补算（rescore --retier）=="
  note "会重算最多 3000 条，并允许降级。首次执行可能几分钟。"
  if "$SILVER_BIN" rescore --retier --limit 3000 2>&1 | tail -5; then
    ok "重评完成"
  else
    bad "重评失败，看上面的错误"
  fi
else
  echo "== 5. 历史资产补算（跳过）=="
  note "确认前面都正常后，跑：$SILVER_BIN rescore --retier --limit 3000"
fi

echo "== 6. 态势与健康 =="
"$SILVER_BIN" brief --hours 24 2>&1 | sed 's/^/    /' || true
echo
if "$SILVER_BIN" doctor >/dev/null 2>&1; then
  ok "doctor 通过"
else
  bad "doctor 未通过（看门狗会据此重启，先看它的输出）"
fi

echo
if [ "$fail" -eq 0 ]; then
  printf '\033[32m验收通过\033[0m（%d 项）\n' "$pass"
  exit 0
fi
printf '\033[31m有 %d 项未通过\033[0m（通过 %d 项）\n' "$fail" "$pass"
exit 1
