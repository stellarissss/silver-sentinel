# 卡死再复发：status/verify/pull 全量解析账本根治（v1.16.14）

日期：2026-11-22　触发：用户反馈「网站崩了，恢复之」

## 现象

- 生产 `119.45.14.187:18700` ping 正常（30ms），`/login` 偶发 15s 超时，首页静态资源加载不出来。
- 服务 `active`，但主进程 `VmRSS 868MB + VmSwap 874MB`，`MemAvailable` 在 91MB↔920MB 剧烈震荡，`kswapd0` 持续换页。
- 这就是用户端「崩」的本质：**系统级内存抖动（thrashing）**——进程工作集逼近 1.9G 上限，请求处理时大量缺页，表现成卡顿/超时。

## 根因

v1.16.13 已把 `vault.py` 里 **push 侧**的全量解析改成流式（`iter_manifest` + `_last_entry` O(1)），但**漏掉了另外四条路径**，它们仍把整个账本 `read_bytes()/splitlines()/json.loads` 成 dict 列表：

| 路径 | 触发频率 | 全量解析对象 |
|------|----------|--------------|
| `status()` | 运维页 SSE / API **每 15s** | 全部账本（manifest + 2×remote） |
| `pull()` → `_pull_manifests()` | vault sync 每 120s | node 账本 77MB / 21 万条 |
| `verify()` | 手动/自检 | 全部账本 + 保管链 |
| `import_ledger()` | 导入时 | 全部远端账本 |

生产账本已膨胀到 **node 77M + custody 105M + remote 44M ≈ 226MB**。`status()` 每 15s 被前端轮询调用一次，每次把 226MB parse 成几十万个 dict——一次几百 MB 内存 + 长时间持有 GIL，把 1.9G 机器推入 swap 颠簸。**前端页面开着就会周期性把机器拖垮**，这是本次「打开网站就卡死」的直接机制。

## 修复（v1.16.14）

新增三个流式 helper，替换全部全量解析：

- `_count_lines(path)`：二进制块数换行符，O(1) 内存拿条目数（不再 parse 整表）。
- `_first_entry(path)`：只读文件头取首条的 `node` 标识。
- `_verify_chain(path)`：逐条解析逐条丢弃，流式校验 `seq`/`prev`/`hash`，内存恒定。

改造点：

1. `status()`：计数走 `_count_lines`，首条走 `_first_entry`，末条走 `_last_entry`；不再 `read_manifest` 整表。这是最高频路径，根治关键。
2. `verify()`：主链与保管链全部改 `_verify_chain`；`deep` 采样用 `deque(maxlen=sample)` 只留末尾窗口。
3. `_pull_manifests()`：改为只落盘 + 记路径，`pull()` 用 `iter_manifest` 逐条流式处理；`origin` 用 `_first_entry`，计数用 `_count_lines`。
4. `import_ledger()`：计数改 `_count_lines`。
5. 保留 `_last_entry` 尾部损坏时的全表兜底（罕见正确性路径）。

## 运维止血（同步生效，不改代码）

- `SILVER_VAULT_INTERVAL` 120 → 900（降低 sync 周期）
- `SILVER_CAPTURE_MIN_FREE_MEM_MB` 350 → 420（更早挡住 Chromium）
- `SILVER_WORKERS` 3 → 2（降并发）
- 备份原 env 为 `/etc/silver-sentinel.env.bak-*`

## 验证

- 全量测试 **587 passed**（新增 4 项流式回归测试）。
- ruff 全过、AST 语法校验通过。
- 生产覆盖安装 v1.16.14（不触碰 env/unit），重启后 heartbeat `version=1.16.14`。
- **`status()` 实测：耗时 1.79s、峰值 RSS 仅 58MB**（旧版解析 226MB 会冲到几百 MB）——流式化生效的直接证据。
- **内存趋势（部署后 4 次采样）**：`avail` 稳定 515–566MB、进程 `swap` 从修复前的 0↔727MB 剧烈震荡降到 **16–20MB 平稳**；RSS 稳定 831–858MB。`kswapd` 换页停止，用户端卡顿根因消除。
- **HTTP 验收**：`/`、`/login`、静态资源连续采样全部 0.06–0.34s（偶发首次连接抖动 1 次，非服务问题）。
- 近 30min 仅 3 次 `database is locked`（重启后建图/取证并发写库短暂竞争，有 try/except 兜底，周期持续推进，非致命）。

提交：`7ecf908`，已推送 GitHub main。

## 遗留

- 1.9G 内存仍是吞吐硬约束。账本会持续增长，`_publish_ledger` 在跨设备后端时仍整读账本（当前 `vault_skip_same_device_copy=1` 同盘，不触发）。若需更高吞吐，应扩容内存或迁移账本到独立存储。
- 建议后续给 `Backend` 加流式 `put_file`，彻底消除跨设备 push 的整读峰值。
