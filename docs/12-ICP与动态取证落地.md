# ICP 备案与动态取证：从「接不上」到「能跑」

> 这两个能力以前都写在能力表里，实际值是 `icp: false` / `sandbox_web: false`。
> 本轮把它们落到「可以在服务器上跑、且能验证」的状态。

## 一、ICP 备案

### 1.1 为什么这件事不简单

工信部备案查询没有公开 API。真实链路是：

```
POST /icpproject_query/api/auth        → 拿 bussiness token（authKey = md5("testtest"+ts)）
POST /icpproject_query/api/image/getCheckImagePoint
                                       → 返回大图 + 小图，需要算出点击坐标
POST /icpproject_query/api/checkImagePoint
                                       → AES-ECB 加密坐标回传，通过后放行查询
```

也就是说，**必须有验证码识别**。自己写 CV 是重复造轮子，而且模型要跟着验证码改版走。

### 1.2 选型

| 方案 | 结论 |
| --- | --- |
| `ICPQuery-MCP` | 功能对，但它是 MCP server，我们要的是 HTTP 客户端；5 次/分钟也偏保守 |
| 第三方付费 API | 便宜但不稳定、来源不明，证据链上不敢用 |
| **`ICP_Query`（HG-ha）** | **选它**：自带 Siamese 验证码模型、提供 `GET /query/{type}?search=`、有 Docker 镜像 |
| 自己爬 | 验证码改版就废，且风控会封 IP |

`ICP_Query` 支持 8 种查询，其中两个对我们最关键：

- `web` —— 网站备案（域名 / 备案号 / 企业名）
- `bweb` —— **违法违规网站名单**（`blackListLevel`：2 = 暂无违规，<2 = 已列管）

`bweb` 是意外收获：它比「有没有备案」更硬，是官方已经定性的名单。

### 1.3 部署（服务器实测）

```bash
docker run -d --name ymicp --restart unless-stopped \
  -p 127.0.0.1:16181:16181 yiminger/ymicp
# 只绑 127.0.0.1，不对外暴露
```

`/etc/silver-sentinel.env`：

```ini
SILVER_ICP_ENABLED=1
SILVER_ICP_API=http://127.0.0.1:16181
SILVER_ICP_RPM=40          # 总速率上限，避免把出口 IP 打进黑名单
SILVER_ICP_TIMEOUT=60      # 验证码重试时单次可能 30 秒以上
SILVER_ICP_VIOLATION=1     # 同时查违法违规名单（多一次请求）
SILVER_ICP_CACHE_DAYS=30
```

### 1.4 客户端修了三个真问题

1. **解析永远是空**。`_iter_records` 只认 `data/result/list`，而 `ICP_Query` 把记录放在
   `params.list` 里 → 所有域名都被判成「未备案」。这是「接了但没生效」的典型。
2. **接口出错被当成未备案**。`code=500` / `success=false` 时 `list` 为空，
   旧逻辑直接 `unregistered`。一次风控就会批量制造假结论，还会写进举报材料。
   现在区分 `unknown` 与 `unregistered`，且 `unknown` 不写缓存。
3. **没有违规名单**。新增 `/query/bweb` 解析与 `ICP-001` 规则（权重 34）。

### 1.5 实测

| 输入 | 结果 |
| --- | --- |
| `baidu.com` | `registered` · 京ICP证030173号 · 北京百度网讯科技有限公司 · 违规名单 clean |
| `qq.com` | `registered` · 粤B2-20090059 · 深圳市腾讯计算机系统有限公司 · clean |
| 5 个诈骗域名 | 全部 `unregistered`（一次接口故障都没有） |

单次耗时 0.6–32 秒（验证码识别 + 重试）。

### 1.5.1 风控实测（重要）

第一批按 4 并发 / 40 每分钟跑，**十几条之后就被封了**：

```
{"code":500,"message":"当前访问已被创宇盾拦截"}
…/api/image/getCheckImagePoint → 403
```

也就是说工信部不只看频率，还看突发形态。结论：

| 参数 | 建议值 | 理由 |
| --- | --- | --- |
| 并发 | 1–2 | 并发是最容易被识别的特征 |
| 速率 | ≤5/分钟 | 实测 40/分钟必封；5/分钟可持续 |
| 冷却 | 连续 4 次失败即停 15 分钟 | 封禁信号（拦截/403）直接冷却 1 小时 |
| 缓存 | 30 天 | 备案信息变化慢，重复查纯属浪费额度 |

代码里已按这个口径设默认值，并加了熔断：连续失败或明确封禁时整体冷却，
回填命令会立刻停手（`aborted` 字段说明原因），不再继续打。

被封后的出路有两条：等解封（数小时），或让 ICP 查询也走境外 SOCKS5 出口
（`ICP_Query` 的 `config.yml` 支持 `proxy.tunnel.url`）。**这两件事可以用同一个出口解决**——
这也是下一轮最该先做的基础设施。

### 1.6 批量回填

ICP 查询慢，塞进每轮调度会拖死富化队列。做法是离线补：

```bash
silver-sentinel icp --limit 2000 --workers 4          # 只查 tier>=candidate 的存量
silver-sentinel icp --limit 50 --refresh --dry-run    # 先看会查哪些
```

结果直接进 `icp_cache`，服务下次研判自动复用；`--refresh` 才忽略缓存。

---

## 二、动态取证

### 2.1 原来的问题

沙箱代码写得很细（禁内网、只写只读、WebRTC 屏蔽、蜜罐探针），但：

1. 服务器上没有 Chromium → `sandbox_web: false`；
2. 没有隔离出口 → 即便装了浏览器，OPSEC 也会 fail-closed；
3. 就算跑起来，也**只存了「页面正文」一段文本**，没有 HTML 原文、没有截图、没有网络请求。

结果是 22 小时的证据里，1,354 条是评分快照，**原始页面 0 条**。
评分快照只能证明「我们当时这么判」，不能证明「对方当时长这样」。

### 2.2 现在抓什么

| 证据 | 格式 | 用途 |
| --- | --- | --- |
| `page_text` | txt | 快速检索、给 LLM 看 |
| `page_html` | html | 取证：DOM 结构、隐藏元素、注释里的联系方式 |
| `screenshot` | png | 「受害者看到的这一屏」，改版后仍可核对 |
| `network` | json | 运行时请求：外传地址、第三方 SDK、POST 目标 |

四份都走 `evidence.append()`，进 AES-256-GCM 证据仓，带哈希链与保管链。

截图时机在 `wait_for_timeout(2500)` 之后——**必须等 JS 跑完**。
本地验证页故意做成「首屏显示活动已结束，1.2 秒后 JS 换成真内容」，
截图里拿到了被藏起来的「国家惠民养老补贴申领中心」，静态 HTML 里没有这段。

### 2.3 出口：唯一还缺的东西

`SILVER_OPSEC_REQUIRE_PROXY_SANDBOX=1` 时，没有代理就拒绝运行可疑目标——
这是对的：浏览器是最强的指纹（TLS、Canvas、WebRTC），直连等于把采集机 IP 送给对方。

服务器在境内，Tor 建不了链。可行方案按成本排序：

| 方案 | 成本 | 说明 |
| --- | --- | --- |
| **境外小 VPS + gost** | ¥10–20/月 | 推荐。一条命令起 SOCKS5，可随时换 IP |
| 商业 SOCKS5 代理池 | ¥50+/月 | 无需运维，但供应商能看到全部流量 |
| Cloudflare WARP | 免费 | 境内连通性不稳定，出口是 Cloudflare 段 |

`gost` 的起法（在境外机器上，10 秒）：

```bash
docker run -d --name relay --restart unless-stopped -p 1080:1080 \
  ghcr.io/go-gost/gost:latest -L "socks5://user:pass@:1080?udp=false"
```

然后在本机：

```ini
SILVER_OPSEC_PROXIES=socks5h://user:pass@<relay-ip>:1080
```

`socks5h` 让**代理解析 DNS**，本地解析记录不会泄露；配好后
`capability_report()` 的 `sandbox_web` 会自动变 `true`。

### 2.4 已验证的部分

在没有代理的前提下，用本地假目标（`127.0.0.1`，走 `internal` 分类）跑通了全链路：

```
status 200  final http://127.0.0.1:18999/  title 活动已结束
apk_links ['https://cdn.example-bad.top/pkg/silver.apk']   ← JS 拼出来的
screenshot_bytes 22796  html_len 858
EV page_text 151 / page_html 1048 / screenshot 22796 / network 183
```

截图确认能看到 cloaking 后的真实内容。也就是说：**代码路径是通的，缺的只是一个出口**。

### 2.5 边界

- 只发 GET/HEAD；POST 一律拦截并记录，绝不真的提交表单（否则等于替受害者报名）。
- 内网地址、云元数据地址在路由层直接 abort。
- 页面回显采集端 IP 或探针串时标记「疑似蜜罐」，不继续深入。
- 证据落盘前经过 `opsec.redact()`，把自身 IP / 主机名 / 数据目录抹掉。

---

## 三、验证清单

| 项 | 命令 | 期望 |
| --- | --- | --- |
| 备案可用 | `silver-sentinel icp --limit 3 --workers 1` | `registered` 或 `unregistered`，无 `unknown` |
| 违规名单 | 同上 | `listed` / `clean` |
| 能力自陈 | `GET /api/health` | `icp: true`；`sandbox_web: false, blocked_by: no-proxy` |
| 存量清理 | `discover reconcile` | 默认只报告，`--apply` 才写库 |
| 动态取证 | 配好代理后 `enrich <id> --probe` | 证据表出现 page_html / screenshot / network |
