# 银发哨兵 · Silver Sentinel

面向「领鸡蛋骗局」线上化形态的 **持续发现 — 动态取证 — 图谱归因 — 处置闭环** 系统。

不是又一个钓鱼网址库，而是针对中国涉老诈骗特有载体的一套研判工程：**应用商店搜不到、没有 ICP 备案、只能扫码安装的仿冒「国家项目」App**，以及围绕它运转的微信群裂变、签到返利、拉人头与虚拟货币收款。

v1.0 的定位从「拿线索来查」改成「**挂在服务器上一直盯着**」：CT 日志、域名排列、备案库三路并行发现，证据只追加不修改，团伙按图上的共同基础设施归并，沙箱里真跑页面与安装包。

![概览](docs/screenshots/v1-overview.png)

---

## 为什么需要它

线下那套「免费领鸡蛋 → 健康讲座 → 专家义诊 → 高价特效药」并没有消失，只是把最后一步搬到了手机上。央视 2026 年 10 月公布的典型案例里，一个团伙用「免费领鸡蛋」「专家义诊」引流，发展成「老板操控、讲师授课、门店收割」的产业链，抓获 120 人、涉案 500 余万元。同期公安部通报的涉诈 App 案件，涉案金额已达 60 亿元量级。

这类骗局有几个传统 URL 黑名单拦不住的特征：

| 特征 | 为什么难拦 |
| --- | --- |
| 载体是 APK，不是网页 | 网页能下线，安装包留在老人手机里继续跑 |
| 应用商店搜不到，只能扫码/外链装 | 绕过了商店审核这一道最有效的关口 |
| 域名寿命以周计 | 黑名单永远慢一步，得靠证书/模板/收款地址做归并 |
| 话术高度本地化 | 「民族资产解冻」「国补」「高龄补助」这类词，通用引擎识别不了 |
| 受害人不报案 | 老人常因「家丑不可外扬」错过追赃时机，线索需要主动发现 |

银发哨兵针对的正是这五点。

---

## v1.0 做了什么

| 环节 | v0.1 | v1.0 |
| --- | --- | --- |
| **发现** | 关键词盯 crt.sh，单点 | CT 日志直连（RFC 6962）+ certstream + 域名排列探测，三路冗余；词库 363 词根 / 6 语义簇，中文词自动派生拼音变体，实测 5 万域名/秒匹配 |
| **准入** | 高分才入库 | 命中一个词就入库（`candidate` 档），先记录再评估，确认无害才降级/冷存 |
| **取证** | 只存数据库 | 只追加事件日志（哈希链 + fsync）+ 增量分片副本（dir/S3/WebDAV）+ 内容寻址证据文件 |
| **归因** | 字段比对猜团伙 | 图数据库（内置 SQLite 图引擎 / Neo4j）20 类节点、17 种关系，社区发现自动成团，共用证书权重远高于共用 IP |
| **动态** | 不碰可疑站点 | 沙箱内真跑网页（Playwright，阻断内网与非 GET）、APK（MobSF / adb / 静态推演三级降级） |
| **运营** | 无 | 能力降级自陈、任务记账、Prometheus 指标、SSE 实时流、运维页 |

![发现流](docs/screenshots/v1-discover.png)

---

## 能力

| 环节 | 具体做什么 |
| --- | --- |
| **发现** | 监听 CT 日志新证书、按语义簇派生域名排列做 DNS 探测、按词根翻历史证书；命中即入库，同时记录「为什么进来」 |
| **研判** | 44 条可解释规则 + 词库暗示 + 可选 LLM；输出风险分、判定等级、逐条可核对的依据 |
| **记录** | 线索库 + 证据哈希链；每条证据可追溯到采集时刻与原文摘录，删改即断链 |
| **监控** | 分级（candidate/watch/confirmed/cold/dismissed）+ 驻留衰减；高分目标自动进富化与实测队列 |
| **归因** | 域名、证书指纹、模板指纹、钱包地址、收款手机号、备案主体、包名、内嵌域名进同一张图，社区发现成团，输出「谁和谁是一伙的、凭什么」 |
| **处置** | 一键生成 12321 / 12377 / 网络违法犯罪举报网站 / 12315 的结构化材料，附法条与证据清单；举报对象指向**主体与基础设施**，不是单个安装包 |

![关系图谱](docs/screenshots/v1-graph.png)

---

## 快速开始

```bash
git clone https://github.com/stellarissss/silver-sentinel.git
cd silver-sentinel
python3 -m pip install -e ".[full]"     # 不加 [full] 也能跑，只是少了沙箱/流式/S3/Neo4j

silver-sentinel serve                   # 控制台 http://127.0.0.1:8000
```

零配置即可运行：不配任何 key 时，系统只用本地规则引擎 + 内置图引擎，LLM 与沙箱环节自动弃权，并在运维页明示——不会假装可用。

### 长期监控怎么起

```bash
# 一个进程全包：发现引擎 + 周期调度 + 副本 + 控制台
SILVER_AUTOSTART=1 silver-sentinel serve --host 0.0.0.0 --port 8000

# 或者分开跑，各自独立重启
silver-sentinel discover run          # 发现常驻
silver-sentinel serve                 # 控制台
```

`SILVER_AUTOSTART_MONITOR=1` 是旧写法，两种都认。

### Docker

```bash
cp .env.example .env
docker compose up -d --build                    # 最小可用
docker compose --profile graph up -d            # + Neo4j
docker compose --profile replica up -d          # + MinIO（异地副本）
docker compose --profile sandbox up -d          # + MobSF（APK 动态分析）
```

默认只绑 `127.0.0.1:8000`。对外暴露请在前置反代上加鉴权，别裸奔。

---

## 命令行

```bash
# 研判单条线索（现场排查）
silver-sentinel scan url "http://kuaishou-yinfa.top/reg?invite=888" \
  --text "免费领鸡蛋，应用商店搜不到，请点击继续安装"
silver-sentinel apk ./samples/guohui.apk

# 发现层
silver-sentinel discover words                    # 看词库覆盖（363 词根 / 6 簇）
silver-sentinel discover inject guohui-vip.top    # 人工导入线索清单
silver-sentinel discover inject --file seeds.txt  # 批量导入
silver-sentinel discover search 国惠 中科 民族资产 # 翻 crt.sh 历史补漏
silver-sentinel discover status                   # 吞吐、游标、DNS 池健康

# 流水线
silver-sentinel cycle                             # 研判→富化→建图→团伙→衰减
silver-sentinel enrich 42 --probe                 # 单个目标富化并实测网页
silver-sentinel graph rebuild                     # 重建图谱并重新归并团伙

# 证据可靠性
silver-sentinel log verify                        # 逐条重算哈希链
silver-sentinel log tail -n 30                    # 看最近发生了什么
silver-sentinel replica sync --with-db            # 推一次异地副本
silver-sentinel replica restore                   # 从副本拉回事件日志

# 运营
silver-sentinel ops                               # 能力降级 + 积压 + 完整性一屏
silver-sentinel list --verdict high_risk
silver-sentinel report 3 --channel 12321 --out 举报材料.md
```

---

## 发现层：宁可错杀一万

发现的难点不是「找不到坏域名」，而是**在几十亿条证书里既不漏、又不把自己跑死**。

### 三路冗余

| 通路 | 做什么 | 断了会怎样 |
| --- | --- | --- |
| **CT 日志直连**（主路） | 按 RFC 6962 轮询 `get-sth` / `get-entries`，解析 DER 取 CN 与 SAN；游标落盘，重启续跑 | 换下一个日志。内置日志集按国内可达性排序 |
| **certstream**（补强） | 订阅聚合 WebSocket，延迟更低 | 自动重连退避；公共实例常断流，所以只作补强 |
| **DNS 排列探测** | 从词库派生 139+ 词根，单词 + `机构词×主题词` 组合，批量解析 | 独立线程，令牌桶限速，与 CT 互不影响 |

CT 条目解析踩过的坑写在代码注释里：`x509_entry`(type=0) 的证书长度在 leaf_input 第 12–15 字节，`precert_entry` 得从 `extra_data` 的证书链里按第 3–6 字节取长度——两处读错就会静默丢证书。

### 词库：六个语义簇，363 词根

| 簇 | 例子 | 作用 |
| --- | --- | --- |
| `authority` | 国科、中科、社科院、发改委、民政部、卫健委、乡村振兴局、老龄委 | 冒充主体，最硬的信号之一 |
| `policy_theme` | 养老、康养、银发、社保、医保、低保、高龄补贴、共同富裕 | 政策热点，骗子蹭得最勤 |
| `scam_signature` | 民族资产解冻、云数贸、1040工程、资金盘、解冻费、报单、对碰奖 | 老骗局的黑话，命中即高危 |
| `inducement` | 免费领、领鸡蛋、米面油、到场即送、签到领、现金红包 | 引流入口 |
| `carrier` | APP、平台、公众号、工作站、服务中心、专员、主任 | 载体与身份包装 |
| `brand` | kuaishou、douyin、unionpay、icbc、psbc、chinamobile | 仿冒品牌 |

中文词用 `pypinyin` 自动派生拼音变体（`国惠 → guohui`），预编译成一条 alternation 正则一次扫完，**5 万域名/秒**。

### 防噪音的三道闸

发现层故意放得很宽，噪音靠后面几层拦：

1. **白名单极窄**：只放行政府与主流平台的确切域名/后缀，且「伪造的 gov.cn」不放行（`gov.cn.evil.top` 会被判出来），有测试守着。
2. **语义簇降权**：`scam_signature`/`authority`/`brand` 是强簇；`policy_theme`/`carrier`/`inducement` 在没有强簇支撑时权重打到 0.30–0.55。「免费测血压」这种正常宣传不会单独构成可疑。
3. **ICP 备案节奏**：只对 `candidate` 及以上分级查备案，令牌桶 10 次/分钟，30 天缓存；查询失败记 `unknown` 而不是 `unregistered`——**没查到 ≠ 未备案**，这个区分决定了会不会冤枉正规站。

不无差别扫端口、不主动爬全网。低效，而且会被运营商盯上。

---

## 分级：先记录，后判断

「宁可错杀」如果只体现在阈值上，结果就是名单爆炸、没人看得完。所以分级和评分是两件事：

| 档位 | 含义 | 怎么进 | 怎么出 |
| --- | --- | --- | --- |
| `candidate` | 有嫌疑，证据不够 | 词库命中 / 分数 ≥12 / 发现层直投 | 升级、转 `cold`、或人工 `dismissed` |
| `watch` | 值得持续盯 | 分数 ≥50，或 ≥32 且有紧迫性（域名 ≤30 天、强制下载、非商店分发、情报源命中） | 升级或衰减 |
| `confirmed` | 已确认 | 人工复核或命中官方清单（`SILVER_CONFIRM_REQUIRES_OFFICIAL`） | 不回退 |
| `cold` | 冷存 | 分数低于 0.30 且无强证据 | 保留 180 天，新证据可复活 |
| `dismissed` | 已排除 | 人工，必须填理由 | 不回退 |

首次分级可以自由落档，**之后只允许升级**（已确认的不降级）。衰减按「多久没新证据」逐级下移，避免名单只涨不落。

---

## 归因：把工具追到人

举报一个 APK 没用——换个包名重签一次就复活。要追的是**背后那套基础设施**：同一张签名证书、同一个收款钱包、同一个备案主体、同一套页面模板。

图谱里 20 类节点、17 种关系，边权按「伪造难度」定：

| 关系 | 权重 | 理由 |
| --- | --- | --- |
| `SHARES_CERT` 共用签名证书 | 0.90 | 换证书要重新签名，成本最高 |
| `USES_WALLET` 共用收款地址 | 0.85 | 资金链换不掉 |
| `ICP_ENTITY` 同一备案主体 | 0.70 | 实名信息，但可买壳 |
| `SAME_TEMPLATE` 同页面模板 | 0.65 | 换个皮就变，但批量作业常用同一套 |
| `RESOLVES_TO` 解析到同一 IP | 0.35 | 共用 CDN 会把半个互联网连成一团，只做弱边且限定 `url/domain → domain` 方向 |

社区发现用 Louvain；节点少于 50 时直接取连通分量，避免把一个小簇切碎。**单点不成团**：一个社区里可疑资产不足 2 个、又没有已确认资产时，不建团伙——名单虚胖比漏报更难用。

成团时写清楚「凭什么」：

```
guohui-minsheng | assets 3 | 含 9 个关联节点（apk 2、url 1）；
2 处互相内嵌，2 处同页面模板，2 处同一证书签名；其中 2 项高度可疑
```

---

## 证据不会丢

服务器被攻破、磁盘坏掉、误删库——这三种情况都得能说清「当时到底看到了什么」。

```
evidence/           内容寻址：sha256 命名，落盘即校验
events.jsonl        只追加 + 哈希链：seq | ts | kind | payload | prev_hash | hash
  ├─ group commit：1 秒或 256 条 fsync 一次，跨进程 flock 保护
  ├─ 写前重读尾部校准 seq，防多进程链分叉
  └─ verify --deep：seq 连续 + prev_hash 衔接 + 内容哈希 三段校验
replica/            增量分片：part-00000001.jsonl …，写完回读比对大小
  ├─ dir / s3(minio) / webdav
  └─ 数据库用 sqlite3.backup 拿一致性快照
```

`replica restore` 能把副本拉回本地重建事件日志；`log verify` 会指出断在第几行、为什么断（序号断裂 / 前序哈希不符 / 内容被改写）。

外网可达的服务建议把 `SILVER_REPLICA_BACKEND` 指到另一台机器或对象存储——同机备份不叫备份。

---

## 沙箱边界

会真跑可疑页面和 APK，但边界写死在代码里：

- **内网地址一律阻断**：解析目标域名，命中私有网段直接拒（防 SSRF）。`SILVER_SANDBOX_ALLOW_PRIVATE` 只给本地调试用。
- **只发 GET/HEAD**：任何 POST/PUT/DELETE 在路由层 abort。我们是观察者，不替对方提交表单、不触发它的业务写操作。
- **每次新建上下文**，`accept_downloads=False`，不主动下载 APK。
- **APK 三级降级**：MobSF REST → adb/emulator → 静态行为推演。降级时结果里明确标 `static-inference`，**绝不冒充动态结果**。
- 抓到的表单动作、跳转链、页面正文都进证据链，而不是只留一句「页面可疑」。

---

## 判定模型

三个刻意的设计决定，决定了这个工具能不能被信任：

**1. 用 noisy-OR 聚合，不用加权求和。**
求和会让「十条弱特征」轻易超过「一条铁证」。noisy-OR 下每条信号的边际贡献递减，符合证据的实际证明力：

```
risk = 1 − Π(1 − weightᵢ/100 × confidenceᵢ)
```

**2. 风险分与置信度分离。**
分数回答「有多像」，置信度回答「证据够不够、来自几个独立维度」。只命中一条信号时，即使权重很高也判「证据不足」——系统允许弃权。

**3. 「确认涉诈」不由分数授予。**
机器最高只判到「高度可疑」。`confirmed` 只来自人工复核或命中官方通报清单。误伤一个正常应用的代价，远高于漏报一次。

每条信号都会回填它实际读到的原文，所以用户看到的不是「系统认为可疑」，而是：

> 命中「忽略风险、继续安装」。主动教用户绕过系统安装防护，正规应用不会提出此类要求。

规则库是声明式 YAML，加规则不用改代码：

```yaml
- id: PER-001
  category: persuasion
  title: 免费领鸡蛋/米面油引流
  weight: 18
  confidence: 0.85
  when:
    text_any: [免费领鸡蛋, 领鸡蛋, 送鸡蛋, 听课领礼品, 答谢会]
  detail: 以极低成本的实物礼品换取到场与信任，是涉老骗局的入口。
```

外挂覆盖自己的规则：`SILVER_RULES_PATH=./my_rules.yaml`。

---

## 架构

```
                    ┌──────────── 发现层（三路冗余） ────────────┐
CT 日志 ─┐           │ CTLogFollower(RFC6962)                    │
certstream ─┼──▶ 白名单 → 词库(363 词/6 簇/拼音) → 去重 → 队列 ──▶ 批量落库
DNS 排列 ─┘           │ 命中即入库 tier=candidate + 发现流水       │
                    └───────────────────┬───────────────────────┘
                                        ▼
       研判(44 规则 + noisy-OR) → 分级(triage) → 富化(RDAP/ICP/页面实测)
                                        ▼
                        图构建(20 节点/17 关系) → 社区发现 → 团伙
                                        ▼
                        证据(sha256) + 事件日志(哈希链) + 异地副本
                                        ▼
                        FastAPI 控制台 / SSE / Prometheus / CLI
```

```
src/silver_sentinel/
├── discover/       keywords 词库 · ct 日志跟随 · dnsprobe 排列探测 · engine 编排
├── enrich/         registry RDAP · icp 备案判定
├── graph/          schema 节点关系 · store 内置/Neo4j · build 装配 · community 社区发现
├── sandbox/        web 页面执行 · apk 权限行为推演
├── core/           eventlog 哈希链 · replica 副本 · bus 内存事件总线
├── triage.py       分级与衰减
├── pipeline.py     周期编排 + 调度器
├── api_extra.py    发现/图/运维/指标/SSE 接口
├── scoring/        声明式规则求值 + noisy-OR 聚合 + 弃权
├── rules/          44 条判定规则
├── collectors/     被动情报采集 · 自实现 AXML 解析
└── web/            FastAPI + 原生前端（无构建步骤）
```

存储默认单文件 SQLite（WAL）；`SILVER_DB_URL` 可切 Postgres。图可切 Neo4j，缺驱动自动回落内置引擎。

---

## 运维

```bash
silver-sentinel ops            # 能力降级、积压、事件日志完整性
curl :8000/api/metrics         # Prometheus 文本格式
curl -N :8000/api/stream       # SSE：发现流 / 周期事件
```

建议盯的四个指标：

| 指标 | 健康值 | 异常含义 |
| --- | --- | --- |
| `sentinel_discover_certs_total` 增速 | 持续增长 | 长时间不涨 = CT 通路断了 |
| `sentinel_discover_queue` | < 容量 30% | 持续满 = 研判跟不上发现 |
| `sentinel_eventlog_ok` | 1 | 0 = 证据链断了，立刻查 `log verify` |
| `sentinel_cycle_errors_total` | 不增长 | 增长 = 富化/建图在报错 |

---

## 数据来源与合规边界

**只读第三方情报为主，动态取证受控。** crt.sh、CT 日志、RDAP、URLhaus、OpenPhish 都是公开被动数据源。沙箱执行只在需要时对具体目标做，且阻断内网、只发 GET——我们观察它给普通访问者看什么，不替它产生业务动作。

**不提供可直接点击的诈骗网址清单。** 那种清单既会过期，也会被二次传播利用。系统提供的是判定方法、可核查的证据结构和举报通路。

**证据链可自证。** 每条事件带 `prev_hash`，删改一条即断链，适合作为向监管提交材料时的完整性证明。

**举报对象是主体不是工具。** 输出聚焦域名、证书、收款地址、备案主体、包名的关联关系，便于向 12321 / 12377 / 公安网安提交「一套基础设施」而非「一个安装包」。

---

## 已知局限

- **ICP 备案**依赖自建服务（`icpquery-mcp` / `ICP_Query_lite` / WebScan 任一）。未配置时按「未知」处理，不参与加分——宁可少判，不可错判。且 `beian.miit.gov.cn` 在部分机房不可达，需要前置代理。
- **微信生态**（小程序、公众号、群聊）无法自动化采集，只能录入名称后做文本与名单匹配，这部分需要人工配合截图。
- **CT 日志可达性因地区而异**：`nessie/yeti.ct.digicert.com` 在部分环境解析失败，程序会自动换下一个并记日志，不会卡死在某一个上。
- **沙箱不等于真实设备**：Playwright 跑的是桌面 Chromium，移动端 UA 与 WebView 行为有差异；APK 动态分析需要 MobSF 或真机，否则只有静态推演。
- **LLM 不是必需项**。没有 key 时系统照常工作，只是少了「把信号串成剧本」那层叙事。
- **不替代执法**。系统输出是线索，不是定性结论；同名不同主体真实存在，命中通报后必须人工核对包名、域名与收款方。

---

## 文档

- [威胁画像：领鸡蛋骗局如何线上化](docs/01-威胁画像.md)
- [判定规则与评分模型](docs/02-识别规则.md)
- [处置手册：举报渠道、材料模板与家属话术](docs/03-处置与举报.md)
- [架构、部署与长期运维](docs/04-架构与运维.md)
- [调研来源](docs/05-调研来源.md)
- [v1.0 升级说明](docs/06-v1.0-升级说明.md)
- [30 分钟试运行验收报告](docs/07-试运行报告.md)

---

## 免责声明

本项目用于反诈研究、预警与举报辅助，不构成法律意见。所有判定均为基于公开特征的技术推断，最终认定以有权机关调查结果为准。使用者应遵守《个人信息保护法》《网络安全法》等法律法规，不得将本工具用于侵犯他人合法权益的用途。

MIT License.
