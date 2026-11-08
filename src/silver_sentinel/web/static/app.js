/* 银发哨兵 · 控制台前端
   无构建步骤、无框架。所有渲染走 escapeHtml，避免把线索内容当 HTML 执行。 */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  view: "overview",
  scanKind: "url",
  verdict: "",
  query: "",
  currentAsset: null,
  // 线索库的浏览状态：分页与排序都交给服务端，前端不做全量拉取
  assetTier: "active",
  assetSort: "score",
  assetOrder: "desc",
  assetOffset: 0,
  assetLimit: 50,
  // 同源折叠：同证书/同收单/同模板折成一行。默认开——
  // 一张证书 91 个域名平铺出来，人工审阅看到的是九十次重复劳动。
  assetCollapse: true,
  expandedGroups: new Set(),
};

const VIEW_TITLES = {
  overview: "概览",
  discover: "发现流",
  scan: "研判台",
  assets: "线索库",
  graph: "关系图谱",
  campaigns: "团伙",
  watch: "监控",
  ops: "运维",
  rules: "规则库",
  settings: "设置",
};

/* 每页一句话说明 + 展开后的操作指引。
   之前十个页面长得一样，新人进来不知道从哪儿下手，也不知道这页到底该看什么。 */
const VIEW_DESC = {
  overview: "今天要不要多看两眼：风险指数、待处置量、取证与监控覆盖。",
  discover: "系统正在看什么：发现漏斗卡在哪一步、实时命中的域名、词库命中排行。",
  scan: "手工查单条：链接、域名、安装包、话术、小程序，结论带证据出处。",
  assets: "所有线索的台账：按分级筛选、排序、翻页，点开看证据矩阵。",
  graph: "基础设施关系图：共享证书、模板、收款地址的资产会连在一起。",
  campaigns: "被归并成团伙的一组资产，以及还不能确认、但共享基础设施的簇。",
  watch: "在盯谁：自动纳管与人工目标、上次巡检、变更次数与下次时间。",
  ops: "机器自身状态：能力矩阵、取证队列、任务台账、事件日志与证据链校验。",
  rules: "判定依据：规则清单、权重，以及词库规模与长期误报词的搁置情况。",
  settings: "在界面里配 AI 与取证出口，保存即时生效，不用改环境变量重启。",
};

const VIEW_HELP = {
  overview: [
    "风险指数是四项加权：高危占比 40%、近 24 小时高危新增 30%、证据完备率 20%、监控覆盖率 10%。每一项都能看原始计数，不给你一个说不清来历的数字。",
    "「有效线索」不含已排除的误报；两者分母不同，别拿总数当工作量。",
    "点击「风险最高线索」任意一行，抽屉里有完整证据与一键举报材料。",
  ],
  discover: [
    "漏斗五段：已解析证书 → 命中词根 → 去重后 → 通过快筛 → 实际入池。哪一段掉得最狠，问题就在哪。",
    "命中很多但入池很少，通常是快筛阈值太高或词太泛；命中本身就少，是词库还不够或情报源没连上。",
    "「词库命中排行」里长期命中高、确认率低的词会被自动搁置，不再占用探测配额。",
  ],
  scan: [
    "五种输入：链接、域名、安装包、话术、小程序名称。研判结果会显示每条规则命中的依据，不命中也会明说「证据不足」而不是「安全」。",
    "勾选「调用 LLM」只在灰度区间内且证据齐全时才会真正请求，避免为几十条低价值样本付钱。",
    "研判完可以直接点「查看完整证据」进抽屉，那里有取证与举报入口。",
  ],
  assets: [
    "默认只看有效线索（已确认 / 观察中 / 候选）。要看误报或历史记录，把筛选切到「全部」或「已排除」。",
    "表头可点击排序，排序与翻页都在服务端完成，几万条也不会卡。",
    "「取证」一列显示页面证据状态：已取证带条数、待取证、失败（把鼠标放上去能看到原因）。",
  ],
  graph: [
    "节点是资产与基础设施元素，边是共享关系。点域名/安装包节点可直接打开线索详情。",
    "图太大时只给连接最多的节点标名，避免糊成一片；滚轮缩放、拖拽平移。",
    "「重建图」会按当前线索库重算边与团伙，耗时与线索量成正比。",
  ],
  campaigns: [
    "团伙是共享证书、模板指纹、收款地址或包名前缀的一组资产，归并靠证据而不是猜测。",
    "「关联簇」是强度还不足以判定为团伙、但明显共享基础设施的一组，通常是最值得先看的新线索。",
  ],
  watch: [
    "asset 类型的目标是自动纳管的：分级为「已确认 / 观察中」时会自动进来，不用手动加。",
    "每次巡检都会重新取证并比对指纹（正文相似度、截图、证书、解析 IP、安装包哈希），有变化才算一次变更。",
    "连续失败的目标会按 30 分钟起步指数退避，最长一天一次，不会一直空转。",
  ],
  ops: [
    "能力矩阵是诚实的：没配代理、没装浏览器、没连 LLM 都会如实写「未启用」，不会假装在跑。",
    "取证队列卡住时先看「最近失败」的原因，多数是出口被墙、DNS 不解析或目标已下线。",
    "「校验证据链」会重算事件日志与证据的哈希链，任何一条被改动都会被抓出来。",
  ],
  rules: [
    "规则分两类：基础设施规则（域名、证书、权限）与内容规则（页面正文、话术文本）。",
    "权重 × 置信度决定它对分数的贡献；同一维度多命中会被压制，避免一个特征刷满分数。",
    "规则是声明式 YAML，改完重启即生效，不需要改代码。",
  ],
  settings: [
    "密钥保存在本地数据库，界面只回显掩码；留空表示「不修改」，不会把掩码当新密钥写回去。",
    "出口模式四态：自动（有代理走代理）、仅代理（没有代理就拒绝取证）、强制直连、关闭取证。保存后下一次出站即生效，不用重启。",
    "取证涉及访问可疑站点，建议走境外代理；直连只用于临时验证，服务器 IP 会暴露在对方日志里。",
  ],
};


const VERDICT_LABEL = {
  confirmed: "确认涉诈",
  high_risk: "高度可疑",
  suspicious: "可疑",
  low: "低风险",
  insufficient: "证据不足",
  benign: "已排除",
};

const KIND_LABEL = {
  domain: "域名",
  url: "网址",
  apk: "安卓安装包",
  text: "话术样本",
  miniapp: "小程序 / 公众号",
  account: "网络账号",
  wechat: "微信",
  qq: "QQ",
  phone: "电话号码",
  wallet: "收款地址",
  sample: "样本",
};

const CATEGORY_LABEL = {
  distribution: "分发渠道",
  impersonation: "身份冒充",
  financial: "资金模式",
  persuasion: "诱导话术",
  technical: "技术特征",
  reputation: "外部信誉",
};

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtTime(iso) {
  if (!iso) return "—";
  try {
    // 后端统一输出无时区的 UTC，补 Z 让浏览器按本地时区渲染
    const normalized = /[Zz]|[+-]\d{2}:?\d{2}$/.test(iso) ? iso : `${iso}Z`;
    const d = new Date(normalized);
    if (Number.isNaN(d.getTime())) return iso.slice(0, 16).replace("T", " ");
    return d.toLocaleString("zh-CN", { hour12: false, month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
  } catch { return iso; }
}

function toast(msg) {
  let node = $(".toast");
  if (!node) {
    node = document.createElement("div");
    node.className = "toast";
    document.body.appendChild(node);
  }
  node.textContent = msg;
  node.classList.add("show");
  clearTimeout(node._timer);
  node._timer = setTimeout(() => node.classList.remove("show"), 2600);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: options.body instanceof FormData ? {} : { "Content-Type": "application/json" },
    ...options,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { detail: text }; }
  if (!res.ok) throw new Error((data && data.detail) || `请求失败 ${res.status}`);
  return data;
}

function badge(verdict) {
  return `<span class="badge ${escapeHtml(verdict)}">${escapeHtml(VERDICT_LABEL[verdict] || verdict)}</span>`;
}

function scoreColor(score) {
  if (score >= 70) return "var(--c-confirmed)";
  if (score >= 40) return "var(--c-high)";
  if (score >= 15) return "var(--c-suspicious)";
  return "var(--c-low)";
}

// 后端存的是 pending / captured / failed / dead 四态，界面用词要跟它对齐
const CAPTURE_LABEL = {
  pending: "待取证",
  captured: "已取证",
  failed: "失败",
  dead: "站点失联",
  skipped: "跳过",
};

// 列表里只放短标签；失败原因留给 title，避免把一列撑成三行
function captureShort(a) {
  const st = (a && a.capture_state) || "pending";
  if (st === "captured") return `${a.evidence_count || 0} 件`;
  return CAPTURE_LABEL[st] || st;
}

function captureTitle(a) {
  const st = (a && a.capture_state) || "pending";
  if (a && a.capture_error) return `${CAPTURE_LABEL[st] || st}：${a.capture_error}`;
  if (a && a.last_capture_at) return `${CAPTURE_LABEL[st] || st} · ${fmtTime(a.last_capture_at)}`;
  return CAPTURE_LABEL[st] || st;
}

function fmtBytes(n) {
  const v = Number(n || 0);
  if (v >= 1 << 20) return (v / (1 << 20)).toFixed(1) + " MB";
  if (v >= 1 << 10) return (v / (1 << 10)).toFixed(1) + " KB";
  return v + " B";
}

/* ---------------- 路由 ---------------- */

function switchView(view, { syncHash = true } = {}) {
  state.view = view;
  // 地址栏跟着走：刷新后停在当前页，分享链接也能直接打开对应视图
  if (syncHash && location.hash.slice(1) !== view) {
    history.replaceState(null, "", view === "overview" ? location.pathname : `#${view}`);
  }
  $$(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === view));
  $$(".view").forEach(v => v.classList.toggle("active", v.id === `view-${view}`));
  $("#page-title").textContent = VIEW_TITLES[view] || view;
  renderPageMeta(view);
  const loaders = {
    overview: loadOverview,
    discover: loadDiscover,
    assets: loadAssets,
    scan: loadScanRecent,
    graph: loadGraphView,
    campaigns: loadCampaigns,
    watch: loadWatch,
    ops: loadOps,
    rules: loadRules,
    settings: loadSettings,
  };
  if (loaders[view]) loaders[view]();
}

/* ---------------- 页面说明 ---------------- */

function renderPageMeta(view) {
  const desc = $("#page-desc");
  if (desc) desc.textContent = VIEW_DESC[view] || "";
  renderHelp(view);
}

function helpOpen() {
  try { return localStorage.getItem("ss-help") === "1"; } catch { return false; }
}

function renderHelp(view) {
  const box = $("#page-help");
  const btn = $("#btn-help");
  if (!box || !btn) return;
  const lines = VIEW_HELP[view] || [];
  box.innerHTML = lines.length
    ? `<ul>${lines.map(l => `<li>${escapeHtml(l)}</li>`).join("")}</ul>`
    : "";
  const open = helpOpen() && lines.length > 0;
  box.hidden = !open;
  btn.classList.toggle("on", open);
  btn.title = open ? "收起本页说明" : "展开本页说明";
}

function toggleHelp() {
  const next = helpOpen() ? "0" : "1";
  try { localStorage.setItem("ss-help", next); } catch { /* 无痕模式下写不进去，不影响功能 */ }
  renderHelp(state.view);
}

/* ---------------- 数据变更公告 ---------------- */

function renderNotices(items) {
  const box = $("#notices");
  if (!box) return;
  if (!items || !items.length) { box.innerHTML = ""; return; }
  box.innerHTML = items.map(n => `
    <div class="notice ${escapeHtml(n.level || "info")}">
      <span class="notice-dot"></span>
      <span>${escapeHtml(n.text || "")}</span>
    </div>`).join("");
}

/* ---------------- 健康与概览 ---------------- */

async function loadHealth() {
  // 每个状态位单独设值：某个元素在改版中被移除时不该让整块状态失效
  const setStatus = (sel, text, cls) => {
    const el = $(sel);
    if (!el) return;
    el.textContent = text;
    el.className = cls;
  };

  try {
    const h = await api("/api/health");

    setStatus("#st-net", h.network ? "在线" : "离线", h.network ? "ok" : "off");

    // 发现引擎：真的在跑才算「采集中」，否则如实写「未启动」
    setStatus(
      "#st-discover",
      h.discover_running ? "采集中" : "未启动",
      h.discover_running ? "ok" : "off"
    );
    setStatus(
      "#st-llm",
      h.llm && h.llm.configured ? h.llm.model : "未配置",
      h.llm && h.llm.configured ? "ok" : "warn"
    );

    const chain = h.evidence_chain || {};
    if (chain.ok === null || chain.ok === undefined || !chain.checked) {
      setStatus("#st-chain", "空", "off");
    } else if (chain.ok) {
      setStatus("#st-chain", `完好 ${chain.checked}`, "ok");
    } else {
      setStatus("#st-chain", "异常", "bad");
    }

    const hint = $("#top-hint");
    if (hint) hint.textContent = `规则 ${h.rules.count} 条 · 引擎 v${h.rules.version}`;
  } catch (e) {
    setStatus("#st-net", "不可达", "bad");
    toast(`状态检查失败：${e.message}`);
  }
}

async function loadOverview() {
  const [s, risk] = await Promise.all([
    api("/api/stats"),
    api("/api/risk").catch(() => null),
  ]);

  const cov = s.evidence_coverage || {};
  const kpis = [
    { num: s.active_assets, lab: "有效线索", hint: s.dismissed_assets ? `另有 ${s.dismissed_assets} 条已排除` : "不含已排除", cls: "" },
    { num: s.pending_action, lab: "高危待处置", hint: "高度可疑 + 已确认", cls: "danger" },
    { num: s.new_24h, lab: "近 24 小时新增", hint: `近 7 天 ${s.new_7d} 条`, cls: "warn" },
    { num: s.pending_capture, lab: "待取证", hint: "还没打开过页面", cls: "" },
    { num: s.watch_count, lab: "已纳入监控", hint: "周期复访中", cls: "good" },
    { num: s.campaigns, lab: "归并团伙", hint: `${s.reports || 0} 份举报材料`, cls: "" },
  ];
  $("#kpis").innerHTML = kpis.map(k => `
    <div class="kpi ${k.cls}">
      <div class="num">${k.num}</div>
      <div class="lab">${k.lab}</div>
      <div class="kpi-hint">${escapeHtml(k.hint)}</div>
    </div>`).join("");

  renderRiskStrip(risk);
  renderNotices(s.notices);

  renderBars($("#verdict-chart"), s.by_verdict, v => VERDICT_LABEL[v] || v);
  renderBars($("#category-chart"), s.by_category, x => x, "category");

  const top = s.top_assets || [];
  $("#top-assets").innerHTML = top.length ? top.map(a => `
    <div class="row-item" data-asset="${a.id}">
      <div class="row-main">
        <strong>${escapeHtml(a.value)}</strong>
        <span>${escapeHtml(a.tier_label || a.tier)} · ${escapeHtml(KIND_LABEL[a.kind] || a.kind)} · ${fmtTime(a.last_seen)} · 取证 ${captureShort(a)}</span>
        ${a.purpose ? `<span class="tag" title="${escapeHtml(a.purpose.reason || "")}">${escapeHtml(a.purpose.label)}${a.purpose.suppressed ? " · 不占队列" : ""}</span>` : ""}
      </div>
      <div class="row-meta">${badge(a.verdict)}</div>
      <div class="score-chip"><b>${a.score}</b></div>
    </div>`).join("") : `<div class="empty">还没有线索。去「研判台」输入第一条可疑链接或安装包。</div>`;

  $$("#top-assets .row-item").forEach(el => el.addEventListener("click", () => openAsset(el.dataset.asset)));
}

/* 风险指数条：一个总分 + 四项可解释构成 + 七日趋势 */
function renderRiskStrip(risk) {
  const box = $("#risk-strip");
  if (!box) return;
  if (!risk) { box.innerHTML = ""; return; }

  const levelLabel = RISK_LEVEL[risk.level] || risk.level;
  const parts = (risk.parts || []).map(p => `
    <div class="risk-part" title="${escapeHtml(p.hint || "")}">
      <div class="rp-top">
        <span>${escapeHtml(p.label)}</span>
        <b>${p.score.toFixed(0)}</b>
      </div>
      <div class="rp-track"><i style="width:${Math.max(0, Math.min(100, p.score))}%"></i></div>
      <div class="rp-raw"><span>${escapeHtml(p.raw)}</span><span>权重 ${Math.round(p.weight * 100)}%</span></div>
    </div>`).join("");

  box.innerHTML = `
    <div class="risk-main">
      <div class="risk-score">
        <span class="risk-num">${risk.index.toFixed(1)}</span>
        <span class="risk-level ${escapeHtml(risk.level)}">${escapeHtml(levelLabel)}</span>
      </div>
      <div class="risk-caption">风险指数 · 四项加权</div>
      <div class="risk-counts">${riskCounts(risk.counts)}</div>
      ${(risk.counts && risk.counts.active || 0) < 5
        ? `<div class="risk-caveat">样本不足 5 条，指数仅供参考</div>`
        : ""}
    </div>
    <div class="risk-parts">${parts}</div>
    <div class="risk-trend">${renderTrend(risk.trend)}</div>`;
}

const RISK_LEVEL = { high: "高", elevated: "偏高", moderate: "中等", low: "低" };

// 拆成独立小块：整串比会把「·」丢在行尾，看起来像断句
function riskCounts(c = {}) {
  const bits = [
    `有效 ${c.active || 0}`,
    `高危 ${c.high || 0}`,
    `24h 新增 ${c.new_high_24h || 0}`,
    `有证据 ${c.with_evidence || 0}`,
    `监控 ${c.watch_covered || 0}/${c.watch_total || 0}`,
  ];
  return bits.map(t => `<span>${escapeHtml(t)}</span>`).join("");
}

function renderTrend(points) {
  const list = (points || []).filter(p => typeof p.index === "number");
  if (list.length < 2) {
    return `<div class="trend-empty">暂无历史：每日副本快照生成后会出现趋势</div>`;
  }
  const w = 108;
  const h = 26;
  const max = Math.max(...list.map(p => p.index), 1);
  const min = Math.min(...list.map(p => p.index), 0);
  const span = Math.max(1, max - min);
  const pts = list.map((p, i) => {
    const x = (i / (list.length - 1)) * (w - 2) + 1;
    const y = h - 2 - ((p.index - min) / span) * (h - 6);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  const last = list[list.length - 1];
  const first = list[0];
  const delta = last.index - first.index;
  const arrow = delta > 0.5 ? "↑" : delta < -0.5 ? "↓" : "→";
  return `
    <svg class="trend-svg" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
      <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="1.2" />
    </svg>
    <div class="trend-meta">七日 ${arrow} ${Math.abs(delta).toFixed(1)} · 最新 ${last.index.toFixed(1)}（${escapeHtml(last.date)}）</div>`;
}

const VERDICT_COLOR = {
  confirmed: "var(--c-confirmed)",
  high_risk: "var(--c-high)",
  suspicious: "var(--c-suspicious)",
  insufficient: "var(--c-insufficient)",
  low: "var(--c-low)",
  benign: "var(--c-benign)",
};

// 维度分布不配色相：同一把墨色，只让最高的那条用朱红，避免六色打架
const CATEGORY_PALETTE = Array(6).fill("var(--ink-2)");

function renderBars(container, data, labelFn = x => x, mode = "verdict") {
  const entries = Object.entries(data || {}).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { container.innerHTML = `<div class="empty">暂无数据</div>`; return; }
  const max = Math.max(...entries.map(([, v]) => v));

  container.innerHTML = entries.map(([k, v], i) => {
    const color = mode === "verdict"
      ? (VERDICT_COLOR[k] || "var(--ink-2)")
      : (i === 0 ? "var(--accent)" : CATEGORY_PALETTE[i % CATEGORY_PALETTE.length]);
    return `
      <div class="bar-row">
        <div class="bar-label">${escapeHtml(labelFn(k))}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:0;background:${color}" data-w="${Math.round((v / max) * 100)}"></div>
        </div>
        <div class="bar-val">${v}</div>
      </div>`;
  }).join("");

  requestAnimationFrame(() => {
    container.querySelectorAll(".bar-fill").forEach((b) => {
      b.style.width = (b.dataset.w || 0) + "%";
    });
  });
}

/* ---------------- 研判 ---------------- */

function bindScan() {
  $$("#scan-tabs .tab").forEach(tab => {
    tab.addEventListener("click", () => {
      state.scanKind = tab.dataset.kind;
      $$("#scan-tabs .tab").forEach(t => t.classList.toggle("active", t === tab));
      $$(".input-pane").forEach(p => p.classList.toggle("active", p.id === `input-${state.scanKind}`));
    });
  });

  const dz = $("#dropzone");
  const fileInput = $("#in-apk");
  dz.addEventListener("click", () => fileInput.click());
  dz.addEventListener("dragover", e => { e.preventDefault(); dz.classList.add("over"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("over"));
  dz.addEventListener("drop", e => {
    e.preventDefault();
    dz.classList.remove("over");
    if (e.dataTransfer.files.length) { fileInput.files = e.dataTransfer.files; fileInput.dispatchEvent(new Event("change")); }
  });
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) {
      $(".dz-inner strong").textContent = fileInput.files[0].name;
      $(".dz-inner span").textContent = `${(fileInput.files[0].size / 1024 / 1024).toFixed(1)} MB · 已就绪`;
    }
  });

  $("#btn-scan").addEventListener("click", runScan);
}

async function runScan() {
  const btn = $("#btn-scan");
  const useLlm = $("#use-llm").checked;
  const kind = state.scanKind;

  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span>研判中`;
  $("#scan-result").innerHTML = "";

  try {
    let data;
    if (kind === "apk") {
      const file = $("#in-apk").files[0];
      if (!file) throw new Error("请先选择 APK 文件");
      const fd = new FormData();
      fd.append("file", file);
      data = await api(`/api/scan/apk?run_llm=${useLlm}`, { method: "POST", body: fd });
    } else {
      const map = { url: "#in-url", domain: "#in-domain", text: "#in-text", miniapp: "#in-miniapp" };
      const value = $(map[kind]).value.trim();
      if (!value) throw new Error("请输入要研判的内容");
      const meta = kind === "miniapp" ? { distribution_channel: $("#in-channel").value } : {};
      data = await api("/api/scan", {
        method: "POST",
        body: JSON.stringify({
          kind: kind === "miniapp" ? "miniapp" : kind,
          value,
          meta,
          run_llm: useLlm,
        }),
      });
    }
    renderScanResult(data);
    loadHealth();
  } catch (e) {
    $("#scan-result").innerHTML = `<div class="panel"><div class="empty">${escapeHtml(e.message)}</div></div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "开始研判";
  }
}

function renderScanResult(data) {
  const a = data.assessment;
  const asset = data.asset;
  const color = scoreColor(a.score);

  const grouped = {};
  (a.signals || []).forEach(s => {
    (grouped[s.category] = grouped[s.category] || []).push(s);
  });

  const signalHtml = Object.entries(grouped).map(([cat, items]) => `
    <div class="signal-group">
      <h3>${escapeHtml(CATEGORY_LABEL[cat] || cat)}</h3>
      ${items.map(s => `
        <div class="signal">
          <div>
            <div class="t">${escapeHtml(s.title)}</div>
            ${s.detail ? `<div class="d">${escapeHtml(s.detail)}</div>` : ""}
          </div>
          <div class="w">${s.weight.toFixed(0)} · ${s.confidence.toFixed(2)}</div>
        </div>`).join("")}
    </div>`).join("");

  const llm = a.llm;
  const llmHtml = llm ? `
    <div class="signal-group">
      <h3>LLM 研判 · ${escapeHtml(llm.model || "")} · 阶段「${escapeHtml(llm.stage || "未知")}」</h3>
      <div class="signal accent">
        <div>
          <div class="t">${escapeHtml(llm.reasoning || "（无推理内容）")}</div>
          <div class="d">手法：${escapeHtml((llm.tactics || []).join("、") || "—")}</div>
          ${(llm.missing_evidence || []).length ? `<div class="d">仍缺：${escapeHtml(llm.missing_evidence.join("；"))}</div>` : ""}
        </div>
        <div class="w">${(llm.confidence ?? 0).toFixed(2)}</div>
      </div>
    </div>` : `<div class="note-line">未启用或未配置 LLM，本次结论仅由规则引擎给出（不臆测、不补全）。</div>`;

  const factsHtml = renderFacts(asset, a);

  $("#scan-result").innerHTML = `
    <div class="panel">
      <div class="result-card">
        <div>
          <div class="gauge" style="background:conic-gradient(${color} ${Math.round(a.score * 3.6)}deg, var(--rule) 0deg)">
            <div class="gauge-inner">
              <div class="gauge-num" style="color:${color}">${a.score.toFixed(0)}</div>
              <div class="gauge-lab">RISK</div>
            </div>
          </div>
        </div>
        <div class="result-head">
          <div>${badge(a.verdict)} <span class="hint">置信度 ${a.confidence.toFixed(2)} · ${a.independent_sources} 个独立来源 · 覆盖 ${Object.keys(a.coverage || {}).length} 个维度</span></div>
          <div class="result-title">${escapeHtml(asset.value)}</div>
          <div class="result-sub">${escapeHtml(asset.kind)} · ${escapeHtml(asset.normalized)}</div>
          <div class="meta-grid">
            <div class="meta-cell"><div class="k">处置优先级</div><div class="v">${escapeHtml(data.priority || "—")}</div></div>
            <div class="meta-cell"><div class="k">命中信号</div><div class="v">${(a.signals || []).length}</div></div>
            <div class="meta-cell"><div class="k">关联团伙</div><div class="v">${asset.campaign_id || "—"}</div></div>
            <div class="meta-cell"><div class="k">扫描次数</div><div class="v">${asset.scan_count}</div></div>
          </div>
          <div class="row">
            <button class="btn sm primary" onclick="openAsset(${asset.id})">查看完整证据与举报材料</button>
          </div>
        </div>
      </div>

      ${(a.notes || []).length ? a.notes.map(n => `<div class="note-line">${escapeHtml(n)}</div>`).join("") : ""}
      ${signalHtml || `<div class="signal-group"><div class="empty">未命中任何规则。这不等于安全，只是现有证据不足以下结论。</div></div>`}
      ${llmHtml}
      ${factsHtml}

      <div class="advice">
        <h3>现在该做什么</h3>
        <ol>${(data.advice || []).map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ol>
      </div>
    </div>`;
}

function renderFacts(asset, a) {
  const facts = a.facts || {};
  const interesting = [
    ["package_name", "包名"],
    ["distribution_channel", "分发方式"],
    ["domain_age_days", "域名年龄(天)"],
    ["brand_lookalike", "仿冒线索"],
    ["icp_registered", "ICP 备案"],
    ["dangerous_permission_count", "高危权限数"],
    ["urlhaus_listed", "URLhaus"],
    ["openphish_listed", "OpenPhish"],
  ].filter(([k]) => {
    const v = facts[k];
    if (v === undefined || v === null || v === "" || v === "unknown") return false;
    return true;
  });

  if (!interesting.length) return "";
  return `
    <div class="signal-group">
      <h3>关键事实</h3>
      <div class="meta-grid">
        ${interesting.map(([k, label]) => `
          <div class="meta-cell">
            <div class="k">${label}</div>
            <div class="v">${escapeHtml(typeof facts[k] === "boolean" ? (facts[k] ? "是" : "否") : facts[k])}</div>
          </div>`).join("")}
      </div>
    </div>`;
}

async function loadScanRecent() {
  const box = $("#scan-recent");
  if (!box) return;
  try {
    const data = await api("/api/assets?limit=8");
    if (!data.items.length) {
      box.innerHTML = `<div class="empty">还没有研判记录。左边输入第一条可疑链接即可。</div>`;
      return;
    }
    box.innerHTML = data.items.map(a => `
      <div class="row-item" data-asset="${a.id}">
        <div class="row-main">
          <strong>${escapeHtml(a.value)}</strong>
          <span>${escapeHtml(KIND_LABEL[a.kind] || a.kind)} · ${fmtTime(a.last_seen)}</span>
        </div>
        <div class="score-chip"><b>${a.score}</b></div>
      </div>`).join("");
    $$("#scan-recent .row-item").forEach(el => el.addEventListener("click", () => openAsset(el.dataset.asset)));
  } catch (e) {
    box.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  }
}

/* ---------------- 线索库 ---------------- */

const ASSET_COLUMNS = [
  { key: "verdict", label: "判定", cls: "col-verdict", sort: "" },
  { key: "value", label: "标识", cls: "", sort: "value" },
  { key: "kind", label: "类型", cls: "col-kind", sort: "" },
  { key: "score", label: "风险分", cls: "col-score", sort: "score" },
  { key: "confidence", label: "置信", cls: "col-conf", sort: "" },
  { key: "capture", label: "取证", cls: "col-capture", sort: "" },
  { key: "last_seen", label: "最近发现", cls: "col-time", sort: "last_seen" },
  { key: "scan_count", label: "次数", cls: "col-count", sort: "scan_count" },
];

async function loadAssets() {
  const params = new URLSearchParams({
    tier: state.assetTier,
    sort: state.assetSort,
    order: state.assetOrder,
    limit: String(state.assetLimit),
    offset: String(state.assetOffset),
    collapse: state.assetCollapse ? "1" : "0",
  });
  if (state.verdict) params.set("verdict", state.verdict);
  if (state.query) params.set("q", state.query);

  const box = $("#asset-table");
  try {
    const data = await api(`/api/assets?${params.toString()}`);

    // 翻页翻过头（比如换了筛选）就退回第一页，别让用户对着空表发愣
    if (!data.items.length && data.total > 0 && state.assetOffset > 0) {
      state.assetOffset = Math.max(0, (Math.ceil(data.total / state.assetLimit) - 1) * state.assetLimit);
      return loadAssets();
    }

    renderAssetMeta(data);
    renderAssetPager(data);

    // 统计行里的「另有 N 条冷存 / 已排除」可以直接点进去，不用猜下拉框
    document.querySelectorAll("[data-tier-jump]").forEach(btn => {
      btn.addEventListener("click", () => {
        state.assetTier = btn.dataset.tierJump;
        state.assetOffset = 0;
        const sel = $("#filter-tier");
        if (sel) sel.value = state.assetTier;
        loadAssets();
      });
    });

    // 折叠开关。关掉之后就是原始逐条列表——排查单个域名时更需要那种视图。
    const ct = document.querySelector("[data-collapse-toggle]");
    if (ct) ct.addEventListener("click", () => {
      state.assetCollapse = !state.assetCollapse;
      state.assetOffset = 0;
      state.expandedGroups.clear();
      loadAssets();
    });

    if (!data.items.length) {
      box.innerHTML = state.query || state.verdict
        ? `<div class="empty">没有匹配的线索。<button class="btn ghost sm" id="btn-clear-filter">清除筛选</button></div>`
        : `<div class="empty">这个分类下还没有线索。<br>去「研判台」手工研判一条，或让发现引擎跑一会儿。</div>`;
      const clear = $("#btn-clear-filter");
      if (clear) clear.addEventListener("click", () => {
        state.query = ""; state.verdict = ""; state.assetOffset = 0;
        $("#filter-q").value = ""; $("#filter-verdict").value = "";
        loadAssets();
      });
      return;
    }

    box.innerHTML = `
      <table class="data">
        <thead><tr>
          ${ASSET_COLUMNS.map(c => `<th class="${c.cls}${c.sort ? " sortable" : ""}${state.assetSort === c.sort ? " sorted" + (state.assetOrder === "desc" ? " desc" : "") : ""}"
            ${c.sort ? `data-sort="${c.sort}"` : ""}>${c.label}</th>`).join("")}
        </tr></thead>
        <tbody>
          ${data.items.map(a => assetRowHtml(a)).join("")}
        </tbody>
      </table>`;

    bindAssetRows();
    $$("#asset-table thead th[data-sort]").forEach(th => th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (state.assetSort === key) {
        state.assetOrder = state.assetOrder === "desc" ? "asc" : "desc";
      } else {
        state.assetSort = key;
        state.assetOrder = key === "value" ? "asc" : "desc";
      }
      state.assetOffset = 0;
      loadAssets();
    }));
  } catch (e) {
    box.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  }
}

/* ---------------- 行渲染：折叠组 / 普通行 ---------------- */

function assetRowHtml(a) {
  const g = a.group;
  if (!g || !g.collapsed) {
    // 2 条及以下的组不折叠，但要把「另有 N 条同源」写出来——
    // 关联信息不该因为不值得折就消失。
    const extra = g && g.size > 1
      ? `<span class="chip" title="${escapeHtml(g.label)}">+${g.size - 1} 同源</span>`
      : "";
    return assetCells(a, extra);
  }
  const open = state.expandedGroups.has(g.key);
  const kindLabel = { campaign: "同团伙", cert: "同证书", backend: "同收单", template: "同模板" }[g.kind] || g.label || "同源";
  return `
    <tr class="group-row${open ? " open" : ""}" data-asset="${a.id}" data-group="${escapeHtml(g.key)}">
      <td>${badge(a.verdict)}</td>
      <td class="clip">
        <div class="cell-line">
          <span class="g-toggle" data-toggle="${escapeHtml(g.key)}" title="${open ? "收起" : "展开"}这一批">${open ? "▾" : "▸"}</span>
          <span class="cell-main">${escapeHtml(a.value)}</span>
        </div>
        <span class="cell-sub">
          <span class="g-badge" title="${escapeHtml(g.label || kindLabel)}">×${g.size} ${escapeHtml(kindLabel)}</span>
          ${g.decoy_count ? `<span class="chip warn" title="组内有 ${g.decoy_count} 条诱饵页，展开可见">含 ${g.decoy_count} 诱饵</span>` : ""}
          ${decoyChip(a)}
          ${a.campaign_name ? `<span class="dim">团伙 ${escapeHtml(a.campaign_name)}</span>` : ""}
        </span>
      </td>
      <td class="mono">${escapeHtml(KIND_LABEL[a.kind] || a.kind)}</td>
      <td class="mono" style="color:${scoreColor(a.score)}">${a.score}</td>
      <td class="mono">${a.confidence.toFixed(2)}</td>
      <td class="mono"><span class="cap-dot ${escapeHtml(a.capture_state || "pending")}" title="${escapeHtml(captureTitle(a))}">${escapeHtml(captureShort(a))}</span></td>
      <td class="mono">${fmtTime(a.last_seen)}</td>
      <td class="mono">${a.scan_count}</td>
    </tr>
    ${open ? g.members.map(m => memberRowHtml(m)).join("") : ""}`;
}

function memberRowHtml(m) {
  const tierTxt = TIER_LABEL[m.tier] || m.tier || "";
  return `
    <tr class="group-member" data-asset="${m.id}">
      <td class="mono dim">${escapeHtml(tierTxt)}</td>
      <td class="clip">
        <div class="cell-line">
          <span class="m-indent">└</span>
          <span class="cell-main mono">${escapeHtml(m.value)}</span>
        </div>
        ${m.decoy_kind ? `<span class="cell-sub"><span class="chip warn">诱饵</span></span>` : ""}
      </td>
      <td class="mono dim">${escapeHtml(KIND_LABEL[m.kind] || m.kind || "")}</td>
      <td class="mono" style="color:${scoreColor(m.score)}">${m.score}</td>
      <td class="mono dim" colspan="4">
        <span class="cap-dot ${escapeHtml(m.capture_state || "pending")}">${escapeHtml(captureShort(m))}</span>
        <span class="dim">${escapeHtml(m.verdict || "")}</span>
      </td>
    </tr>`;
}

function assetCells(a, groupBadge) {
  return `
    <tr data-asset="${a.id}">
      <td>${badge(a.verdict)}</td>
      <td class="clip">
        <span class="cell-main">${escapeHtml(a.value)}</span>
        ${groupBadge ? `<span class="cell-sub">${groupBadge}</span>` : ""}
        <span class="cell-sub">
          ${decoyChip(a)}
          ${a.campaign_name ? `<span class="dim">团伙 ${escapeHtml(a.campaign_name)}</span>` : ""}
        </span>
      </td>
      <td class="mono">${escapeHtml(KIND_LABEL[a.kind] || a.kind)}</td>
      <td class="mono" style="color:${scoreColor(a.score)}">${a.score}</td>
      <td class="mono">${a.confidence.toFixed(2)}</td>
      <td class="mono"><span class="cap-dot ${escapeHtml(a.capture_state || "pending")}" title="${escapeHtml(captureTitle(a))}">${escapeHtml(captureShort(a))}</span></td>
      <td class="mono">${fmtTime(a.last_seen)}</td>
      <td class="mono">${a.scan_count}</td>
    </tr>`;
}

function decoyChip(a) {
  const d = a.decoy;
  if (!d) return "";
  if (d.blocked_by) return `<span class="chip warn" title="${escapeHtml(d.blocked_by)}">WAF 拦截</span>`;
  if (d.honeypot) return `<span class="chip bad" title="${escapeHtml((d.honeypot_reasons || []).join("；"))}">蜜罐</span>`;
  const label = { security_check: "核验诱饵", redirect_shell: "跳转壳", expired: "收尾页", blank_shell: "空壳", download_shell: "下载壳" }[d.kind] || "诱饵";
  return `<span class="chip warn" title="${escapeHtml(d.reason || "")}">${escapeHtml(label)}</span>`;
}

function bindAssetRows() {
  $$("#asset-table tbody tr[data-asset]").forEach(tr =>
    tr.addEventListener("click", () => openAsset(tr.dataset.asset)));

  $$("#asset-table .g-toggle").forEach(el => el.addEventListener("click", (ev) => {
    ev.stopPropagation();
    const key = el.dataset.toggle;
    if (state.expandedGroups.has(key)) state.expandedGroups.delete(key);
    else state.expandedGroups.add(key);
    loadAssets();
  }));
}

function renderAssetMeta(data) {
  const el = $("#asset-meta");
  if (!el) return;
  const from = data.total ? data.offset + 1 : 0;
  const to = Math.min(data.offset + data.items.length, data.total);
  const tierLabel = { active: "有效线索", all: "全部", confirmed: "已确认", watch: "观察中",
    candidate: "候选", cold: "冷存", dismissed: "已排除" }[data.tier] || data.tier;
  // 「有效 0 条」最容易被读成「东西丢了」。把其它档位的数字摆出来，一眼就能解释清楚。
  const c = data.tier_counts || {};
  const other = data.tier === "active"
    ? (c.cold ? `<button class="ev-link" data-tier-jump="cold">另有 ${c.cold} 条冷存（评分不足，先记着）</button>` : "")
      + (c.dismissed ? `<button class="ev-link" data-tier-jump="dismissed">已排除 ${c.dismissed}</button>` : "")
    : "";
  // 折叠后「共 12 项」和「95 条」不是一回事，两个数都得给——
  // 否则用户会以为折叠把线索弄丢了。
  const folded = data.collapsed && data.raw_total > data.total
    ? `<span>${data.raw_total} 条折成 <b>${data.total}</b> 项（${data.group_count || 0} 组同源）</span>`
    : "";
  const toggle = `<button class="ev-link" data-collapse-toggle>${data.collapsed ? "展开全部（不折叠）" : "按同源折叠"}</button>`;
  el.innerHTML = `<span>${escapeHtml(tierLabel)}</span><span>共 <b>${data.total}</b> 项</span>`
    + (data.total ? `<span>当前 ${from}–${to}</span>` : "")
    + folded + other + toggle;
}

function renderAssetPager(data) {
  const el = $("#asset-pager");
  if (!el) return;
  const pages = Math.max(1, Math.ceil(data.total / data.limit));
  const cur = Math.floor(data.offset / data.limit) + 1;
  if (pages <= 1) { el.innerHTML = ""; return; }

  // 页数多时只给首尾与当前邻域，中间用省略号，避免一排 200 个按钮
  const nums = [];
  const push = (n) => { if (n >= 1 && n <= pages && !nums.includes(n)) nums.push(n); };
  push(1);
  for (let n = cur - 2; n <= cur + 2; n++) push(n);
  push(pages);
  nums.sort((a, b) => a - b);

  const buttons = [];
  let prev = 0;
  nums.forEach(n => {
    if (prev && n - prev > 1) buttons.push(`<span class="pager-gap">…</span>`);
    buttons.push(`<button class="pager-btn${n === cur ? " active" : ""}" data-page="${n}">${n}</button>`);
    prev = n;
  });

  el.innerHTML = `
    <button class="pager-btn" data-page="${cur - 1}" ${cur <= 1 ? "disabled" : ""}>上一页</button>
    ${buttons.join("")}
    <button class="pager-btn" data-page="${cur + 1}" ${cur >= pages ? "disabled" : ""}>下一页</button>
    <span class="pager-info">第 ${cur} / ${pages} 页</span>`;

  $$("#asset-pager .pager-btn[data-page]").forEach(btn => btn.addEventListener("click", () => {
    const page = Number(btn.dataset.page);
    if (!page || page === cur) return;
    state.assetOffset = (page - 1) * state.assetLimit;
    loadAssets();
  }));
}

/* ---------------- 同源批次卡片 ---------------- */

function renderGroupCard(g) {
  if (!g || !g.size) return "";
  const elder = g.elder_count ? `<span class="g-badge">其中 ${g.elder_count} 条涉老</span>` : "";
  const rows = (g.members || []).slice(0, 15).map(m => `
    <div class="peer-row" data-asset="${m.id}">
      <span class="mono peer-val">${escapeHtml(m.value)}</span>
      ${m.elder ? `<span class="chip warn">涉老</span>` : ""}
      <span class="mono dim">${escapeHtml(TIER_LABEL[m.tier] || m.tier || "")}</span>
      <span class="mono" style="color:${scoreColor(m.score)}">${m.score}</span>
    </div>`).join("");
  const more = (g.members || []).length > 15
    ? `<div class="peer-more dim">另有 ${g.members.length - 15} 条，在列表页展开这一组查看</div>` : "";
  return `
    <div class="section-title">同源批次
      <span class="hint">${escapeHtml(g.label)} · ${g.size} 条</span>${elder}
    </div>
    <div class="peer-list">${rows}${more}</div>`;
}

/* ---------------- 诱饵 / 蜜罐卡片 ---------------- */

function renderDecoyCard(d) {
  const label = { security_check: "核验诱饵", redirect_shell: "跳转壳", expired: "收尾页", blank_shell: "空壳页", download_shell: "下载壳页" }[d.kind] || "诱饵";
  const cls = d.honeypot ? "bad" : "warn";
  const lines = [];
  if (d.blocked_by) lines.push(`<div class="d">被 <b>${escapeHtml(d.blocked_by)}</b> 拦截，本页不是目标站的内容，已按失败重试。</div>`);
  if (d.reason) lines.push(`<div class="d">${escapeHtml(d.reason)}</div>`);
  if (d.honeypot) {
    lines.push(`<div class="d">反自动化措施：${escapeHtml((d.honeypot_reasons || []).join("；"))}</div>`);
  }
  if ((d.downstream || []).length) {
    lines.push(`<div class="d">去向：${d.downstream.map(u => `<span class="mono">${escapeHtml(u)}</span>`).join("、")}</div>`);
  }
  // 「诱饵不是坏消息」这件事必须写在界面上，否则复核的人会顺手把它排除掉。
  lines.push(`<div class="d dim">诱饵不等于无关：它把访客送到下一跳，是分发链路上的节点。排除它等于放弃入口。</div>`);

  return `
    <div class="section-title">形态判定
      <span class="hint">${escapeHtml(d.blocked_by ? "基础设施拦截" : label)}</span>
    </div>
    <div class="notice ${cls}"><div>${lines.join("")}</div></div>`;
}

/* ---------------- 详情抽屉 ---------------- */

async function openAsset(id) {
  try {
    const a = await api(`/api/assets/${id}`);
    state.currentAsset = a;

    $("#drawer-title").textContent = `${KIND_LABEL[a.kind] || a.kind} · ${a.tier_label || a.tier}`;
    $("#drawer-body").innerHTML = `
      <div class="drawer-hero">
        <div class="hero-top">${badge(a.verdict)}
          <span class="tag ${a.capture_state === "captured" ? "green" : ""}">${escapeHtml(captureShort(a))}</span>
          ${a.campaign ? `<span class="tag">团伙 ${escapeHtml(a.campaign.name)}</span>` : ""}
          ${a.purpose ? `<span class="tag" title="${escapeHtml(a.purpose.reason || "")}">用途：${escapeHtml(a.purpose.label)}${a.purpose.confidence ? ` ${(a.purpose.confidence * 100).toFixed(0)}%` : ""}${a.purpose.source === "model" ? " · 模型" : ""}</span>` : ""}
        </div>
        <div class="result-title">${escapeHtml(a.value)}</div>
        ${a.normalized && a.normalized !== a.value
          ? `<div class="result-sub mono">${escapeHtml(a.normalized)}</div>` : ""}
      </div>

      <div class="meta-grid">
        <div class="meta-cell"><div class="k">风险分</div><div class="v" style="color:${scoreColor(a.score)}">${a.score}</div></div>
        <div class="meta-cell"><div class="k">置信度</div><div class="v">${a.confidence}</div></div>
        <div class="meta-cell"><div class="k">首次发现</div><div class="v">${fmtTime(a.first_seen)}</div></div>
        <div class="meta-cell"><div class="k">最近发现</div><div class="v">${fmtTime(a.last_seen)}</div></div>
        <div class="meta-cell"><div class="k">上次取证</div><div class="v">${a.last_capture_at ? fmtTime(a.last_capture_at) : "未取证"}</div></div>
        <div class="meta-cell"><div class="k">扫描次数</div><div class="v">${a.scan_count}</div></div>
      </div>

      <div class="row actions drawer-acts">
        <button class="btn primary sm" data-act="capture">立即取证</button>
        <button class="btn ghost sm" data-act="watch">加入监控</button>
        <a class="btn ghost sm" href="/api/assets/${a.id}/evidence.zip" download>下载证据包</a>
        ${a.kind === "domain" || a.kind === "url"
          ? `<a class="btn ghost sm" href="${escapeHtml(a.value.startsWith("http") ? a.value : `http://${a.value}`)}" target="_blank" rel="noopener noreferrer nofollow">打开原始页面</a>`
          : ""}
        <button class="btn ghost sm" data-act="tier" data-tier="confirmed">标记已确认</button>
        <button class="btn danger sm" data-act="tier" data-tier="dismissed">标记已排除</button>
      </div>
      <div id="drawer-action-msg"></div>

      ${a.purpose && a.purpose.suppressed ? `<div class="notice">该站用途为「${escapeHtml(a.purpose.label)}」，不占高危队列：${escapeHtml(a.purpose.reason || "")}</div>` : ""}

      ${renderGroupCard(a.group)}
      ${a.decoy ? renderDecoyCard(a.decoy) : ""}

      <div class="section-title">证据矩阵
        <span class="hint">${(a.evidence_matrix && a.evidence_matrix.present) || 0}
          / ${(a.evidence_matrix && a.evidence_matrix.expected) || 8} 类已采集</span>
      </div>
      ${renderEvidenceMatrix(a)}

      <div class="section-title">证据清单（${(a.evidence || []).length}）</div>
      ${renderEvidenceList(a)}

      ${a.evidence_deleted && a.evidence_deleted.length ? `
        <div class="section-title">回收站（${a.evidence_deleted.length}）
          <span class="hint">软删除，文件已移入回收站，7 天后物理清理</span>
        </div>
        ${a.evidence_deleted.map(e => `
          <div class="signal">
            <div>
              <div class="t">${escapeHtml(e.kind)}</div>
              <div class="d">${fmtTime(e.deleted_at)} · ${escapeHtml(e.deleted_by || "")} · ${escapeHtml(e.delete_reason || "未填原因")}</div>
            </div>
            <div class="w"><button class="btn ghost sm" data-restore="${e.id}">恢复</button></div>
          </div>`).join("")}
      ` : ""}

      ${(a.changes || []).length ? `
        <div class="section-title">变更历史（${a.changes.length}）
          <span class="hint">每次复访比对上一条快照：正文相似度、截图、证书、解析地址、安装包哈希</span>
        </div>
        ${a.changes.slice(0, 12).map(c => `
          <div class="status-line">
            <span class="dotmark warn"></span>
            <b>${escapeHtml((c.items || []).join("、") || "变更")}</b>
            <span class="mono">${fmtTime(c.at)}</span>
          </div>`).join("")}
      ` : ""}

      <div class="section-title">判定信号（${(a.signals || []).length}）</div>
      ${(a.signals || []).map(s => `
        <div class="signal">
          <div>
            <div class="t">${escapeHtml(s.title)} <span class="rule-id">${escapeHtml(s.rule_id)}</span></div>
            ${s.detail ? `<div class="d">${escapeHtml(s.detail)}</div>` : ""}
            ${s.evidence ? `<div class="d">依据：${escapeHtml(s.evidence)}</div>` : ""}
          </div>
          <div class="w">${s.weight.toFixed(0)} · ${s.confidence.toFixed(2)}</div>
        </div>`).join("") || `<div class="empty">无信号。这不等于安全，只是现有证据不足以下结论。</div>`}

      <div class="section-title">一键举报</div>
      <div id="report-panel"><div class="empty"><span class="spinner"></span>准备中</div></div>

      <div class="advice">
        <h3>给家属的建议</h3>
        <ol>${(a.advice || []).map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ol>
      </div>`;

    bindDrawerActions(a);
    mountReport(a.id);
    $("#drawer").classList.add("show");
    $("#drawer-mask").classList.add("show");
  } catch (e) {
    toast(e.message);
  }
}

/* ---- 证据矩阵：固定八格，缺哪格、为什么缺，一眼看到 ---- */

function renderEvidenceMatrix(a) {
  const m = a.evidence_matrix || { items: [] };
  const cells = (m.items || []).map(it => {
    const state = it.present ? "on" : "off";
    const acts = it.present ? `
      <div class="ev-acts">
        ${it.previewable ? `<button class="ev-link" data-preview="${it.evidence_id}" data-mime="${escapeHtml(it.mime || "")}">预览</button>` : ""}
        <a class="ev-link" href="/api/evidence/${it.evidence_id}/download">下载</a>
        <button class="ev-link danger" data-del="${it.evidence_id}">删除</button>
      </div>` : "";
    const meta = it.present
      ? `${fmtBytes(it.size)}${it.count > 1 ? ` · 共 ${it.count} 条` : ""}${it.captured_at ? ` · ${fmtTime(it.captured_at)}` : ""}`
      : (m.error ? `未采集 · ${escapeHtml(String(m.error).slice(0, 60))}` : "未采集");
    return `
      <div class="ev-cell ${state}">
        <div class="ev-head">
          <span class="ev-label">${escapeHtml(it.label)}</span>
          <span class="ev-state">${it.present ? "有" : "无"}</span>
        </div>
        <div class="ev-meta">${meta}</div>
        ${acts}
      </div>`;
  }).join("");

  // 八格是「该有什么」。研判快照、二维码这类派生证据不占格子，
  // 塞进去会让最后一行只剩一格、拉成通栏，看起来像排版坏了。
  const extra = (m.others || []).length
    ? `<div class="note-line">另有 ${(m.others || []).length} 类派生证据（${escapeHtml((m.others || []).map(o => o.label).join("、"))}），见下方清单。</div>`
    : "";

  return `<div class="ev-grid">${cells}</div>${extra}
    ${m.state === "failed" ? `<div class="note-line">上次取证失败：${escapeHtml(m.error || "原因未知")}</div>` : ""}`;
}

function renderEvidenceList(a) {
  const rows = a.evidence || [];
  if (!rows.length) {
    return `<div class="empty">还没有证据。点上面的「立即取证」打开页面，会把 HTML、正文、截图、证书、网络请求一起存下来。</div>`;
  }
  return rows.map(e => `
    <div class="signal">
      <div>
        <div class="t">${escapeHtml(e.kind_label || e.kind)}${e.note ? ` · ${escapeHtml(e.note)}` : ""}</div>
        <div class="d mono">SHA-256 ${escapeHtml((e.sha256 || "").slice(0, 20))}… · ${fmtBytes(e.size)} · ${fmtTime(e.captured_at)}</div>
      </div>
      <div class="w">
        ${e.previewable ? `<button class="ev-link" data-preview="${e.id}" data-mime="${escapeHtml(e.mime || "")}">预览</button>` : ""}
        <a class="ev-link" href="/api/evidence/${e.id}/download">下载</a>
        <button class="ev-link danger" data-del="${e.id}">删除</button>
      </div>
    </div>`).join("");
}

function bindDrawerActions(a) {
  const body = $("#drawer-body");

  const msg = (html) => {
    const el = $("#drawer-action-msg");
    if (el) el.innerHTML = html;
  };

  body.querySelectorAll("[data-act]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const act = btn.dataset.act;
      if (act === "capture") {
        msg(`<div class="note-line"><span class="spinner"></span> 正在打开页面取证，通常 5–20 秒…</div>`);
        btn.disabled = true;
        try {
          const r = await api(`/api/assets/${a.id}/capture`, { method: "POST" });
          toast(r.ok ? `取证完成：${(r.evidence || []).length} 类证据` : `未取到：${r.reason || "未知原因"}`);
          await openAsset(a.id);
          loadHealth();
        } catch (e) {
          msg(`<div class="note-line">取证失败：${escapeHtml(e.message)}</div>`);
          btn.disabled = false;
        }
        return;
      }
      if (act === "watch") {
        try {
          const r = await api("/api/watch", {
            method: "POST",
            body: JSON.stringify({ kind: "asset", asset_id: a.id }),
          });
          toast(r.added ? "已加入监控" : "已在该监控列表中");
        } catch (e) { toast(e.message); }
        return;
      }
      if (act === "tier") {
        const tier = btn.dataset.tier;
        try {
          await api(`/api/assets/${a.id}/tier`, {
            method: "POST",
            body: JSON.stringify({ tier, reason: "界面人工判定", reviewer: "界面操作员" }),
          });
          toast(tier === "dismissed" ? "已排除" : "已确认");
          await openAsset(a.id);
        } catch (e) { toast(e.message); }
      }
    });
  });

  body.querySelectorAll("[data-preview]").forEach(btn => {
    btn.addEventListener("click", () => togglePreview(btn));
  });

  body.querySelectorAll("[data-del]").forEach(btn => {
    btn.addEventListener("click", async () => {
      const reason = window.prompt("删除原因（可留空，会写进证据链留痕）", "误采/重复");
      if (reason === null) return;
      try {
        await api(`/api/evidence/${btn.dataset.del}?reason=${encodeURIComponent(reason)}`, { method: "DELETE" });
        toast("已移入回收站");
        await openAsset(a.id);
      } catch (e) { toast(e.message); }
    });
  });

  body.querySelectorAll("[data-restore]").forEach(btn => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/evidence/${btn.dataset.restore}/restore`, { method: "POST" });
        toast("已恢复");
        await openAsset(a.id);
      } catch (e) { toast(e.message); }
    });
  });

  // 同源批次里的兄弟条目可以直接跳过去：排查一组站时不必回列表再搜
  body.querySelectorAll(".peer-row[data-asset]").forEach(row => {
    row.addEventListener("click", () => openAsset(Number(row.dataset.asset)));
  });
}

/* 预览放在矩阵下方通栏，不塞进 168px 的格子里。
   早先放在格子内，一段 HTML 会把那一格拉成两屏高，整行跟着变形。 */
function previewSlot() {
  let slot = document.getElementById("ev-preview-slot");
  if (slot) return slot;
  slot = document.createElement("div");
  slot.id = "ev-preview-slot";
  slot.className = "ev-preview-slot";
  const grid = document.querySelector("#drawer-body .ev-grid");
  if (grid && grid.parentNode) grid.parentNode.insertBefore(slot, grid.nextSibling);
  else document.getElementById("drawer-body").appendChild(slot);
  return slot;
}

function previewTitle(btn) {
  const cell = btn.closest(".ev-cell");
  if (cell) {
    const label = cell.querySelector(".ev-label");
    return label ? label.textContent.trim() : "证据预览";
  }
  const row = btn.closest(".signal");
  if (row) {
    const t = row.querySelector(".t");
    return t ? t.textContent.split("·")[0].trim() : "证据预览";
  }
  return "证据预览";
}

async function togglePreview(btn) {
  const id = btn.dataset.preview;
  const mime = btn.dataset.mime || "";
  const slot = previewSlot();
  const open = slot.dataset.id === String(id) && slot.classList.contains("show");

  document.querySelectorAll("[data-preview]").forEach(b => b.classList.remove("active"));
  if (open) {
    slot.classList.remove("show");
    slot.innerHTML = "";
    slot.dataset.id = "";
    return;
  }

  btn.classList.add("active");
  slot.dataset.id = String(id);
  slot.classList.add("show");
  slot.innerHTML = `
    <div class="ev-preview-head">
      <b>${escapeHtml(previewTitle(btn))}</b>
      <span class="hint">证据 #${escapeHtml(String(id))}</span>
      <button class="btn ghost sm" data-close-preview>关闭预览</button>
    </div>
    <div class="ev-preview-body"><div class="note-line"><span class="spinner"></span> 加载中…</div></div>`;

  const body = slot.querySelector(".ev-preview-body");
  slot.querySelector("[data-close-preview]").addEventListener("click", () => togglePreview(btn));

  if (mime.startsWith("image/")) {
    const img = new Image();
    img.alt = "证据截图";
    img.loading = "lazy";
    img.onload = () => { body.innerHTML = ""; body.appendChild(img); };
    img.onerror = () => { body.innerHTML = `<div class="note-line">预览失败，请下载原文件</div>`; };
    img.src = `/api/evidence/${id}/preview`;
    return;
  }

  try {
    const res = await fetch(`/api/evidence/${id}/preview`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const pre = document.createElement("pre");
    pre.className = "ev-text";
    pre.textContent = text.length > 60000 ? `${text.slice(0, 60000)}\n\n…（已截断，完整内容请下载）` : text;
    body.innerHTML = "";
    body.appendChild(pre);
  } catch (e) {
    body.innerHTML = `<div class="note-line">预览失败：${escapeHtml(e.message)}</div>`;
  }

  slot.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

function closeDrawer() {
  $("#drawer").classList.remove("show");
  $("#drawer-mask").classList.remove("show");
}

/* ---------------- 团伙 / 监控 / 规则 ---------------- */

async function loadCampaigns() {
  const box = $("#campaign-list");
  try {
    const data = await api("/api/campaigns");
    box.innerHTML = data.items.length ? data.items.map(c => `
      <div class="row-item" style="cursor:default">
        <div class="row-main">
          <strong>${escapeHtml(c.name)}</strong>
          <span>${c.assets} 个资产 · 首次 ${fmtTime(c.first_seen)} · 最近 ${fmtTime(c.last_seen)}</span>
          ${c.summary ? `<span class="row-note">${escapeHtml(c.summary)}</span>` : ""}
        </div>
        <div class="row-meta"><span class="badge insufficient">${escapeHtml(c.status)}</span></div>
        <div class="score-chip"><b>${c.assets}</b></div>
      </div>`).join("") : `<div class="empty">还没有形成团伙。同一套模板 / 证书 / 收款地址的资产会自动归并——先去「关系图谱」点一次「重建图」。</div>`;
  } catch (e) {
    box.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  }
  loadClusters();
}

async function loadClusters() {
  const box = $("#cluster-list");
  if (!box) return;
  box.innerHTML = `<div class="empty"><span class="spinner"></span>计算关联簇…</div>`;
  try {
    const data = await api("/api/graph/communities?min_size=2");
    if (!data.items.length) {
      box.innerHTML = `<div class="empty">没有达到阈值的关联簇。簇越小越可能是同一批域名，重建图后再看。</div>`;
      return;
    }
    box.innerHTML = data.items.map(c => `
      <div class="row-item" style="cursor:default">
        <div class="row-main">
          <strong>${escapeHtml(c.anchor || "未命名簇")}</strong>
          <span>${c.size} 个节点 · 强度 ${Number(c.weight).toFixed(1)} · ${escapeHtml((c.by_type && Object.entries(c.by_type).map(([k, v]) => `${k}×${v}`).join(" ")) || "")}</span>
          <span class="row-note">${escapeHtml((c.reasons || []).join("；"))}</span>
        </div>
        <div class="score-chip"><b>${c.size}</b></div>
      </div>`).join("");
  } catch (e) {
    box.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  }
}

async function loadWatch() {
  const [w, runs] = await Promise.all([api("/api/watch"), api("/api/runs")]);

  const changed = w.items.filter(t => (t.change_count || 0) > 0).length;
  const failed = w.items.filter(t => (t.fail_count || 0) > 0).length;
  const summary = $("#watch-summary");
  if (summary) {
    summary.innerHTML = `
      <span>共 <b>${w.total || w.items.length}</b> 个目标</span>
      <span>自动纳管 <b>${w.auto || 0}</b></span>
      <span>有变更 <b>${changed}</b></span>
      <span>有失败 <b>${failed}</b></span>`;
  }

  $("#watch-list").innerHTML = w.items.length ? w.items.map(t => `
    <div class="row-item" ${t.asset_id ? `data-watch-asset="${t.asset_id}"` : 'style="cursor:default"'}>
      <div class="row-main">
        <strong>${escapeHtml(t.asset_value || t.value)}
          <span class="tag ${t.auto ? "" : "blue"}">${t.auto ? "自动" : "人工"}</span>
          ${t.asset_tier ? `<span class="tag">${escapeHtml(TIER_LABEL[t.asset_tier] || t.asset_tier)}</span>` : ""}
        </strong>
        <span>每 ${t.interval_minutes} 分钟 · 上次 ${fmtTime(t.last_run_at)} · 下次 ${fmtTime(t.next_run_at)}
          ${t.change_count ? ` · <b class="warn-text">变更 ${t.change_count} 次</b>` : " · 无变更"}
          ${t.fail_count ? ` · 失败 ${t.fail_count} 次` : ""}</span>
      </div>
      <div class="row-meta">
        <span class="badge ${t.enabled ? "low" : "insufficient"}">${t.enabled ? "启用" : "停用"}</span>
        <button class="btn sm ghost" data-del="${t.id}">删除</button>
      </div>
    </div>`).join("") : `<div class="empty">还没有监控目标。分级为「已确认 / 观察中」的资产会自动进来；也可以点右上角「同步高危目标」一次性补齐。</div>`;

  $$("#watch-list [data-del]").forEach(btn => btn.addEventListener("click", async (ev) => {
    ev.stopPropagation();
    await api(`/api/watch/${btn.dataset.del}`, { method: "DELETE" });
    toast("已删除");
    loadWatch();
  }));
  $$("#watch-list [data-watch-asset]").forEach(row => row.addEventListener("click", () => {
    openAsset(row.dataset.watchAsset);
  }));

  $("#run-list").innerHTML = runs.items.length ? runs.items.map(r => {
    const st = r.stats || {};
    const bits = [];
    if (st.captured) bits.push(`取证 ${st.captured}`);
    if (st.changes) bits.push(`变更 ${st.changes}`);
    if (st.assets) bits.push(`资产 ${st.assets}`);
    return `
      <div class="row-item" style="cursor:default">
        <div class="row-main">
          <strong>#${r.id} · ${escapeHtml(r.trigger)} · ${escapeHtml(r.status)}</strong>
          <span>${escapeHtml(bits.join(" · ") || JSON.stringify(st).slice(0, 90))}</span>
        </div>
        <div class="row-meta"><span class="hint">${fmtTime(r.started_at)}</span></div>
        <div class="score-chip">${r.error ? "!" : "✓"}</div>
      </div>`;
  }).join("") : `<div class="empty">暂无调度记录</div>`;
}

const TIER_LABEL = { confirmed: "已确认", watch: "观察中", candidate: "候选", cold: "冷存", dismissed: "已排除" };

async function loadRules() {
  try {
    const [data, lib] = await Promise.all([
      api("/api/rules"),
      api("/api/discover/keywords?limit=200").catch(() => null),
    ]);

    const contentIds = new Set((data.items || []).filter(r => /^CT-/.test(r.id)).map(r => r.id));
    $("#rule-list").innerHTML = `
      <div class="rule-item rule-head">
        <div class="rule-id">ID</div><div>标题</div>
        <div class="rule-w">权重</div><div class="rule-w">置信</div>
      </div>
      ${data.items.map(r => `
        <div class="rule-item">
          <div class="rule-id">${escapeHtml(r.id)}</div>
          <div>${escapeHtml(r.title)}
            <span class="rule-cat">${escapeHtml(CATEGORY_LABEL[r.category] || r.category)}</span>
            ${contentIds.has(r.id) ? `<span class="tag">内容</span>` : ""}
          </div>
          <div class="rule-w">${r.weight.toFixed(0)}</div>
          <div class="rule-w">${r.confidence.toFixed(2)}</div>
        </div>`).join("")}`;

    renderLexicon(lib);
  } catch (e) {
    $("#rule-list").innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  }
}

const CLUSTER_LABEL = {
  policy_theme: "政策主题", inducement: "诱导话术", scam_signature: "诈骗特征",
  authority: "权威冒用", elder_care: "养老照护", health_product: "保健品",
  investment: "投资理财", project_scam: "工程/项目骗局", honorific: "称谓敬语",
  channel: "传播渠道", payment: "支付收款", ai_hype: "AI 概念", collectible: "收藏品",
  travel_elder: "老年旅游", variant: "仿冒变体", brand: "品牌词", generic: "通用词",
  sales_jargon: "运营黑话",
};

function renderLexicon(lib) {
  const el = $("#lexicon-stats");
  if (!el) return;
  if (!lib || !lib.library) {
    el.innerHTML = `<div class="empty">词库未加载（发现引擎未启动时可能读不到）</div>`;
    return;
  }
  const library = lib.library;
  const clusters = Object.entries(library.by_cluster || {}).sort((a, b) => b[1] - a[1]);
  const hits = (lib.hits || []).filter(h => h.hits > 0);
  const noisy = hits
    .map(h => ({ ...h, ratio: h.hits ? (h.dismissed || 0) / h.hits : 0 }))
    .filter(h => h.hits >= 5)
    .sort((a, b) => b.ratio - a.ratio)
    .slice(0, 8);

  el.innerHTML = `
    <div class="lex-summary">
      <span>词条 <b>${library.terms}</b></span>
      <span>拼音索引 <b>${library.pinyin_terms}</b></span>
      <span>语义簇 <b>${clusters.length}</b></span>
    </div>
    <div class="lex-clusters">
      ${clusters.map(([k, v]) => `<span class="chip">${escapeHtml(CLUSTER_LABEL[k] || k)} ${v}</span>`).join("")}
    </div>
    <div class="section-title">命中与误报（命中 ≥5 次）</div>
    ${noisy.length ? noisy.map(h => `
      <div class="status-line">
        <b>${escapeHtml(h.term)}</b>
        <span>命中 ${h.hits} · 排除 ${h.dismissed || 0} · 确认 ${h.confirmed || 0}</span>
        <span class="${h.ratio >= 0.8 ? "warn-text" : ""}">误报 ${(h.ratio * 100).toFixed(0)}%</span>
      </div>`).join("") : `<div class="empty">还没有足够样本判断哪些词在制造噪声。</div>`}
    <div class="note-line">误报率 ≥80% 且命中 ≥25 次的词会被自动搁置，不再占用 DNS 探测配额。</div>`;
}

/* ---------------- 初始化 ---------------- */

function bindGlobal() {
  $$(".nav-item").forEach(b => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#btn-refresh").addEventListener("click", () => { loadHealth(); switchView(state.view); });
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer-mask").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

  $("#btn-help").addEventListener("click", toggleHelp);

  $("#filter-q").addEventListener("input", e => {
    state.query = e.target.value.trim();
    state.assetOffset = 0;
    clearTimeout(window._qf);
    window._qf = setTimeout(loadAssets, 300);
  });
  $("#filter-verdict").addEventListener("change", e => {
    state.verdict = e.target.value;
    state.assetOffset = 0;
    loadAssets();
  });
  $("#filter-tier").addEventListener("change", e => {
    state.assetTier = e.target.value;
    state.assetOffset = 0;
    loadAssets();
  });

  $("#btn-watch-add").addEventListener("click", async () => {
    const kind = $("#watch-kind").value;
    const value = $("#watch-value").value.trim();
    const interval = parseInt($("#watch-interval").value, 10) || 360;
    if (!value) { toast("请填写监控目标"); return; }
    try {
      await api("/api/watch", { method: "POST", body: JSON.stringify({ kind, value, interval_minutes: interval }) });
      $("#watch-value").value = "";
      toast("已加入监控");
      loadWatch();
    } catch (e) { toast(e.message); }
  });

  $("#btn-watch-run").addEventListener("click", async () => {
    toast("正在执行一轮采集，可能需要几十秒…");
    try {
      const r = await api("/api/watch/run", { method: "POST" });
      toast(`完成 ${r.results.length} 个任务`);
      loadWatch();
      loadHealth();
    } catch (e) { toast(e.message); }
  });
}

function init() {
  const sel = $("#filter-verdict");
  Object.entries(VERDICT_LABEL).forEach(([k, v]) => {
    const opt = document.createElement("option");
    opt.value = k;
    opt.textContent = v;
    sel.appendChild(opt);
  });

  bindGlobal();
  bindScan();
  if (window.ssSkeleton) window.ssSkeleton();
  renderPageMeta("overview");
  loadHealth();
  loadOverview();

  // 深链：/ #discover 直接打开对应视图
  if (location.hash) {
    const v = location.hash.slice(1);
    if (VIEW_TITLES[v]) switchView(v, { syncHash: false });
  }
  // 前进/后退、手改地址栏都要能切视图。缺了这一段，hash 变了页面没反应。
  window.addEventListener("hashchange", () => {
    const v = location.hash.slice(1) || "overview";
    if (VIEW_TITLES[v] && v !== state.view) switchView(v, { syncHash: false });
  });
}

document.addEventListener("DOMContentLoaded", init);
window.openAsset = openAsset;
// views.js 里点发现流的一行要开抽屉，历史上它调的是 openDrawer；
// 这两个名字指向同一个函数，避免再出现 ReferenceError。
window.openDrawer = openAsset;
window.closeDrawer = closeDrawer;
window.ssState = state;
window.switchView = switchView;
window.loadHealth = loadHealth;
window.loadAssets = loadAssets;
