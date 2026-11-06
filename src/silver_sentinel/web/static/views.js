/* 银发哨兵 · v1.0 新增视图
   发现流 / 关系图谱 / 运维。
   依赖 app.js 暴露的 $ $$ api escapeHtml toast。
   所有来自线索的字符串一律走 escapeHtml —— 这些内容是敌意数据。 */

/* ================= 发现流 ================= */

let discoverTimer = null;

async function loadDiscover() {
  try {
    const [status, kpi] = await Promise.all([
      api("/api/discover/status"),
      api("/api/stats").catch(() => null),
    ]);
    renderDiscoverKpis(status, kpi);
    renderSources(status);
    renderKeywordHits();
    loadFunnel($("#funnel"));
    await loadDiscoverFeed();
    startDiscoverPolling();
  } catch (e) {
    toast(`发现流加载失败：${e.message}`);
  }
}

function renderDiscoverKpis(status, kpi) {
  const s = status.stats || {};
  const lib = status.keyword_library || {};
  const items = [
    { label: "已观测域名", value: fmtNum(s.seen), hint: "CT + DNS 探测累计" },
    { label: "命中词根", value: fmtNum(s.matched), hint: "进入判定" },
    { label: "入候选池", value: fmtNum(s.queued), hint: "已落库待研判" },
    { label: "待写队列", value: fmtNum(status.pending), hint: "内存缓冲" },
    { label: "词库规模", value: fmtNum(lib.terms), hint: `${(lib.by_cluster && Object.keys(lib.by_cluster).length) || 0} 个语义簇` },
    { label: "证书吞吐", value: `${s.certs_per_min || 0}/分`, hint: `入池 ${s.assets_per_min || 0}/分` },
  ];
  const el = $("#discover-kpis");
  if (!el) return;
  el.innerHTML = items
    .map(
      (i) => `<div class="kpi">
        <div class="num">${escapeHtml(String(i.value))}</div>
        <div class="lab">${escapeHtml(i.label)}</div>
        <div class="kpi-hint">${escapeHtml(i.hint)}</div>
      </div>`
    )
    .join("");
}

function renderSources(status) {
  const el = $("#source-status");
  if (!el) return;
  const rows = [];

  (status.followers || []).forEach((f) => {
    const ok = !f.error;
    const host = String(f.url || "").replace(/^https?:\/\//, "").slice(0, 34);
    rows.push({
      name: host,
      state: ok ? "ok" : "warn",
      detail: ok ? `滞后 ${f.lag ?? "—"}` : String(f.error).slice(0, 40),
    });
  });

  if (status.stream) {
    rows.push({
      name: "certstream",
      state: status.stream.connected ? "ok" : "warn",
      detail: status.stream.connected ? `已连接 ${fmtNum(status.stream.total)}` : "未连接",
    });
  }

  if (status.dns) {
    rows.push({
      name: "DNS 探测",
      state: "ok",
      detail: `查询 ${fmtNum(status.dns.queried)} · 存在 ${fmtNum(status.dns.exists)}`,
    });
  }

  if (status.seeds) {
    rows.push({ name: "词根种子", state: "ok", detail: `${fmtNum(status.seeds.seeds)} 个` });
  }

  el.innerHTML = rows.length
    ? rows
        .map(
          (r) => `<div class="status-line">
            <span class="dotmark ${r.state}"></span>
            <b>${escapeHtml(r.name)}</b>
            <span class="muted">${escapeHtml(r.detail)}</span>
          </div>`
        )
        .join("")
    : `<div class="empty">无情报源</div>`;
}

async function renderKeywordHits() {
  const el = $("#keyword-hits");
  if (!el) return;
  try {
    const data = await api("/api/discover/keywords?limit=18");
    const hits = data.hits || [];
    el.innerHTML = hits.length
      ? hits
          .map(
            (h) => `<div class="status-line">
              <b>${escapeHtml(h.term)}</b>
              <span class="muted">${fmtNum(h.hits)} 次</span>
            </div>`
          )
          .join("")
      : `<div class="empty">暂无命中</div>`;
  } catch {
    el.innerHTML = `<div class="empty">读取失败</div>`;
  }
}

async function loadDiscoverFeed() {
  const el = $("#discover-feed");
  if (!el) return;
  try {
    const data = await api("/api/discover/events?limit=60");
    el.innerHTML = data.items.length
      ? data.items.map(renderFeedRow).join("")
      : `<div class="empty">还没有发现记录。引擎启动后会陆续出现。</div>`;
  } catch (e) {
    el.innerHTML = `<div class="empty">读取失败：${escapeHtml(e.message)}</div>`;
  }
}

function renderFeedRow(e) {
  const terms = (e.terms || []).filter(Boolean).slice(0, 4);
  const hint = typeof e.hint === "number" ? e.hint : 0;
  const tone = hint >= 0.8 ? "red" : hint >= 0.5 ? "orange" : "blue";
  return `<div class="feed-row" ${e.asset_id ? `data-asset="${e.asset_id}"` : ""}>
    <span class="feed-time mono">${fmtTime(e.created_at)}</span>
    <span class="tag ${tone}">${escapeHtml(e.source)}</span>
    <span class="feed-value mono">${escapeHtml(e.value)}</span>
    <span class="feed-terms">${terms.map((t) => `<i>${escapeHtml(t)}</i>`).join("")}</span>
    <span class="feed-hint mono">${hint.toFixed(2)}</span>
  </div>`;
}

function startDiscoverPolling() {
  if (discoverTimer) return;
  discoverTimer = setInterval(() => {
    if (state.view !== "discover") return;
    loadDiscoverFeed();
    api("/api/discover/status").then((s) => renderDiscoverKpis(s)).catch(() => {});
  }, 8000);
}

/* ================= 实时推送 ================= */

let sse = null;

function connectStream() {
  if (sse || !window.EventSource) return;
  try {
    sse = new EventSource("/api/stream");
    const mark = $("#st-stream");
    sse.addEventListener("hello", () => {
      if (mark) { mark.textContent = "已连接"; mark.className = "ok"; }
    });
    sse.addEventListener("discovery", (ev) => {
      const d = JSON.parse(ev.data);
      const dot = $("#dot-discover");
      if (dot) dot.classList.add("live");
      setTimeout(() => dot && dot.classList.remove("live"), 1200);
      if (state.view === "discover") {
        const feed = $("#discover-feed");
        if (feed) {
          const row = document.createElement("div");
          row.className = "feed-row new";
          row.innerHTML = `<span class="feed-time mono">刚刚</span>
            <span class="tag blue">${escapeHtml(d.source || "live")}</span>
            <span class="feed-value mono">${escapeHtml(d.value || "")}</span>
            <span class="feed-terms">${(d.terms || []).slice(0, 4).map((t) => `<i>${escapeHtml(t)}</i>`).join("")}</span>
            <span class="feed-hint mono">${Number(d.score || 0).toFixed(2)}</span>`;
          feed.prepend(row);
          while (feed.children.length > 80) feed.lastChild.remove();
        }
      }
    });
    sse.addEventListener("cycle", () => {
      if (state.view === "ops") loadOps();
    });
    sse.onerror = () => {
      if (mark) { mark.textContent = "重连中"; mark.className = "warn"; }
    };
  } catch (e) {
    console.warn("SSE 不可用", e);
  }
}

/* ================= 关系图谱 ================= */

// 类型只用一个色相环，饱和度与亮度统一：图上看不出「一把荧光笔」，
// 但仍能靠色相区分。具体明度跟着主题走。
const NODE_HUE = {
  domain: 210, url: 218, ip: 192, asn: 176, cert: 266, apk: 28,
  wallet: 44, phone: 330, landline: 342, qq: 202, wechat: 152,
  email: 214, bank_card: 18, entity: 4, registrar: 212, template: 284,
  brand: 48, campaign: 0, keyword: 212,
};

const GRAPH_TYPE_LABEL = {
  domain: "域名", url: "网址", ip: "IP", cert: "证书", apk: "安装包",
  wallet: "钱包", phone: "手机号", email: "邮箱", bank_card: "银行卡",
  entity: "主体", campaign: "团伙", template: "模板",
};

function cssVar(name, fallback) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

function withAlpha(color, alpha) {
  const raw = String(color).trim().replace("#", "");
  const full = raw.length === 3 ? raw.split("").map((c) => c + c).join("") : raw;
  const n = parseInt(full, 16);
  if (!isFinite(n)) return `rgba(26,26,23,${alpha})`;
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
}

function nodeColor(type) {
  const h = NODE_HUE[type] ?? 212;
  const dark = document.documentElement.getAttribute("data-theme") === "dark";
  return `hsl(${h} ${dark ? 42 : 30}% ${dark ? 62 : 41}%)`;
}

const graphState = {
  nodes: [],
  edges: [],
  scale: 1,
  offsetX: 0,
  offsetY: 0,
  dragging: null,
  panning: false,
  last: { x: 0, y: 0 },
  hover: null,
  raf: null,
  alpha: 1,
};

async function loadGraphView() {
  buildLegend();
  const canvas = $("#graph-canvas");
  if (!canvas) return;
  bindGraphEvents(canvas);
  await loadGraphOverview();
}

function buildLegend() {
  const el = $("#graph-legend");
  if (!el) return;
  el.innerHTML = Object.keys(GRAPH_TYPE_LABEL)
    .map((k) => `<span class="lg-row"><i style="background:${nodeColor(k)}"></i>${escapeHtml(GRAPH_TYPE_LABEL[k])}</span>`)
    .join("");
}

async function loadGraphOverview() {
  toast("加载全局图…");
  try {
    const data = await api("/api/graph/overview?limit=40");
    setGraphData(data);
  } catch (e) {
    toast(`图加载失败：${e.message}`);
  }
}

async function loadGraphNode(key) {
  toast(`加载 ${key}…`);
  try {
    const data = await api(`/api/graph/node?key=${encodeURIComponent(key)}`);
    setGraphData(data);
  } catch (e) {
    toast(`节点加载失败：${e.message}`);
  }
}

function setGraphData(data) {
  const canvas = $("#graph-canvas");
  if (!canvas) return;
  const w = canvas.clientWidth || 900;
  const h = canvas.clientHeight || 620;

  const baseR = (n) => (n.type === "campaign" ? 16 : n.type === "domain" ? 11 : 8);

  // 网格初始化：按画布长宽比铺成行列，力导向只做局部微调。
  // 早先用同心圆初始化，外圈节点一上来就被斥力顶到边界，沿四条边排成直线。
  const N = (data.nodes || []).length;
  const cols = Math.max(1, Math.round(Math.sqrt((N * w) / Math.max(h, 1))));
  const rows = Math.max(1, Math.ceil(N / cols));
  const cw = w / (cols + 1);
  const ch = h / (rows + 1);

  graphState.nodes = (data.nodes || []).map((n, i) => ({
    ...n,
    x: cw * ((i % cols) + 1) + (Math.random() - 0.5) * 16,
    y: ch * (Math.floor(i / cols) + 1) + (Math.random() - 0.5) * 16,
    vx: 0,
    vy: 0,
    r: baseR(n) * (data.nodes.length > 150 ? 0.6 : data.nodes.length > 80 ? 0.76 : 1),
  }));

  const index = new Map(graphState.nodes.map((n) => [n.id, n]));
  graphState.edges = (data.edges || [])
    .map((e) => ({ ...e, a: index.get(e.source), b: index.get(e.target) }))
    .filter((e) => e.a && e.b);

  // 度数决定谁配拥有标签。图一大就全标，会糊成一片黑框，不如只标连接最多的那些。
  const deg = new Map();
  graphState.edges.forEach((e) => {
    deg.set(e.source, (deg.get(e.source) || 0) + 1);
    deg.set(e.target, (deg.get(e.target) || 0) + 1);
  });
  const budget = graphState.nodes.length > 60 ? 12 : graphState.nodes.length;
  graphState.labelSet = new Set(
    [...graphState.nodes]
      .sort((a, b) => (deg.get(b.id) || 0) - (deg.get(a.id) || 0))
      .slice(0, budget)
      .map((n) => n.id)
  );

  graphState.scale = 1;
  graphState.offsetX = 0;
  graphState.offsetY = 0;
  graphState.alpha = 1;
  startSimulation();
}

function startSimulation() {
  if (graphState.raf) cancelAnimationFrame(graphState.raf);
  const step = () => {
    simulate();
    drawGraph();
    if (graphState.alpha > 0.02) {
      graphState.alpha *= 0.985;
      graphState.raf = requestAnimationFrame(step);
    } else {
      graphState.raf = null;
    }
  };
  step();
}

function simulate() {
  const nodes = graphState.nodes;
  const edges = graphState.edges;
  const n = nodes.length;
  if (!n) return;

  const canvas = $("#graph-canvas");
  const w = canvas ? canvas.clientWidth : 900;
  const h = canvas ? canvas.clientHeight : 520;
  const alpha = graphState.alpha;

  // 斥力：O(n²)，节点数控制在几百以内足够。
  // 节点越多需要的分离力越大，否则两百个点会挤成中心一团。
  const spread = Math.min(1.6, 1 + n / 200);
  for (let i = 0; i < n; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < n; j++) {
      const b = nodes[j];
      let dx = a.x - b.x;
      let dy = a.y - b.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
      const force = (1200 * spread * alpha) / d2;
      const d = Math.sqrt(d2);
      const fx = (dx / d) * force;
      const fy = (dy / d) * force;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    }
  }

  // 弹簧
  edges.forEach((e) => {
    const dx = e.b.x - e.a.x;
    const dy = e.b.y - e.a.y;
    const d = Math.sqrt(dx * dx + dy * dy) || 1;
    const target = n > 120 ? 72 : n > 60 ? 96 : 128;
    const k = 0.018 * (e.weight || 0.3) * alpha * 3;
    const f = (d - target) * k;
    const fx = (dx / d) * f;
    const fy = (dy / d) * f;
    e.a.vx += fx; e.a.vy += fy;
    e.b.vx -= fx; e.b.vy -= fy;
  });

  // 向心 + 阻尼
  nodes.forEach((p) => {
    p.vx += (w / 2 - p.x) * 0.009 * alpha;
    p.vy += (h / 2 - p.y) * 0.009 * alpha;
    p.vx *= 0.86;
    p.vy *= 0.86;
    if (!p.fixed) {
      p.x += p.vx;
      p.y += p.vy;
    }
    // 软边界：撞墙时给一个回推力，而不是硬截断。
    // 硬截断会让两成节点沿着四条边贴成一排，图看起来像被框住了。
    const pad = 26;
    if (p.x < pad) p.vx += (pad - p.x) * 1.2;
    if (p.x > w - pad) p.vx -= (p.x - (w - pad)) * 1.2;
    if (p.y < pad) p.vy += (pad - p.y) * 1.2;
    if (p.y > h - pad) p.vy -= (p.y - (h - pad)) * 1.2;
    p.x = Math.max(12, Math.min(w - 12, p.x));
    p.y = Math.max(12, Math.min(h - 12, p.y));
  });
}

function drawGraph() {
  const canvas = $("#graph-canvas");
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth;
  const h = canvas.clientHeight;
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr;
    canvas.height = h * dpr;
  }
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  ctx.save();
  ctx.translate(graphState.offsetX, graphState.offsetY);
  ctx.scale(graphState.scale, graphState.scale);

  const ink = cssVar("--ink", "#1a1a17");
  const surface = cssVar("--surface", "#ffffff");
  const accent = cssVar("--accent", "#b8342a");

  // 边：细线。权重只用线宽表达，不用颜色
  graphState.edges.forEach((e) => {
    const active = graphState.hover && (e.a.id === graphState.hover || e.b.id === graphState.hover);
    ctx.strokeStyle = active ? withAlpha(accent, .55) : withAlpha(ink, .2);
    ctx.lineWidth = active ? 1.3 : Math.max(0.7, (e.weight || 0.2) * 1.1);
    ctx.beginPath();
    ctx.moveTo(e.a.x, e.a.y);
    ctx.lineTo(e.b.x, e.b.y);
    ctx.stroke();
  });

  // 节点：空心圆环。填充用纸色盖住穿过它的边，看起来才干净
  graphState.nodes.forEach((p) => {
    const isHover = graphState.hover === p.id;
    ctx.beginPath();
    ctx.arc(p.x, p.y, p.r + (isHover ? 2 : 0), 0, Math.PI * 2);
    ctx.fillStyle = surface;
    ctx.fill();
    ctx.strokeStyle = nodeColor(p.type);
    ctx.lineWidth = isHover ? 2 : 1.4;
    ctx.stroke();

    if (isHover || graphState.scale > 1.25 || (graphState.nodes.length <= 40 && graphState.labelSet && graphState.labelSet.has(p.id))) {
      const label = shortLabel(p);
      ctx.font = `${isHover ? "500 " : ""}10px ui-monospace, monospace`;
      ctx.textAlign = "center";
      ctx.fillStyle = isHover ? ink : withAlpha(ink, .58);
      ctx.fillText(label, p.x, p.y + p.r + 13);
    }
  });

  ctx.restore();
}

// 主题一换，画布上的线色也得跟着换，否则浅底上留着一层深色描边
window.addEventListener("ss:theme", () => {
  try {
    if (graphState && graphState.nodes && graphState.nodes.length) drawGraph();
  } catch (e) {}
});

function shortLabel(node) {
  const raw = String(node.label || node.id || "");
  const value = raw.includes(":") ? raw.split(":").slice(1).join(":") : raw;
  if (node.type === "wallet" || /^(0x[0-9a-f]{20,}|T[1-9A-HJ-NP-Za-km-z]{20,})$/i.test(value)) {
    return `钱包 ${value.slice(0, 5)}…${value.slice(-4)}`;
  }
  if (node.type === "cert") return `证书 ${value.slice(0, 8)}…`;
  if (node.type === "template") return `模板 ${value.slice(0, 8)}`;
  return value.length > 20 ? value.slice(0, 19) + "…" : value;
}

function bindGraphEvents(canvas) {
  if (canvas.dataset.bound) return;
  canvas.dataset.bound = "1";

  const toWorld = (ev) => {
    const rect = canvas.getBoundingClientRect();
    const x = (ev.clientX - rect.left - graphState.offsetX) / graphState.scale;
    const y = (ev.clientY - rect.top - graphState.offsetY) / graphState.scale;
    return { x, y };
  };

  const pick = (x, y) => {
    let best = null;
    let bestD = 18;
    graphState.nodes.forEach((p) => {
      const d = Math.hypot(p.x - x, p.y - y);
      if (d < bestD) { bestD = d; best = p; }
    });
    return best;
  };

  canvas.addEventListener("mousedown", (ev) => {
    const p = toWorld(ev);
    const node = pick(p.x, p.y);
    if (node) {
      node.fixed = true;
      graphState.dragging = node;
    } else {
      graphState.panning = true;
      graphState.last = { x: ev.clientX, y: ev.clientY };
    }
  });

  canvas.addEventListener("mousemove", (ev) => {
    const p = toWorld(ev);
    if (graphState.dragging) {
      graphState.dragging.x = p.x;
      graphState.dragging.y = p.y;
      graphState.alpha = Math.max(graphState.alpha, 0.3);
      if (!graphState.raf) startSimulation();
      return;
    }
    if (graphState.panning) {
      graphState.offsetX += ev.clientX - graphState.last.x;
      graphState.offsetY += ev.clientY - graphState.last.y;
      graphState.last = { x: ev.clientX, y: ev.clientY };
      drawGraph();
      return;
    }
    const node = pick(p.x, p.y);
    graphState.hover = node ? node.id : null;
    canvas.style.cursor = node ? "pointer" : "grab";
    drawGraph();
  });

  const release = () => {
    if (graphState.dragging) graphState.dragging.fixed = false;
    graphState.dragging = null;
    graphState.panning = false;
  };
  canvas.addEventListener("mouseup", release);
  canvas.addEventListener("mouseleave", () => { release(); graphState.hover = null; drawGraph(); });

  canvas.addEventListener("click", (ev) => {
    const p = toWorld(ev);
    const node = pick(p.x, p.y);
    if (!node) return;
    if (node.type === "domain" || node.type === "apk" || node.type === "url") {
      openAssetByValue(node.id);
    } else {
      toast(`${node.type}：${node.label || node.id}`);
    }
  });

  canvas.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const rect = canvas.getBoundingClientRect();
    const mx = ev.clientX - rect.left;
    const my = ev.clientY - rect.top;
    const factor = ev.deltaY < 0 ? 1.12 : 0.89;
    const next = Math.max(0.25, Math.min(3.5, graphState.scale * factor));
    graphState.offsetX = mx - (mx - graphState.offsetX) * (next / graphState.scale);
    graphState.offsetY = my - (my - graphState.offsetY) * (next / graphState.scale);
    graphState.scale = next;
    drawGraph();
  }, { passive: false });
}

async function openAssetByValue(key) {
  const value = key.split(":").slice(1).join(":");
  try {
    const data = await api(`/api/assets?q=${encodeURIComponent(value)}&limit=5`);
    if (data.items && data.items.length) {
      openDrawer(data.items[0].id);
    } else {
      toast(`未在线索库找到：${value}`);
    }
  } catch (e) {
    toast(e.message);
  }
}

/* ================= 运维 ================= */

async function loadOps() {
  try {
    const [status, tasks, events, queue, funnel] = await Promise.all([
      api("/api/ops/status"),
      api("/api/ops/tasks?limit=20"),
      api("/api/ops/events?limit=40"),
      api("/api/capture/queue").catch(() => null),
      api("/api/funnel").catch(() => null),
    ]);
    renderCapabilities(status.capabilities || {});
    renderRuntime(status);
    renderTasks(tasks.items || []);
    renderEventTail(events.items || []);
    renderOpsKpis(queue, funnel, status);
    renderCaptureQueue(queue);
    renderFunnel($("#funnel-ops"), funnel);
  } catch (e) {
    toast(`运维数据加载失败：${e.message}`);
  }
}

/* 运维 KPI：把「机器有没有在干活」压缩成五行数字 */
function renderOpsKpis(queue, funnel, status) {
  const el = $("#ops-kpis");
  if (!el) return;
  const q = queue || {};
  const done = q.done || 0;
  const failed = q.failed || 0;
  const okRate = done + failed ? (done / (done + failed)) * 100 : 0;
  const cov = (funnel && funnel.coverage) || {};
  const items = [
    { num: q.pending_assets || 0, lab: "待取证资产", hint: "有效且未打开过页面", cls: "" },
    { num: q.queued || 0, lab: "队列中", hint: q.oldest_queued ? `最久等待 ${fmtTime(q.oldest_queued)}` : "空闲", cls: "" },
    { num: done, lab: "已取证", hint: "本次进程内完成", cls: "good" },
    { num: failed, lab: "取证失败", hint: failed ? "看下面的失败原因" : "无", cls: failed ? "danger" : "" },
    { num: done + failed ? `${okRate.toFixed(0)}%` : "—", lab: "取证成功率", hint: "完成 / (完成+失败)", cls: "" },
    { num: `${((cov.ratio || 0) * 100).toFixed(0)}%`, lab: "证据覆盖率", hint: `${cov.captured || 0}/${cov.active || 0} 条有效线索有页面证据`, cls: "" },
  ];
  el.innerHTML = items.map(i => `
    <div class="kpi ${i.cls}">
      <div class="num">${escapeHtml(String(i.num))}</div>
      <div class="lab">${escapeHtml(i.lab)}</div>
      <div class="kpi-hint">${escapeHtml(i.hint)}</div>
    </div>`).join("");
}

function renderCaptureQueue(queue) {
  const el = $("#capture-queue");
  if (!el) return;
  if (!queue) { el.innerHTML = `<div class="empty">读取失败</div>`; return; }
  const rows = [
    ["排队中", queue.queued || 0],
    ["执行中", queue.running || 0],
    ["已完成", queue.done || 0],
    ["失败", queue.failed || 0],
    ["跳过（不支持取证的类型）", queue.skipped || 0],
    ["有效但未取证资产", queue.pending_assets || 0],
  ];
  const fails = queue.recent_failures || [];
  el.innerHTML = rows.map(([k, v]) => `
      <div class="status-line"><b>${escapeHtml(k)}</b><span>${fmtNum(v)}</span></div>`).join("")
    + (fails.length ? `
      <div class="section-title">最近失败</div>
      ${fails.map(f => `<div class="status-line">
        <span class="dotmark bad"></span>
        <b>资产 #${f.asset_id}</b>
        <span>${escapeHtml(String(f.error || "").slice(0, 70))}（第 ${f.attempts} 次）</span>
      </div>`).join("")}` : "");
}

/* 五段漏斗：每一段都写绝对值和转化率，谁掉得最狠一眼能看出来 */
function renderFunnel(el, data) {
  if (!el) return;
  const steps = (data && data.steps) || [];
  if (!steps.length) {
    el.innerHTML = `<div class="empty">发现引擎未启动，暂无漏斗数据。</div>`;
    return;
  }
  const max = Math.max(...steps.map((s) => s.value || 0), 1);
  el.innerHTML = steps.map((s, i) => {
    const value = s.value || 0;
    const width = value ? Math.max(2, (value / max) * 100).toFixed(1) : "0";
    const rate = i === 0
      ? "起点"
      : (s.rate ? `转化 ${(s.rate * 100).toFixed(1)}%` : "—");
    return `
      <div class="funnel-row">
        <div class="fs-label">${escapeHtml(s.label)}</div>
        <div class="fs-track"><i style="width:${width}%"></i></div>
        <div class="fs-num">${fmtNum(value)}</div>
        <div class="fs-rate">${rate}</div>
      </div>`;
  }).join("")
    + `<div class="funnel-foot">近 24 小时：新增线索 <b>${fmtNum(data.admitted_24h)}</b> 条 · 发现事件 <b>${fmtNum(data.events_24h)}</b> 条</div>`;
}

async function loadFunnel(el) {
  if (!el) return;
  try {
    renderFunnel(el, await api("/api/funnel"));
  } catch (e) {
    el.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  }
}

/* ================= 设置 ================= */

const SETTINGS = { data: null };

async function loadSettings() {
  try {
    const data = await api("/api/settings");
    SETTINGS.data = data;
    fillSettings(data);
  } catch (e) {
    toast(`设置读取失败：${e.message}`);
  }
}

function fillSettings(d) {
  const llm = d.llm || {};
  const eg = d.egress || {};
  const cap = d.capture || {};

  const set = (sel, val) => { const el = $(sel); if (el) el.value = val; };
  set("#set-llm-base", llm.base_url || "");
  set("#set-llm-model", llm.model || "");
  set("#set-llm-low", llm.gray_low ?? 25);
  set("#set-llm-high", llm.gray_high ?? 70);

  const key = $("#set-llm-key");
  if (key) {
    key.value = "";
    key.placeholder = llm.has_key
      ? `当前 ${llm.api_key_masked}，留空表示不修改`
      : "sk-…（填写后保存即生效）";
  }

  const enabled = $("#set-llm-enabled");
  if (enabled) enabled.checked = !!llm.enabled;

  const preset = $("#set-llm-preset");
  if (preset) {
    preset.innerHTML = (llm.presets || [])
      .map(p => `<option value="${escapeHtml(p.model)}">${escapeHtml(p.label)}</option>`)
      .join("") + `<option value="">自定义</option>`;
    preset.value = (llm.presets || []).some(p => p.model === llm.model) ? llm.model : "";
    preset.onchange = () => {
      const hit = (llm.presets || []).find(p => p.model === preset.value);
      if (!hit) return;
      set("#set-llm-model", hit.model);
      set("#set-llm-base", hit.base_url);
    };
  }

  const state = $("#llm-state");
  if (state) {
    state.textContent = llm.ready ? `已就绪 · ${llm.model}` : (llm.has_key ? "已填密钥但模型未就绪" : "未配置密钥");
  }

  document.querySelectorAll('input[name="egress-mode"]').forEach(r => {
    r.checked = r.value === (eg.mode || "auto");
  });

  const px = $("#set-egress-proxies");
  if (px) {
    px.value = "";
    px.placeholder = (eg.proxies_masked || []).length
      ? `当前已配置 ${eg.proxy_count} 条（已隐藏凭据）：\n${eg.proxies_masked.join("\n")}\n留空表示不修改`
      : "socks5h://user:pass@host:1080\n每行一个，或逗号分隔";
  }

  const egState = $("#egress-state");
  if (egState) {
    const modeLabel = { auto: "自动", proxy: "仅代理", direct: "强制直连", off: "已关闭" }[eg.mode] || eg.mode;
    egState.textContent = `${modeLabel} · 当前生效：${eg.effective === "proxy" ? "代理" : eg.effective === "off" ? "不出网" : "直连"}`;
  }

  renderEgressWarning(eg);

  set("#set-apk-max", cap.apk_max_mb ?? 50);
  set("#set-apk-daily", cap.apk_daily_mb ?? 300);
  set("#set-apk-tiers", cap.apk_tiers || "watch,confirmed");

  // 保存后统一回填，避免前端自己猜服务端把值规范化成了什么
  const refill = (data) => { SETTINGS.data = data; fillSettings(data); };
  window.ssRefillSettings = refill;
}

function renderEgressWarning(eg) {
  const el = $("#egress-warning");
  if (!el) return;
  const mode = eg.mode || "auto";
  const count = eg.proxy_count || 0;
  if (mode === "proxy" && count === 0) {
    el.className = "note-line warn-text";
    el.textContent = "已选「仅代理」但没有可用代理：所有取证都会被拒绝。要么填代理，要么改成「自动」。";
  } else if (mode === "direct" || (mode === "auto" && count === 0)) {
    el.className = "note-line warn-text";
    el.textContent = "当前会以本机 IP 直接访问可疑站点，对方日志里能看到你的地址。正式运行建议配一条境外 SOCKS5。";
  } else if (mode === "off") {
    el.className = "note-line";
    el.textContent = "取证已关闭：不会再打开任何页面，「待取证」会一直累积。";
  } else {
    el.className = "note-line";
    el.textContent = `出口正常：${count} 条代理可用，取证会轮换使用。`;
  }
  // 配了代理但没被判定为隔离，才值得提醒；没配代理的情况上面已经说清楚了
  if (count > 0 && eg.isolated === false && mode !== "off") {
    el.textContent += " 注意：代理已配置但未判定为隔离出口，确认代理确实生效再上生产。";
  }
}

const CAP_LABEL = {
  network: "外网访问",
  ct_stream: "CT 实时流",
  icp: "ICP 备案",
  graph: "关系图谱",
  sandbox_web: "网页沙箱",
  sandbox_apk: "APK 沙箱",
  egress: "取证出口",
  replica: "异地副本",
  vault: "加密保险库",
  llm: "AI 研判",
  report: "举报材料",
};

/* 固定顺序 + 固定 11 格。
   后端会多返回 sandbox_web_blocked_by / llm_model 两个附属字段，
   它们不是独立能力，硬塞成格子会多出一个空位，看起来像界面坏了。 */
const CAP_ORDER = ["network", "ct_stream", "icp", "graph", "sandbox_web", "sandbox_apk",
  "egress", "replica", "vault", "llm", "report"];

const CAP_TEXT = {
  "direct-degraded": "直连（未隔离）",
  blocked: "被关闭",
  off: "未启用",
  "static-only": "仅静态解析",
  "material+fill-local": "本机生成",
  "material+fill": "可自动填表",
  unconfigured: "未配置",
};

function capState(value) {
  if (value === true || value === "ready" || value === "builtin" || value === "neo4j") return "ok";
  if (value === "static-only" || value === "off" || value === false || value === "unconfigured") return "off";
  if (value === "direct-degraded" || value === "blocked" || value === "material+fill-local") return "warn";
  if (value === "mobsf" || value === "emulator" || value === "material+fill") return "ok";
  return "warn";
}

function renderCapabilities(caps) {
  const el = $("#capability-grid");
  if (!el) return;

  el.innerHTML = CAP_ORDER.map((key) => {
    const raw = caps[key];
    let text = CAP_TEXT[raw] !== undefined ? CAP_TEXT[raw] : String(raw);
    if (key === "llm" && raw === "ready" && caps.llm_model) text = `就绪 · ${caps.llm_model}`;
    if (key === "sandbox_web" && caps.sandbox_web_blocked_by) {
      text += `（${CAP_TEXT[caps.sandbox_web_blocked_by] || caps.sandbox_web_blocked_by}）`;
    }
    if (raw === true) text = "可用";
    return `<div class="cap">
        <span class="cap-name">${escapeHtml(CAP_LABEL[key] || key)}</span>
        <span class="cap-state ${capState(raw)}">${escapeHtml(text)}</span>
      </div>`;
  }).join("");
}

function renderRuntime(status) {
  const el = $("#runtime-stats");
  if (!el) return;
  const d = status.discover || {};
  const s = d.stats || {};
  const rows = [
    ["版本", status.version],
    ["数据目录", status.data_dir],
    ["发现引擎", d.running ? "运行中" : "停止"],
    ["已观测", fmtNum(s.seen)],
    ["入池", fmtNum(s.queued)],
    ["调度周期", `${(status.scheduler || {}).cycles || 0} 次`],
    ["图节点", fmtNum((status.graph || {}).nodes)],
    ["图边", fmtNum((status.graph || {}).edges)],
    ["事件序号", fmtNum((status.eventlog || {}).seq)],
    ["事件体积", fmtBytes((status.eventlog || {}).bytes)],
    ["副本", (status.replica || {}).enabled ? (status.replica || {}).backend : "未启用"],
  ];
  el.innerHTML = rows
    .map(([k, v]) => `<div class="status-line"><b>${escapeHtml(k)}</b><span class="muted">${escapeHtml(String(v ?? "—"))}</span></div>`)
    .join("");
}

function renderTasks(items) {
  const el = $("#task-list");
  if (!el) return;
  el.innerHTML = items.length
    ? items
        .map((t) => {
          const stats = t.stats || {};
          const summary =
            t.kind === "cycle"
              ? `研判 ${stats.scanned || 0} · 富化 ${stats.enriched || 0} · 边 ${stats.graph_edges || 0}`
              : JSON.stringify(stats).slice(0, 80);
          return `<div class="status-line">
            <span class="tag ${t.status === "done" ? "green" : t.status === "failed" ? "red" : "blue"}">${escapeHtml(t.status)}</span>
            <b>${escapeHtml(t.kind)}</b>
            <span class="muted">${escapeHtml(summary)}</span>
            <span class="mono muted">${t.elapsed != null ? t.elapsed + "s" : ""}</span>
          </div>`;
        })
        .join("")
    : `<div class="empty">暂无任务</div>`;
}

function renderEventTail(items) {
  const el = $("#event-tail");
  if (!el) return;
  el.innerHTML = items.length
    ? items
        .slice()
        .reverse()
        .map(
          (e) => `<div class="feed-row">
            <span class="feed-time mono">${fmtTime(e.ts)}</span>
            <span class="tag blue">${escapeHtml(e.kind)}</span>
            <span class="feed-value mono">${escapeHtml(JSON.stringify(e.payload).slice(0, 150))}</span>
          </div>`
        )
        .join("")
    : `<div class="empty">无事件</div>`;
}

/* ================= 小工具 ================= */

function fmtNum(n) {
  const v = Number(n || 0);
  if (v >= 1e8) return (v / 1e8).toFixed(2) + "亿";
  if (v >= 1e4) return (v / 1e4).toFixed(1) + "万";
  return String(v);
}

function fmtBytes(n) {
  const v = Number(n || 0);
  if (v >= 1 << 20) return (v / (1 << 20)).toFixed(1) + " MB";
  if (v >= 1 << 10) return (v / (1 << 10)).toFixed(1) + " KB";
  return v + " B";
}

/* ================= 事件绑定 ================= */

document.addEventListener("DOMContentLoaded", () => {
  const inject = $("#btn-inject");
  if (inject) {
    inject.addEventListener("click", async () => {
      const raw = ($("#inject-values") || {}).value || "";
      const values = raw.split(/[\s,;\n]+/).map((s) => s.trim()).filter(Boolean);
      if (!values.length) return toast("请填入至少一个域名");
      try {
        const r = await api("/api/discover/inject", {
          method: "POST",
          body: JSON.stringify({
            values,
            source: ($("#inject-source") || {}).value || "manual",
            note: ($("#inject-note") || {}).value || "",
          }),
        });
        toast(`已注入 ${r.added} 条，跳过 ${r.skipped} 条`);
        $("#inject-values").value = "";
        loadDiscover();
      } catch (e) {
        toast(`注入失败：${e.message}`);
      }
    });
  }

  const crtsh = $("#btn-crtsh");
  if (crtsh) {
    crtsh.addEventListener("click", async () => {
      const lib = await api("/api/discover/keywords?limit=1").catch(() => null);
      const terms = (lib && lib.hits || []).map((h) => h.term).slice(0, 3);
      if (!terms.length) return toast("词库暂无命中词，先注入几个样本");
      toast(`正在按词根回溯 ${terms.join("、")}…`);
      try {
        const r = await api("/api/discover/search", { method: "POST", body: JSON.stringify({ terms }) });
        toast(`回溯入队 ${r.queued} 条`);
        loadDiscover();
      } catch (e) {
        toast(`回溯失败：${e.message}`);
      }
    });
  }

  const gLoad = $("#btn-graph-load");
  if (gLoad) {
    gLoad.addEventListener("click", () => {
      const key = ($("#graph-key") || {}).value || "";
      if (!key.includes(":")) return toast("格式：domain:example.com");
      loadGraphNode(key);
    });
  }
  const gOverview = $("#btn-graph-overview");
  if (gOverview) gOverview.addEventListener("click", loadGraphOverview);

  const gRebuild = $("#btn-graph-rebuild");
  if (gRebuild) {
    gRebuild.addEventListener("click", async () => {
      toast("重建图中…");
      try {
        const r = await api("/api/graph/rebuild", { method: "POST" });
        toast(`图已重建：${r.edges} 条边，${(r.campaigns || {}).communities || 0} 个簇`);
        loadGraphOverview();
      } catch (e) {
        toast(`重建失败：${e.message}`);
      }
    });
  }

  const runCycle = $("#btn-run-cycle");
  if (runCycle) {
    runCycle.addEventListener("click", async () => {
      toast("执行一轮…");
      try {
        const r = await api("/api/ops/cycle", { method: "POST" });
        toast(`完成：研判 ${r.scanned || 0}，富化 ${r.enriched || 0}`);
        loadOps();
      } catch (e) {
        toast(`执行失败：${e.message}`);
      }
    });
  }

  const runReplica = $("#btn-run-replica");
  if (runReplica) {
    runReplica.addEventListener("click", async () => {
      try {
        const r = await api("/api/ops/replica", { method: "POST" });
        toast(r.ok ? `副本已同步：${r.event_bytes || 0} 字节` : `副本未同步：${r.reason || r.error || ""}`);
        loadOps();
      } catch (e) {
        toast(e.message);
      }
    });
  }

  const verify = $("#btn-verify-chain");
  if (verify) {
    verify.addEventListener("click", async () => {
      try {
        const r = await api("/api/ops/verify");
        const el = r.eventlog || {};
        const ec = r.evidence_chain || {};
        if (el.ok && ec.ok) {
          toast(`校验通过：事件 ${el.checked} 条，证据 ${ec.checked} 条`);
        } else {
          const bad = !el.ok ? el : ec;
          toast(`校验失败：第 ${bad.broken_at ?? "?"} 条 — ${bad.reason || "存在断点"}`);
        }
      } catch (e) {
        toast(e.message);
      }
    });
  }

  const feed = $("#discover-feed");
  if (feed) {
    feed.addEventListener("click", (ev) => {
      const row = ev.target.closest("[data-asset]");
      if (row) window.openAsset(Number(row.dataset.asset));
    });
  }

  /* ---- 取证 ---- */
  const runCapture = $("#btn-run-capture");
  if (runCapture) {
    runCapture.addEventListener("click", async () => {
      runCapture.disabled = true;
      toast("正在取证，两个目标通常需要 10–40 秒…");
      try {
        const r = await api("/api/capture/run?limit=2", { method: "POST" });
        toast(r.ok ? `完成 ${r.ok} 个，失败 ${r.failed || 0} 个` : `没有可执行的任务（排队 ${r.queued ?? 0}）`);
        loadOps();
      } catch (e) {
        toast(`取证失败：${e.message}`);
      } finally {
        runCapture.disabled = false;
      }
    });
  }

  /* ---- 监控批量同步 ---- */
  const sync = $("#btn-watch-sync");
  if (sync) {
    sync.addEventListener("click", async () => {
      try {
        const r = await api("/api/watch/sync", { method: "POST", body: JSON.stringify({ limit: 120 }) });
        toast(`检查 ${r.considered} 个高危目标，新增 ${r.added}，清理 ${r.removed}`);
        window.loadWatch && window.loadWatch();
      } catch (e) {
        toast(e.message);
      }
    });
  }

  /* ---- 团伙重建 ---- */
  const rebuild = $("#btn-campaign-rebuild");
  if (rebuild) {
    rebuild.addEventListener("click", async () => {
      rebuild.disabled = true;
      toast("正在重新归并…");
      try {
        const r = await api("/api/graph/rebuild", { method: "POST" });
        toast(`已归并：${r.edges} 条边，${(r.campaigns || {}).communities || 0} 个簇`);
        window.switchView("campaigns");
      } catch (e) {
        toast(`归并失败：${e.message}`);
      } finally {
        rebuild.disabled = false;
      }
    });
  }

  /* ---- 设置：AI ---- */
  const llmSave = $("#btn-llm-save");
  if (llmSave) {
    llmSave.addEventListener("click", async () => {
      llmSave.disabled = true;
      try {
        const data = await api("/api/settings/llm", {
          method: "POST",
          body: JSON.stringify({
            base_url: ($("#set-llm-base") || {}).value || "",
            api_key: ($("#set-llm-key") || {}).value || "",
            model: ($("#set-llm-model") || {}).value || "",
            enabled: !!($("#set-llm-enabled") || {}).checked,
            gray_low: Number(($("#set-llm-low") || {}).value || 0),
            gray_high: Number(($("#set-llm-high") || {}).value || 100),
          }),
        });
        if (window.ssRefillSettings) window.ssRefillSettings(data);
        window.loadHealth && window.loadHealth();
        toast("已保存，下一次研判即生效");
      } catch (e) {
        toast(`保存失败：${e.message}`);
      } finally {
        llmSave.disabled = false;
      }
    });
  }

  const llmTest = $("#btn-llm-test");
  if (llmTest) {
    llmTest.addEventListener("click", async () => {
      const out = $("#llm-test-result");
      if (out) out.textContent = "测试中…";
      llmTest.disabled = true;
      try {
        const r = await api("/api/settings/llm/test", {
          method: "POST",
          body: JSON.stringify({
            base_url: ($("#set-llm-base") || {}).value || "",
            api_key: ($("#set-llm-key") || {}).value || "",
            model: ($("#set-llm-model") || {}).value || "",
          }),
        });
        if (out) {
          out.textContent = r.ok
            ? `连通正常 · ${r.model || ""} · ${Math.round((r.elapsed || 0) * 1000)}ms · 回复「${r.reply || ""}」`
            : `失败：${r.error || "未知原因"}`;
          out.className = r.ok ? "hint ok-text" : "hint warn-text";
        }
      } catch (e) {
        if (out) { out.textContent = `失败：${e.message}`; out.className = "hint warn-text"; }
      } finally {
        llmTest.disabled = false;
      }
    });
  }

  /* ---- 设置：出口 ---- */
  const egSave = $("#btn-egress-save");
  if (egSave) {
    egSave.addEventListener("click", async () => {
      const picked = document.querySelector('input[name="egress-mode"]:checked');
      egSave.disabled = true;
      try {
        const data = await api("/api/settings/egress", {
          method: "POST",
          body: JSON.stringify({
            mode: picked ? picked.value : "auto",
            proxies: ($("#set-egress-proxies") || {}).value || "",
          }),
        });
        if (window.ssRefillSettings) window.ssRefillSettings(data);
        window.loadHealth && window.loadHealth();
        toast("出口设置已生效（不用重启）");
      } catch (e) {
        toast(`保存失败：${e.message}`);
      } finally {
        egSave.disabled = false;
      }
    });
  }

  const egClear = $("#btn-egress-clear");
  if (egClear) {
    egClear.addEventListener("click", async () => {
      if (!window.confirm("清空全部代理？清空后「仅代理」模式会拒绝取证。")) return;
      try {
        const data = await api("/api/settings/egress", {
          method: "POST",
          body: JSON.stringify({ mode: (document.querySelector('input[name="egress-mode"]:checked') || {}).value || "auto", proxies: "-" }),
        });
        if (window.ssRefillSettings) window.ssRefillSettings(data);
        toast("已清空代理");
      } catch (e) {
        toast(e.message);
      }
    });
  }

  /* ---- 设置：APK 配额 ---- */
  const capSave = $("#btn-capture-save");
  if (capSave) {
    capSave.addEventListener("click", async () => {
      capSave.disabled = true;
      try {
        const data = await api("/api/settings/capture", {
          method: "POST",
          body: JSON.stringify({
            apk_max_mb: Number(($("#set-apk-max") || {}).value || 50),
            apk_daily_mb: Number(($("#set-apk-daily") || {}).value || 300),
            apk_tiers: ($("#set-apk-tiers") || {}).value || "",
          }),
        });
        if (window.ssRefillSettings) window.ssRefillSettings(data);
        toast("配额已保存");
      } catch (e) {
        toast(`保存失败：${e.message}`);
      } finally {
        capSave.disabled = false;
      }
    });
  }

  connectStream();
});
