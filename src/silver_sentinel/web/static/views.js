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
    const data = await api("/api/graph/overview?limit=90");
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

  graphState.nodes = (data.nodes || []).map((n, i) => ({
    ...n,
    x: w / 2 + Math.cos((i / Math.max(1, data.nodes.length)) * Math.PI * 2) * (170 + (i % 7) * 26),
    y: h / 2 + Math.sin((i / Math.max(1, data.nodes.length)) * Math.PI * 2) * (150 + (i % 5) * 22),
    vx: 0,
    vy: 0,
    r: n.type === "campaign" ? 13 : n.type === "domain" ? 9 : 6,
  }));

  const index = new Map(graphState.nodes.map((n) => [n.id, n]));
  graphState.edges = (data.edges || [])
    .map((e) => ({ ...e, a: index.get(e.source), b: index.get(e.target) }))
    .filter((e) => e.a && e.b);

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

  // 斥力：O(n²)，节点数控制在几百以内足够
  for (let i = 0; i < n; i++) {
    const a = nodes[i];
    for (let j = i + 1; j < n; j++) {
      const b = nodes[j];
      let dx = a.x - b.x;
      let dy = a.y - b.y;
      let d2 = dx * dx + dy * dy;
      if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
      const force = (2600 * alpha) / d2;
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
    const target = 128;
    const k = 0.02 * (e.weight || 0.3) * alpha * 3;
    const f = (d - target) * k;
    const fx = (dx / d) * f;
    const fy = (dy / d) * f;
    e.a.vx += fx; e.a.vy += fy;
    e.b.vx -= fx; e.b.vy -= fy;
  });

  // 向心 + 阻尼
  nodes.forEach((p) => {
    p.vx += (w / 2 - p.x) * 0.0016 * alpha;
    p.vy += (h / 2 - p.y) * 0.0016 * alpha;
    p.vx *= 0.86;
    p.vy *= 0.86;
    if (!p.fixed) {
      p.x += p.vx;
      p.y += p.vy;
    }
    p.x = Math.max(30, Math.min(w - 30, p.x));
    p.y = Math.max(30, Math.min(h - 30, p.y));
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
    ctx.strokeStyle = active ? withAlpha(accent, .55) : withAlpha(ink, .15);
    ctx.lineWidth = active ? 1.3 : Math.max(0.4, (e.weight || 0.2) * 1.1);
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

    if (isHover || graphState.scale > 1.05 || p.type === "campaign" || p.type === "domain") {
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
    const [status, tasks, events] = await Promise.all([
      api("/api/ops/status"),
      api("/api/ops/tasks?limit=20"),
      api("/api/ops/events?limit=40"),
    ]);
    renderCapabilities(status.capabilities || {});
    renderRuntime(status);
    renderTasks(tasks.items || []);
    renderEventTail(events.items || []);
  } catch (e) {
    toast(`运维数据加载失败：${e.message}`);
  }
}

const CAP_LABEL = {
  network: "外网访问",
  ct_stream: "CT 实时流",
  icp: "ICP 备案",
  graph: "关系图谱",
  sandbox_web: "网页沙箱",
  sandbox_apk: "APK 沙箱",
  replica: "异地副本",
  llm: "LLM 研判",
};

function renderCapabilities(caps) {
  const el = $("#capability-grid");
  if (!el) return;
  el.innerHTML = Object.entries(caps)
    .map(([k, v]) => {
      let state = "off";
      let text = String(v);
      if (v === true || v === "ready" || v === "builtin" || v === "neo4j") state = "ok";
      else if (v === "static-only" || v === "off" || v === false) state = "off";
      el.dataset.x = "";
      return `<div class="cap ${state}">
        <span class="cap-name">${escapeHtml(CAP_LABEL[k] || k)}</span>
        <span class="cap-state">${escapeHtml(text)}</span>
      </div>`;
    })
    .join("");
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
        toast(
          el.ok && ec.ok
            ? `校验通过：事件 ${el.checked} 条，证据 ${ec.checked} 条`
            : `校验失败：${el.reason || ec.reason || "存在断点"}`
        );
      } catch (e) {
        toast(e.message);
      }
    });
  }

  const feed = $("#discover-feed");
  if (feed) {
    feed.addEventListener("click", (ev) => {
      const row = ev.target.closest("[data-asset]");
      if (row) openDrawer(Number(row.dataset.asset));
    });
  }

  connectStream();
});
