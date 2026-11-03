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
};

const VERDICT_LABEL = {
  confirmed: "确认涉诈",
  high_risk: "高度可疑",
  suspicious: "可疑",
  low: "低风险",
  insufficient: "证据不足",
  benign: "已排除",
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
  if (score >= 70) return "#ff5f56";
  if (score >= 40) return "#ffa94d";
  if (score >= 15) return "#ffd43b";
  return "#4ade80";
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
  const loaders = {
    overview: loadOverview,
    discover: loadDiscover,
    assets: loadAssets,
    graph: loadGraphView,
    campaigns: loadCampaigns,
    watch: loadWatch,
    ops: loadOps,
    rules: loadRules,
  };
  if (loaders[view]) loaders[view]();
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
  const s = await api("/api/stats");

  const kpis = [
    { num: s.total_assets, lab: "线索总数", cls: "" },
    { num: s.pending_action, lab: "待处置（高危及确认）", cls: "danger" },
    { num: s.recent_7d, lab: "近 7 天新增", cls: "warn" },
    { num: s.campaigns, lab: "归并团伙", cls: "" },
    { num: s.reports, lab: "已生成举报材料", cls: "good" },
  ];
  $("#kpis").innerHTML = kpis.map(k => `
    <div class="kpi ${k.cls}">
      <div class="num">${k.num}</div>
      <div class="lab">${k.lab}</div>
    </div>`).join("");

  renderBars($("#verdict-chart"), s.by_verdict, v => VERDICT_LABEL[v] || v);
  renderBars($("#category-chart"), s.by_category, x => x, "category");

  const top = s.top_assets || [];
  $("#top-assets").innerHTML = top.length ? top.map(a => `
    <div class="row-item" data-asset="${a.id}">
      <div class="row-main">
        <strong>${escapeHtml(a.value)}</strong>
        <span>${escapeHtml(a.kind)} · ${fmtTime(a.last_seen)} · ${a.scan_count} 次扫描</span>
      </div>
      <div class="row-meta">${badge(a.verdict)}</div>
      <div class="score-chip"><b>${a.score}</b></div>
    </div>`).join("") : `<div class="empty">还没有线索。去「研判台」输入第一条可疑链接或安装包。</div>`;

  $$("#top-assets .row-item").forEach(el => el.addEventListener("click", () => openAsset(el.dataset.asset)));
}

const VERDICT_COLOR = {
  confirmed: "#ff5f56",
  high_risk: "#ffa94d",
  suspicious: "#ffd43b",
  insufficient: "#5b7189",
  low: "#4ade80",
  benign: "#22d3ee",
};

const CATEGORY_PALETTE = ["#4da3ff", "#22d3ee", "#a78bfa", "#ffa94d", "#ff5f56", "#4ade80"];

function renderBars(container, data, labelFn = x => x, mode = "verdict") {
  const entries = Object.entries(data || {}).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  if (!entries.length) { container.innerHTML = `<div class="empty">暂无数据</div>`; return; }
  const max = Math.max(...entries.map(([, v]) => v));

  container.innerHTML = entries.map(([k, v], i) => {
    const color = mode === "verdict"
      ? (VERDICT_COLOR[k] || "#4da3ff")
      : CATEGORY_PALETTE[i % CATEGORY_PALETTE.length];
    return `
      <div class="bar-row">
        <div class="bar-label">${escapeHtml(labelFn(k))}</div>
        <div class="bar-track">
          <div class="bar-fill" style="width:${Math.round((v / max) * 100)}%;background:linear-gradient(90deg,${color}55,${color})"></div>
        </div>
        <div class="bar-val">${v}</div>
      </div>`;
  }).join("");
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
      <div class="signal" style="border-left-color:#22d3ee">
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
          <div class="gauge" style="background:conic-gradient(${color} ${Math.round(a.score * 3.6)}deg, #1b2938 0deg)">
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

/* ---------------- 线索库 ---------------- */

async function loadAssets() {
  const params = new URLSearchParams();
  if (state.verdict) params.set("verdict", state.verdict);
  if (state.query) params.set("q", state.query);
  const data = await api(`/api/assets?${params.toString()}`);

  if (!data.items.length) {
    $("#asset-table").innerHTML = `<div class="empty">没有匹配的线索。</div>`;
    return;
  }

  $("#asset-table").innerHTML = `
    <table>
      <thead><tr>
        <th class="col-verdict">判定</th><th>标识</th><th class="col-kind">类型</th>
        <th class="col-score">风险分</th><th class="col-conf">置信</th>
        <th class="col-time">最近发现</th><th class="col-count">次数</th>
      </tr></thead>
      <tbody>
        ${data.items.map(a => `
          <tr data-asset="${a.id}">
            <td>${badge(a.verdict)}</td>
            <td class="clip">${escapeHtml(a.value)}</td>
            <td class="mono">${escapeHtml(a.kind)}</td>
            <td class="mono" style="color:${scoreColor(a.score)}">${a.score}</td>
            <td class="mono">${a.confidence.toFixed(2)}</td>
            <td class="mono">${fmtTime(a.last_seen)}</td>
            <td class="mono">${a.scan_count}</td>
          </tr>`).join("")}
      </tbody>
    </table>`;

  $$("#asset-table tbody tr").forEach(tr => tr.addEventListener("click", () => openAsset(tr.dataset.asset)));
}

/* ---------------- 详情抽屉 ---------------- */

async function openAsset(id) {
  try {
    const a = await api(`/api/assets/${id}`);
    state.currentAsset = a;

    const signals = (a.signals || []).map(s => `
      <div class="signal">
        <div>
          <div class="t">${escapeHtml(s.title)} <span class="rule-id">${escapeHtml(s.rule_id)}</span></div>
          ${s.detail ? `<div class="d">${escapeHtml(s.detail)}</div>` : ""}
          ${s.evidence ? `<div class="d">依据：${escapeHtml(s.evidence)}</div>` : ""}
        </div>
        <div class="w">${s.weight.toFixed(0)} · ${s.confidence.toFixed(2)}</div>
      </div>`).join("") || `<div class="empty">无信号</div>`;

    const evidence = (a.evidence || []).map(e => `
      <div class="signal" style="border-left-color:#2a3b4f">
        <div>
          <div class="t">${escapeHtml(e.kind)} · ${escapeHtml(e.note || "")}</div>
          <div class="d">SHA-256 ${escapeHtml(e.sha256.slice(0, 32))}… · ${e.size} 字节 · ${fmtTime(e.captured_at)}</div>
        </div>
      </div>`).join("") || `<div class="empty">无归档证据</div>`;

    $("#drawer-title").textContent = a.kind.toUpperCase();
    $("#drawer-body").innerHTML = `
      <div>${badge(a.verdict)} <span class="hint">风险分 ${a.score} · 置信 ${a.confidence}</span></div>
      <div class="result-title" style="margin-top:10px">${escapeHtml(a.value)}</div>

      <dl class="kv" style="margin-top:16px">
        <dt>规范化</dt><dd>${escapeHtml(a.normalized)}</dd>
        <dt>首次发现</dt><dd>${fmtTime(a.first_seen)}</dd>
        <dt>最近发现</dt><dd>${fmtTime(a.last_seen)}</dd>
        <dt>团伙</dt><dd>${a.campaign ? escapeHtml(a.campaign.name) : "未归并"}</dd>
        <dt>复核</dt><dd>${a.reviewed_by ? escapeHtml(a.reviewed_by) : "未复核"}</dd>
      </dl>

      <div class="section-title">判定信号（${(a.signals || []).length}）</div>
      ${signals}

      <div class="section-title">证据链（${(a.evidence || []).length}）</div>
      ${evidence}

      <div class="section-title">处置</div>
      <div class="row" style="flex-wrap:wrap">
        <select id="report-channel" style="flex:1;min-width:180px">
          <option value="12321">12321 网络不良信息举报</option>
          <option value="12377">12377 网信办举报</option>
          <option value="cyberpolice">公安部网络违法犯罪举报</option>
          <option value="12315">12315 市场监管</option>
          <option value="96110">96110 反诈专线（话术卡）</option>
          <option value="registrar">域名注册商滥用举报</option>
        </select>
        <button class="btn primary sm" id="btn-gen-report">生成举报材料</button>
      </div>
      <div id="report-box"></div>

      <div class="advice">
        <h3>给家属的建议</h3>
        <ol>${(a.advice || []).map(x => `<li>${escapeHtml(x)}</li>`).join("")}</ol>
      </div>`;

    $("#btn-gen-report").addEventListener("click", () => generateReport(a.id));
    $("#drawer").classList.add("show");
    $("#drawer-mask").classList.add("show");
  } catch (e) {
    toast(e.message);
  }
}

async function generateReport(id) {
  const channel = $("#report-channel").value;
  $("#report-box").innerHTML = `<div class="empty"><span class="spinner"></span>生成中</div>`;
  try {
    const r = await api(`/api/assets/${id}/report?channel=${channel}`, { method: "POST" });
    $("#report-box").innerHTML = `
      <div class="row" style="justify-content:space-between">
        <span class="hint">已保存草稿 #${r.id}，可直接全选复制</span>
        <button class="btn sm ghost" id="btn-copy">复制</button>
      </div>
      <pre class="report">${escapeHtml(r.body)}</pre>`;
    $("#btn-copy").addEventListener("click", async () => {
      await navigator.clipboard.writeText(r.body);
      toast("已复制到剪贴板");
    });
  } catch (e) {
    $("#report-box").innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  }
}

function closeDrawer() {
  $("#drawer").classList.remove("show");
  $("#drawer-mask").classList.remove("show");
}

/* ---------------- 团伙 / 监控 / 规则 ---------------- */

async function loadCampaigns() {
  const data = await api("/api/campaigns");
  $("#campaign-list").innerHTML = data.items.length ? data.items.map(c => `
    <div class="row-item" style="cursor:default">
      <div class="row-main">
        <strong>${escapeHtml(c.name)}</strong>
        <span>${c.assets} 个资产 · 首次 ${fmtTime(c.first_seen)} · 最近 ${fmtTime(c.last_seen)}</span>
      </div>
      <div class="row-meta"><span class="badge insufficient">${escapeHtml(c.status)}</span></div>
      <div class="score-chip"><b>${c.assets}</b></div>
    </div>`).join("") : `<div class="empty">还没有形成团伙。同一套模板/证书/收款地址的资产会自动归并。</div>`;
}

async function loadWatch() {
  const [w, runs] = await Promise.all([api("/api/watch"), api("/api/runs")]);
  $("#watch-list").innerHTML = w.items.length ? w.items.map(t => `
    <div class="row-item" style="cursor:default">
      <div class="row-main">
        <strong>${escapeHtml(t.value)}</strong>
        <span>${escapeHtml(t.kind)} · 每 ${t.interval_minutes} 分钟 · 上次 ${fmtTime(t.last_run_at)}</span>
      </div>
      <div class="row-meta"><span class="badge ${t.enabled ? "low" : "insufficient"}">${t.enabled ? "启用" : "停用"}</span></div>
      <div><button class="btn sm ghost" data-del="${t.id}">删除</button></div>
    </div>`).join("") : `<div class="empty">还没有监控目标。建议先加「领鸡蛋」「国补」「民族资产解冻」等关键词。</div>`;

  $$("#watch-list [data-del]").forEach(btn => btn.addEventListener("click", async () => {
    await api(`/api/watch/${btn.dataset.del}`, { method: "DELETE" });
    toast("已删除");
    loadWatch();
  }));

  $("#run-list").innerHTML = runs.items.length ? runs.items.map(r => `
    <div class="row-item" style="cursor:default">
      <div class="row-main">
        <strong>#${r.id} · ${escapeHtml(r.trigger)} · ${escapeHtml(r.status)}</strong>
        <span>${escapeHtml(JSON.stringify(r.stats || {}))}</span>
      </div>
      <div class="row-meta"><span class="hint">${fmtTime(r.started_at)}</span></div>
      <div class="score-chip">${r.error ? "!" : "✓"}</div>
    </div>`).join("") : `<div class="empty">暂无调度记录</div>`;
}

async function loadRules() {
  const data = await api("/api/rules");
  $("#rule-list").innerHTML = data.items.map(r => `
    <div class="rule-item">
      <div class="rule-id">${escapeHtml(r.id)}</div>
      <div>${escapeHtml(r.title)} <span class="rule-cat">${escapeHtml(CATEGORY_LABEL[r.category] || r.category)}</span></div>
      <div class="rule-w">${r.weight.toFixed(0)}</div>
      <div class="rule-w">${r.confidence.toFixed(2)}</div>
    </div>`).join("");
}

/* ---------------- 初始化 ---------------- */

function bindGlobal() {
  $$(".nav-item").forEach(b => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#btn-refresh").addEventListener("click", () => { loadHealth(); switchView(state.view); });
  $("#drawer-close").addEventListener("click", closeDrawer);
  $("#drawer-mask").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", e => { if (e.key === "Escape") closeDrawer(); });

  $("#filter-q").addEventListener("input", e => {
    state.query = e.target.value.trim();
    clearTimeout(window._qf);
    window._qf = setTimeout(loadAssets, 300);
  });
  $("#filter-verdict").addEventListener("change", e => {
    state.verdict = e.target.value;
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
