/* 银发哨兵 · 界面增强层
   主题、命令面板、数字滚动、请求进度线、表格排序、快捷键。
   这一层只碰表现，不碰数据与判定逻辑，任何一项失效都不影响主流程。 */
(function () {
  "use strict";

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const root = document.documentElement;

  const VIEW_LABEL = {
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

  // 别名：人说「资产」「列表」「首页」，系统里叫「线索库」「概览」
  const VIEW_ALIAS = {
    overview: "首页 总览 首页看板 kpi",
    discover: "实时 发现 ct 日志 流",
    scan: "扫描 检查 查一下 研判 查询",
    assets: "资产 线索 列表 库 域名 清单",
    graph: "图 节点 关系 网络 图谱",
    campaigns: "团伙 归并 组织 campaign",
    watch: "监控 盯防 关键词 watch",
    ops: "运维 状态 任务 日志 能力",
    rules: "规则 判定 权重 rule",
  };

  /* ---------------------------------------------------------- 主题 */
  function applyTheme(t) {
    root.setAttribute("data-theme", t);
    try { localStorage.setItem("ss-theme", t); } catch (e) {}
    const btn = $("#btn-theme");
    if (btn) btn.title = t === "dark" ? "切换到浅色" : "切换到深色";
    // 画布不会自己重算颜色，得有人喊一声
    window.dispatchEvent(new CustomEvent("ss:theme", { detail: t }));
  }

  applyTheme(root.getAttribute("data-theme") || "light");

  const themeBtn = $("#btn-theme");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      applyTheme(root.getAttribute("data-theme") === "dark" ? "light" : "dark");
    });
  }

  // 跟系统走，但只在用户没手动选过时
  try {
    const mq = matchMedia("(prefers-color-scheme: dark)");
    mq.addEventListener("change", (e) => {
      if (localStorage.getItem("ss-theme")) return;
      root.setAttribute("data-theme", e.matches ? "dark" : "light");
    });
  } catch (e) {}

  /* ---------------------------------------------------------- 请求进度线 */
  const line = $("#topline");
  let inflight = 0;
  let lineTimer = null;

  function lineStart() {
    if (!line) return;
    inflight += 1;
    clearTimeout(lineTimer);
    line.classList.add("on");
    line.style.width = "12%";
    requestAnimationFrame(() => { if (inflight) line.style.width = "68%"; });
  }

  function lineDone() {
    if (!line) return;
    inflight = Math.max(0, inflight - 1);
    if (inflight) return;
    line.style.width = "100%";
    lineTimer = setTimeout(() => {
      line.classList.remove("on");
      line.style.width = "0";
    }, 260);
  }

  const rawFetch = window.fetch;
  if (typeof rawFetch === "function") {
    window.fetch = function (...args) {
      lineStart();
      return rawFetch.apply(this, args).finally(lineDone);
    };
  }

  /* ---------------------------------------------------------- 数字滚动 */
  const seenNum = new WeakSet();

  function fmtNum(v, dec) {
    const s = dec ? v.toFixed(dec) : String(Math.round(v));
    if (!dec) return s.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    const [a, b] = s.split(".");
    return a.replace(/\B(?=(\d{3})+(?!\d))/g, ",") + (b ? "." + b : "");
  }

  function animateNum(el) {
    if (seenNum.has(el)) return;
    if (el.children.length) return;
    const text = (el.textContent || "").trim();
    if (!text || text === "…" || text === "—") return;

    const m = text.match(/-?\d[\d,]*(?:\.\d+)?/);
    if (!m) return;
    const raw = m[0];
    const num = parseFloat(raw.replace(/,/g, ""));
    if (!isFinite(num)) return;
    seenNum.add(el);
    // 0 与极小值不滚，免得看起来像卡住
    if (num === 0) return;

    const dec = (raw.split(".")[1] || "").length;
    const pre = text.slice(0, m.index);
    const post = text.slice(m.index + raw.length);
    const t0 = performance.now();
    const dur = Math.min(760, 320 + Math.log10(Math.max(num, 10)) * 150);

    function frame(t) {
      const p = Math.min(1, (t - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      el.textContent = pre + fmtNum(num * e, dec) + post;
      if (p < 1) requestAnimationFrame(frame);
      else el.textContent = text;
    }
    requestAnimationFrame(frame);
  }

  function scanNums(scope) {
    if (!scope || scope.nodeType !== 1) return;
    if (scope.matches && scope.matches(".kpi .num, .gauge-num")) animateNum(scope);
    $$(".kpi .num, .gauge-num", scope).forEach(animateNum);
  }

  let scanQueued = false;
  const pendingNodes = [];

  const numObs = new MutationObserver((muts) => {
    for (const m of muts) {
      m.addedNodes.forEach((n) => { if (n.nodeType === 1) pendingNodes.push(n); });
    }
    if (scanQueued || !pendingNodes.length) return;
    scanQueued = true;
    requestAnimationFrame(() => {
      scanQueued = false;
      const batch = pendingNodes.splice(0, pendingNodes.length);
      batch.forEach(scanNums);
    });
  });
  numObs.observe(document.body, { childList: true, subtree: true });

  /* ---------------------------------------------------------- 表格排序 */
  function cellValue(tr, idx) {
    const td = tr.children[idx];
    if (!td) return "";
    const raw = (td.textContent || "").trim();
    const num = parseFloat(raw.replace(/[^\d.-]/g, ""));
    return { raw, num: isFinite(num) ? num : null };
  }

  document.addEventListener("click", (ev) => {
    const th = ev.target.closest("#asset-table thead th, .table-wrap thead th");
    if (!th) return;
    const table = th.closest("table");
    const tbody = table && table.tBodies[0];
    if (!tbody) return;

    const idx = Array.prototype.indexOf.call(th.parentNode.children, th);
    const desc = !th.classList.contains("desc");
    Array.from(th.parentNode.children).forEach((x) => x.classList.remove("sorted", "desc"));
    th.classList.add("sorted");
    if (desc) th.classList.add("desc");

    const rows = Array.from(tbody.rows);
    rows.sort((ra, rb) => {
      const a = cellValue(ra, idx);
      const b = cellValue(rb, idx);
      if (a.num !== null && b.num !== null) return desc ? b.num - a.num : a.num - b.num;
      return desc ? b.raw.localeCompare(a.raw, "zh-CN") : a.raw.localeCompare(b.raw, "zh-CN");
    });
    rows.forEach((r) => tbody.appendChild(r));
  });

  /* ---------------------------------------------------------- 时钟 */
  const clock = $("#side-clock");
  function tick() {
    if (!clock) return;
    const d = new Date();
    clock.textContent = `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  }
  tick();
  setInterval(tick, 20000);

  /* ---------------------------------------------------------- 视图切换回顶 */
  let lastView = null;
  const viewObs = new MutationObserver(() => {
    const active = $(".view.active");
    if (active && active !== lastView) {
      lastView = active;
      window.scrollTo({ top: 0, behavior: "instant" in window ? "instant" : "auto" });
    }
  });
  $$(".view").forEach((v) => viewObs.observe(v, { attributes: true, attributeFilter: ["class"] }));

  /* ---------------------------------------------------------- 命令面板 */
  const cmdk = $("#cmdk");
  const cmdkInput = $("#cmdk-input");
  const cmdkList = $("#cmdk-list");

  let items = [];
  let sel = 0;
  let searchToken = 0;

  function baseItems() {
    const out = Object.entries(VIEW_LABEL).map(([id, label]) => ({
      type: "view",
      id,
      label,
      hint: "视图",
      key: `${label} ${id} ${VIEW_ALIAS[id] || ""}`.toLowerCase(),
      run: () => window.switchView(id),
    }));
    out.push({
      type: "action",
      label: "切换深色 / 浅色主题",
      hint: "外观",
      key: "主题 深色 浅色 暗色 外观 theme dark light",
      run: () => applyTheme(root.getAttribute("data-theme") === "dark" ? "light" : "dark"),
    });
    out.push({
      type: "action",
      label: "刷新当前视图",
      hint: "动作",
      key: "刷新 重载 更新 refresh reload",
      run: () => { window.loadHealth && window.loadHealth(); window.switchView(window.state ? window.state.view : "overview"); },
    });
    return out;
  }

  function renderList() {
    if (!cmdkList) return;
    if (!items.length) {
      cmdkList.innerHTML = `<div class="cmdk-item" style="color:var(--ink-3);cursor:default">没有匹配项</div>`;
      return;
    }
    cmdkList.innerHTML = items
      .map((it, i) => `<div class="cmdk-item${i === sel ? " sel" : ""}" data-i="${i}">
        <span>${escapeText(it.label)}</span>
        <span class="k">${escapeText(it.hint || "")}</span>
      </div>`)
      .join("");
    const cur = cmdkList.querySelector(".sel");
    if (cur) cur.scrollIntoView({ block: "nearest" });
  }

  function escapeText(v) {
    return String(v == null ? "" : v)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  async function searchAssets(q, token) {
    try {
      const res = await fetch(`/api/assets?q=${encodeURIComponent(q)}&limit=6`);
      if (!res.ok) return;
      const data = await res.json();
      if (token !== searchToken) return;
      const rows = (data.items || []).slice(0, 6).map((a) => ({
        type: "asset",
        label: `${a.value}`,
        key: `${a.value} ${a.kind} ${a.verdict}`.toLowerCase(),
        hint: `${a.verdict} · ${a.score}`,
        run: () => window.openAsset(a.id),
      }));
      items = [...rows, ...items.filter((i) => i.type !== "asset")];
      sel = 0;
      renderList();
    } catch (e) { /* 搜索失败不影响跳转 */ }
  }

  function openCmdk() {
    if (!cmdk) return;
    cmdk.classList.add("show");
    if (cmdkInput) { cmdkInput.value = ""; cmdkInput.focus(); }
    items = baseItems();
    sel = 0;
    renderList();
  }

  function closeCmdk() {
    if (!cmdk) return;
    cmdk.classList.remove("show");
    if (cmdkInput) cmdkInput.blur();
  }

  const cmdkBtn = $("#btn-cmdk");
  if (cmdkBtn) cmdkBtn.addEventListener("click", openCmdk);

  if (cmdk) {
    cmdk.addEventListener("click", (e) => { if (e.target === cmdk) closeCmdk(); });
  }

  if (cmdkInput) {
    cmdkInput.addEventListener("input", () => {
      const q = cmdkInput.value.trim();
      const token = ++searchToken;
      const low = q.toLowerCase();
      items = baseItems().filter((i) => !q || (i.key || i.label).includes(low));
      sel = 0;
      renderList();
      if (q.length >= 2) searchAssets(q, token);
    });

    cmdkInput.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { e.preventDefault(); sel = Math.min(items.length - 1, sel + 1); renderList(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); sel = Math.max(0, sel - 1); renderList(); }
      else if (e.key === "Enter") {
        e.preventDefault();
        const it = items[sel];
        if (it) { closeCmdk(); it.run(); }
      } else if (e.key === "Escape") { e.preventDefault(); closeCmdk(); }
    });
  }

  if (cmdkList) {
    cmdkList.addEventListener("click", (e) => {
      const row = e.target.closest(".cmdk-item[data-i]");
      if (!row) return;
      const it = items[Number(row.dataset.i)];
      if (it) { closeCmdk(); it.run(); }
    });
  }

  /* ---------------------------------------------------------- 快捷键 */
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((e.target.tagName || "").toUpperCase());

    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      cmdk && cmdk.classList.contains("show") ? closeCmdk() : openCmdk();
      return;
    }
    if (e.key === "Escape") {
      if (cmdk && cmdk.classList.contains("show")) { closeCmdk(); return; }
      const drawer = $("#drawer");
      if (drawer && drawer.classList.contains("show")) { window.closeDrawer && window.closeDrawer(); }
      return;
    }
    // 单键 g 开头的跳转，像 vim 那样
    if (!typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
      if (e.key === "/") { e.preventDefault(); openCmdk(); }
      if (e.key === "g") {
        window.__ssG = true;
        setTimeout(() => { window.__ssG = false; }, 900);
        return;
      }
      if (window.__ssG) {
        const map = { o: "overview", d: "discover", s: "scan", a: "assets", g: "graph", c: "campaigns", w: "watch", p: "ops", r: "rules" };
        const v = map[e.key];
        window.__ssG = false;
        if (v) { e.preventDefault(); window.switchView(v); }
      }
    }
  });

  /* ---------------------------------------------------------- 抽屉焦点回收 */
  // 抽屉打开时把焦点送进去，关闭时回到触发元素，键盘操作才连续
  let lastFocus = null;
  const drawerObs = new MutationObserver(() => {
    const drawer = $("#drawer");
    if (!drawer) return;
    if (drawer.classList.contains("show")) {
      lastFocus = document.activeElement;
      const close = $("#drawer-close");
      if (close) close.focus({ preventScroll: true });
    } else if (lastFocus && document.contains(lastFocus)) {
      lastFocus.focus({ preventScroll: true });
      lastFocus = null;
    }
  });
  const drawerEl = $("#drawer");
  if (drawerEl) drawerObs.observe(drawerEl, { attributes: true, attributeFilter: ["class"] });

  /* ---------------------------------------------------------- 骨架屏 */
  // 线上首屏要等 SQLite 聚合（近三千条线索）才出数，这一段页面是空的。
  // 空屏和坏掉的页面长得一样，用户第一反应是刷新——所以先摆占位。
  const skelRows = (n, widths) =>
    Array.from({ length: n }, (_, i) =>
      `<div class="skel-row"><span class="skel" style="width:${widths[i % widths.length]}"></span></div>`
    ).join("");

  function paintSkeleton() {
    const kpis = $("#kpis");
    if (kpis && !kpis.children.length) {
      kpis.innerHTML = Array.from({ length: 5 }, () => `
        <div class="kpi">
          <div class="skel" style="width:54%;height:30px"></div>
          <div class="skel" style="width:38%;height:10px;margin-top:11px"></div>
        </div>`).join("");
    }
    ["#verdict-chart", "#category-chart"].forEach((sel) => {
      const el = $(sel);
      if (el && !el.children.length) el.innerHTML = skelRows(4, ["58%", "51%", "46%", "39%"]);
    });
    const top = $("#top-assets");
    if (top && !top.children.length) top.innerHTML = skelRows(5, ["46%", "38%", "52%", "33%", "44%"]);
  }
  window.ssSkeleton = paintSkeleton;
})();
