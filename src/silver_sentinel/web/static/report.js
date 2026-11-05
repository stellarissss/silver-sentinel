/* 半自动举报面板。
   分工：服务端准备证据与填表载荷，浏览器扩展负责把字段填进去。
   扩展不在时退化为「下载证据包 + 打开举报页 + 复制正文」，人照样能完成。 */

const REPORT = {
  assetId: 0,
  channelId: "",
  data: null,
  built: null,
  loading: false,
};

const FILL_LABEL = { auto: "可自动填充", semi: "半自动填充", mailto: "生成邮件", guide: "人工填写" };
const CAPTCHA_LABEL = { image: "图形验证码", slider: "滑块验证", turnstile: "人机校验", none: "" };
const ATTACH_LABEL = { multi: "可附多附件", single: "可附附件", none: "不支持附件" };

function extReady() {
  return document.documentElement.dataset.ssExt === "1";
}

async function mountReport(assetId) {
  REPORT.assetId = assetId;
  REPORT.channelId = "";
  REPORT.built = null;
  const box = $("#report-panel");
  if (!box) return;
  box.innerHTML = `<div class="empty"><span class="spinner"></span>正在判定类别</div>`;
  await loadReportPreview("");
}

async function loadReportPreview(channelId) {
  const box = $("#report-panel");
  if (!box) return;
  box.innerHTML = `<div class="empty"><span class="spinner"></span>准备材料</div>`;
  try {
    const data = await api(`/api/report/preview?asset_id=${REPORT.assetId}&channel=${encodeURIComponent(channelId)}`);
    REPORT.data = data;
    REPORT.channelId = data.channel.id;
    renderReportPanel();
  } catch (e) {
    box.innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  }
}

function renderReportPanel() {
  const box = $("#report-panel");
  const d = REPORT.data;
  if (!box || !d) return;

  const chips = (c) => {
    const out = [];
    if (c.id === d.routes[0]?.id) out.push(`<span class="chip on">推荐</span>`);
    if (c.login_required) out.push(`<span class="chip warn">需登录</span>`);
    if (CAPTCHA_LABEL[c.captcha]) out.push(`<span class="chip">${CAPTCHA_LABEL[c.captcha]}</span>`);
    if (c.attachment !== "none") out.push(`<span class="chip">${ATTACH_LABEL[c.attachment]}</span>`);
    out.push(`<span class="chip dim">${FILL_LABEL[c.fill] || c.fill}</span>`);
    return out.join("");
  };

  const cards = d.routes.map((c) => `
    <button class="chan-card ${c.id === REPORT.channelId ? "active" : ""}" data-chan="${c.id}">
      <div class="chan-name">${escapeHtml(c.short)}</div>
      <div class="chan-op">${escapeHtml(c.operator)}</div>
      <div class="chan-chips">${chips(c)}</div>
    </button>`).join("");

  const over = d.body_limit && d.body_length > d.body_limit;

  box.innerHTML = `
    <div class="harm-bar">
      <div>
        <span class="harm-label">${escapeHtml(d.harm.label)}</span>
        <span class="hint">${escapeHtml(d.harm.reason)}</span>
      </div>
    </div>

    <div class="chan-grid">${cards}</div>

    <div class="section-title" style="margin-top:16px">举报正文
      <span class="hint" id="body-count">${d.body_length}${d.body_limit ? " / " + d.body_limit : ""} 字</span>
    </div>
    <textarea id="report-body" class="report-input ${over ? "over" : ""}" rows="12" ${d.body_limit ? `maxlength="${d.body_limit}"` : ""}>${escapeHtml(d.body)}</textarea>

    <div class="row" style="margin-top:10px;flex-wrap:wrap;gap:8px">
      <button class="btn primary sm" id="btn-build">生成证据包并打开举报页</button>
      <button class="btn sm ghost" id="btn-copy-body">复制正文</button>
      <button class="btn sm ghost" id="btn-download">只下载证据包</button>
    </div>
    <div class="guide-list">${d.guide.map((g) => `<div>· ${escapeHtml(g)}</div>`).join("")}</div>
    <div id="report-result"></div>`;

  $$(".chan-card", box).forEach((el) =>
    el.addEventListener("click", () => loadReportPreview(el.dataset.chan)));

  const ta = $("#report-body");
  ta.addEventListener("input", () => {
    $("#body-count").textContent = `${ta.value.length}${d.body_limit ? " / " + d.body_limit : ""} 字`;
    ta.classList.toggle("over", d.body_limit > 0 && ta.value.length > d.body_limit);
  });

  $("#btn-build").addEventListener("click", () => buildReport(true));
  $("#btn-download").addEventListener("click", () => buildReport(false));
  $("#btn-copy-body").addEventListener("click", async () => {
    await navigator.clipboard.writeText(ta.value);
    toast("正文已复制");
  });
}

async function buildReport(openAfter) {
  const bodyEl = $("#report-body");
  const btn = $("#btn-build");
  if (btn) btn.disabled = true;
  $("#report-result").innerHTML = `<div class="empty"><span class="spinner"></span>正在生成证据包（PDF + ZIP + 哈希）</div>`;
  try {
    const r = await api("/api/report/build", {
      method: "POST",
      body: JSON.stringify({
        asset_id: REPORT.assetId,
        channel: REPORT.channelId,
        harm: "",
        reporter: "",
        body: bodyEl ? bodyEl.value : "",
      }),
    });
    REPORT.built = r;
    renderBuilt(r, openAfter);
  } catch (e) {
    $("#report-result").innerHTML = `<div class="empty">${escapeHtml(e.message)}</div>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderBuilt(r, openAfter) {
  const kb = (r.size / 1024).toFixed(0);
  const hasExt = extReady();
  $("#report-result").innerHTML = `
    <div class="built">
      <div class="built-head">
        <b>材料已生成</b>
        <span class="mono">${escapeHtml(r.code)}</span>
        <span class="hint">${kb} KB · PDF SHA-256 ${escapeHtml((r.pdf_sha256 || "").slice(0, 12))}…</span>
      </div>
      <div class="row" style="gap:8px;flex-wrap:wrap;margin-top:8px">
        <button class="btn primary sm" id="btn-open-fill">打开举报页并填充</button>
        <a class="btn sm ghost" href="${r.files.zip}" download>下载证据包 (ZIP)</a>
        <a class="btn sm ghost" href="${r.files.pdf}" download>下载材料 (PDF)</a>
      </div>
      <div class="hint" style="margin-top:8px">
        ${hasExt
          ? "已检测到浏览器扩展：点击后会自动打开举报页并填好字段，你只需过验证码、核对后提交。"
          : "未检测到浏览器扩展：点击会打开举报页并复制正文，证据包需手动拖入附件框。"}
      </div>
    </div>`;

  $("#btn-open-fill").addEventListener("click", () => openAndFill(r, hasExt));
  if (openAfter) openAndFill(r, hasExt);
}

async function openAndFill(r, hasExt) {
  if (hasExt) {
    window.postMessage({ type: "SS_OPEN_REPORT", code: r.code, url: r.entry_url }, location.origin);
    toast("已请求扩展打开举报页");
    return;
  }
  await navigator.clipboard.writeText(r.body).catch(() => {});
  window.open(r.entry_url, "_blank", "noopener");
  toast("已打开举报页，正文已复制；证据包在下载目录");
}

/* 扩展把「已提交／失败」回报过来，这里登记回执 */
window.addEventListener("message", async (ev) => {
  if (ev.source !== window) return;
  const d = ev.data || {};
  if (d.type === "SS_SUBMITTED" && d.code) {
    try {
      await api(`/api/report/bundles/${encodeURIComponent(d.code)}/mark`, {
        method: "POST",
        body: JSON.stringify({ status: "submitted", receipt: d.receipt || "", note: d.note || "" }),
      });
      toast("已登记回执");
    } catch (e) {
      toast("回执登记失败：" + e.message);
    }
  }
  if (d.type === "SS_EXT_RESULT") {
    if (d.ok) toast(`扩展已接管：准备填充 ${d.steps || 0} 项`);
    else toast("扩展未能打开举报页：" + (d.error || "未知错误"));
  }
  if (d.type === "SS_EXT_READY") {
    document.documentElement.dataset.ssExt = "1";
    const el = $("#report-result .hint");
    if (el) el.textContent = "已检测到浏览器扩展，可自动填充。";
  }
});

document.addEventListener("DOMContentLoaded", () => {
  if (extReady()) return;
  // 扩展注入后会立刻发一条 ready；给 300ms 让它在首屏完成握手
  window.postMessage({ type: "SS_PING_EXT" }, location.origin);
});
