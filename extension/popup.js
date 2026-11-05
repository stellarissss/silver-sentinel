const $ = (s) => document.querySelector(s);

async function loadState() {
  const { apiBase } = await chrome.storage.local.get("apiBase");
  const el = $("#state");
  try {
    const res = await fetch(`${(apiBase || "http://127.0.0.1:18700").replace(/\/+$/, "")}/api/health`, { cache: "no-store" });
    el.textContent = res.ok ? "已连接" : "连接异常";
    el.className = res.ok ? "ok" : "err";
  } catch {
    el.textContent = "未连接";
    el.className = "err";
  }
  const { pending } = await chrome.storage.session.get("pending");
  if (pending && pending.code) {
    $("#code").value = pending.code;
    $("#tip").textContent = `最近一次材料 ${pending.code}，共 ${(pending.fill.steps || []).length} 项待填。`;
  }
}

$("#go").addEventListener("click", async () => {
  const code = $("#code").value.trim();
  if (!code) return;
  $("#tip").textContent = "正在取材料…";
  const res = await chrome.runtime.sendMessage({ type: "OPEN_FILL", code });
  $("#tip").textContent = res && res.ok
    ? `已打开举报页，准备填 ${res.steps} 项。`
    : `失败：${(res && res.error) || "未知错误"}`;
});

$("#opt").addEventListener("click", () => chrome.runtime.openOptionsPage());
loadState();
