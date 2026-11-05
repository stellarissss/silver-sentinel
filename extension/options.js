const $ = (s) => document.querySelector(s);

chrome.storage.local.get(["apiBase", "token"]).then((s) => {
  $("#api").value = s.apiBase || "http://127.0.0.1:18700";
  $("#token").value = s.token || "";
});

$("#save").addEventListener("click", async () => {
  const apiBase = ($("#api").value || "").trim().replace(/\/+$/, "");
  const token = ($("#token").value || "").trim();
  const msg = $("#msg");

  if (!/^https?:\/\//.test(apiBase)) {
    msg.className = "err";
    msg.textContent = "地址需以 http:// 或 https:// 开头";
    return;
  }

  await chrome.storage.local.set({ apiBase, token });

  try {
    const res = await fetch(`${apiBase}/api/health`, { headers: token ? { "x-ss-token": token } : {} });
    const data = await res.json();
    msg.className = "ok";
    msg.textContent = `已保存。服务版本 ${data.version || "?"}，${data.ok === false ? "状态异常" : "连接正常"}。`;
  } catch (e) {
    msg.className = "err";
    msg.textContent = `已保存，但连不上：${e.message}`;
  }

  // 跨域访问服务器上的哨兵时，需要额外授权该来源
  try {
    const origin = new URL(apiBase).origin + "/*";
    const granted = await chrome.permissions.contains({ origins: [origin] });
    if (!granted) await chrome.permissions.request({ origins: [origin] });
  } catch (_) { /* 本机地址已在 manifest 里，无需再申请 */ }
});
