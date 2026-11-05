/* 后台：取填表载荷、预置 cookie、开标签页。
   不在后台代提交——提交必须发生在人眼前，验证码也必须人过。 */

const DEFAULT_API = "http://127.0.0.1:18700";

async function getConfig() {
  const s = await chrome.storage.local.get(["apiBase", "token"]);
  return { apiBase: (s.apiBase || DEFAULT_API).replace(/\/+$/, ""), token: s.token || "" };
}

async function fetchJSON(path) {
  const { apiBase, token } = await getConfig();
  const res = await fetch(apiBase + path, {
    headers: token ? { "x-ss-token": token } : {},
    cache: "no-store",
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`请求失败 ${res.status} ${txt.slice(0, 120)}`);
  }
  return res.json();
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

async function setCookies(fill) {
  const host = hostOf(fill.entry_url);
  if (!host) return [];
  const done = [];
  for (const p of fill.pre || []) {
    if (p.action !== "cookie") continue;
    try {
      await chrome.cookies.set({
        url: `https://${host}/`,
        name: p.name,
        value: String(p.value),
        path: p.path || "/",
        secure: !!p.secure,
      });
      done.push(p.name);
    } catch (e) {
      console.warn("cookie 设置失败", p.name, e);
    }
  }
  return done;
}

async function openAndFill(code, url) {
  const fill = await fetchJSON(`/api/report/bundles/${encodeURIComponent(code)}/fill`);
  const cookies = await setCookies(fill);
  await chrome.storage.session.set({
    pending: { code, fill, cookies, at: Date.now() },
  });
  const tab = await chrome.tabs.create({ url: url || fill.entry_url, active: true });
  return { ok: true, code, tabId: tab.id, cookies, steps: (fill.steps || []).length };
}

async function reportBack(code, status, receipt, note) {
  const { apiBase, token } = await getConfig();
  const res = await fetch(`${apiBase}/api/report/bundles/${encodeURIComponent(code)}/mark`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(token ? { "x-ss-token": token } : {}) },
    body: JSON.stringify({ status, receipt: receipt || "", note: note || "" }),
  });
  return res.ok;
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case "OPEN_FILL":
          sendResponse(await openAndFill(msg.code, msg.url));
          break;
        case "GET_PENDING": {
          const { pending } = await chrome.storage.session.get("pending");
          sendResponse({ pending: pending && Date.now() - pending.at < 30 * 60 * 1000 ? pending : null });
          break;
        }
        case "GET_FILE": {
          // 附件用后台取，content script 受页面 CORS 限制
          const { apiBase, token } = await getConfig();
          const res = await fetch(`${apiBase}${msg.path}`, {
            headers: token ? { "x-ss-token": token } : {},
          });
          if (!res.ok) throw new Error(`附件下载失败 ${res.status}`);
          const buf = new Uint8Array(await res.arrayBuffer());
          const cd = res.headers.get("content-disposition") || "";
          const fromHeader = (cd.match(/filename\*=UTF-8''([^;]+)/i) || [])[1]
            || (cd.match(/filename="?([^";]+)"?/i) || [])[1];
          let name = msg.name || "evidence.bin";
          if (!msg.name && fromHeader) {
            try { name = decodeURIComponent(fromHeader); } catch { name = fromHeader; }
          }
          // 分块转 base64：附件动辄几百 KB，一次性展开会爆栈
          let bin = "";
          const CHUNK = 0x8000;
          for (let i = 0; i < buf.length; i += CHUNK) {
            bin += String.fromCharCode.apply(null, buf.subarray(i, i + CHUNK));
          }
          sendResponse({
            ok: true,
            name,
            mime: res.headers.get("content-type") || "application/octet-stream",
            data: btoa(bin),
          });
          break;
        }
        case "REPORT_BACK":
          sendResponse({ ok: await reportBack(msg.code, msg.status, msg.receipt, msg.note) });
          break;
        case "PING": {
          const { apiBase } = await getConfig();
          sendResponse({ ok: true, apiBase });
          break;
        }
        default:
          sendResponse({ ok: false, error: "unknown message" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e && e.message ? e.message : e) });
    }
  })();
  return true;   // 异步
});

chrome.runtime.onInstalled.addListener(async () => {
  const s = await chrome.storage.local.get(["apiBase"]);
  if (!s.apiBase) await chrome.storage.local.set({ apiBase: DEFAULT_API });
});
