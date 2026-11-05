/* 通用填表执行器。
   只认动作，不认网站——渠道改版时改服务端的 fill 载荷即可，不必重发扩展。 */

(() => {
  const MARK = "ss-filled:";

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function waitFor(selector, timeout = 8000) {
    return new Promise((resolve) => {
      const found = document.querySelector(selector);
      if (found) return resolve(found);
      const t0 = Date.now();
      const mo = new MutationObserver(() => {
        const el = document.querySelector(selector);
        if (el) {
          mo.disconnect();
          resolve(el);
        } else if (Date.now() - t0 > timeout) {
          mo.disconnect();
          resolve(null);
        }
      });
      mo.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => {
        mo.disconnect();
        resolve(document.querySelector(selector));
      }, timeout);
    });
  }

  /* React/Vue 受控组件只认原型上的 setter，直接 el.value = x 会被框架覆盖 */
  function setNativeValue(el, value) {
    const proto = el instanceof HTMLTextAreaElement
      ? HTMLTextAreaElement.prototype
      : HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new Event("blur", { bubbles: true }));
  }

  function fireChange(el) {
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  /* 12377 用了 jquery-nice-select，原生 select 被隐藏，改完值要让插件同步显示 */
  function syncNiceSelect(el) {
    const jq = window.jQuery || window.$;
    if (!jq) return;
    try {
      const $el = jq(el);
      if ($el.data("niceSelect")) $el.niceSelect("update");
    } catch (_) { /* 插件不在或版本不同，忽略 */ }
  }

  async function doFill(step) {
    const el = await waitFor(step.selector, 4000);
    if (!el) return false;
    setNativeValue(el, step.value ?? "");
    el.style.outline = "2px solid #4da3ff";
    el.style.outlineOffset = "1px";
    setTimeout(() => { el.style.outline = ""; }, 2500);
    return true;
  }

  async function doSelect(step) {
    const el = await waitFor(step.selector, 5000);
    if (!el) return false;
    let hit = null;
    if (step.value != null) {
      hit = Array.from(el.options).find((o) => o.value === String(step.value));
    }
    if (!hit && step.text) {
      hit = Array.from(el.options).find((o) => (o.textContent || "").trim().includes(step.text));
    }
    if (!hit && step.value != null) {
      hit = Array.from(el.options).find((o) => (o.textContent || "").trim() === String(step.value));
    }
    if (!hit) return false;
    el.value = hit.value;
    el.selectedIndex = hit.index;
    fireChange(el);
    syncNiceSelect(el);
    return true;
  }

  async function doRadio(step) {
    const nodes = Array.from(document.querySelectorAll(step.selector));
    const hit =
      nodes.find((n) => String(n.value) === String(step.value)) ||
      nodes.find((n) => {
        const lab = n.closest("label") || document.querySelector(`label[for="${n.id}"]`);
        return lab && (lab.textContent || "").includes(step.text || "");
      });
    if (!hit) return false;
    hit.click();
    return true;
  }

  async function doCheck(step) {
    const el = await waitFor(step.selector, 4000);
    if (!el) return false;
    if (!el.checked) el.click();
    return true;
  }

  async function doAttach(step, fill) {
    const el = await waitFor(step.selector, 5000);
    if (!el) return false;
    const kind = step.file || "zip";
    const code = fill.bundle_id;
    const res = await chrome.runtime.sendMessage({
      type: "GET_FILE",
      path: `/api/report/bundles/${encodeURIComponent(code)}/file?kind=${kind}`,
      name: (fill.file_names && fill.file_names[kind]) || "",
    });
    if (!res || !res.ok) throw new Error(res && res.error ? res.error : "附件取回失败");
    const bin = atob(res.data);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    const file = new File([arr], res.name, { type: res.mime });
    const dt = new DataTransfer();
    dt.items.add(file);
    el.files = dt.files;
    el.dispatchEvent(new Event("change", { bubbles: true }));
    // 部分站点（如 12377）依赖 name 取文件
    el.setAttribute("name", el.getAttribute("name") || "upload_file");
    return true;
  }

  function doHighlight(step) {
    const el = document.querySelector(step.selector);
    if (!el) return false;
    el.scrollIntoView({ block: "center", behavior: "smooth" });
    el.style.boxShadow = "0 0 0 3px rgba(255,95,86,.55)";
    setTimeout(() => { el.style.boxShadow = ""; }, 6000);
    if (step.note) el.setAttribute("title", step.note);
    return true;
  }

  /* 站点没有稳定 id 时按标签文字匹配：只填空框，不覆盖用户已输入的内容 */
  function doAutoLabel(step) {
    let filled = 0;
    const pairs = step.fields || [];
    for (const [label, value] of pairs) {
      if (!value) continue;
      const nodes = Array.from(document.querySelectorAll("input[type=text],input[type=url],input:not([type]),textarea"));
      for (const el of nodes) {
        if (el.value) continue;
        const lab = el.closest("label") || document.querySelector(`label[for="${el.id}"]`);
        const text = [
          lab ? lab.textContent : "",
          el.getAttribute("placeholder") || "",
          el.getAttribute("aria-label") || "",
          el.getAttribute("name") || "",
        ].join(" ").toLowerCase();
        if (text.includes(String(label).toLowerCase())) {
          setNativeValue(el, value);
          filled++;
          break;
        }
      }
    }
    return filled > 0;
  }

  async function applyAll(fill) {
    const code = fill.bundle_id;
    const results = [];
    for (const step of fill.steps || []) {
      try {
        let ok = false;
        switch (step.action) {
          case "wait":
            ok = !!(await waitFor(step.selector, step.timeout || 6000));
            break;
          case "fill":
            ok = await doFill(step);
            break;
          case "select":
            ok = await doSelect(step);
            break;
          case "radio":
            ok = await doRadio(step);
            break;
          case "check":
            ok = await doCheck(step);
            break;
          case "attach":
            ok = await doAttach(step, fill);
            break;
          case "highlight":
            ok = doHighlight(step);
            break;
          case "auto_label":
            ok = doAutoLabel(step);
            break;
          default:
            ok = false;
        }
        results.push({ step: step.action, selector: step.selector || "", ok, note: step.note || "" });
        await sleep(120);   // 给页面的联动逻辑留出时间
      } catch (e) {
        results.push({ step: step.action, ok: false, error: String(e.message || e) });
      }
    }
    return results;
  }

  /* ---------------------------------------------------------------- 悬浮条 */
  function showBar(fill, results) {
    if (document.getElementById("ss-bar-host")) return;
    const host = document.createElement("div");
    host.id = "ss-bar-host";
    host.style.cssText = "position:fixed;z-index:2147483647;right:16px;bottom:16px;";
    const root = host.attachShadow({ mode: "open" });
    const okCount = results.filter((r) => r.ok).length;
    const fails = results.filter((r) => !r.ok);
    const remaining = (fill.manual || []).join(" → ");

    root.innerHTML = `
      <style>
        .bar{font:13px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
             background:#111a24;color:#dbe6f2;border:1px solid #2a3b4f;border-radius:12px;
             padding:12px 14px;max-width:340px;box-shadow:0 8px 28px rgba(0,0,0,.45)}
        .t{font-weight:600;color:#4ade80;margin-bottom:4px}
        .m{color:#7b8fa6;font-size:12px}
        .r{color:#ffa94d;font-size:12px;margin-top:6px}
        .row{display:flex;gap:8px;margin-top:10px}
        button{font:12px/1 -apple-system,"PingFang SC",sans-serif;padding:6px 10px;border-radius:7px;
               border:1px solid #2a3b4f;background:#16212e;color:#dbe6f2;cursor:pointer}
        button.p{background:#1e5c96;border-color:#4da3ff;color:#fff}
        .x{position:absolute;right:6px;top:6px;background:none;border:0;color:#4d6076;font-size:16px;cursor:pointer}
      </style>
      <div class="bar">
        <button class="x" id="x">×</button>
        <div class="t">银发哨兵已填 ${okCount} 项</div>
        <div class="m">材料 ${fill.bundle_id}</div>
        ${remaining ? `<div class="m">还需你完成：${remaining}</div>` : ""}
        ${fails.length ? `<div class="r">${fails.length} 项未填上（页面可能改版）：${fails.slice(0,3).map((f) => f.selector).join("、")}</div>` : ""}
        <div class="row">
          <button class="p" id="done">已提交，登记回执</button>
          <button id="fail">提交失败</button>
        </div>
      </div>`;

    document.documentElement.appendChild(host);
    root.getElementById("x").onclick = () => host.remove();

    const report = async (status) => {
      const receipt = status === "submitted" ? prompt("如有受理编号／回执号，填在这里（可留空）") || "" : "";
      const res = await chrome.runtime.sendMessage({ type: "REPORT_BACK", code: fill.bundle_id, status, receipt });
      root.querySelector(".t").textContent = res && res.ok ? "回执已登记到银发哨兵" : "回执登记失败，请到控制台手动登记";
    };
    root.getElementById("done").onclick = () => report("submitted");
    root.getElementById("fail").onclick = () => report("failed");
  }

  /* ---------------------------------------------------------------- 启动 */
  async function boot() {
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: "GET_PENDING" });
    } catch (_) {
      return;   // 扩展刚更新、后台未就绪
    }
    const pending = res && res.pending;
    if (!pending || !pending.fill) return;

    const key = MARK + pending.code + location.pathname;
    if (sessionStorage.getItem(key)) return;   // 同一页刷新不重复填

    const results = await applyAll(pending.fill);
    sessionStorage.setItem(key, "1");
    if (results.some((r) => r.ok)) showBar(pending.fill, results);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => setTimeout(boot, 400));
  } else {
    setTimeout(boot, 400);
  }
})();
