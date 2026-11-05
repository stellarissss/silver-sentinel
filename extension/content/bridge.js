/* 控制台页面与扩展之间的桥。
   页面没有权限直接调扩展 API，因此走 window.postMessage ↔ chrome.runtime 中转。 */

(() => {
  const ORIGIN = location.origin;

  function announce() {
    document.documentElement.dataset.ssExt = "1";
    window.postMessage({ type: "SS_EXT_READY" }, ORIGIN);
  }

  announce();

  window.addEventListener("message", async (ev) => {
    if (ev.source !== window) return;
    const d = ev.data || {};

    if (d.type === "SS_PING_EXT") {
      announce();
      return;
    }

    if (d.type === "SS_OPEN_REPORT" && d.code) {
      try {
        const res = await chrome.runtime.sendMessage({ type: "OPEN_FILL", code: d.code, url: d.url });
        window.postMessage(
          { type: "SS_EXT_RESULT", code: d.code, ok: !!(res && res.ok), error: res && res.error, steps: res && res.steps },
          ORIGIN,
        );
      } catch (e) {
        window.postMessage({ type: "SS_EXT_RESULT", code: d.code, ok: false, error: String(e.message || e) }, ORIGIN);
      }
    }
  });
})();
