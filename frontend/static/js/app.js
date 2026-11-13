/* Shared UI: language toggle, mobile drawer. */
(function () {
  const side = document.getElementById("side");
  const scrim = document.getElementById("scrim");

  function setDrawer(open) {
    side.classList.toggle("open", open);
    scrim.classList.toggle("show", open);
  }

  document.getElementById("menuBtn").addEventListener("click", function () {
    setDrawer(!side.classList.contains("open"));
  });
  scrim.addEventListener("click", function () { setDrawer(false); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") setDrawer(false); });
  document.getElementById("langBtn").addEventListener("click", window.CG.toggle);

  // Readable label for a stored scan target (messages are stored as a length only).
  window.CG.targetLabel = function (type, target) {
    return type === "phishing" ? CG.t("msg") + " (" + CG.num(target) + " " + CG.t("chars") + ")" : target;
  };

  // One history row: dot, "label ·", target (own bidi isolate, so ellipsis cuts the right end), meta.
  window.CG.scanRow = function (dot, label, target, meta) {
    const mk = function (tag, cls, text) { const e = document.createElement(tag); e.className = cls; e.textContent = text; return e; };
    const row = mk("div", "row", ""), main = mk("span", "main-t flexrow", "");
    main.append(mk("span", "lbl", label + " ·"), mk("bdi", "tgt", target));
    row.append(mk("span", "dot " + dot, ""), main, mk("span", "meta", meta));
    return row;
  };

  // Global system-status pill (from the engine's real incident state).
  const pill = document.getElementById("sysPill");
  let sysState = null;
  function drawPill() {
    if (!sysState || !pill) return;
    pill.hidden = false; pill.className = "status-pill ss-" + sysState;
    pill.title = window.CG.t("sys_pill");
    document.getElementById("sysText").textContent = window.CG.t("ss_" + sysState);
  }
  async function pollStatus() {
    try {
      const r = await fetch("/api/engine/stats", { headers: { Accept: "application/json" } });
      const j = await r.json();
      if (j.ok) { sysState = j.system_status; drawPill(); }
    } catch (e) { /* offline pill simply stays hidden */ }
  }
  document.addEventListener("cg:lang", drawPill);
  pollStatus();
  setInterval(function () { if (!document.hidden) pollStatus(); }, 8000);

  // ---- one shared live-stream connection per page, plus alert toasts on every page
  const listeners = {}, openFns = [];
  let es = null, isOpen = false;
  function connect() {
    if (es || !window.EventSource) return;
    es = new EventSource("/api/stream");
    es.onopen = function () { isOpen = true; openFns.forEach(function (f) { f(); }); };
    es.onerror = function () { isOpen = false; };
    ["sim", "event", "alert", "timeline", "incident", "action", "reset"].forEach(function (t) {
      es.addEventListener(t, function (ev) {
        let d;
        try { d = JSON.parse(ev.data); } catch (e) { return; }
        (listeners[t] || []).forEach(function (f) { try { f(d); } catch (e) { console.error(e); } });
      });
    });
  }
  window.CG.on = function (topic, fn) { (listeners[topic] = listeners[topic] || []).push(fn); connect(); };
  window.CG.onOpen = function (fn) { openFns.push(fn); if (isOpen) fn(); connect(); };

  const toasts = document.getElementById("toasts");
  window.CG.on("alert", function (d) {
    if (!toasts) return;
    const t = document.createElement("a");
    t.href = "/soc"; t.className = "toast sev-" + d.severity;
    const h = document.createElement("strong"); h.textContent = window.CG.t("toast_alert") + " · " + window.CG.t("sev_" + d.severity);
    const p = document.createElement("span"); p.textContent = (d.title && d.title[window.CG.lang]) || d.rule_id;
    t.append(h, p);
    toasts.prepend(t);
    while (toasts.children.length > 3) toasts.lastChild.remove();
    setTimeout(function () { t.remove(); }, 7000);
  });

  window.CG.apply();
})();
