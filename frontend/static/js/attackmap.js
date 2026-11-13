/* CYRO attack map. Offline dotted world map; arcs are drawn from the origin stored on each real
   engine event (simulated origins are illustrative SIM-NN nodes) to the protected server. */
(function () {
  CG.add({
    ar: { mp_attack: "هجوم نفذ", mp_blocked: "تم حظره", mp_local: "مستخدم محلي", mp_server: "الخادم المحمي",
          mp_note: "مصادر الهجوم في المحاكاة نقاط توضيحية (SIM) ولا تمثل مواقع أو دول حقيقية.",
          mp_origins: "المصادر", mp_passed: "نفذت", mp_blk: "حُظرت", mp_tip_allowed: "محاولات نفذت", mp_tip_blocked: "محاولات محظورة", mp_tip_last: "آخر نشاط",
          mp_empty: "ستظهر الهجمات هنا لحظة حدوثها. شغّل محاكاة من المختبر." },
    en: { mp_attack: "Attack passed", mp_blocked: "Blocked", mp_local: "Local user", mp_server: "Protected server",
          mp_note: "Attack origins in the simulation are illustrative SIM points and do not represent real locations or countries.",
          mp_origins: "Origins", mp_passed: "Passed", mp_blk: "Blocked", mp_tip_allowed: "Attempts passed", mp_tip_blocked: "Attempts blocked", mp_tip_last: "Last activity",
          mp_empty: "Attacks appear here the moment they happen. Run a simulation from the lab." }
  });

  const LON0 = -180, LON1 = 180, LAT0 = 80, LAT1 = -58, ASPECT = (LAT0 - LAT1) / (LON1 - LON0);
  let dotsPromise = null;
  const loadDots = function () {
    return dotsPromise || (dotsPromise = fetch("/static/data/world-dots.json").then(function (r) { return r.json(); })
      .then(function (j) { return j.dots; }).catch(function () { return []; }));
  };
  const css = function (n, fallback) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim() || fallback; };
  const instances = [];

  function mount(box) {
    const server = [Number(box.dataset.lat), Number(box.dataset.lon)];
    const legendBox = box.parentNode.querySelector(".map-legend");
    const base = document.createElement("canvas"), over = document.createElement("canvas"), tip = document.createElement("div");
    base.className = "map-canvas"; over.className = "map-canvas over"; tip.className = "map-tip"; tip.hidden = true;
    box.append(base, over, tip);
    const bctx = base.getContext("2d"), octx = over.getContext("2d");
    const S = { w: 0, h: 0, dpr: 1, dots: [], nodes: new Map(), arcs: [], hover: null, passed: 0, blocked: 0, dirty: true };
    const col = { danger: "#EF4444", safe: "#22C55E", accent: "#00A3FF", dot: "#3D5073" };

    const proj = function (lon, lat) { return [((lon - LON0) / (LON1 - LON0)) * S.w, ((LAT0 - lat) / (LAT0 - LAT1)) * S.h]; };

    function drawBase() {
      bctx.setTransform(S.dpr, 0, 0, S.dpr, 0, 0);
      bctx.clearRect(0, 0, S.w, S.h);
      bctx.fillStyle = col.dot;
      const r = Math.max(1.05, S.w / 760);
      bctx.beginPath();
      S.dots.forEach(function (d) { const p = proj(d[0], d[1]); bctx.moveTo(p[0] + r, p[1]); bctx.arc(p[0], p[1], r, 0, 6.2832); });
      bctx.fill();
    }
    function resize() {
      const w = Math.floor(box.getBoundingClientRect().width);
      if (w < 100) return;
      S.w = w; S.h = Math.round(w * ASPECT); S.dpr = window.devicePixelRatio || 1;
      box.style.height = S.h + "px";
      [base, over].forEach(function (c) { c.width = Math.round(S.w * S.dpr); c.height = Math.round(S.h * S.dpr); });
      drawBase();
    }

    function colorFor(node) { return node.local ? col.accent : node.last === "dropped" ? col.safe : col.danger; }

    let lastPaint = 0;
    function frame(now) {
      if (!box.isConnected) return;
      if (document.hidden || now - lastPaint < 40) { requestAnimationFrame(frame); return; }
      lastPaint = now;
      octx.setTransform(S.dpr, 0, 0, S.dpr, 0, 0);
      octx.clearRect(0, 0, S.w, S.h);
      const sp = proj(server[1], server[0]);
      // protected server marker with a slow radar ring
      const ring = (now % 2400) / 2400;
      octx.strokeStyle = col.accent; octx.globalAlpha = 0.5 * (1 - ring); octx.lineWidth = 1.5;
      octx.beginPath(); octx.arc(sp[0], sp[1], 6 + ring * 16, 0, 6.2832); octx.stroke();
      octx.globalAlpha = 1; octx.fillStyle = col.accent;
      octx.beginPath(); octx.arc(sp[0], sp[1], 5, 0, 6.2832); octx.fill();
      octx.strokeStyle = "#FFFFFF"; octx.lineWidth = 1.5; octx.beginPath(); octx.arc(sp[0], sp[1], 5, 0, 6.2832); octx.stroke();
      octx.fillStyle = "#E8F0FB"; octx.font = "600 " + Math.max(10, S.w / 85) + "px Segoe UI, Tahoma, sans-serif";
      octx.textAlign = "start"; octx.fillText(CG.t("mp_server"), sp[0] + 10, sp[1] - 8);

      S.nodes.forEach(function (n) {
        const p = proj(n.lon, n.lat), c = colorFor(n), age = now - n.ts;
        if (age < 2600) {
          octx.strokeStyle = c; octx.globalAlpha = 0.6 * (1 - age / 2600); octx.lineWidth = 1.4;
          octx.beginPath(); octx.arc(p[0], p[1], 4 + (age / 2600) * 14, 0, 6.2832); octx.stroke();
        }
        octx.globalAlpha = 1; octx.fillStyle = c;
        octx.beginPath(); octx.arc(p[0], p[1], 3 + Math.min(3, Math.log2(n.passed + n.blocked + 1) / 2), 0, 6.2832); octx.fill();
      });

      S.arcs = S.arcs.filter(function (a) {
        const age = now - a.t0, dur = 1000, fade = 1400;
        if (age > dur + fade) return false;
        const p = Math.min(1, age / dur) * a.reach, f = age > dur ? 1 - (age - dur) / fade : 1;
        const x0 = a.from[0], y0 = a.from[1], x1 = a.to[0], y1 = a.to[1];
        const mx = (x0 + x1) / 2, my = (y0 + y1) / 2 - Math.hypot(x1 - x0, y1 - y0) * 0.28;
        const at = function (t) { const u = 1 - t; return [u * u * x0 + 2 * u * t * mx + t * t * x1, u * u * y0 + 2 * u * t * my + t * t * y1]; };
        octx.strokeStyle = a.color; octx.globalAlpha = 0.9 * f; octx.lineWidth = a.thin ? 1 : 1.8;
        octx.beginPath();
        for (let i = 0; i <= 30; i++) { const t = (i / 30) * p; const q = at(t); if (i === 0) octx.moveTo(q[0], q[1]); else octx.lineTo(q[0], q[1]); }
        octx.stroke();
        const h = at(p);
        octx.globalAlpha = f; octx.fillStyle = a.color; octx.beginPath(); octx.arc(h[0], h[1], 2.8, 0, 6.2832); octx.fill();
        if (age > dur) {                                    // impact: red flash if it got through, green shield ring if blocked
          octx.globalAlpha = 0.7 * f; octx.strokeStyle = a.color; octx.lineWidth = 2;
          octx.beginPath(); octx.arc(h[0], h[1], 4 + ((age - dur) / fade) * 12, 0, 6.2832); octx.stroke();
        }
        octx.globalAlpha = 1;
        return true;
      });
      if (S.dirty) { S.dirty = false; legend(); }
      requestAnimationFrame(frame);
    }

    function legend() {
      if (!legendBox) return;
      const item = function (color, text) {
        const s = document.createElement("span"); s.className = "lg-item";
        const d = document.createElement("i"); d.style.background = color;
        s.append(d, document.createTextNode(text)); return s;
      };
      const stat = document.createElement("span"); stat.className = "lg-stat";
      stat.textContent = CG.t("mp_origins") + ": " + CG.num(S.nodes.size) + "  ·  " + CG.t("mp_passed") + ": " + CG.num(S.passed) + "  ·  " + CG.t("mp_blk") + ": " + CG.num(S.blocked);
      legendBox.replaceChildren(item(col.danger, CG.t("mp_attack")), item(col.safe, CG.t("mp_blocked")), item(col.accent, CG.t("mp_local")), stat);
    }

    function add(e, animate) {
      const g = e.details && e.details.geo;
      if (!g) return;
      const code = (e.details && e.details.origin) || e.source, local = code === "LOCAL", key = local ? "L:" + e.source : code;
      let n = S.nodes.get(key);
      if (!n) { n = { code: code, lon: g[1], lat: g[0], passed: 0, blocked: 0, ts: -1e9, kind: null, last: null, local: local }; S.nodes.set(key, n); }
      n.lon = g[1]; n.lat = g[0]; n.kind = e.kind; n.last = e.outcome;
      if (e.outcome === "dropped") { n.blocked++; S.blocked++; } else { n.passed++; S.passed++; }
      S.dirty = true;
      if (!animate) return;
      const now = performance.now();
      n.ts = now;
      const a = { from: proj(g[1], g[0]), to: proj(server[1], server[0]), t0: now, thin: local,
                  color: local ? col.accent : e.outcome === "dropped" ? col.safe : col.danger, reach: e.outcome === "dropped" ? 0.86 : 1 };
      S.arcs.push(a);
      if (S.arcs.length > 160) S.arcs.shift();
    }
    function set(list) {
      S.nodes.clear(); S.arcs = []; S.passed = S.blocked = 0;
      (list || []).forEach(function (e) { add(e, false); });
      S.dirty = true;
    }
    function clear() { set([]); }

    over.addEventListener("pointermove", function (ev) {
      const r = over.getBoundingClientRect(), x = ev.clientX - r.left, y = ev.clientY - r.top;
      let best = null, bd = 16;
      S.nodes.forEach(function (n) { const p = proj(n.lon, n.lat), d = Math.hypot(p[0] - x, p[1] - y); if (d < bd) { bd = d; best = n; } });
      if (!best) { tip.hidden = true; return; }
      const title = document.createElement("strong"); title.textContent = best.local ? CG.t("mp_local") : best.code;
      const l1 = document.createElement("div"); l1.textContent = CG.t("mp_tip_allowed") + ": " + CG.num(best.passed);
      const l2 = document.createElement("div"); l2.textContent = CG.t("mp_tip_blocked") + ": " + CG.num(best.blocked);
      const l3 = document.createElement("div"); l3.className = "dim"; l3.textContent = CG.t("mp_tip_last") + ": " + (best.kind ? CG.t("k_" + best.kind) : "-");
      tip.replaceChildren(title, l1, l2, l3); tip.hidden = false;
      tip.style.left = Math.min(S.w - 170, Math.max(4, x + 12)) + "px"; tip.style.top = Math.max(4, y - 10) + "px";
    });
    over.addEventListener("pointerleave", function () { tip.hidden = true; });

    new ResizeObserver(resize).observe(box);
    document.addEventListener("cg:lang", function () { S.dirty = true; });
    loadDots().then(function (d) { S.dots = d; resize(); });
    resize(); legend(); requestAnimationFrame(frame);
    const api = { add: function (e) { add(e, true); }, set: set, clear: clear };
    instances.push(api);
    return api;
  }

  window.AttackMap = { mount: mount };
})();
