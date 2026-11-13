/* Dashboard: renders only real data returned by /api/stats. */
(function () {
  const CIRC = 326.7;
  const TYPE_KEY = { url: "nav_url", phishing: "nav_phish", file: "nav_file" };
  const VERDICT_DOT = { safe: "safe", suspicious: "warn", dangerous: "danger" };
  const EMPTY = { total_scans: 0, threats: 0, suspicious_urls: 0, files_analyzed: 0,
                  protection: null, activity: [], recent: [], alerts: [] };
  let data = EMPTY;

  const $ = function (id) { return document.getElementById(id); };
  const SVGNS = "http://www.w3.org/2000/svg";

  function emptyNote(box, key) {
    box.replaceChildren();
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = CG.t(key);
    box.appendChild(p);
  }

  function renderStats() {
    document.querySelectorAll("[data-stat]").forEach(function (el) {
      el.textContent = CG.num(data[el.dataset.stat] || 0);
    });
  }

  function renderGauge() {
    const g = $("gauge"), bar = $("gaugeBar"), p = data.protection;
    g.classList.remove("is-safe", "is-warn", "is-danger");
    if (p === null || p === undefined) {
      $("gaugeNum").textContent = "—";
      $("gaugeState").textContent = CG.t("pr_none");
      bar.style.strokeDashoffset = CIRC;
      return;
    }
    const level = p >= 80 ? "safe" : p >= 50 ? "warn" : "danger";
    g.classList.add("is-" + level);
    $("gaugeNum").textContent = CG.num(Math.round(p)) + "%";
    $("gaugeState").textContent = CG.t(p >= 80 ? "pr_good" : p >= 50 ? "pr_mid" : "pr_low");
    bar.classList.add("animate");
    bar.style.strokeDashoffset = (CIRC * (1 - p / 100)).toFixed(1);
  }

  function renderChart() {
    const box = $("chart"), a = data.activity || [];
    const max = a.reduce(function (m, d) { return Math.max(m, d.count); }, 0);
    if (!a.length || max === 0) { emptyNote(box, "ch_empty"); return; }
    const W = 350, H = 200, pad = 22, bw = 30, step = (W - pad * 2) / a.length;
    const svg = document.createElementNS(SVGNS, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("role", "img");
    a.forEach(function (d, i) {
      const h = Math.max(2, (d.count / max) * (H - 56));
      const x = pad + i * step + (step - bw) / 2;
      const r = document.createElementNS(SVGNS, "rect");
      r.setAttribute("class", "bar"); r.setAttribute("x", x); r.setAttribute("y", H - 24 - h);
      r.setAttribute("width", bw); r.setAttribute("height", h); r.setAttribute("rx", 4);
      svg.appendChild(r);
      [["val", H - 28 - h, CG.num(d.count)], ["axis", H - 8, String(d.day).slice(5)]].forEach(function (s) {
        const t = document.createElementNS(SVGNS, "text");
        t.setAttribute("class", s[0]); t.setAttribute("x", x + bw / 2);
        t.setAttribute("y", s[1]); t.setAttribute("text-anchor", "middle");
        t.textContent = s[2]; svg.appendChild(t);
      });
    });
    box.replaceChildren(svg);
  }

  function row(dotClass, text, meta) {
    const r = document.createElement("div"); r.className = "row";
    const d = document.createElement("span"); d.className = "dot " + dotClass;
    const t = document.createElement("span"); t.className = "main-t"; t.textContent = text;
    const m = document.createElement("span"); m.className = "meta"; m.textContent = meta;
    r.append(d, t, m); return r;
  }

  function fmt(ts) {
    const d = new Date(ts);
    return isNaN(d) ? "" : d.toLocaleString(CG.lang === "ar" ? "ar-u-nu-latn" : "en-GB",
      { dateStyle: "short", timeStyle: "short" });
  }

  function renderLists() {
    const rec = $("recent"), al = $("alerts");
    if (!data.recent.length) emptyNote(rec, "rc_empty");
    else rec.replaceChildren.apply(rec, data.recent.map(function (s) {
      return CG.scanRow(VERDICT_DOT[s.verdict] || "", CG.t(TYPE_KEY[s.type] || "nav_dash"), CG.targetLabel(s.type, s.target), fmt(s.time));
    }));
    if (!data.alerts.length) emptyNote(al, "al_empty");
    else al.replaceChildren.apply(al, data.alerts.map(function (x) {
      return CG.scanRow(x.level === "danger" ? "danger" : "warn",
        CG.t(x.level === "danger" ? "al_danger" : "al_warn") + " · " + CG.t(TYPE_KEY[x.type] || "nav_dash"),
        CG.targetLabel(x.type, x.target), fmt(x.time));
    }));
  }

  function render() { renderStats(); renderGauge(); renderChart(); renderLists(); }

  document.addEventListener("cg:lang", render);

  fetch("/api/stats", { headers: { Accept: "application/json" } })
    .then(function (r) { return r.ok ? r.json() : EMPTY; })
    .catch(function () { return EMPTY; })
    .then(function (j) { data = Object.assign({}, EMPTY, j); render(); });
})();
