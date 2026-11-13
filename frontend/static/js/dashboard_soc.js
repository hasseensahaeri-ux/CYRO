/* Dashboard SOC section: every number is read from the engine database via /api/engine/*. */
(function () {
  CG.add({
    ar: { d_threats: "كشف التهديدات", d_refresh: "تحديث", th_more: "تفاصيل أكثر", th_none: "لا توجد تهديدات مكتشفة بعد.", th_source: "المصدر",
      tr_vs: "عن الساعة السابقة", tr_new: "نشاط جديد", ago_now: "الآن", ago_min: "د", ago_hour: "س", ago_day: "يوم",
      is_detected: "مكتشفة", is_responding: "قيد الاستجابة", is_mitigated: "تم احتواؤها", is_failed: "فشل التحقق", is_closed: "مغلقة",
      d_map: "خريطة الهجمات المباشرة", d_demo: "تشغيل عرض هجوم", d_top: "أكثر المصادر حظرًا", top_none: "لا توجد مصادر محظورة بعد.", top_events: "حدث",
      d_timeline: "الخط الزمني للكشف (آخر ساعة)", d_severity: "توزيع خطورة التهديدات", d_attacks: "إحصاءات الهجمات", d_recent: "آخر الأحداث الأمنية",
      d_scans: "نتائج فحوصات الأدوات", sys: "حالة أمان النظام", ss_secure: "آمن", ss_elevated: "مرتفع الخطورة", ss_critical: "حرج",
      m_events: "إجمالي الأحداث الأمنية", m_threats: "التهديدات المكتشفة", m_blocked: "التهديدات المحظورة", m_crit: "تنبيهات حرجة", m_active: "حوادث نشطة",
      e_none: "لا توجد أحداث بعد. شغّل محاكاة أو أجرِ فحصًا.", c_none: "لا توجد هجمات مكتشفة بعد.", t_none: "لا توجد أحداث في آخر ساعة.", s_none: "لا توجد تنبيهات بعد.",
      series_events: "الأحداث", series_alerts: "التنبيهات", total: "الإجمالي",
      sev_low: "منخفضة", sev_medium: "متوسطة", sev_high: "عالية", sev_critical: "حرجة",
      cat_brute_force: "تخمين كلمات المرور", cat_port_scan: "فحص المنافذ", cat_traffic: "حركة غير طبيعية", cat_ddos: "DDoS", cat_phishing: "التصيد", cat_url: "روابط خطيرة", cat_malware: "ملفات مشبوهة",
      k_login_failed: "فشل دخول", k_login_success: "دخول ناجح", k_conn_attempt: "اتصال بمنفذ", k_request: "طلب", k_message: "رسالة", k_file: "ملف", k_url_click: "نقر رابط", k_file_open: "فتح ملف", k_url_scan: "فحص رابط", k_comm_send: "رسالة مرسلة", k_comm_inject: "حقن حزمة", k_comm_reject: "رفض حزمة", k_comm_accept: "قبول رسالة", k_comm_intercept: "اعتراض", k_comm_handshake: "مصافحة مفاتيح", k_comm_packet: "حزمة", sess_comm: "اتصال",
      o_dropped: "محظور", o_allowed: "مسموح", sess_live: "حي", sess_sim: "محاكاة" },
    en: { d_threats: "Threat detection", d_refresh: "Refresh", th_more: "More details", th_none: "No threats detected yet.", th_source: "Source",
      tr_vs: "vs previous hour", tr_new: "new activity", ago_now: "now", ago_min: "min ago", ago_hour: "h ago", ago_day: "d ago",
      is_detected: "Detected", is_responding: "Responding", is_mitigated: "Mitigated", is_failed: "Verification failed", is_closed: "Closed",
      d_map: "Live attack map", d_demo: "Run an attack demo", d_top: "Top blocked sources", top_none: "No blocked sources yet.", top_events: "events",
      d_timeline: "Detection timeline (last hour)", d_severity: "Threat severity distribution", d_attacks: "Attack statistics", d_recent: "Recent security events",
      d_scans: "Tool scan results", sys: "System security status", ss_secure: "Secure", ss_elevated: "Elevated", ss_critical: "Critical",
      m_events: "Total security events", m_threats: "Threats detected", m_blocked: "Threats blocked", m_crit: "Critical alerts", m_active: "Active incidents",
      e_none: "No events yet. Run a simulation or a scan.", c_none: "No attacks detected yet.", t_none: "No events in the last hour.", s_none: "No alerts yet.",
      series_events: "Events", series_alerts: "Alerts", total: "Total",
      sev_low: "Low", sev_medium: "Medium", sev_high: "High", sev_critical: "Critical",
      cat_brute_force: "Brute force", cat_port_scan: "Port scan", cat_traffic: "Abnormal traffic", cat_ddos: "DDoS", cat_phishing: "Phishing", cat_url: "Dangerous links", cat_malware: "Suspicious files",
      k_login_failed: "Login failed", k_login_success: "Login ok", k_conn_attempt: "Port connect", k_request: "Request", k_message: "Message", k_file: "File", k_url_click: "Link click", k_file_open: "File open", k_url_scan: "URL scan", k_comm_send: "Message sent", k_comm_inject: "Packet injected", k_comm_reject: "Packet rejected", k_comm_accept: "Message accepted", k_comm_intercept: "Intercept", k_comm_handshake: "Key handshake", k_comm_packet: "Packet", sess_comm: "comm",
      o_dropped: "Blocked", o_allowed: "Allowed", sess_live: "live", sess_sim: "simulation" }
  });
  CG.apply();          // translations were added after the first apply
  const el = CG.el, $ = function (id) { return document.getElementById(id); };
  const NS = "http://www.w3.org/2000/svg";
  const SEV = ["low", "medium", "high", "critical"], SEV_COL = { low: "#1769FF", medium: "#F59E0B", high: "#EF4444", critical: "#B91C1C" };
  let stats = null, buckets = [], events = [], top = [], threats = [];
  const openTh = new Set();
  const map = AttackMap.mount($("attackMap"));
  const svgEl = function (tag, attrs, title) {
    const e = document.createElementNS(NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (title) { const t = document.createElementNS(NS, "title"); t.textContent = title; e.appendChild(t); }
    return e;
  };
  const empty = function (key) { return el("p", "empty", CG.t(key)); };

  // Change vs the previous hour; "polarity" says whether an increase is good, bad or just informational.
  function delta(tr, polarity) {
    if (!tr || (!tr.now && !tr.prev)) return null;
    if (!tr.prev) return { text: CG.t("tr_new"), cls: "info" };
    const pct = Math.round(((tr.now - tr.prev) / tr.prev) * 100);
    if (!pct) return { text: "0% " + CG.t("tr_vs"), cls: "info" };
    const up = pct > 0;
    const cls = polarity === "info" ? "info" : (up === (polarity === "good")) ? "good" : "bad";
    return { text: (up ? "▲ " : "▼ ") + CG.num(Math.abs(pct)) + "% " + CG.t("tr_vs"), cls: cls };
  }
  function ago(t) {
    const m = Math.max(0, Math.round((Date.now() - new Date(String(t)).getTime()) / 60000));
    if (m < 1) return CG.t("ago_now");
    if (m < 60) return CG.num(m) + " " + CG.t("ago_min");
    if (m < 1440) return CG.num(Math.round(m / 60)) + " " + CG.t("ago_hour");
    return CG.num(Math.round(m / 1440)) + " " + CG.t("ago_day");
  }
  function drawThreats() {
    const box = $("threatList");
    if (!threats.length) { box.replaceChildren(empty("th_none")); return; }
    box.replaceChildren.apply(box, threats.map(function (i) {
      const open = openTh.has(i.id), item = el("div", "acc-item" + (open ? " open" : ""));
      const head = el("button", "acc-head"); head.type = "button"; head.setAttribute("aria-expanded", open ? "true" : "false");
      head.append(el("span", "dot " + (i.severity === "critical" || i.severity === "high" ? "danger" : i.severity === "medium" ? "warn" : "")),
                  el("span", "acc-title", i.title[CG.lang]), el("span", "meta", ago(i.created_at)), el("span", "chev", open ? "▴" : "▾"));
      head.addEventListener("click", function () { if (openTh.has(i.id)) openTh.delete(i.id); else openTh.add(i.id); drawThreats(); });
      item.appendChild(head);
      if (open) {
        const body = el("div", "acc-body"), chips = el("div", "chips");
        chips.append(el("span", "chip on", i.rule_id), el("span", "chip", CG.t("th_source") + ": " + (i.source === "distributed" ? "…" : i.source)),
                     el("span", "badge st-" + i.status, CG.t("is_" + i.status)));
        const more = el("a", "btn btn-ghost btn-sm", CG.t("th_more")); more.href = "/soc#inc-" + i.id;
        body.append(el("p", "", i.analysis.summary[CG.lang]), chips, more);
        item.appendChild(body);
      }
      return item;
    }));
  }

  function drawStrip() {
    const box = $("dashStrip");
    if (!stats) return;
    const st = el("div", "ss ss-" + stats.system_status);
    st.append(el("span", "k", CG.t("sys")), el("strong", "", CG.t("ss_" + stats.system_status)));
    const kids = [st];
    [["m_events", stats.events, "events", "info"], ["m_threats", stats.alerts, "alerts", "bad"], ["m_blocked", stats.dropped, "dropped", "good"],
     ["m_crit", stats.critical_alerts], ["m_active", stats.active_incidents]].forEach(function (m) {
      const c = el("div", "metric"); c.append(el("span", "k", CG.t(m[0])), el("strong", "", CG.num(m[1])));
      const dl = m[2] ? delta(stats.trends && stats.trends[m[2]], m[3]) : null;
      if (dl) c.append(el("span", "delta " + dl.cls, dl.text));
      kids.push(c);
    });
    box.replaceChildren.apply(box, kids);
  }

  function drawTimeline() {
    const box = $("tlChart"), max = buckets.reduce(function (m, b) { return Math.max(m, b.events, b.alerts); }, 0);
    if (!max) { box.replaceChildren(empty("t_none")); return; }
    const W = 600, H = 200, pl = 28, pb = 22, pt = 10, n = buckets.length;
    const x = function (i) { return pl + (i * (W - pl - 8)) / (n - 1 || 1); }, y = function (v) { return H - pb - (v / max) * (H - pb - pt); };
    const svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, role: "img" });
    [0, 0.5, 1].forEach(function (f) {
      svg.appendChild(svgEl("line", { x1: pl, x2: W - 8, y1: y(max * f), y2: y(max * f), class: "grid" }));
      const t = svgEl("text", { x: 2, y: y(max * f) - 4, class: "axis big" }); t.textContent = Math.round(max * f); svg.appendChild(t);
    });
    [["events", "line-events"], ["alerts", "line-alerts"]].forEach(function (s) {
      svg.appendChild(svgEl("polyline", { points: buckets.map(function (b, i) { return x(i) + "," + y(b[s[0]]); }).join(" "), class: "line " + s[1] }));
      buckets.forEach(function (b, i) {
        const when = new Date(b.t * 1000).toLocaleTimeString(CG.lang === "ar" ? "ar-u-nu-latn" : "en-GB", { hour: "2-digit", minute: "2-digit" });
        svg.appendChild(svgEl("circle", { cx: x(i), cy: y(b[s[0]]), r: 4, class: "pt " + s[1] }, when + " · " + CG.t("series_" + s[0]) + ": " + b[s[0]]));
      });
    });
    [0, Math.floor(n / 2), n - 1].forEach(function (i) {
      const t = svgEl("text", { x: x(i), y: H - 5, class: "axis big", "text-anchor": "middle" });
      t.textContent = new Date(buckets[i].t * 1000).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }); svg.appendChild(t);
    });
    const legend = el("div", "chips");
    legend.append(el("span", "chip on", "● " + CG.t("series_events")), el("span", "chip danger-chip", "● " + CG.t("series_alerts")));
    box.replaceChildren(svg, legend);
  }

  function drawSeverity() {
    const box = $("sevChart"), sev = stats ? stats.by_severity : {}, total = SEV.reduce(function (a, k) { return a + (sev[k] || 0); }, 0);
    if (!total) { box.replaceChildren(empty("s_none")); return; }
    const R = 40, C = 2 * Math.PI * R, svg = svgEl("svg", { viewBox: "0 0 120 120", class: "donut" });
    svg.appendChild(svgEl("circle", { cx: 60, cy: 60, r: R, fill: "none", stroke: "#1F2A3D", "stroke-width": 16 }));
    let off = 0;
    SEV.forEach(function (k) {
      const v = sev[k] || 0; if (!v) return;
      const len = (v / total) * C;
      svg.appendChild(svgEl("circle", { cx: 60, cy: 60, r: R, fill: "none", stroke: SEV_COL[k], "stroke-width": 16, class: "arc",
        "stroke-dasharray": len + " " + (C - len), "stroke-dashoffset": -off, transform: "rotate(-90 60 60)" }, CG.t("sev_" + k) + ": " + v));
      off += len;
    });
    const mid = svgEl("text", { x: 60, y: 60, "text-anchor": "middle", class: "donut-n" }); mid.textContent = total; svg.appendChild(mid);
    const sub = svgEl("text", { x: 60, y: 76, "text-anchor": "middle", class: "axis" }); sub.textContent = CG.t("total"); svg.appendChild(sub);
    const legend = el("div", "legend");
    SEV.forEach(function (k) {
      const r = el("div", "lg"); const d = el("span", "dot"); d.style.background = SEV_COL[k];
      r.append(d, el("span", "", CG.t("sev_" + k)), el("strong", "", CG.num(sev[k] || 0))); legend.appendChild(r);
    });
    box.replaceChildren(el("div", "donut-wrap"), legend);
    box.firstChild.appendChild(svg);
  }

  function drawCategories() {
    const box = $("catChart"), cats = stats ? stats.by_category : {}, keys = Object.keys(cats).sort(function (a, b) { return cats[b] - cats[a]; });
    if (!keys.length) { box.replaceChildren(empty("c_none")); return; }
    const max = cats[keys[0]];
    box.replaceChildren.apply(box, keys.map(function (k) {
      const row = el("div", "hbar"), fill = el("div", "hfill"), track = el("div", "htrack");
      fill.style.width = Math.max(4, Math.round((cats[k] / max) * 100)) + "%";
      track.appendChild(fill); row.title = CG.t("cat_" + k) + ": " + cats[k];
      row.append(el("span", "hl", CG.t("cat_" + k)), track, el("strong", "hv", CG.num(cats[k])));
      return row;
    }));
  }

  function drawEvents() {
    const box = $("evList");
    if (!events.length) { box.replaceChildren(empty("e_none")); return; }
    box.replaceChildren.apply(box, events.map(function (e) {
      const when = new Date(e.ts * 1000).toLocaleTimeString(CG.lang === "ar" ? "ar-u-nu-latn" : "en-GB");
      const src = e.source === "distributed" ? "…" : e.source;
      return CG.scanRow(e.outcome === "dropped" ? "safe" : "", CG.t("k_" + e.kind) + " · " + CG.t(e.session === "live" ? "sess_live" : String(e.session).indexOf("comm-") === 0 ? "sess_comm" : "sess_sim"),
                        src + " → " + e.target, CG.t("o_" + e.outcome) + " · " + when);
    }));
  }

  function drawTop() {
    const box = $("topList");
    if (!top.length) { box.replaceChildren(empty("top_none")); return; }
    box.replaceChildren.apply(box, top.map(function (s) {
      const r = el("div", "row");
      r.append(el("span", "dot danger"), el("span", "main-t mono", s.source), el("span", "meta", CG.num(s.events) + " " + CG.t("top_events")));
      return r;
    }));
  }
  function draw() { drawThreats(); drawTop(); drawStrip(); drawTimeline(); drawSeverity(); drawCategories(); drawEvents(); }
  async function load() {
    const [s, t, e, tp, th] = await Promise.all([CG.apiGet("/api/engine/stats"), CG.apiGet("/api/engine/timeline?span=3600&bucket=300"),
      CG.apiGet("/api/engine/events?limit=8"), CG.apiGet("/api/engine/top-sources?limit=5"), CG.apiGet("/api/engine/incidents?limit=6")]);
    if (s.ok) stats = s; if (t.ok) buckets = t.buckets; if (e.ok) events = e.events; if (tp.ok) top = tp.sources; if (th.ok) threats = th.incidents;
    draw();
  }
  document.addEventListener("cg:lang", draw);
  $("thRefresh").addEventListener("click", load);
  let timer = null;
  const soon = function () { clearTimeout(timer); timer = setTimeout(load, 700); };
  async function loadMap() { const r = await CG.apiGet("/api/engine/map?limit=300"); if (r.ok) map.set(r.events); }
  ["alert", "incident"].forEach(function (t) { CG.on(t, soon); });
  CG.on("event", function (d) { map.add(d); });
  CG.on("reset", function () { loadMap(); soon(); });
  loadMap();
  setInterval(function () { if (!document.hidden) load(); }, 6000);
  load();
})();
