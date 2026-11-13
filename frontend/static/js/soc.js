/* SOC Center. All data comes from the engine's database and the live /api/stream feed. */
(function () {
  CG.add({
    ar: { t_live: "المراقبة المباشرة", t_alerts: "إدارة التنبيهات", t_incidents: "تتبع الحوادث", t_rules: "قواعد الكشف", t_logs: "السجلات الأمنية",
      c_rate: "معدل الأحداث (آخر 5 دقائق)", sys: "حالة النظام", ss_secure: "آمن", ss_elevated: "مرتفع الخطورة", ss_critical: "حرج",
      m_events: "الأحداث", m_alerts: "التنبيهات", m_active: "حوادث نشطة", m_blocked: "محاولات محظورة", m_crit: "تنبيهات حرجة",
      h_id: "#", h_time: "الوقت", h_sev: "الخطورة", h_rule: "القاعدة", h_source: "المصدر", h_target: "الهدف", h_status: "الحالة", h_actions: "إجراءات",
      h_title: "العنوان", h_name: "الاسم", h_cond: "شروط الكشف", h_desc: "الوصف", h_count: "التنبيهات", h_kind: "النوع", h_outcome: "النتيجة", h_session: "الجلسة", h_details: "التفاصيل",
      a_ack: "اعتماد", a_resolve: "حل", a_reopen: "إعادة فتح", a_close: "إغلاق الحادثة", pdf_ar: "تقرير PDF عربي", pdf_en: "PDF Report English",
      al_open: "مفتوح", al_acknowledged: "معتمد", al_resolved: "محلول",
      i_summary: "ملخص التحليل", i_timeline: "الخط الزمني", i_actions: "الإجراءات الدفاعية", i_evidence: "الأدلة", i_verified: "تم التحقق", i_not: "لم يتم التحقق",
      empty_alerts: "لا توجد تنبيهات. ستظهر هنا عند اكتشاف تهديد.", empty_inc: "لا توجد حوادث بعد.", empty_logs: "لا توجد سجلات مطابقة.", empty_live: "بانتظار الأحداث… شغّل محاكاة أو أجرِ فحصًا.", empty_chart: "لا توجد أحداث في آخر 5 دقائق.",
      l_probes: "إظهار أحداث التحقق", l_apply: "تطبيق", f_all_kinds: "كل الأنواع", f_all_out: "كل النتائج", f_all_sess: "كل الجلسات",
      o_allowed: "مسموح", o_dropped: "محظور", sess_live: "فحوصات حية", sess_sim: "محاكاة",
      sev_low: "منخفضة", sev_medium: "متوسطة", sev_high: "عالية", sev_critical: "حرجة",
      is_detected: "مكتشفة", is_responding: "قيد الاستجابة", is_mitigated: "تم احتواؤها", is_failed: "فشل التحقق", is_closed: "مغلقة",
      st_detection: "كشف", st_analysis: "تحليل", st_incident: "حادثة", st_response: "استجابة", st_verification: "تحقق", st_mitigated: "احتواء", st_failed: "فشل", st_report: "تقرير", st_closed: "إغلاق",
      k_login_failed: "فشل دخول", k_login_success: "دخول ناجح", k_conn_attempt: "اتصال بمنفذ", k_request: "طلب", k_message: "رسالة", k_file: "ملف",
      k_url_click: "نقر رابط", k_file_open: "فتح ملف", k_url_scan: "فحص رابط", k_comm_send: "رسالة مرسلة", k_comm_inject: "حقن حزمة", k_comm_reject: "رفض حزمة", k_comm_accept: "قبول رسالة", k_comm_intercept: "اعتراض", k_comm_handshake: "مصافحة مفاتيح", k_comm_packet: "حزمة", sess_comm: "مختبر الاتصال", distributed: "مصادر موزعة",
      err_incident_active: "لا يمكن إغلاق حادثة ما زالت قيد الاستجابة." },
    en: { t_live: "Live monitoring", t_alerts: "Alert management", t_incidents: "Incident tracking", t_rules: "Detection rules", t_logs: "Security logs",
      c_rate: "Event rate (last 5 minutes)", sys: "System status", ss_secure: "Secure", ss_elevated: "Elevated", ss_critical: "Critical",
      m_events: "Events", m_alerts: "Alerts", m_active: "Active incidents", m_blocked: "Blocked attempts", m_crit: "Critical alerts",
      h_id: "#", h_time: "Time", h_sev: "Severity", h_rule: "Rule", h_source: "Source", h_target: "Target", h_status: "Status", h_actions: "Actions",
      h_title: "Title", h_name: "Name", h_cond: "Detection conditions", h_desc: "Description", h_count: "Alerts", h_kind: "Type", h_outcome: "Outcome", h_session: "Session", h_details: "Details",
      a_ack: "Acknowledge", a_resolve: "Resolve", a_reopen: "Reopen", a_close: "Close incident", pdf_ar: "PDF report (Arabic)", pdf_en: "PDF report (English)",
      al_open: "Open", al_acknowledged: "Acknowledged", al_resolved: "Resolved",
      i_summary: "Analysis summary", i_timeline: "Timeline", i_actions: "Defensive actions", i_evidence: "Evidence", i_verified: "Verified", i_not: "Not verified",
      empty_alerts: "No alerts. They appear here when a threat is detected.", empty_inc: "No incidents yet.", empty_logs: "No matching logs.", empty_live: "Waiting for events… run a simulation or a scan.", empty_chart: "No events in the last 5 minutes.",
      l_probes: "Show verification events", l_apply: "Apply", f_all_kinds: "All types", f_all_out: "All outcomes", f_all_sess: "All sessions",
      o_allowed: "Allowed", o_dropped: "Blocked", sess_live: "Live scans", sess_sim: "Simulation",
      sev_low: "Low", sev_medium: "Medium", sev_high: "High", sev_critical: "Critical",
      is_detected: "Detected", is_responding: "Responding", is_mitigated: "Mitigated", is_failed: "Verification failed", is_closed: "Closed",
      st_detection: "Detection", st_analysis: "Analysis", st_incident: "Incident", st_response: "Response", st_verification: "Verification", st_mitigated: "Mitigated", st_failed: "Failed", st_report: "Report", st_closed: "Closed",
      k_login_failed: "Login failed", k_login_success: "Login ok", k_conn_attempt: "Port connect", k_request: "Request", k_message: "Message", k_file: "File",
      k_url_click: "Link click", k_file_open: "File open", k_url_scan: "URL scan", k_comm_send: "Message sent", k_comm_inject: "Packet injected", k_comm_reject: "Packet rejected", k_comm_accept: "Message accepted", k_comm_intercept: "Intercept", k_comm_handshake: "Key handshake", k_comm_packet: "Packet", sess_comm: "Comm lab", distributed: "Distributed sources",
      err_incident_active: "An incident that is still being handled cannot be closed." }
  });

  const el = CG.el, $ = function (id) { return document.getElementById(id); };
  const L = function (o) { return o ? o[CG.lang] : ""; };
  const KINDS = ["comm_send", "comm_inject", "comm_intercept", "comm_reject", "comm_accept", "comm_handshake", "login_failed", "login_success", "conn_attempt", "request", "message", "file", "url_scan", "url_click", "file_open"];
  let tab = "live", stats = null, alerts = [], incidents = [], rules = [], logs = [], sessions = [], live = [], openInc = null, buckets = [];
  const time = function (ts) { return new Date(ts * 1000).toLocaleTimeString(CG.lang === "ar" ? "ar-u-nu-latn" : "en-GB"); };
  const stamp = function (t) { const d = new Date(String(t)); return isNaN(d) ? "" : d.toLocaleString(CG.lang === "ar" ? "ar-u-nu-latn" : "en-GB", { dateStyle: "short", timeStyle: "medium" }); };
  const sess = function (s) { return s === "live" ? CG.t("sess_live") : String(s).indexOf("comm-") === 0 ? CG.t("sess_comm") : CG.t("sess_sim") + " " + String(s).replace("sim-", "").slice(-5); };
  const badge = function (cls, text) { return el("span", "badge " + cls, text); };
  const src = function (s) { return s === "distributed" ? CG.t("distributed") : s; };

  function table(cols, rows, emptyKey) {
    if (!rows.length) return el("p", "empty", CG.t(emptyKey));
    const t = el("table", "tbl"), hr = el("tr");
    cols.forEach(function (c) { hr.appendChild(el("th", "", CG.t(c.h))); });
    t.appendChild(el("thead")).appendChild(hr);
    const body = el("tbody");
    rows.forEach(function (r) {
      const tr = el("tr");
      if (r._click) { tr.className = "clickable"; tr.addEventListener("click", r._click); }
      cols.forEach(function (c) { const td = el("td"); const v = c.v(r); if (v instanceof Node) td.appendChild(v); else td.textContent = v; tr.appendChild(td); });
      body.appendChild(tr);
    });
    t.appendChild(body);
    return t;
  }

  // ---------- header strip ----------
  function drawStrip() {
    const box = $("socStrip");
    if (!stats) { box.replaceChildren(); return; }
    const status = el("div", "ss ss-" + stats.system_status);
    status.append(el("span", "k", CG.t("sys")), el("strong", "", CG.t("ss_" + stats.system_status)));
    const kids = [status];
    [["m_events", stats.events], ["m_alerts", stats.alerts], ["m_crit", stats.critical_alerts], ["m_active", stats.active_incidents], ["m_blocked", stats.dropped]].forEach(function (m) {
      const c = el("div", "metric"); c.append(el("span", "k", CG.t(m[0])), el("strong", "", CG.num(m[1]))); kids.push(c);
    });
    box.replaceChildren.apply(box, kids);
  }

  // ---------- live ----------
  function drawRate() {
    const box = $("rateChart"), max = buckets.reduce(function (m, b) { return Math.max(m, b.events); }, 0);
    if (!max) { box.replaceChildren(el("p", "empty", CG.t("empty_chart"))); return; }
    const NS = "http://www.w3.org/2000/svg", W = 600, H = 120, bw = W / buckets.length;
    const svg = document.createElementNS(NS, "svg"); svg.setAttribute("viewBox", "0 0 " + W + " " + H); svg.setAttribute("preserveAspectRatio", "none");
    buckets.forEach(function (b, i) {
      const h = Math.max(b.events ? 3 : 0, (b.events / max) * (H - 10));
      const r = document.createElementNS(NS, "rect");
      r.setAttribute("class", "bar" + (b.alerts ? " alert" : "")); r.setAttribute("x", i * bw + 1); r.setAttribute("y", H - h);
      r.setAttribute("width", Math.max(1, bw - 2)); r.setAttribute("height", h); r.setAttribute("rx", 2);
      const tt = document.createElementNS(NS, "title"); tt.textContent = time(b.t) + " · " + CG.t("m_events") + ": " + b.events + " · " + CG.t("m_alerts") + ": " + b.alerts;
      r.appendChild(tt); svg.appendChild(r);
    });
    box.replaceChildren(svg);
  }
  function liveRow(it) {
    const r = el("div", "frow actor-" + (it.alert ? "attacker" : "system"));
    if (it.alert) {
      r.append(el("span", "dot danger"), el("span", "t", time(it.ts)), el("span", "msg", "▲ " + L(it.title)), el("span", "meta mono", it.rule_id + " · " + src(it.source)), badge("sev-" + it.severity, CG.t("sev_" + it.severity)));
    } else {
      r.append(el("span", "dot " + (it.outcome === "dropped" ? "safe" : "")), el("span", "t", time(it.ts)), el("span", "msg", CG.t("k_" + it.kind) + " · " + sess(it.session)),
               el("span", "meta mono", src(it.source) + " → " + it.target), badge(it.outcome, CG.t("o_" + it.outcome)));
    }
    return r;
  }
  function drawLive() {
    const box = $("liveList");
    if (!live.length) { box.replaceChildren(el("p", "empty", CG.t("empty_live"))); return; }
    box.replaceChildren.apply(box, live.map(liveRow));
  }

  // ---------- alerts ----------
  async function setAlert(id, status) { await CG.api("/api/engine/alerts/" + id + "/status", { status: status }); loadAlerts(); }
  function drawAlerts() {
    const act = function (r) {
      const w = el("div", "btn-row");
      if (r.status === "open") { const b = el("button", "btn btn-ghost btn-sm", CG.t("a_ack")); b.type = "button"; b.addEventListener("click", function () { setAlert(r.id, "acknowledged"); }); w.appendChild(b); }
      if (r.status !== "resolved") { const b = el("button", "btn btn-ghost btn-sm", CG.t("a_resolve")); b.type = "button"; b.addEventListener("click", function () { setAlert(r.id, "resolved"); }); w.appendChild(b); }
      else { const b = el("button", "btn btn-ghost btn-sm", CG.t("a_reopen")); b.type = "button"; b.addEventListener("click", function () { setAlert(r.id, "open"); }); w.appendChild(b); }
      return w;
    };
    $("alertsTbl").replaceChildren(table([
      { h: "h_id", v: function (r) { return String(r.id); } }, { h: "h_time", v: function (r) { return time(r.ts); } },
      { h: "h_sev", v: function (r) { return badge("sev-" + r.severity, CG.t("sev_" + r.severity)); } },
      { h: "h_rule", v: function (r) { return r.rule_id + " · " + L(r.title); } }, { h: "h_source", v: function (r) { return src(r.source); } },
      { h: "h_status", v: function (r) { return badge("al-" + r.status, CG.t("al_" + r.status)); } }, { h: "h_actions", v: act }], alerts, "empty_alerts"));
  }

  // ---------- incidents ----------
  function drawIncidents() {
    $("incTbl").replaceChildren(table([
      { h: "h_id", v: function (r) { return String(r.id); } }, { h: "h_time", v: function (r) { return stamp(r.created_at); } },
      { h: "h_sev", v: function (r) { return badge("sev-" + r.severity, CG.t("sev_" + r.severity)); } },
      { h: "h_title", v: function (r) { return L(r.title_); } }, { h: "h_status", v: function (r) { return badge("st-" + r.status, CG.t("is_" + r.status)); } }],
      incidents.map(function (i) { return Object.assign({}, i, { title_: i.title, _click: function () { openIncident(i.id); } }); }), "empty_inc"));
  }
  async function openIncident(id) {
    openInc = id;
    const r = await CG.apiGet("/api/engine/incidents/" + id);
    if (!r.ok) return;
    const i = r.incident, box = $("incDetail");
    const head = el("div", "inc-head");
    head.append(el("strong", "", "#" + i.id + " " + L(i.title)), badge("sev-" + i.severity, CG.t("sev_" + i.severity)), badge("st-" + i.status, CG.t("is_" + i.status)));
    const tl = el("div", "tl"); i.timeline.forEach(function (t) {
      const row = el("div", "tl-row tl-" + t.stage); row.append(el("span", "tl-stage", CG.t("st_" + t.stage)), el("span", "tl-msg", time(t.ts) + " · " + L(t.message))); tl.appendChild(row);
    });
    const acts = table([{ h: "i_actions", v: function (a) { return a.action; } }, { h: "h_target", v: function (a) { return a.target; } },
      { h: "h_status", v: function (a) { return badge(a.verified ? "st-mitigated" : "st-failed", CG.t(a.verified ? "i_verified" : "i_not")); } }], i.actions, "empty_inc");
    const ev = el("div", "chips"); Object.keys(i.analysis.evidence || {}).forEach(function (k) {
      const v = i.analysis.evidence[k]; ev.appendChild(el("span", "chip", k + ": " + (Array.isArray(v) ? v.join(", ") : v)));
    });
    const btns = el("div", "btn-row");
    [["pdf_ar", "ar"], ["pdf_en", "en"]].forEach(function (p) { const a = el("a", "btn btn-ghost btn-sm", CG.t(p[0])); a.href = "/api/engine/incidents/" + i.id + "/pdf?lang=" + p[1]; btns.appendChild(a); });
    if (i.status !== "closed") {
      const c = el("button", "btn btn-sm", CG.t("a_close")); c.type = "button";
      c.addEventListener("click", async function () {
        const x = await CG.api("/api/engine/incidents/" + i.id + "/close", {});
        if (!x.ok) { $("incDetail").prepend(el("div", "alert alert-danger", CG.t("err_" + x.error))); return; }
        loadIncidents(); openIncident(i.id);
      }); btns.appendChild(c);
    }
    box.replaceChildren(el("div", "inc-card wide", ""));
    box.firstChild.append(head, el("h3", "", CG.t("i_summary")), el("p", "", L(i.analysis.summary)), el("h3", "", CG.t("i_evidence")), ev,
                          el("h3", "", CG.t("i_timeline")), tl, el("h3", "", CG.t("i_actions")), acts, btns);
  }

  // ---------- rules & logs ----------
  function drawRules() {
    $("rulesTbl").replaceChildren(table([
      { h: "h_id", v: function (r) { return r.id; } }, { h: "h_name", v: function (r) { return L(r.name); } },
      { h: "h_sev", v: function (r) { return badge("sev-" + r.severity, CG.t("sev_" + r.severity)); } },
      { h: "h_cond", v: function (r) { return L(r.conditions); } }, { h: "h_desc", v: function (r) { return L(r.description); } },
      { h: "h_count", v: function (r) { return CG.num(r.alerts); } }], rules, "empty_inc"));
  }
  function fillFilters() {
    const fill = function (id, first, opts) {
      const s = $(id), cur = s.value; s.replaceChildren(); s.appendChild(new Option(first, ""));
      opts.forEach(function (o) { s.appendChild(new Option(o[1], o[0])); }); s.value = cur;
    };
    fill("fKind", CG.t("f_all_kinds"), KINDS.map(function (k) { return [k, CG.t("k_" + k)]; }));
    fill("fOutcome", CG.t("f_all_out"), [["allowed", CG.t("o_allowed")], ["dropped", CG.t("o_dropped")]]);
    fill("fSession", CG.t("f_all_sess"), sessions.map(function (s) { return [s, sess(s)]; }));
  }
  function drawLogs() {
    $("logsTbl").replaceChildren(table([
      { h: "h_time", v: function (r) { return stamp(r.created_at); } }, { h: "h_session", v: function (r) { return sess(r.session); } },
      { h: "h_kind", v: function (r) { return CG.t("k_" + r.kind); } }, { h: "h_source", v: function (r) { return src(r.source); } },
      { h: "h_target", v: function (r) { return r.target; } },
      { h: "h_outcome", v: function (r) { return badge(r.outcome, CG.t("o_" + r.outcome)); } },
      { h: "h_details", v: function (r) { return Object.keys(r.details).filter(function (k) { return k !== "text"; }).slice(0, 4).map(function (k) { return k + "=" + String(r.details[k]).slice(0, 24); }).join(" "); } }], logs, "empty_logs"));
  }

  // ---------- loading ----------
  async function loadStats() { const r = await CG.apiGet("/api/engine/stats"); if (r.ok) { stats = r; drawStrip(); } }
  async function loadAlerts() { const r = await CG.apiGet("/api/engine/alerts?limit=200"); if (r.ok) { alerts = r.alerts; drawAlerts(); } }
  async function loadIncidents() { const r = await CG.apiGet("/api/engine/incidents?limit=200"); if (r.ok) { incidents = r.incidents; drawIncidents(); } }
  async function loadRules() { const r = await CG.apiGet("/api/engine/rules"); if (r.ok) { rules = r.rules; drawRules(); } }
  async function loadRate() { const r = await CG.apiGet("/api/engine/timeline?span=300&bucket=10"); if (r.ok) { buckets = r.buckets; drawRate(); } }
  async function loadLogs() {
    const q = new URLSearchParams({ limit: "200" });
    [["fKind", "kind"], ["fOutcome", "outcome"], ["fSession", "session"]].forEach(function (p) { if ($(p[0]).value) q.set(p[1], $(p[0]).value); });
    if ($("fProbes").checked) q.set("probes", "1");
    const [l, s] = await Promise.all([CG.apiGet("/api/engine/events?" + q), CG.apiGet("/api/engine/sessions")]);
    if (s.ok) { sessions = s.sessions; fillFilters(); }
    if (l.ok) { logs = l.events; drawLogs(); }
  }
  function refresh() {
    loadStats();
    if (tab === "live") loadRate(); else if (tab === "alerts") loadAlerts(); else if (tab === "incidents") { loadIncidents(); if (openInc) openIncident(openInc); } else if (tab === "rules") loadRules();
  }
  let timer = null;
  function soon() { clearTimeout(timer); timer = setTimeout(refresh, 600); }

  document.querySelectorAll(".tab").forEach(function (b) {
    b.addEventListener("click", function () {
      tab = b.dataset.tab;
      document.querySelectorAll(".tab").forEach(function (x) { x.classList.toggle("is-active", x === b); });
      document.querySelectorAll(".tabpane").forEach(function (p) { p.hidden = p.dataset.pane !== tab; });
      if (tab === "logs") loadLogs(); else refresh();
    });
  });
  $("fApply").addEventListener("click", loadLogs);

  const map = AttackMap.mount($("attackMap"));
  async function loadMap() { const r = await CG.apiGet("/api/engine/map?limit=300"); if (r.ok) map.set(r.events); }
  loadMap();
  CG.on("event", function (d) {
    map.add(d);
    live.unshift(d); if (live.length > 80) live.pop();
    if (tab === "live") { if (live.length === 1) drawLive(); else { const box = $("liveList"); box.prepend(liveRow(d)); while (box.children.length > 80) box.lastChild.remove(); } }
    soon();
  });
  CG.on("alert", function (d) { live.unshift(Object.assign({ alert: true }, d)); if (tab === "live") drawLive(); soon(); });
  ["incident", "timeline"].forEach(function (t) { CG.on(t, soon); });
  CG.on("reset", function () { live = []; drawLive(); refresh(); loadMap(); });
  document.addEventListener("cg:lang", function () { drawStrip(); drawRate(); drawLive(); drawAlerts(); drawIncidents(); drawRules(); drawLogs(); fillFilters(); if (openInc) openIncident(openInc); });

  CG.apply(); fillFilters(); drawLive(); drawRate();
  loadStats(); loadRate(); loadAlerts(); loadIncidents(); loadRules();
  const deep = /^#inc-(\d+)$/.exec(location.hash);
  if (deep) { document.querySelector("[data-tab=incidents]").click(); setTimeout(function () { openIncident(Number(deep[1])); }, 400); }
  setInterval(function () { if (!document.hidden) refresh(); }, 5000);
})();
