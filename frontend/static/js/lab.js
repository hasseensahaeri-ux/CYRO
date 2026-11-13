/* Attack Simulation Lab. Everything shown comes from the local engine through /api/lab and /api/stream. */
(function () {
  CG.add({
    ar: { lab_map: "خريطة الهجوم المباشرة", lab_pick: "اختر سيناريو الهجوم", lab_speed: "السرعة", lab_start: "بدء المحاكاة", lab_pause: "إيقاف مؤقت", lab_resume: "استئناف",
      lab_stop: "إيقاف", lab_reset: "إعادة ضبط", lab_pipeline: "مسار الدفاع", lab_feed: "الأحداث المباشرة", lab_incidents: "الحوادث والاستجابة",
      lab_what: "وصف الهجوم", lab_how: "طريقة عمله", lab_goal: "الهدف التعليمي", lab_rules: "قواعد الكشف", lab_steps: "الأحداث", lab_dur: "المدة التقريبية",
      lab_safe: "محاكاة محلية بالكامل: لا اتصال بالإنترنت ولا هجمات حقيقية، والمصادر عناوين اختبار محجوزة.",
      lab_empty: "ابدأ المحاكاة لتظهر الأحداث هنا.", lab_inc_empty: "لا توجد حوادث بعد. ستظهر عند كشف الهجوم.",
      s_idle: "جاهز", s_running: "قيد التشغيل", s_paused: "متوقفة مؤقتًا", s_finished: "اكتملت", s_stopped: "أُوقفت",
      p_attack: "الهجوم", p_detection: "الكشف", p_analysis: "التحليل", p_incident: "الحادثة", p_response: "الاستجابة", p_mitigated: "الاحتواء", p_report: "التقرير",
      st_detection: "كشف", st_analysis: "تحليل", st_incident: "حادثة", st_response: "استجابة", st_verification: "تحقق", st_mitigated: "احتواء", st_failed: "فشل", st_report: "تقرير",
      o_pending: "…", o_allowed: "مسموح", o_dropped: "محظور",
      k_login_failed: "فشل دخول", k_login_success: "دخول ناجح", k_conn_attempt: "اتصال بمنفذ", k_request: "طلب", k_message: "رسالة",
      k_file: "ملف", k_url_click: "نقر رابط", k_file_open: "فتح ملف",
      ev_probe: "تحقق: محاولة اختبار بعد الاستجابة",
      sev_low: "منخفضة", sev_medium: "متوسطة", sev_high: "عالية", sev_critical: "حرجة",
      is_detected: "مكتشفة", is_responding: "قيد الاستجابة", is_mitigated: "تم احتواؤها", is_failed: "فشل التحقق", is_closed: "مغلقة",
      r_title: "نتيجة المحاكاة", r_detected_ok: "تم كشف الهجوم واحتواؤه", r_detected_partial: "تم كشف الهجوم لكن الاستجابة لم تكتمل", r_missed: "لم يُكشف الهجوم",
      r_stopped_note: "أُوقفت المحاكاة قبل نهايتها، والنتيجة جزئية.",
      r_alerts: "التنبيهات", r_mitigated: "حوادث تم احتواؤها", r_ttd: "زمن الكشف (زمن السيناريو)", r_resp: "زمن الاستجابة", r_events: "الأحداث", r_blocked: "محاولات تم حظرها", sec: "ثانية",
      err_lab_busy: "توجد محاكاة قيد التشغيل. أوقفها أو أعد ضبطها أولًا.", err_lab_state: "هذا الإجراء غير متاح في الحالة الحالية.", pick_first: "اختر سيناريو أولًا." },
    en: { lab_map: "Live attack map", lab_pick: "Choose an attack scenario", lab_speed: "Speed", lab_start: "Start simulation", lab_pause: "Pause", lab_resume: "Resume",
      lab_stop: "Stop", lab_reset: "Reset", lab_pipeline: "Defense pipeline", lab_feed: "Live events", lab_incidents: "Incidents and response",
      lab_what: "Attack description", lab_how: "How it works", lab_goal: "Learning goal", lab_rules: "Detection rules", lab_steps: "Events", lab_dur: "Approx. duration",
      lab_safe: "Fully local simulation: no internet and no real attacks; sources are reserved test addresses.",
      lab_empty: "Start the simulation to see events here.", lab_inc_empty: "No incidents yet. They appear when the attack is detected.",
      s_idle: "Ready", s_running: "Running", s_paused: "Paused", s_finished: "Finished", s_stopped: "Stopped",
      p_attack: "Attack", p_detection: "Detection", p_analysis: "Analysis", p_incident: "Incident", p_response: "Response", p_mitigated: "Mitigated", p_report: "Report",
      st_detection: "Detection", st_analysis: "Analysis", st_incident: "Incident", st_response: "Response", st_verification: "Verification", st_mitigated: "Mitigated", st_failed: "Failed", st_report: "Report",
      o_pending: "…", o_allowed: "Allowed", o_dropped: "Blocked",
      k_login_failed: "Login failed", k_login_success: "Login ok", k_conn_attempt: "Port connect", k_request: "Request", k_message: "Message",
      k_file: "File", k_url_click: "Link click", k_file_open: "File open",
      ev_probe: "Verification: test attempt after the response",
      sev_low: "Low", sev_medium: "Medium", sev_high: "High", sev_critical: "Critical",
      is_detected: "Detected", is_responding: "Responding", is_mitigated: "Mitigated", is_failed: "Verification failed", is_closed: "Closed",
      r_title: "Simulation result", r_detected_ok: "Attack detected and mitigated", r_detected_partial: "Attack detected but the response is incomplete", r_missed: "Attack not detected",
      r_stopped_note: "The simulation was stopped early; the result is partial.",
      r_alerts: "Alerts", r_mitigated: "Incidents mitigated", r_ttd: "Time to detect (scenario time)", r_resp: "Response time", r_events: "Events", r_blocked: "Attempts blocked", sec: "s",
      err_lab_busy: "A simulation is already running. Stop or reset it first.", err_lab_state: "This action is not available in the current state.", pick_first: "Pick a scenario first." }
  });

  const el = CG.el, $ = function (id) { return document.getElementById(id); };
  const L = function (o) { return o ? o[CG.lang] : ""; };
  const STAGES = ["attack", "detection", "analysis", "incident", "response", "mitigated", "report"];
  const STAGE_OF = { detection: "detection", analysis: "analysis", incident: "incident", response: "response",
                     verification: "response", mitigated: "mitigated", failed: "mitigated", report: "report" };
  const MAX_ROWS = 150;
  const map = AttackMap.mount($("attackMap"));
  let scenarios = [], selected = null, status = { state: "idle" }, msg = null;
  let items = new Map(), order = [], incs = new Map(), pipe = {};

  // ---------- scenario picker & info ----------
  function drawScenarios() {
    const box = $("scnList");
    box.replaceChildren.apply(box, scenarios.map(function (s) {
      const b = el("button", "scn-card" + (selected === s.id ? " sel" : ""));
      b.type = "button"; b.disabled = busy();
      b.append(el("strong", "", L(s.name)), el("span", "", L(s.description)));
      b.addEventListener("click", function () { selected = s.id; drawScenarios(); drawInfo(); updateControls(); });
      return b;
    }));
  }
  function drawInfo() {
    const box = $("scnInfo"), s = scenarios.find(function (x) { return x.id === selected; });
    if (!s) { box.hidden = true; return; }
    box.hidden = false;
    const blocks = [["lab_what", L(s.description)], ["lab_how", L(s.how)], ["lab_goal", L(s.goal)]].map(function (b) {
      const d = el("div", "info-block"); d.append(el("h3", "", CG.t(b[0])), el("p", "", b[1])); return d;
    });
    const meta = el("div", "chips");
    meta.append(el("span", "chip on", CG.t("lab_rules") + ": " + s.rules.join(", ")),
                el("span", "chip", CG.t("lab_steps") + ": " + CG.num(s.steps)),
                el("span", "chip", CG.t("lab_dur") + ": ~" + CG.num(s.duration_s) + " " + CG.t("sec")));
    box.replaceChildren.apply(box, blocks.concat([meta, el("p", "note", CG.t("lab_safe"))]));
  }

  // ---------- controls ----------
  const busy = function () { return status.state === "running" || status.state === "paused"; };
  function updateControls() {
    const s = status.state;
    $("bStart").disabled = busy() || !selected;
    $("bPause").disabled = s !== "running";
    $("bResume").disabled = s !== "paused";
    $("bStop").disabled = !busy();
    $("bReset").disabled = s === "idle";
    $("speed").disabled = busy();
    const chip = $("stateChip");
    chip.textContent = CG.t("s_" + s);
    chip.className = "chip " + (s === "running" ? "on" : s === "paused" ? "warn" : "");
    $("progFill").style.width = (status.total ? Math.round(100 * status.step / status.total) : 0) + "%";
    drawMsg();
  }
  function drawMsg() {
    const box = $("labMsg"); box.replaceChildren();
    if (msg) box.appendChild(el("div", "alert alert-danger", CG.t(msg)));
  }
  async function control(action, body) {
    msg = null;
    const r = await CG.api("/api/lab/" + action, body || {});
    if (!r.ok) { msg = "err_" + r.error; updateControls(); return false; }
    status = r; updateControls(); return true;
  }

  // ---------- pipeline ----------
  function drawPipe() {
    const box = $("pipe");
    box.replaceChildren.apply(box, STAGES.map(function (s) {
      const li = el("li", "pstep " + (pipe[s] || ""));
      li.append(el("span", "pdot"), el("span", "", CG.t("p_" + s)));
      return li;
    }));
  }
  function mark(stage, failed) {
    if (stage === "detection") pipe = { attack: "done" };
    const i = STAGES.indexOf(stage);
    STAGES.forEach(function (s, k) { if (k < i && !pipe[s]) pipe[s] = "done"; });
    pipe[stage] = failed ? "failed" : "done";
    drawPipe();
  }

  // ---------- live feed ----------
  function paintItem(it) {
    const kind = CG.t("k_" + it.kind);
    it.el.className = "frow actor-" + it.actor + (it.probe ? " probe" : "");
    it.el.replaceChildren(
      el("span", "dot " + (it.actor === "attacker" ? "danger" : it.actor === "legit" ? "safe" : "")),
      el("span", "t", it.at !== null ? "+" + CG.num(Number(it.at).toFixed(1)) + "s" : "·"),
      el("span", "msg", it.probe ? CG.t("ev_probe") : it.note ? L(it.note) : kind),
      el("span", "meta mono", it.source + " → " + it.target + " · " + kind),
      el("span", "badge " + (it.outcome || "pending"), CG.t("o_" + (it.outcome || "pending"))));
  }
  function addItem(it) {
    it.el = el("div", "");
    paintItem(it);
    $("feed").prepend(it.el);
    order.push(it);
    if (it.step) items.set(it.step, it);
    while (order.length > MAX_ROWS) { const old = order.shift(); old.el.remove(); if (old.step) items.delete(old.step); }
  }
  function feedEmpty() {
    if (!order.length) $("feed").replaceChildren(el("p", "empty", CG.t("lab_empty")));
  }

  // ---------- incident cards ----------
  function card(id) {
    if (!incs.has(id)) {
      const c = { id: id, title: null, severity: null, status: "detected", entries: [], el: el("div", "inc-card") };
      incs.set(id, c);
      const box = $("incList");
      if (!box.querySelector(".inc-card")) box.replaceChildren();
      box.prepend(c.el);
    }
    return incs.get(id);
  }
  function paintCard(c) {
    const head = el("div", "inc-head");
    head.append(el("strong", "", "#" + c.id + " " + (c.title ? L(c.title) : "")));
    if (c.severity) head.append(el("span", "badge sev-" + c.severity, CG.t("sev_" + c.severity)));
    head.append(el("span", "badge st-" + c.status, CG.t("is_" + c.status)));
    const list = el("div", "tl");
    c.entries.forEach(function (e) {
      const r = el("div", "tl-row tl-" + e.stage);
      r.append(el("span", "tl-stage", CG.t("st_" + e.stage)), el("span", "tl-msg", L(e.message)));
      list.append(r);
    });
    c.el.replaceChildren(head, list);
  }
  function incEmpty() {
    if (!incs.size) $("incList").replaceChildren(el("p", "empty", CG.t("lab_inc_empty")));
  }

  // ---------- result ----------
  function drawResult() {
    const box = $("labResult"), r = status.result;
    if (!r || (status.state !== "finished" && status.state !== "stopped")) { box.hidden = true; return; }
    box.hidden = false;
    const ok = r.detected && r.failed === 0 && r.mitigated > 0;
    const banner = el("div", "alert " + (ok ? "alert-safe" : r.detected ? "alert-warn" : "alert-danger"),
      CG.t(ok ? "r_detected_ok" : r.detected ? "r_detected_partial" : "r_missed"));
    const sec = function (v) { return v === null || v === undefined ? "—" : CG.num(v) + " " + CG.t("sec"); };
    const grid = el("div", "metrics");
    [["r_alerts", CG.num(r.alerts)], ["r_mitigated", CG.num(r.mitigated) + " / " + CG.num(r.incidents.length)],
     ["r_ttd", sec(r.time_to_detect_s)], ["r_resp", sec(r.response_s)], ["r_events", CG.num(r.events)],
     ["r_blocked", CG.num(r.blocked_attempts)]].forEach(function (m) {
      const c = el("div", "metric"); c.append(el("span", "k", CG.t(m[0])), el("strong", "", m[1])); grid.append(c);
    });
    const kids = [el("h2", "", CG.t("r_title")), banner, grid];
    if (status.state === "stopped") kids.push(el("p", "note", CG.t("r_stopped_note")));
    box.replaceChildren.apply(box, kids);
  }

  function clearView() {
    items = new Map(); order = []; incs = new Map(); pipe = {};
    map.clear(); $("feed").replaceChildren(); $("incList").replaceChildren();
    feedEmpty(); incEmpty(); drawPipe(); drawResult();
  }

  // ---------- stream ----------
  function mine(d) { return d.session && d.session === status.session; }
  const handlers = {
    sim: function (d) {
      if (d.type === "state") {
        const was = status.session;
        status = d;
        if (d.session !== was && d.state === "idle") clearView();
        updateControls(); drawScenarios(); drawResult();
      } else if (mine(d)) {
        status.step = d.step; status.total = d.total; updateControls();
        if (!order.length) $("feed").replaceChildren();
        mark("attack");
        addItem({ step: d.step, at: d.at, kind: d.kind, source: d.source, target: d.target, actor: d.actor, note: d.note, outcome: null });
      }
    },
    event: function (d) {
      if (!mine(d)) return;
      map.add(d);
      const step = d.details && d.details.sim_step;
      if (step && items.has(step)) { const it = items.get(step); it.outcome = d.outcome; paintItem(it); return; }
      if (!order.length) $("feed").replaceChildren();
      addItem({ step: step || null, at: step ? d.ts - status.t0 : null, kind: d.kind, source: d.source, target: d.target,
                actor: "system", probe: !step, outcome: d.outcome, note: null });
    },
    alert: function () { /* the detection stage arrives through the incident timeline */ },
    timeline: function (d) {
      if (!mine(d)) return;
      mark(STAGE_OF[d.stage], d.stage === "failed");
      const c = card(d.incident_id); c.entries.push({ stage: d.stage, message: d.message }); paintCard(c);
    },
    incident: function (d) {
      if (!mine(d)) return;
      const c = card(d.id); c.title = d.title; c.severity = d.severity; c.status = d.status; paintCard(c);
    },
    reset: function () { /* the state message clears the view */ }
  };

  async function resync() {
    const st = await CG.apiGet("/api/lab/status");
    if (!st.ok) return;
    status = st; updateControls();
    clearView();
    if (st.session) {
      const ev = await CG.apiGet("/api/engine/events?session=" + encodeURIComponent(st.session) + "&limit=200");
      const list = await CG.apiGet("/api/engine/incidents?session=" + encodeURIComponent(st.session));
      const gm = await CG.apiGet("/api/engine/map?limit=300&session=" + encodeURIComponent(st.session));
      if (gm.ok) map.set(gm.events);
      if (ev.ok && ev.events.length) {
        $("feed").replaceChildren();
        ev.events.slice().reverse().forEach(function (e) {
          const step = e.details && e.details.sim_step;
          addItem({ step: step || null, at: step ? e.ts - st.t0 : null, kind: e.kind, source: e.source, target: e.target,
                    actor: "system", probe: !step, outcome: e.outcome, note: null });
        });
      }
      if (list.ok) {
        for (const i of list.incidents.slice().reverse()) {
          const d = await CG.apiGet("/api/engine/incidents/" + i.id);
          if (!d.ok) continue;
          const c = card(i.id); c.title = i.title; c.severity = i.severity; c.status = i.status;
          c.entries = d.incident.timeline.map(function (t) { return { stage: t.stage, message: t.message }; });
          d.incident.timeline.forEach(function (t) { mark(STAGE_OF[t.stage], t.stage === "failed"); });
          paintCard(c);
        }
      }
    }
    drawResult();
  }

  function repaintAll() {
    drawScenarios(); drawInfo(); updateControls(); drawPipe(); drawResult();
    order.forEach(paintItem); incs.forEach(paintCard);
    feedEmpty(); incEmpty();
  }

  async function init() {
    const r = await CG.apiGet("/api/lab/scenarios");
    if (r.ok) scenarios = r.scenarios;
    drawScenarios(); drawPipe(); feedEmpty(); incEmpty(); updateControls();
    Object.keys(handlers).forEach(function (t) { CG.on(t, handlers[t]); });
    CG.onOpen(function () { resync().then(function () { if (status.scenario) { selected = status.scenario; drawScenarios(); drawInfo(); updateControls(); } }); });
  }

  $("bStart").addEventListener("click", async function () {
    if (!selected) { msg = "pick_first"; drawMsg(); return; }
    clearView();
    if (!(await control("start", { scenario: selected, speed: Number($("speed").value) }))) resync();
  });
  $("bPause").addEventListener("click", function () { control("pause"); });
  $("bResume").addEventListener("click", function () { control("resume"); });
  $("bStop").addEventListener("click", function () { control("stop"); });
  $("bReset").addEventListener("click", async function () { if (await control("reset")) { selected = null; drawScenarios(); drawInfo(); clearView(); } });
  document.addEventListener("cg:lang", repaintAll);
  CG.apply();
  init();
})();
