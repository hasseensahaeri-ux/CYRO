/* Reports page: create report snapshots, download PDF, browse scan history. */
(function () {
  CG.add({
    ar: { rp_new: "إنشاء تقرير جديد", rp_title: "عنوان التقرير", rp_title_ph: "مثال: تقرير فحوصات المعرض", rp_scope: "نطاق التقرير",
          rp_last10: "آخر 10 عمليات فحص", rp_last50: "آخر 50 عملية فحص", rp_all: "كل عمليات الفحص", rp_create: "إنشاء التقرير",
          rp_saved: "التقارير المحفوظة", rp_history: "سجل عمليات الفحص", rp_none: "لا توجد تقارير بعد.", rp_hist_none: "لا توجد عمليات فحص مسجلة بعد.",
          rp_done: "تم إنشاء التقرير. يمكنك تنزيله من القائمة أدناه.", err_no_scans: "لا توجد عمليات فحص لإنشاء تقرير منها. أجرِ فحصًا أولًا.",
          rp_pdf_ar: "PDF عربي", rp_pdf_en: "PDF English", rp_scans: "عملية فحص" },
    en: { rp_new: "Create a new report", rp_title: "Report title", rp_title_ph: "e.g. Expo scan report", rp_scope: "Report scope",
          rp_last10: "Last 10 scans", rp_last50: "Last 50 scans", rp_all: "All scans", rp_create: "Create report",
          rp_saved: "Saved reports", rp_history: "Scan history", rp_none: "No reports yet.", rp_hist_none: "No scans recorded yet.",
          rp_done: "Report created. Download it from the list below.", err_no_scans: "There are no scans to build a report from. Run a scan first.",
          rp_pdf_ar: "PDF عربي", rp_pdf_en: "PDF English", rp_scans: "scans" }
  });
  const el = CG.el;
  const TYPE_KEY = { url: "nav_url", phishing: "nav_phish", file: "nav_file" };
  const DOT = { safe: "safe", suspicious: "warn", dangerous: "danger" };
  let reports = null, scans = null, msg = null;
  const fmt = function (t) { return String(t).replace("T", " ").slice(0, 16); };

  function empty(box, key) { box.replaceChildren(el("p", "empty", CG.t(key))); }

  function drawReports() {
    const box = document.getElementById("repList");
    if (reports === null) return;
    if (!reports.length) { empty(box, "rp_none"); return; }
    box.replaceChildren.apply(box, reports.map(function (r) {
      const row = el("div", "row wrap-row");
      const t = el("span", "main-t", r.title);
      const m = el("span", "meta", CG.num(r.scan_count) + " " + CG.t("rp_scans") + " · " + fmt(r.created_at));
      row.append(t, m);
      ["ar", "en"].forEach(function (l) {
        const a = el("a", "btn btn-ghost btn-sm", CG.t("rp_pdf_" + l));
        a.href = "/api/reports/" + r.id + "/pdf?lang=" + l;
        row.appendChild(a);
      });
      return row;
    }));
  }
  function drawHistory() {
    const box = document.getElementById("histList");
    if (scans === null) return;
    if (!scans.length) { empty(box, "rp_hist_none"); return; }
    box.replaceChildren.apply(box, scans.map(function (s) {
      return CG.scanRow(DOT[s.verdict] || "", CG.t(TYPE_KEY[s.type]), CG.targetLabel(s.type, s.target),
        CG.num(s.score) + "/100 · " + fmt(s.created_at));
    }));
  }
  function drawMsg() {
    const box = document.getElementById("repMsg");
    box.replaceChildren();
    if (msg) box.appendChild(el("div", "alert " + (msg.ok ? "alert-safe" : "alert-danger"), CG.t(msg.key)));
  }
  function draw() { drawReports(); drawHistory(); drawMsg(); }

  async function load() {
    const [a, b] = await Promise.all([CG.apiGet("/api/reports"), CG.apiGet("/api/scans")]);
    if (a.ok) reports = a.reports; if (b.ok) scans = b.scans;
    if (!a.ok || !b.ok) msg = { ok: false, key: "err_" + (a.error || b.error) };
    draw();
  }

  document.getElementById("repForm").addEventListener("submit", async function (e) {
    e.preventDefault();
    const btn = document.getElementById("repBtn"), scope = document.getElementById("repScope").value;
    btn.disabled = true;
    const r = await CG.api("/api/reports", { title: document.getElementById("repTitle").value,
                                              limit: scope === "all" ? null : Number(scope) });
    btn.disabled = false;
    msg = r.ok ? { ok: true, key: "rp_done" } : { ok: false, key: "err_" + r.error };
    if (r.ok) await load(); else draw();
  });
  document.addEventListener("cg:lang", draw);
  CG.apply();
  load();
})();
