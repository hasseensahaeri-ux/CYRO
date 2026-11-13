/* File integrity page: SHA-256 via the local server (files are never stored or executed). */
(function () {
  CG.add({
    ar: { f_a: "الملف الأول", f_b: "الملف الثاني (اختياري للمقارنة)", f_exp: "أو قارن مع Hash متوقع (SHA-256)",
          f_exp_ph: "64 خانة سداسية عشرية", f_btn: "حساب SHA-256 والتحقق",
          f_hint: "لا يُحفظ الملف ولا يُنفَّذ. الحد الأقصى للحجم:",
          f_name: "الاسم", f_size: "الحجم", f_type: "النوع المكتشف", f_hash: "SHA-256", f_copy: "نسخ", f_copied: "تم النسخ",
          f_match: "المحتوى متطابق: الـ Hash نفسه، فلم يتغير الملف.",
          f_diff: "المحتوى مختلف: تغيّر الملف أو أنه ملف آخر.",
          f_mod: "آخر تعديل (من جهازك)", f_status: "مقارنة بآخر فحص", f_new: "ملف جديد: لم يُفحص من قبل", f_unch: "لم يتغير منذ آخر فحص", f_chg: "تغيّر المحتوى منذ آخر فحص",
          f_prev: "البصمة السابقة", f_hist: "سجل فحوصات الملفات وتغييراتها", f_hist_none: "لا توجد فحوصات ملفات مسجلة بعد.",
          f_vs_file: "مقارنة الملفين", f_vs_hash: "مقارنة مع الـ Hash المتوقع" },
    en: { f_a: "First file", f_b: "Second file (optional, to compare)", f_exp: "Or compare with an expected hash (SHA-256)",
          f_exp_ph: "64 hex characters", f_btn: "Compute SHA-256 and verify",
          f_hint: "The file is neither stored nor executed. Maximum size:",
          f_name: "Name", f_size: "Size", f_type: "Detected type", f_hash: "SHA-256", f_copy: "Copy", f_copied: "Copied",
          f_match: "Content matches: identical hash, so the file has not changed.",
          f_diff: "Content differs: the file changed or it is a different file.",
          f_mod: "Last modified (from your device)", f_status: "Compared with last check", f_new: "New file: never checked before", f_unch: "Unchanged since the last check", f_chg: "Content changed since the last check",
          f_prev: "Previous hash", f_hist: "File check and change log", f_hist_none: "No file checks recorded yet.",
          f_vs_file: "Comparing the two files", f_vs_hash: "Comparing with the expected hash" }
  });
  const form = document.getElementById("fileForm");
  const maxBytes = Number(form.dataset.maxMb) * 1024 * 1024;
  const out = document.getElementById("result");
  const btn = document.getElementById("fileBtn");

  function stamp(t) {
    const d = new Date(String(t));
    return isNaN(d) ? "—" : d.toLocaleString(CG.lang === "ar" ? "ar-u-nu-latn" : "en-GB", { dateStyle: "medium", timeStyle: "short" });
  }
  let history = [];
  function drawHistory() {
    const box = document.getElementById("histBox");
    if (!history.length) { box.replaceChildren(CG.el("p", "empty", CG.t("f_hist_none"))); return; }
    box.replaceChildren.apply(box, history.map(function (h) {
      return CG.scanRow(h.status === "changed" ? "warn" : h.status === "new" ? "" : "safe",
        CG.t("f_" + (h.status === "new" ? "new" : h.status === "changed" ? "chg" : "unch")), h.name + "  ·  " + h.sha256.slice(0, 12) + "…", stamp(h.checked_at));
    }));
  }
  async function loadHistory() {
    const r = await CG.apiGet("/api/file-history?limit=30");
    if (r.ok) { history = r.history; drawHistory(); }
  }

  function size(n) {
    if (n < 1024) return CG.num(n) + " B";
    if (n < 1048576) return CG.num((n / 1024).toFixed(1)) + " KB";
    return CG.num((n / 1048576).toFixed(2)) + " MB";
  }
  function row(label, node) {
    const r = CG.el("div", "kv");
    r.appendChild(CG.el("span", "k", label));
    if (typeof node === "string") r.appendChild(CG.el("span", "v", node)); else r.appendChild(node);
    return r;
  }
  function copyBtn(text) {
    const b = CG.el("button", "btn btn-ghost btn-sm", CG.t("f_copy"));
    b.type = "button";
    b.addEventListener("click", function () {
      const done = function () { b.textContent = CG.t("f_copied"); setTimeout(function () { b.textContent = CG.t("f_copy"); }, 1500); };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, function () {});
    });
    return b;
  }
  function card(f) {
    const c = CG.el("div", "file-card");
    c.appendChild(row(CG.t("f_name"), f.name));
    c.appendChild(row(CG.t("f_size"), size(f.size)));
    c.appendChild(row(CG.t("f_type"), f.kind));
    if (f.history) {
      const h = f.history;
      c.appendChild(row(CG.t("f_mod"), h.modified_at ? stamp(h.modified_at) : "—"));
      c.appendChild(row(CG.t("f_status"), CG.el("span", "chip " + (h.status === "changed" ? "warn" : "on"), CG.t("f_" + (h.status === "new" ? "new" : h.status === "changed" ? "chg" : "unch")))));
      if (h.previous_sha256) c.appendChild(row(CG.t("f_prev"), CG.el("span", "v mono", h.previous_sha256)));
    }
    const h = CG.el("span", "v mono", f.sha256);
    const hw = CG.el("div", "hash-row"); hw.append(h, copyBtn(f.sha256));
    c.appendChild(row(CG.t("f_hash"), hw));
    c.appendChild(CG.verdictBox(f, "file"));
    c.appendChild(CG.findingsList(f.findings));
    return c;
  }
  function render(data) {
    CG.remember(function () {
      const wrap = CG.el("div", "result");
      if (data.compare) {
        const ok = data.compare.match;
        wrap.appendChild(CG.el("h3", "", CG.t(data.compare.against === "file" ? "f_vs_file" : "f_vs_hash")));
        wrap.appendChild(CG.el("div", "alert " + (ok ? "alert-safe" : "alert-warn"), CG.t(ok ? "f_match" : "f_diff")));
      }
      data.files.forEach(function (f) { wrap.appendChild(card(f)); });
      wrap.appendChild(CG.el("p", "note", CG.t("disc_file")));
      out.replaceChildren(wrap);
    });
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const a = document.getElementById("fileA").files[0];
    const b = document.getElementById("fileB").files[0];
    const exp = document.getElementById("expected").value.trim();
    if (!a) { CG.showError(out, "no_file"); return; }
    if (a.size > maxBytes || (b && b.size > maxBytes)) { CG.showError(out, "file_too_large"); return; }
    const fd = new FormData();
    fd.append("file", a);
    fd.append("modified", String(a.lastModified));
    if (b) fd.append("modified2", String(b.lastModified));
    if (b) fd.append("file2", b);
    if (exp) fd.append("expected", exp);
    btn.disabled = true; CG.showLoading(out);
    const r = await CG.apiForm("/api/scan/file", fd);
    btn.disabled = false;
    if (r.ok) { render(r); loadHistory(); } else CG.showError(out, r.error);
  });
  document.addEventListener("cg:lang", drawHistory);
  loadHistory();
  CG.apply();
})();
