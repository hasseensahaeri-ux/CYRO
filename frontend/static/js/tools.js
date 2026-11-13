/* Shared helpers for tool pages: API calls and result rendering (safe DOM APIs only). */
(function () {
  CG.add({
    ar: {
      v_safe: "لا مؤشرات خطورة", v_suspicious: "مشبوه", v_dangerous: "خطير",
      v_safe_file: "لا تحذيرات في الصيغة",
      score: "درجة الخطورة", findings: "مؤشرات التحليل", no_findings: "لم تُكتشف أي مؤشرات بالقواعد المستخدمة.",
      disc_scan: "غياب المؤشرات لا يعني أن العنصر آمن بشكل مؤكد. التحليل قائم على قواعد محلية ولا يغني عن الحذر.",
      disc_file: "الـ Hash يتحقق من سلامة المحتوى فقط ولا يكشف البرمجيات الخبيثة.",
      analyzing: "جارٍ التحليل…",
      checks: "ما فُحص", c_dns: "حل النطاق (DNS)", c_tls: "شهادة HTTPS", c_bl: "قائمة التهديدات المحلية",
      c_yes: "تم", c_no: "لم يتم", c_entries: "نطاق", c_none: "غير مفعّلة",
      links_found: "الروابط المستخرجة",
      err_csrf: "انتهت صلاحية الجلسة. أعد تحميل الصفحة.", err_rate_limit: "طلبات كثيرة. انتظر دقيقة ثم أعد المحاولة.",
      err_invalid_json: "الطلب غير صالح.", err_empty: "أدخل نصًا أولًا.", err_too_long: "المدخل أطول من الحد المسموح.",
      err_invalid_url: "الرابط غير صالح. استخدم رابطًا مثل https://example.com",
      err_internal_blocked: "لا يُسمح بفحص عناوين داخلية أو localhost أو الشبكات الخاصة.",
      err_file_too_large: "حجم الملف يتجاوز الحد المسموح.", err_no_file: "اختر ملفًا أولًا.",
      err_empty_file: "الملف فارغ.", err_invalid_hash: "قيمة Hash غير صالحة (يجب 64 خانة سداسية عشرية).",
      err_network: "تعذر الاتصال بالخادم.", err_server: "حدث خطأ في الخادم.", err_not_found: "غير موجود.",
      err_db: "تعذر حفظ البيانات."
    },
    en: {
      v_safe: "No risk indicators", v_suspicious: "Suspicious", v_dangerous: "Dangerous",
      v_safe_file: "No format warnings",
      score: "Risk score", findings: "Analysis indicators", no_findings: "No indicators found by the rules used.",
      disc_scan: "No indicators does not guarantee the item is safe. The analysis uses local rules and does not replace caution.",
      disc_file: "A hash only verifies content integrity; it does not detect malware.",
      analyzing: "Analyzing…",
      checks: "What was checked", c_dns: "Domain resolution (DNS)", c_tls: "HTTPS certificate", c_bl: "Local threat list",
      c_yes: "Done", c_no: "Not done", c_entries: "domains", c_none: "Not enabled",
      links_found: "Extracted links",
      err_csrf: "Session expired. Reload the page.", err_rate_limit: "Too many requests. Wait a minute and retry.",
      err_invalid_json: "Invalid request.", err_empty: "Enter some text first.", err_too_long: "Input is longer than allowed.",
      err_invalid_url: "Invalid link. Use something like https://example.com",
      err_internal_blocked: "Scanning internal addresses, localhost or private networks is not allowed.",
      err_file_too_large: "File exceeds the allowed size.", err_no_file: "Choose a file first.",
      err_empty_file: "The file is empty.", err_invalid_hash: "Invalid hash (must be 64 hex characters).",
      err_network: "Could not reach the server.", err_server: "Server error.", err_not_found: "Not found.",
      err_db: "Could not save data."
    }
  });

  const token = function () { return document.querySelector('meta[name="csrf-token"]').content; };

  async function request(url, opts) {
    try {
      const r = await fetch(url, opts);
      const j = await r.json().catch(function () { return { ok: false, error: "server" }; });
      return j;
    } catch (e) { return { ok: false, error: "network" }; }
  }
  CG.api = function (url, body) {
    return request(url, { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": token() }, body: JSON.stringify(body) });
  };
  CG.apiGet = function (url) { return request(url, { headers: { Accept: "application/json" } }); };
  CG.apiForm = function (url, form) {
    return request(url, { method: "POST", headers: { "X-CSRF-Token": token() }, body: form });
  };

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  CG.el = el;

  // Re-render the last shown output when the language changes.
  let last = null;
  document.addEventListener("cg:lang", function () { if (last) last(); });
  CG.remember = function (fn) { last = fn; fn(); };

  CG.showError = function (box, code) {
    CG.remember(function () {
      box.replaceChildren(el("div", "alert alert-danger", CG.t("err_" + code)));
    });
  };
  CG.showLoading = function (box) { last = null; box.replaceChildren(el("p", "empty", CG.t("analyzing"))); };

  function findingsList(findings) {
    const list = el("div", "list");
    if (!findings.length) { list.appendChild(el("p", "empty", CG.t("no_findings"))); return list; }
    findings.forEach(function (f) {
      const row = el("div", "finding sev-" + f.severity);
      row.appendChild(el("span", "dot " + (f.severity === "high" ? "danger" : f.severity === "medium" ? "warn" : f.severity === "ok" ? "safe" : "")));
      const body = el("div", "f-body");
      body.appendChild(el("strong", "", f.title[CG.lang]));
      body.appendChild(el("p", "", f.why[CG.lang]));
      row.appendChild(body);
      if (f.points > 0) row.appendChild(el("span", "pts", "+" + f.points));
      list.appendChild(row);
    });
    return list;
  }

  CG.findingsList = findingsList;

  CG.verdictBox = function (r, kind) {
    const box = el("div", "verdict v-" + r.verdict);
    box.appendChild(el("strong", "", CG.t(kind === "file" && r.verdict === "safe" ? "v_safe_file" : "v_" + r.verdict)));
    const meter = el("div", "score-line");
    meter.appendChild(el("span", "", CG.t("score") + ": " + CG.num(r.score) + " / 100"));
    const track = el("div", "track"), bar = el("div", "fill");
    bar.setAttribute("data-w", r.score);
    bar.style.width = r.score + "%";
    track.appendChild(bar); meter.appendChild(track);
    box.appendChild(meter);
    return box;
  };

  CG.renderResult = function (box, r, kind) {
    CG.remember(function () {
      const wrap = el("div", "result");
      wrap.appendChild(CG.verdictBox(r, kind));
      wrap.appendChild(el("h3", "", CG.t("findings")));
      wrap.appendChild(findingsList(r.findings));
      if (r.links && r.links.length) {
        wrap.appendChild(el("h3", "", CG.t("links_found")));
        const l = el("div", "list");
        r.links.forEach(function (k) {
          const row = el("div", "row");
          row.appendChild(el("span", "dot " + (k.verdict === "dangerous" ? "danger" : k.verdict === "suspicious" ? "warn" : "safe")));
          const t = el("span", "main-t", k.url); t.setAttribute("dir", "ltr");
          row.append(t, el("span", "meta", CG.t("v_" + k.verdict)));
          l.appendChild(row);
        });
        wrap.appendChild(l);
      }
      if (r.meta) {
        wrap.appendChild(el("h3", "", CG.t("checks")));
        const m = el("div", "chips");
        m.appendChild(el("span", "chip " + (r.meta.dns_checked ? "on" : ""), CG.t("c_dns") + ": " + CG.t(r.meta.dns_checked ? "c_yes" : "c_no")));
        m.appendChild(el("span", "chip " + (r.meta.tls_checked ? "on" : ""), CG.t("c_tls") + ": " + CG.t(r.meta.tls_checked ? "c_yes" : "c_no")));
        m.appendChild(el("span", "chip " + (r.meta.blocklist_size ? "on" : ""), CG.t("c_bl") + ": " + (r.meta.blocklist_size ? CG.num(r.meta.blocklist_size) + " " + CG.t("c_entries") : CG.t("c_none"))));
        wrap.appendChild(m);
      }
      wrap.appendChild(el("p", "note", CG.t(kind === "file" ? "disc_file" : "disc_scan")));
      box.replaceChildren(wrap);
    });
  };
})();
