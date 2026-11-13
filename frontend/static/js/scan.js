/* URL scanner + phishing detector page logic. */
(function () {
  CG.add({
    ar: { url_label: "الرابط المراد فحصه", url_ph: "https://example.com/login", url_btn: "فحص الرابط",
          url_hint: "يُحلَّل الرابط محليًا. لا يُفتح الموقع ولا تُرسل بياناتك إلى أي خدمة خارجية.",
          ph_label: "نص الرسالة أو البريد", ph_ph: "الصق هنا نص الرسالة المشبوهة…", ph_btn: "تحليل الرسالة",
          ph_hint: "التحليل قائم على قواعد لغوية معلنة (عربي وإنجليزي)، وليس نموذج ذكاء اصطناعي." },
    en: { url_label: "Link to scan", url_ph: "https://example.com/login", url_btn: "Scan link",
          url_hint: "The link is analyzed locally. The site is not opened and your data is not sent to any external service.",
          ph_label: "Message or email text", ph_ph: "Paste the suspicious message here…", ph_btn: "Analyze message",
          ph_hint: "Analysis uses declared language rules (Arabic and English), not an AI model." }
  });
  const form = document.getElementById("scanForm");
  const kind = form.dataset.kind;
  const input = document.getElementById("scanInput");
  const btn = document.getElementById("scanBtn");
  const out = document.getElementById("result");

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    const v = input.value.trim();
    if (!v) { CG.showError(out, "empty"); return; }
    btn.disabled = true; CG.showLoading(out);
    const r = await CG.api("/api/scan/" + kind, kind === "url" ? { url: v } : { text: v });
    btn.disabled = false;
    if (r.ok) CG.renderResult(out, r.result, kind); else CG.showError(out, r.error);
  });
  CG.apply();
})();
