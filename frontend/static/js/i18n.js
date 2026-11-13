/* i18n: Arabic / English with RTL / LTR switching. */
(function () {
  const DICT = {
    ar: {
      menu: "القائمة", tagline: "🛡️ منصة الأمن السيبراني الذكية", nav_g_platform: "المنصة", nav_g_tools: "أدوات الحماية", nav_g_reports: "التقارير والمتابعة",
      ss_secure: "آمن", ss_elevated: "مرتفع الخطورة", ss_critical: "حرج", sys_pill: "حالة النظام", toast_alert: "تنبيه جديد", sev_low: "منخفضة", sev_medium: "متوسطة", sev_high: "عالية", sev_critical: "حرجة",
      nav_dash: "لوحة التحكم", nav_lab: "مختبر المحاكاة", nav_comm: "مختبر الاتصال الآمن", nav_soc: "مركز العمليات SOC", nav_url: "فاحص الروابط", nav_phish: "كاشف التصيد",
      nav_pass: "محلل كلمات المرور", nav_file: "سلامة الملفات",
      nav_quiz: "اختبار الوعي الأمني", nav_reports: "التقارير",
      st_total: "إجمالي عمليات الفحص", st_threats: "نتائج خطيرة في الأدوات",
      st_urls: "الروابط المشبوهة", st_files: "الملفات المحللة",
      pr_title: "مستوى الحماية العام", pr_none: "لا توجد فحوصات بعد",
      pr_note: "نسبة عمليات الفحص التي خلت من مؤشرات خطورة، من آخر 50 فحصًا مسجلًا.",
      pr_good: "جيد", pr_mid: "متوسط", pr_low: "منخفض",
      ch_title: "نشاط الفحص خلال آخر 7 أيام", ch_empty: "لا يوجد نشاط فحص بعد. ابدأ بفحص رابط أو رسالة.",
      rc_title: "آخر عمليات الفحص", rc_empty: "لم تُجرَ أي عملية فحص بعد.",
      al_title: "مركز التنبيهات الأمنية", al_empty: "لا توجد تنبيهات. ستظهر هنا عند اكتشاف تهديد.",
      stub: "هذه الأداة قيد البناء في المرحلة التالية.", err_404: "الصفحة غير موجودة", err_500: "حدث خطأ في الخادم",
      al_danger: "تهديد", al_warn: "تحذير", chars: "حرفًا", msg: "رسالة",
      load_err: "تعذر تحميل البيانات من الخادم."
    },
    en: {
      menu: "Menu", tagline: "🛡️ Intelligent Cybersecurity Platform", nav_g_platform: "Platform", nav_g_tools: "Protection tools", nav_g_reports: "Reports",
      ss_secure: "Secure", ss_elevated: "Elevated", ss_critical: "Critical", sys_pill: "System status", toast_alert: "New alert", sev_low: "Low", sev_medium: "Medium", sev_high: "High", sev_critical: "Critical",
      nav_dash: "Dashboard", nav_lab: "Attack Lab", nav_comm: "Secure Comm Lab", nav_soc: "SOC Center", nav_url: "URL Scanner", nav_phish: "Phishing Detector",
      nav_pass: "Password Analyzer", nav_file: "File Integrity",
      nav_quiz: "Awareness Quiz", nav_reports: "Reports",
      st_total: "Total scans", st_threats: "Dangerous tool results",
      st_urls: "Suspicious URLs", st_files: "Files analyzed",
      pr_title: "Overall protection level", pr_none: "No scans yet",
      pr_note: "Share of scans with no risk indicators, from the last 50 recorded scans.",
      pr_good: "Good", pr_mid: "Moderate", pr_low: "Low",
      ch_title: "Scan activity, last 7 days", ch_empty: "No scan activity yet. Start by scanning a link or a message.",
      rc_title: "Recent scans", rc_empty: "No scans have been run yet.",
      al_title: "Security alerts", al_empty: "No alerts. They will appear here when a threat is found.",
      stub: "This tool is being built in the next phase.", err_404: "Page not found", err_500: "Server error",
      al_danger: "Threat", al_warn: "Warning", chars: "chars", msg: "Message",
      load_err: "Could not load data from the server."
    }
  };

  const KEY = "cg_lang";
  let lang = "ar";
  try { const s = localStorage.getItem(KEY); if (s === "ar" || s === "en") lang = s; } catch (e) {}

  function t(k) { return (DICT[lang] && DICT[lang][k]) || k; }

  function apply() {
    const root = document.documentElement;
    root.lang = lang;
    root.dir = lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-i18n]").forEach(function (el) { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll("[data-i18n-ph]").forEach(function (el) { el.setAttribute("placeholder", t(el.dataset.i18nPh)); });
    document.querySelectorAll("[data-i18n-aria]").forEach(function (el) { el.setAttribute("aria-label", t(el.dataset.i18nAria)); });
    const label = document.getElementById("langLabel");
    if (label) label.textContent = lang === "ar" ? "English" : "العربية";
    document.dispatchEvent(new CustomEvent("cg:lang", { detail: lang }));
  }

  function toggle() {
    lang = lang === "ar" ? "en" : "ar";
    try { localStorage.setItem(KEY, lang); } catch (e) {}
    apply();
  }

  window.CG = {
    t: t,
    apply: apply,
    add: function (d) { Object.keys(d).forEach(function (l) { Object.assign(DICT[l], d[l]); }); },
    toggle: toggle,
    get lang() { return lang; },
    num: function (n) { return Number(n).toLocaleString(lang === "ar" ? "ar-u-nu-latn" : "en-US"); }
  };
})();
