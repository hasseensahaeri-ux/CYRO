/* Password analyzer. Runs 100% in the browser: nothing is sent, stored or logged. */
(function () {
  CG.add({
    ar: { pw_label: "كلمة المرور", pw_ph: "اكتب كلمة المرور لتحليلها", pw_show: "إظهار", pw_hide: "إخفاء",
      pw_privacy: "يتم التحليل داخل متصفحك فقط. لا تُحفظ كلمة المرور ولا تُرسل إلى أي خادم.",
      pw_empty: "اكتب كلمة مرور لبدء التحليل.",
      lv0: "ضعيفة جدًا", lv1: "ضعيفة", lv2: "متوسطة", lv3: "قوية", lv4: "قوية جدًا",
      m_len: "الطول", m_bits: "الإنتروبيا التقديرية", m_time: "زمن التخمين التقديري",
      m_chars: "تنوع الأحرف", ch_lower: "أحرف صغيرة", ch_upper: "أحرف كبيرة", ch_digit: "أرقام", ch_symbol: "رموز", ch_long: "12 حرفًا فأكثر",
      t_instant: "لحظي", t_sec: "ثانية", t_min: "دقيقة", t_hour: "ساعة", t_day: "يوم", t_year: "سنة", t_forever: "قرون عديدة",
      t_note: "تقدير نظري لهجوم تخمين سريع على نسخة مسروقة من قاعدة البيانات، وليس ضمانًا.",
      pt_title: "أنماط مكتشفة", sg_title: "اقتراحات للتحسين", none: "لم تُكتشف أنماط شائعة.",
      pt_common: "كلمة مرور شائعة جدًا", pt_contains: "تحتوي على كلمة شائعة", pt_repeat: "أحرف مكررة متتالية",
      pt_seq: "تسلسل متتابع (مثل abc أو 123)", pt_kbd: "نمط لوحة مفاتيح (مثل qwerty)", pt_year: "تحتوي على سنة",
      pt_single: "نوع واحد فقط من الأحرف",
      sg_len: "اجعلها 12 حرفًا على الأقل، والأفضل 16.", sg_upper: "أضف أحرفًا كبيرة.", sg_lower: "أضف أحرفًا صغيرة.",
      sg_digit: "أضف أرقامًا.", sg_symbol: "أضف رموزًا مثل ! أو #.", sg_avoid: "تجنب الكلمات الشائعة والتسلسلات والسنوات.",
      sg_phrase: "جرّب عبارة طويلة من 4 كلمات عشوائية أو أكثر، ولا تعد استخدامها في أي حساب آخر." },
    en: { pw_label: "Password", pw_ph: "Type a password to analyze", pw_show: "Show", pw_hide: "Hide",
      pw_privacy: "Analysis happens in your browser only. The password is never saved or sent to any server.",
      pw_empty: "Type a password to start the analysis.",
      lv0: "Very weak", lv1: "Weak", lv2: "Medium", lv3: "Strong", lv4: "Very strong",
      m_len: "Length", m_bits: "Estimated entropy", m_time: "Estimated guess time",
      m_chars: "Character variety", ch_lower: "Lowercase", ch_upper: "Uppercase", ch_digit: "Digits", ch_symbol: "Symbols", ch_long: "12+ characters",
      t_instant: "instant", t_sec: "seconds", t_min: "minutes", t_hour: "hours", t_day: "days", t_year: "years", t_forever: "many centuries",
      t_note: "A theoretical estimate for a fast offline guessing attack on a stolen database; not a guarantee.",
      pt_title: "Detected patterns", sg_title: "Suggestions to improve", none: "No common patterns detected.",
      pt_common: "A very common password", pt_contains: "Contains a common word", pt_repeat: "Repeated characters in a row",
      pt_seq: "Sequential run (like abc or 123)", pt_kbd: "Keyboard pattern (like qwerty)", pt_year: "Contains a year",
      pt_single: "Only one kind of character",
      sg_len: "Make it at least 12 characters, ideally 16.", sg_upper: "Add uppercase letters.", sg_lower: "Add lowercase letters.",
      sg_digit: "Add digits.", sg_symbol: "Add symbols like ! or #.", sg_avoid: "Avoid common words, sequences and years.",
      sg_phrase: "Try a long phrase of 4+ random words, and never reuse it on another account." }
  });

  const COMMON = ["password", "passw0rd", "123456", "12345678", "123456789", "1234567890", "12345", "1234", "111111",
    "000000", "123123", "654321", "qwerty", "qwertyuiop", "abc123", "iloveyou", "admin", "admin123", "welcome",
    "letmein", "monkey", "dragon", "football", "login", "master", "sunshine", "princess", "1q2w3e4r", "azerty",
    "trustno1", "hello", "freedom", "whatever", "charlie", "aa123456", "password1", "pass", "اهلا", "محمد", "احمد", "مرحبا"];
  const ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "azertyuiop", "ضصثقفغعهخحجد", "شسيبلاتنمكط", "ئءؤرلاىةوزظ"];
  const LEET = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };

  function analyze(pw) {
    const chars = Array.from(pw), len = chars.length;
    const has = { lower: /[a-z]/.test(pw), upper: /[A-Z]/.test(pw), digit: /\d/.test(pw),
                  symbol: /[^\p{L}\p{N}]/u.test(pw), other: /[^\x00-\x7F]/.test(pw) && /\p{L}/u.test(pw) };
    const pool = (has.lower ? 26 : 0) + (has.upper ? 26 : 0) + (has.digit ? 10 : 0) + (has.symbol ? 33 : 0) + (has.other ? 40 : 0);
    let bits = len * Math.log2(Math.max(pool, 2));
    const low = pw.toLowerCase();
    const norm = low.replace(/[013457@$]/g, function (c) { return LEET[c] || c; });
    const patterns = [];
    if (COMMON.indexOf(low) >= 0 || COMMON.indexOf(norm) >= 0) { patterns.push("common"); bits = Math.min(bits, 10); }
    else if (COMMON.some(function (w) { return w.length >= 4 && (norm.indexOf(w) >= 0 || low.indexOf(w) >= 0); })) { patterns.push("contains"); bits = Math.min(bits - 15, 35); }
    if (/(.)\1{2,}/u.test(pw)) { patterns.push("repeat"); bits -= 8; }
    let run = 1, best = 1, dir = 0;
    for (let i = 1; i < len; i++) {
      const d = chars[i].codePointAt(0) - chars[i - 1].codePointAt(0);
      if (d === 1 || d === -1) { run = d === dir ? run + 1 : 2; dir = d; } else { run = 1; dir = 0; }
      best = Math.max(best, run);
    }
    if (best >= 3) { patterns.push("seq"); bits -= 10; }
    const kbd = ROWS.some(function (r) {
      const rev = Array.from(r).reverse().join("");
      for (let i = 0; i + 4 <= low.length; i++) { const s = low.slice(i, i + 4); if (r.indexOf(s) >= 0 || rev.indexOf(s) >= 0) return true; }
      return false;
    });
    if (kbd) { patterns.push("kbd"); bits -= 12; }
    if (/(19|20)\d\d/.test(pw)) { patterns.push("year"); bits -= 4; }
    if (/^[a-zA-Z]+$/.test(pw) || /^\d+$/.test(pw)) { patterns.push("single"); bits -= 6; }
    bits = Math.max(0, bits);
    if (len < 8) bits = Math.min(bits, 30);
    const level = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    const sg = [];
    if (len < 12) sg.push("sg_len");
    if (!has.upper) sg.push("sg_upper");
    if (!has.lower && !has.other) sg.push("sg_lower");
    if (!has.digit) sg.push("sg_digit");
    if (!has.symbol) sg.push("sg_symbol");
    if (patterns.length) sg.push("sg_avoid");
    if (level < 4) sg.push("sg_phrase");
    return { len: len, bits: bits, level: level, has: has, patterns: patterns, sg: sg };
  }

  function crackTime(bits) {
    const s = Math.pow(2, bits) / 2 / 1e10;
    if (s < 1) return CG.t("t_instant");
    const f = function (n, k) { return CG.num(Math.round(n)) + " " + CG.t(k); };
    if (s < 60) return f(s, "t_sec");
    if (s < 3600) return f(s / 60, "t_min");
    if (s < 86400) return f(s / 3600, "t_hour");
    if (s < 31536000) return f(s / 86400, "t_day");
    if (s < 3.15e9) return f(s / 31536000, "t_year");
    return CG.t("t_forever");
  }

  if (typeof module !== 'undefined') module.exports = { analyze: analyze, crackTime: crackTime };
  const input = document.getElementById("pw"), out = document.getElementById("pwOut"), toggle = document.getElementById("pwToggle");
  const el = CG.el;
  function list(title, items, cls) {
    const w = el("div", "");
    w.appendChild(el("h3", "", title));
    const l = el("div", "list");
    items.forEach(function (k) { const r = el("div", "row"); r.appendChild(el("span", "dot " + cls)); r.appendChild(el("span", "main-t wrap", CG.t(k))); l.appendChild(r); });
    w.appendChild(l); return w;
  }
  function render() {
    const pw = input.value;
    if (!pw) { out.replaceChildren(el("p", "empty", CG.t("pw_empty"))); return; }
    const a = analyze(pw), wrap = el("div", "result");
    const head = el("div", "pw-head");
    head.appendChild(el("strong", "pw-level lv" + a.level, CG.t("lv" + a.level)));
    const meter = el("div", "meter lv" + a.level);
    for (let i = 0; i < 5; i++) meter.appendChild(el("span", "seg" + (i <= a.level ? " on" : "")));
    head.appendChild(meter); wrap.appendChild(head);
    const grid = el("div", "metrics");
    [["m_len", CG.num(a.len)], ["m_bits", CG.num(Math.round(a.bits)) + " bit"], ["m_time", crackTime(a.bits)]].forEach(function (m) {
      const c = el("div", "metric"); c.appendChild(el("span", "k", CG.t(m[0]))); c.appendChild(el("strong", "", m[1])); grid.appendChild(c);
    });
    wrap.appendChild(grid);
    wrap.appendChild(el("h3", "", CG.t("m_chars")));
    const chips = el("div", "chips");
    [["ch_lower", a.has.lower], ["ch_upper", a.has.upper], ["ch_digit", a.has.digit], ["ch_symbol", a.has.symbol], ["ch_long", a.len >= 12]].forEach(function (c) {
      chips.appendChild(el("span", "chip" + (c[1] ? " on" : ""), CG.t(c[0])));
    });
    wrap.appendChild(chips);
    wrap.appendChild(a.patterns.length ? list(CG.t("pt_title"), a.patterns.map(function (p) { return "pt_" + p; }), "warn")
      : el("p", "note", CG.t("none")));
    if (a.sg.length) wrap.appendChild(list(CG.t("sg_title"), a.sg, ""));
    wrap.appendChild(el("p", "note", CG.t("t_note")));
    out.replaceChildren(wrap);
  }

  input.addEventListener("input", render);
  toggle.addEventListener("click", function () {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    toggle.textContent = CG.t(show ? "pw_hide" : "pw_show");
  });
  document.addEventListener("cg:lang", function () { toggle.textContent = CG.t(input.type === "password" ? "pw_show" : "pw_hide"); render(); });
  CG.apply();
})();
