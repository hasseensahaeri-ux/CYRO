/* Security awareness quiz. Scoring happens on the server. */
(function () {
  CG.add({
    ar: { q_start: "ابدأ الاختبار", q_intro: "12 سؤالًا في التصيد والهندسة الاجتماعية وكلمات المرور وأمن الشبكات. ستظهر الإجابات الصحيحة وشرحها في النهاية.",
          q_of: "السؤال", q_next: "التالي", q_finish: "إنهاء وعرض النتيجة", q_pick: "اختر إجابة للمتابعة.",
          q_result: "نتيجتك", q_level: "مستوى الوعي الأمني", q_retry: "إعادة الاختبار", q_review: "مراجعة الإجابات",
          q_yours: "إجابتك", q_right: "الإجابة الصحيحة", q_skipped: "لم تُجب", q_load: "جارٍ تحميل الأسئلة…",
          lvl_excellent: "ممتاز", lvl_good: "جيد", lvl_fair: "متوسط", lvl_low: "يحتاج تحسينًا",
          cat_phishing: "التصيد", cat_social: "الهندسة الاجتماعية", cat_passwords: "كلمات المرور", cat_network: "أمن الشبكات", cat_general: "أمن عام" },
    en: { q_start: "Start quiz", q_intro: "12 questions on phishing, social engineering, passwords and network security. Correct answers and explanations are shown at the end.",
          q_of: "Question", q_next: "Next", q_finish: "Finish and see result", q_pick: "Pick an answer to continue.",
          q_result: "Your result", q_level: "Security awareness level", q_retry: "Retake quiz", q_review: "Answer review",
          q_yours: "Your answer", q_right: "Correct answer", q_skipped: "Not answered", q_load: "Loading questions…",
          lvl_excellent: "Excellent", lvl_good: "Good", lvl_fair: "Fair", lvl_low: "Needs improvement",
          cat_phishing: "Phishing", cat_social: "Social engineering", cat_passwords: "Passwords", cat_network: "Network security", cat_general: "General security" }
  });
  const box = document.getElementById("quiz");
  const el = CG.el;
  let questions = [], answers = {}, idx = 0, result = null, view = "intro", error = null;

  function intro() {
    const w = el("div", "quiz-intro");
    w.appendChild(el("p", "", CG.t("q_intro")));
    const b = el("button", "btn", CG.t("q_start")); b.type = "button";
    b.addEventListener("click", start); w.appendChild(b);
    return w;
  }
  async function start() {
    box.replaceChildren(el("p", "empty", CG.t("q_load")));
    const r = await CG.apiGet("/api/quiz");
    if (!r.ok) { error = r.error; view = "error"; draw(); return; }
    questions = r.questions; answers = {}; idx = 0; result = null; view = "ask"; draw();
  }
  function ask() {
    const q = questions[idx], w = el("div", "quiz");
    const top = el("div", "quiz-top");
    top.appendChild(el("span", "chip on", CG.t("cat_" + q.cat)));
    top.appendChild(el("span", "meta", CG.t("q_of") + " " + CG.num(idx + 1) + " / " + CG.num(questions.length)));
    w.appendChild(top);
    const track = el("div", "track"), fill = el("div", "fill");
    fill.style.width = Math.round((idx / questions.length) * 100) + "%";
    track.appendChild(fill); w.appendChild(track);
    w.appendChild(el("h2", "q-text", q.q[CG.lang]));
    const opts = el("div", "list");
    q.options[CG.lang].forEach(function (text, i) {
      const b = el("button", "opt" + (answers[q.id] === i ? " picked" : ""), text); b.type = "button";
      b.addEventListener("click", function () { answers[q.id] = i; draw(); });
      opts.appendChild(b);
    });
    w.appendChild(opts);
    const last = idx === questions.length - 1;
    const next = el("button", "btn", CG.t(last ? "q_finish" : "q_next")); next.type = "button";
    next.disabled = answers[q.id] === undefined;
    next.addEventListener("click", last ? finish : function () { idx++; draw(); });
    w.appendChild(next);
    return w;
  }
  async function finish() {
    const r = await CG.api("/api/quiz/submit", { answers: answers });
    if (!r.ok) { error = r.error; view = "error"; draw(); return; }
    result = r.result; view = "result"; draw();
  }
  function resultView() {
    const w = el("div", "quiz");
    const head = el("div", "verdict v-" + (result.percent >= 60 ? "safe" : result.percent >= 40 ? "suspicious" : "dangerous"));
    head.appendChild(el("strong", "", CG.num(result.score) + " / " + CG.num(result.total) + "  (" + CG.num(result.percent) + "%)"));
    head.appendChild(el("span", "", CG.t("q_level") + ": " + CG.t("lvl_" + result.level)));
    w.appendChild(head);
    w.appendChild(el("h3", "", CG.t("q_review")));
    const list = el("div", "list");
    result.review.forEach(function (rv, i) {
      const q = questions[i], card = el("div", "review " + (rv.ok ? "ok" : "bad"));
      card.appendChild(el("strong", "", CG.num(i + 1) + ". " + q.q[CG.lang]));
      const opts = q.options[CG.lang];
      card.appendChild(el("p", "", CG.t("q_yours") + ": " + (rv.picked === null ? CG.t("q_skipped") : opts[rv.picked])));
      if (!rv.ok) card.appendChild(el("p", "", CG.t("q_right") + ": " + opts[rv.correct]));
      card.appendChild(el("p", "note", rv.explain[CG.lang]));
      list.appendChild(card);
    });
    w.appendChild(list);
    const b = el("button", "btn", CG.t("q_retry")); b.type = "button"; b.addEventListener("click", start);
    w.appendChild(b);
    return w;
  }
  function draw() {
    if (view === "intro") box.replaceChildren(intro());
    else if (view === "ask") box.replaceChildren(ask());
    else if (view === "result") box.replaceChildren(resultView());
    else box.replaceChildren(el("div", "alert alert-danger", CG.t("err_" + error)));
  }
  document.addEventListener("cg:lang", draw);
  draw();
  CG.apply();
})();
