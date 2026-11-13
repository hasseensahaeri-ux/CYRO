/* CYRO Secure Communication Lab - UI controller. All cryptography comes from CommCore (real Web Crypto);
   every security event is also sent to CYRO's engine, which detects, responds and verifies for real. */
(function () {
  const C = window.CommCore, el = CG.el, $ = function (id) { return document.getElementById(id); };
  CG.add({
    ar: { cm_protection: "حماية الاتصال (CYRO)", cm_p_none: "بلا حماية", cm_p_enc: "تشفير فقط", cm_p_sig: "توقيع فقط", cm_p_full: "حماية CYRO الكاملة",
      cm_t_enc: "التشفير AES-256-GCM", cm_t_enc_d: "يخفي المحتوى ويكشف أي تعديل", cm_t_sig: "التوقيع الرقمي ECDSA", cm_t_sig_d: "يثبت هوية المرسل وسلامة الحزمة",
      cm_t_auth: "تبادل مفاتيح موثّق", cm_t_auth_d: "يمنع الوسيط من استبدال المفاتيح", cm_t_replay: "منع إعادة الإرسال", cm_t_replay_d: "رقم تسلسلي وختم زمني لكل رسالة",
      cm_sender: "المرسل", cm_receiver: "المستقبل", cm_attacker: "المهاجم", cm_channel: "قناة الاتصال", cm_msg: "الرسالة", cm_send: "إرسال", cm_connect: "إنشاء جلسة آمنة",
      cm_log: "سجل الأحداث المباشر", cm_reset: "إعادة ضبط المختبر", cm_defense: "استجابة CYRO",
      cm_safe: "محاكاة محلية بالكامل داخل متصفحك: التشفير حقيقي (Web Crypto) والمهاجم كائن محلي لا يرسل شيئًا لأي جهاز أو شبكة. لا يُخزَّن نص الرسائل في قاعدة البيانات.",
      cm_unsupported: "هذا المختبر يحتاج Web Crypto، وهي متاحة فقط عند فتح الصفحة من localhost أو عبر HTTPS.",
      lvl_insecure: "غير آمنة", lvl_partial: "حماية جزئية", lvl_protected: "محمية بالكامل",
      hs_idle: "الجلسة: لم تُنشأ", hs_ok: "الجلسة: مُنشأة", hs_aborted: "الجلسة: أُجهضت", hs_plain: "الجلسة: لا حاجة لمفتاح", hs_running: "الجلسة: جارٍ التفاوض",
      st_key: "معرّف المفتاح", st_sent: "رسائل", as_idle: "خامل", as_armed: "مسلّح", as_blocked: "محظور بواسطة CYRO",
      ak_none: "بلا هجوم", ak_eavesdrop: "تنصّت", ak_tamper: "تعديل الرسالة", ak_replay: "إعادة إرسال", ak_impersonate: "انتحال المرسل", ak_mitm: "وسيط MITM",
      akd_none: "اتصال سليم دون أي تدخل. جرّبه أولًا.", akd_eavesdrop: "يلتقط الحزمة ويحاول قراءتها دون تغييرها. لا يترك أثرًا على القناة.",
      akd_tamper: "يعترض الحزمة ويغيّر محتواها قبل وصولها (مثل تغيير المبلغ).", akd_replay: "يخزّن حزمة سليمة ويعيد إرسالها لاحقًا لتنفيذها مرة ثانية.",
      akd_impersonate: "يرسل رسالة مزوّرة على أنها من المرسل دون امتلاك مفاتيحه.", akd_mitm: "يستبدل المفاتيح أثناء إنشاء الجلسة ليقف بين الطرفين.",
      md_plain: "نص صريح", md_enc: "مشفرة AES-GCM", md_encsig: "مشفرة وموقّعة", md_sig: "نص صريح موقّع",
      r_integrity: "وسم التشفير (GCM) لا يطابق", r_bad_signature: "التوقيع الرقمي غير صالح", r_replay: "حزمة قديمة أو مكررة", r_handshake_auth: "توقيع المصافحة لا يطابق الهوية الموثّقة",
      ck_signature: "التوقيع", ck_integrity: "السلامة والتشفير", ck_freshness: "الحداثة", ck_pass: "ناجح", ck_fail: "فشل", ck_skip: "غير مفعّل",
      ib_empty: "لا رسائل بعد.", ib_ok: "مقبولة", ib_bad: "مرفوضة",
      oc_attack: "نتيجة الهجوم", oc_conf: "السرية", oc_integ: "السلامة", oc_delivery: "التسليم", oc_detect: "كشف CYRO",
      res_success: "نجح الهجوم", res_partial: "نجاح جزئي", res_failed: "فشل الهجوم", res_blocked: "حُجب الهجوم", res_none: "—",
      conf_exposed: "انكشفت", conf_protected: "محمية", int_compromised: "اختُرقت", int_intact: "سليمة", na: "—",
      dl_accepted: "قُبلت", dl_accepted_mod: "قُبلت بعد التعديل", dl_accepted_replay: "قُبلت نسخة مكررة", dl_accepted_forged: "قُبلت رسالة مزورة", dl_rejected: "رُفضت", dl_aborted: "أُجهضت الجلسة", dl_blocked: "أُسقطت", dl_normal: "سُلّمت",
      det_yes: "اكتُشف وعولج", det_no: "لم يُكتشف",
      ls_eavesdrop_success: "دون تشفير يقرأ أي طرف على القناة الرسالة، والتنصت لا يترك أثرًا يُكتشف، فالتشفير هو الحماية الوحيدة.",
      ls_eavesdrop_failed: "رأى المهاجم نصًا مشفرًا فقط، ومحاولة فك التشفير بلا المفتاح فشلت فعلًا.",
      ls_tamper_success: "لم يكشف شيء التعديل: قبل المستقبل الرسالة المعدّلة. أضف التشفير أو التوقيع.",
      ls_tamper_failed: "كسر التعديل الفحص التشفيري فرفض المستقبل الحزمة، وسجّل CYRO تنبيهًا.",
      ls_replay_success: "قُبلت حزمة سليمة مرتين. التشفير والتوقيع وحدهما لا يثبتان حداثة الرسالة.",
      ls_replay_failed: "كشف الرقم التسلسلي والختم الزمني الحزمة المكررة.",
      ls_impersonate_success: "دون مصادقة لا يستطيع المستقبل معرفة من أرسل الرسالة.",
      ls_impersonate_failed: "لا يملك المهاجم مفتاح الجلسة ولا مفتاح توقيع المرسل، فسقطت الرسالة المزورة.",
      ls_mitm_success: "وقف المهاجم بين الطرفين: التشفير دون مصادقة يعطيك قناة آمنة مع الشخص الخطأ.",
      ls_mitm_partial: "قرأ المهاجم الرسالة لكن التوقيع منع تعديلها. وثّق تبادل المفاتيح ليُمنع القراءة أيضًا.",
      ls_mitm_failed: "كشف التبادل الموثّق استبدال المفتاح فأُجهضت الجلسة. أعد المحاولة بعد أن يحظر CYRO المهاجم.",
      ls_blocked: "أسقط جدار CYRO حزم المهاجم بعد الحادثة السابقة. أعد ضبط المختبر لتجربة هجوم جديد.",
      wv_title: "ما يمر على القناة فعليًا", wv_header: "الترويسة", wv_body: "المحتوى", wv_sig: "التوقيع", wv_none: "لا حزمة بعد.", wv_plain_note: "نص صريح: يقرأه أي شخص",
      df_empty: "ستظهر هنا حوادث CYRO وإجراءاته الدفاعية عند كشف هجوم.",
      is_detected: "مكتشفة", is_responding: "قيد الاستجابة", is_mitigated: "تم احتواؤها", is_failed: "فشل التحقق", is_closed: "مغلقة",
      st_detection: "كشف", st_analysis: "تحليل", st_incident: "حادثة", st_response: "استجابة", st_verification: "تحقق", st_mitigated: "احتواء", st_failed: "فشل", st_report: "تقرير",
      ac_sender: "المرسل", ac_channel: "القناة", ac_attacker: "المهاجم", ac_receiver: "المستقبل", ac_cyro: "CYRO",
      lg_hs_start: "بدء تبادل المفاتيح (ECDH P-256).", lg_hs_ok: "أُنشئت جلسة آمنة، ومعرّف المفتاح {id} متطابق عند الطرفين.", lg_hs_plain: "التشفير متوقف، فلا حاجة لمفتاح جلسة.",
      lg_hs_sub: "استبدل المهاجم المفتاحين العامين أثناء المصافحة.", lg_hs_mitm_ok: "قُبلت المصافحة دون مصادقة: كل طرف يتشارك مفتاحًا مع المهاجم لا مع الطرف الآخر.",
      lg_hs_rejected: "رفض الطرف المصافحة: توقيع المفتاح لا يطابق الهوية الموثّقة مسبقًا. أُجهضت الجلسة.",
      lg_send: "المرسل يرسل الحزمة رقم {seq} ({mode}).", lg_sniff_plain: "التقط المهاجم الحزمة وقرأها: «{text}»",
      lg_sniff_enc: "التقط المهاجم الحزمة فرأى نصًا مشفرًا فقط، وفشلت محاولة فك التشفير.", lg_sniff_mitm: "فك المهاجم التشفير بمفتاح المصافحة المزوّرة وقرأ: «{text}»",
      lg_tamper: "عدّل المهاجم الحزمة ({change}).", lg_replay_cap: "خزّن المهاجم الحزمة لإعادة إرسالها.", lg_replay_send: "يعيد المهاجم إرسال الحزمة المخزنة.",
      lg_forge: "يحقن المهاجم حزمة مزوّرة على أنها من المرسل.", lg_blocked: "أسقط جدار CYRO حزمة المهاجم (المصدر {src} محظور).",
      lg_deliver: "قبل المستقبل الحزمة رقم {seq}: «{text}»", lg_reject: "رفض المستقبل الحزمة رقم {seq}: {reason}.",
      lg_policy_blocked: "منعت سياسة CYRO إرسالًا نصيًا صريحًا وفرضت التشفير على القناة.", lg_policy_enforced: "فرض CYRO التشفير على هذه القناة بعد كشف بيانات حساسة نصية.",
      lg_attacker_blocked: "حظر CYRO مصدر المهاجم {src}.", lg_keys_rotated: "أبطل CYRO المفتاح المخترق وتفاوض الطرفان على مفتاح جديد.",
      lg_incident: "حادثة CYRO رقم {id}: {title} ({status}).", lg_nosession: "لا جلسة آمنة: لم يُرسل شيء.", lg_reset: "أُعيد ضبط المختبر وجلسة CYRO.", lg_net: "تعذر الاتصال بمحرك CYRO؛ يعمل المختبر محليًا دون كشف.",
      lg_change_text: "تغيّر النص من «{from}» إلى «{to}»", lg_change_bit: "قلب بت واحد في النص المشفر" },
    en: { cm_protection: "Channel protection (CYRO)", cm_p_none: "No protection", cm_p_enc: "Encryption only", cm_p_sig: "Signature only", cm_p_full: "Full CYRO protection",
      cm_t_enc: "AES-256-GCM encryption", cm_t_enc_d: "Hides the content and exposes any change", cm_t_sig: "ECDSA digital signature", cm_t_sig_d: "Proves who sent it and that it is intact",
      cm_t_auth: "Authenticated key exchange", cm_t_auth_d: "Stops a man-in-the-middle from swapping keys", cm_t_replay: "Replay protection", cm_t_replay_d: "Sequence number and timestamp on every message",
      cm_sender: "Sender", cm_receiver: "Receiver", cm_attacker: "Attacker", cm_channel: "Communication channel", cm_msg: "Message", cm_send: "Send", cm_connect: "Establish secure session",
      cm_log: "Live event log", cm_reset: "Reset lab", cm_defense: "CYRO response",
      cm_safe: "Fully local simulation inside your browser: the cryptography is real (Web Crypto) and the attacker is a local object that sends nothing to any device or network. Message text is never stored in the database.",
      cm_unsupported: "This lab needs Web Crypto, which is only available on localhost or over HTTPS.",
      lvl_insecure: "Insecure", lvl_partial: "Partially protected", lvl_protected: "Fully protected",
      hs_idle: "Session: not established", hs_ok: "Session: established", hs_aborted: "Session: aborted", hs_plain: "Session: no key needed", hs_running: "Session: negotiating",
      st_key: "Key ID", st_sent: "Messages", as_idle: "Idle", as_armed: "Armed", as_blocked: "Blocked by CYRO",
      ak_none: "No attack", ak_eavesdrop: "Eavesdropping", ak_tamper: "Tampering", ak_replay: "Replay", ak_impersonate: "Impersonation", ak_mitm: "Man-in-the-middle",
      akd_none: "A clean connection with no interference. Try it first.", akd_eavesdrop: "Captures the packet and tries to read it without changing it. Leaves no trace on the channel.",
      akd_tamper: "Intercepts the packet and changes its content before it arrives (for example the amount).", akd_replay: "Stores a valid packet and re-sends it later so it runs again.",
      akd_impersonate: "Sends a forged message claiming to be the sender, without owning its keys.", akd_mitm: "Swaps the keys while the session is being set up to sit between both parties.",
      md_plain: "plain text", md_enc: "AES-GCM encrypted", md_encsig: "encrypted and signed", md_sig: "plain text, signed",
      r_integrity: "encryption tag (GCM) mismatch", r_bad_signature: "invalid digital signature", r_replay: "stale or repeated packet", r_handshake_auth: "handshake signature does not match the pinned identity",
      ck_signature: "Signature", ck_integrity: "Integrity / decryption", ck_freshness: "Freshness", ck_pass: "passed", ck_fail: "failed", ck_skip: "not enabled",
      ib_empty: "No messages yet.", ib_ok: "accepted", ib_bad: "rejected",
      oc_attack: "Attack result", oc_conf: "Confidentiality", oc_integ: "Integrity", oc_delivery: "Delivery", oc_detect: "CYRO detection",
      res_success: "Attack succeeded", res_partial: "Partial success", res_failed: "Attack failed", res_blocked: "Attack blocked", res_none: "—",
      conf_exposed: "Exposed", conf_protected: "Protected", int_compromised: "Compromised", int_intact: "Intact", na: "—",
      dl_accepted: "Accepted", dl_accepted_mod: "Accepted after modification", dl_accepted_replay: "Duplicate accepted", dl_accepted_forged: "Forged message accepted", dl_rejected: "Rejected", dl_aborted: "Session aborted", dl_blocked: "Dropped", dl_normal: "Delivered",
      det_yes: "Detected and handled", det_no: "Not detected",
      ls_eavesdrop_success: "Without encryption anyone on the channel can read the message, and eavesdropping leaves no detectable trace, so encryption is the only protection.",
      ls_eavesdrop_failed: "The attacker saw ciphertext only, and a real decryption attempt without the key failed.",
      ls_tamper_success: "Nothing detected the change: the receiver accepted the modified message. Add encryption or a signature.",
      ls_tamper_failed: "The edit broke the cryptographic check, so the receiver rejected the packet and CYRO raised an alert.",
      ls_replay_success: "A valid packet was accepted twice. Encryption and signatures alone do not prove a message is fresh.",
      ls_replay_failed: "The sequence number and timestamp exposed the repeated packet.",
      ls_impersonate_success: "Without authentication the receiver cannot tell who sent the message.",
      ls_impersonate_failed: "The attacker has neither the session key nor the sender's signing key, so the forged message failed.",
      ls_mitm_success: "The attacker sat between both parties: encryption without authentication gives you a secure channel to the wrong person.",
      ls_mitm_partial: "The attacker read the message but the signature stopped the modification. Authenticate the key exchange to stop the reading too.",
      ls_mitm_failed: "The authenticated handshake exposed the key swap and the session was aborted. Try again after CYRO blocks the attacker.",
      ls_blocked: "CYRO's firewall dropped the attacker's packets after the previous incident. Reset the lab to try a new attack.",
      wv_title: "What actually crosses the channel", wv_header: "Header", wv_body: "Body", wv_sig: "Signature", wv_none: "No packet yet.", wv_plain_note: "plain text: anyone can read it",
      df_empty: "CYRO incidents and defensive actions appear here when an attack is detected.",
      is_detected: "Detected", is_responding: "Responding", is_mitigated: "Mitigated", is_failed: "Verification failed", is_closed: "Closed",
      st_detection: "Detection", st_analysis: "Analysis", st_incident: "Incident", st_response: "Response", st_verification: "Verification", st_mitigated: "Mitigated", st_failed: "Failed", st_report: "Report",
      ac_sender: "Sender", ac_channel: "Channel", ac_attacker: "Attacker", ac_receiver: "Receiver", ac_cyro: "CYRO",
      lg_hs_start: "Starting key exchange (ECDH P-256).", lg_hs_ok: "Secure session established; key ID {id} matches on both sides.", lg_hs_plain: "Encryption is off, so no session key is needed.",
      lg_hs_sub: "The attacker replaced both public keys during the handshake.", lg_hs_mitm_ok: "Handshake accepted without authentication: each side now shares a key with the attacker, not with the other party.",
      lg_hs_rejected: "The handshake was rejected: the key signature does not match the pre-pinned identity. Session aborted.",
      lg_send: "Sender sends packet #{seq} ({mode}).", lg_sniff_plain: "The attacker captured the packet and read it: “{text}”",
      lg_sniff_enc: "The attacker captured the packet and saw ciphertext only; the decryption attempt failed.", lg_sniff_mitm: "The attacker decrypted it with the forged-handshake key and read: “{text}”",
      lg_tamper: "The attacker modified the packet ({change}).", lg_replay_cap: "The attacker stored the packet for replay.", lg_replay_send: "The attacker re-sends the stored packet.",
      lg_forge: "The attacker injects a forged packet claiming to be the sender.", lg_blocked: "CYRO's firewall dropped the attacker's packet (source {src} is blocked).",
      lg_deliver: "The receiver accepted packet #{seq}: “{text}”", lg_reject: "The receiver rejected packet #{seq}: {reason}.",
      lg_policy_blocked: "CYRO policy blocked a clear-text send and enforced encryption on the channel.", lg_policy_enforced: "CYRO enforced encryption on this channel after sensitive clear text was detected.",
      lg_attacker_blocked: "CYRO blocked the attacker source {src}.", lg_keys_rotated: "CYRO revoked the compromised key and both sides negotiated a new one.",
      lg_incident: "CYRO incident #{id}: {title} ({status}).", lg_nosession: "No secure session: nothing was sent.", lg_reset: "The lab and the CYRO session were reset.", lg_net: "Could not reach the CYRO engine; the lab runs locally without detection.",
      lg_change_text: "text changed from “{from}” to “{to}”", lg_change_bit: "one bit flipped in the ciphertext" }
  });

  if (!C || !C.supported) { $("commRoot").replaceChildren(el("div", "alert alert-danger", CG.t("cm_unsupported"))); CG.apply(); return; }

  const RM = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const ATTACKS = ["none", "eavesdrop", "tamper", "replay", "impersonate", "mitm"];
  const PKT_W = 132, PKT_H = 34;
  const newSession = function () { return "comm-" + Array.from(crypto.getRandomValues(new Uint8Array(8)), function (b) { return (b % 36).toString(36); }).join(""); };
  const S = { cfg: Object.assign({}, C.PRESETS.none), attack: "none", world: null, needHS: true, hsState: "idle", keyId: null, mitmActive: false,
              sent: 0, busy: false, session: newSession(), blocked: false, src: null, logs: [], incs: new Map(), outcome: null, inbox: [], checks: null, wire: null, rotate: false };
  const sleep = function (ms) { return new Promise(function (r) { setTimeout(r, RM ? 10 : ms); }); };
  const L = function (o) { return o ? o[CG.lang] : ""; };
  const tt = function (k) { return CG.t(k); };

  // ---------- log ----------
  function fmt(entry) {
    const p = Object.assign({}, entry.p);
    if (p.reason) p.reason = tt("r_" + p.reason);
    if (p.mode) p.mode = tt("md_" + p.mode);
    if (p.change) p.change = p.change.kind === "text" ? tt("lg_change_text").replace("{from}", p.change.from).replace("{to}", p.change.to) : tt("lg_change_bit");
    if (p.title && typeof p.title === "object") p.title = L(p.title);
    if (p.status) p.status = tt("is_" + p.status);
    return tt(entry.key).replace(/\{(\w+)\}/g, function (_, n) { return p[n] !== undefined && p[n] !== null ? p[n] : ""; });
  }
  function drawLog() {
    const box = $("logList");
    if (!S.logs.length) { box.replaceChildren(); return; }
    box.replaceChildren.apply(box, S.logs.map(function (e) {
      const r = el("div", "frow log-" + e.actor);
      r.append(el("span", "dot"), el("span", "t", new Date(e.t).toLocaleTimeString("en-GB")), el("span", "msg", fmt(e)), el("span", "badge actor-" + e.actor, tt("ac_" + e.actor)));
      return r;
    }));
  }
  function log(actor, key, p) { S.logs.unshift({ t: Date.now(), actor: actor, key: key, p: p || {} }); if (S.logs.length > 200) S.logs.pop(); drawLog(); }

  // ---------- status, protection ----------
  function level() { return C.level(S.cfg); }
  function drawStatus() {
    const lv = level(), box = $("statusChips");
    const chip = function (cls, text) { return el("span", "chip " + cls, text); };
    const hsCls = S.hsState === "ok" || S.hsState === "plain" ? "on" : S.hsState === "aborted" ? "danger-chip" : "";
    box.replaceChildren(chip("lv-" + lv, tt("lvl_" + lv)), chip(hsCls, tt("hs_" + S.hsState)),
      chip(S.keyId ? "on mono" : "", tt("st_key") + ": " + (S.keyId || "—")), chip("", tt("st_sent") + ": " + CG.num(S.sent)));
    $("chanLevel").className = "chip lv-" + lv; $("chanLevel").textContent = tt("lvl_" + lv);
    $("wire").className = "wire lv-" + lv;
    $("lockIco").classList.toggle("locked", !!S.cfg.encryption);
    const st = $("atkState");
    st.className = "badge " + (S.blocked ? "st-mitigated" : S.attack !== "none" ? "st-failed" : "");
    st.textContent = S.blocked ? tt("as_blocked") : S.attack !== "none" ? tt("as_armed") : tt("as_idle");
    $("atkDesc").textContent = tt("akd_" + S.attack);
    document.querySelectorAll("[data-preset]").forEach(function (b) {
      const p = C.PRESETS[b.dataset.preset];
      b.classList.toggle("active", Object.keys(p).every(function (k) { return p[k] === S.cfg[k]; }));
    });
    $("bSend").disabled = S.busy; $("bConnect").disabled = S.busy;
  }
  function syncToggles() { $("tEnc").checked = S.cfg.encryption; $("tSig").checked = S.cfg.signature; $("tAuth").checked = S.cfg.authHandshake; $("tReplay").checked = S.cfg.antiReplay; }
  function setCfg(patch) {
    Object.assign(S.cfg, patch);
    S.needHS = true; S.mitmActive = false;
    S.hsState = S.cfg.encryption ? "idle" : "plain"; S.keyId = null;
    syncToggles(); drawStatus();
  }
  function drawAttackPick() {
    const box = $("atkPick");
    box.replaceChildren.apply(box, ATTACKS.map(function (a) {
      const b = el("button", "atk-btn" + (S.attack === a ? " sel" : ""), tt("ak_" + a)); b.type = "button";
      b.setAttribute("role", "radio"); b.setAttribute("aria-checked", S.attack === a ? "true" : "false");
      b.addEventListener("click", function () { if (S.busy) return; S.attack = a; S.needHS = true; S.mitmActive = false; drawAttackPick(); drawStatus(); });
      return b;
    }));
  }

  // ---------- wire / receiver views ----------
  function drawWire() {
    const box = $("wireView"), p = S.wire;
    const title = el("strong", "", tt("wv_title"));
    if (!p) { box.replaceChildren(title, el("p", "empty", tt("wv_none"))); return; }
    const plain = p.body.mode === "plain";
    const row = function (k, v, cls) { const r = el("div", "wv-row"); r.append(el("span", "k", tt(k)), el("span", "v mono " + (cls || ""), v)); return r; };
    const bodyTxt = plain ? new TextDecoder().decode(C.fromHex(p.body.data)) : p.body.data.slice(0, 64) + (p.body.data.length > 64 ? "…" : "");
    box.replaceChildren(title, row("wv_header", C.headerString(p.h)), row("wv_body", bodyTxt + (plain ? "   (" + tt("wv_plain_note") + ")" : ""), plain ? "plain" : "cipher"),
      row("wv_sig", p.sig ? p.sig.slice(0, 40) + "…" : "—"));
  }
  function drawChecks() {
    const box = $("checks"), c = S.checks || { signature: null, integrity: null, freshness: null };
    box.replaceChildren.apply(box, ["signature", "integrity", "freshness"].map(function (k) {
      const v = c[k], r = el("div", "chk " + (v === true ? "pass" : v === false ? "fail" : "skip"));
      r.append(el("span", "ico-s", v === true ? "✓" : v === false ? "✕" : "–"), el("span", "", tt("ck_" + k)), el("span", "k", tt(v === true ? "ck_pass" : v === false ? "ck_fail" : "ck_skip")));
      return r;
    }));
  }
  function drawInbox() {
    const box = $("inbox");
    if (!S.inbox.length) { box.replaceChildren(el("p", "empty", tt("ib_empty"))); return; }
    box.replaceChildren.apply(box, S.inbox.map(function (m) {
      const r = el("div", "msg-item " + (m.ok ? "ok" : "bad"));
      r.append(el("strong", "", "#" + m.seq + " · " + tt(m.ok ? "ib_ok" : "ib_bad")), el("span", "", m.ok ? "“" + m.text + "”" : tt("r_" + m.reason)));
      return r;
    }));
  }
  function drawOutcome() {
    const box = $("outcome"), o = S.outcome;
    if (!o) { box.replaceChildren(); return; }
    const card = function (k, v, cls) { const c = el("div", "oc-card " + cls); c.append(el("span", "k", tt(k)), el("strong", "", v)); return c; };
    const resCls = { success: "bad", partial: "warn", failed: "ok", blocked: "ok", none: "na" }[o.res];
    const cards = el("div", "oc-grid");
    cards.append(card("oc_attack", tt("res_" + o.res), resCls), card("oc_conf", tt(o.conf === "na" ? "na" : "conf_" + o.conf), o.conf === "exposed" ? "bad" : o.conf === "protected" ? "ok" : "na"),
      card("oc_integ", tt(o.integ === "na" ? "na" : "int_" + o.integ), o.integ === "compromised" ? "bad" : o.integ === "intact" ? "ok" : "na"),
      card("oc_delivery", tt("dl_" + o.delivery), /^accepted_/.test(o.delivery) ? "bad" : o.delivery === "normal" || o.delivery === "accepted" ? "na" : "ok"),
      card("oc_detect", tt(o.detected ? "det_yes" : "det_no"), o.detected ? "ok" : o.attack === "none" ? "na" : "warn"));
    const kids = [cards];
    const lessonKey = o.res === "blocked" ? "ls_blocked" : "ls_" + o.attack + "_" + o.res;
    if (o.attack !== "none" && CG.t(lessonKey) !== lessonKey) kids.push(el("p", "lesson", tt(lessonKey)));
    box.replaceChildren.apply(box, kids);
  }

  // ---------- defense panel (live from the engine) ----------
  function incCard(id) {
    if (!S.incs.has(id)) {
      const c = { id: id, title: null, severity: null, status: "detected", entries: [], el: el("div", "inc-card") };
      S.incs.set(id, c);
      const box = $("defList"); if (!box.querySelector(".inc-card")) box.replaceChildren();
      box.prepend(c.el);
    }
    return S.incs.get(id);
  }
  function paintInc(c) {
    const head = el("div", "inc-head");
    head.append(el("strong", "", "#" + c.id + " " + (c.title ? L(c.title) : "")));
    if (c.severity) head.append(el("span", "badge sev-" + c.severity, tt("sev_" + c.severity)));
    head.append(el("span", "badge st-" + c.status, tt("is_" + c.status)));
    const tl = el("div", "tl");
    c.entries.forEach(function (e) { const r = el("div", "tl-row tl-" + e.stage); r.append(el("span", "tl-stage", tt("st_" + e.stage)), el("span", "tl-msg", L(e.message))); tl.append(r); });
    c.el.replaceChildren(head, tl);
  }
  function drawDefense() {
    if (!S.incs.size) $("defList").replaceChildren(el("p", "empty", tt("df_empty")));
    S.incs.forEach(paintInc);
  }
  CG.on("timeline", function (d) { if (!String(d.session).endsWith(":" + S.session)) return; const c = incCard(d.incident_id); c.entries.push({ stage: d.stage, message: d.message }); paintInc(c); });
  CG.on("incident", function (d) { if (!String(d.session).endsWith(":" + S.session)) return; const c = incCard(d.id); c.title = d.title; c.severity = d.severity; c.status = d.status; paintInc(c); });

  // ---------- scene animation ----------
  const zone = $("zone"), track = $("track");
  const vertical = function () { return matchMedia("(max-width: 820px)").matches; };
  const dims = function () {
    const v = vertical();
    return { v: v, L: v ? track.clientHeight : track.clientWidth, len: v ? PKT_H : (PKT_W), dy: v ? Math.round(zone.clientWidth * 0.4) : 86 };
  };
  const tr = function (v, x, y) { return v ? "translate(" + y + "px," + x + "px)" : "translate(" + x + "px," + y + "px)"; };
  function makePkt(label, cls, iconName) {
    const p = el("div", "pkt " + (cls || ""));
    const ic = document.createElementNS("http://www.w3.org/2000/svg", "svg"); ic.setAttribute("class", "ico sm");
    const u = document.createElementNS("http://www.w3.org/2000/svg", "use"); u.setAttribute("href", "#i-" + (iconName || "comm")); ic.appendChild(u);
    p.append(ic, el("span", "mono", label));
    p._pos = { x: 0, y: 0 }; zone.appendChild(p); p.style.transform = tr(vertical(), 0, 0);
    return p;
  }
  function at(f, y) { const g = dims(); return { x: Math.round(f * (g.L - g.len)), y: y || 0 }; }
  function placeAt(p, f, y) { const t = at(f, y); p._pos = t; p.style.transform = tr(vertical(), t.x, t.y); }
  async function go(p, f, y, ms) {
    const g = dims(), t = at(f, y), from = p._pos;
    const a = p.animate([{ transform: tr(g.v, from.x, from.y) }, { transform: tr(g.v, t.x, t.y) }], { duration: RM ? 10 : ms, easing: "cubic-bezier(.4,0,.2,1)", fill: "forwards" });
    p._pos = t; await a.finished.catch(function () { /* cancelled by reset */ });
  }
  const atkY = function () { return dims().dy; };
  function label(p, text, cls) { p.querySelector("span").textContent = text; if (cls !== undefined) p.className = "pkt " + cls; }
  async function dispose(p, cls) { p.classList.add(cls || "gone"); await sleep(450); p.remove(); }
  const pktLabel = function (pk) { return pk.body.mode === "plain" ? new TextDecoder().decode(C.fromHex(pk.body.data)).slice(0, 14) + "…" : pk.body.data.slice(0, 10) + "…"; };
  const pktCls = function (pk) { return pk.body.mode === "plain" ? "plain" : "cipher"; };
  const pktIcon = function (pk) { return pk.body.mode === "plain" ? "comm" : "lock"; };
  const modeOf = function () { return S.cfg.encryption ? (S.cfg.signature ? "encsig" : "enc") : (S.cfg.signature ? "sig" : "plain"); };

  // ---------- engine bridge ----------
  async function post(kind, details) {
    const r = await CG.api("/api/comm/event", { session: S.session, kind: kind, details: details || {} });
    if (!r.ok) { log("cyro", "lg_net"); return { outcome: "allowed", incidents: [] }; }
    if (r.source && (kind === "comm_inject" || kind === "comm_intercept" || kind === "comm_reject")) S.src = r.source;
    return r;
  }
  async function applyIncidents(list) {
    for (const inc of list || []) {
      log("cyro", "lg_incident", { id: inc.id, title: inc.title, status: inc.status });
      for (const a of inc.actions) {
        if (a.action === "block_source") { S.blocked = true; log("cyro", "lg_attacker_blocked", { src: S.src }); }
        if (a.action === "rotate_keys") S.rotate = true;
        if (a.action === "enforce_encryption") { setCfg({ encryption: true }); log("cyro", "lg_policy_enforced"); }
      }
    }
    drawStatus();
  }

  // ---------- protocol flows ----------
  async function doConnect() {
    S.hsState = "running"; drawStatus(); log("sender", "lg_hs_start");
    let mitm = S.attack === "mitm" && S.cfg.encryption;
    if (mitm) {
      const r = await post("comm_inject", { attack: "mitm" });
      if (r.outcome === "dropped") { mitm = false; log("cyro", "lg_blocked", { src: S.src }); }
    }
    const hs = await C.handshake(S.world, mitm);
    if (!S.cfg.encryption) { S.hsState = "plain"; S.needHS = false; log("sender", "lg_hs_plain"); drawStatus(); return; }
    const flight = async function (fromF, toF) {
      const k = makePkt("ECDH key", "key", "lock"); placeAt(k, fromF, 0);
      await go(k, 0.5, 0, 650);
      if (mitm) { label(k, "ECDH (attacker)", "key forged"); await go(k, 0.5, atkY(), 350); await go(k, 0.5, 0, 350); }
      await go(k, toF, 0, 650); await dispose(k);
    };
    await Promise.all([flight(0, 1), flight(1, 0)]);
    if (mitm) log("attacker", "lg_hs_sub");
    if (!hs.established) {
      S.hsState = "aborted"; S.needHS = true; S.keyId = null; log("receiver", "lg_hs_rejected");
      const r = await post("comm_reject", { reason: "handshake_auth", origin: "attacker" });
      await applyIncidents(r.incidents);
      S.outcome = { attack: "mitm", res: "failed", conf: "protected", integ: "intact", delivery: "aborted", detected: (r.incidents || []).length > 0 };
      drawOutcome(); drawStatus(); return;
    }
    S.hsState = "ok"; S.keyId = hs.keyId; S.needHS = false; S.mitmActive = hs.mitm; S.rotate = false;
    log("sender", hs.mitm ? "lg_hs_mitm_ok" : "lg_hs_ok", { id: hs.keyId });
    await post("comm_handshake", { auth: S.cfg.authHandshake, mitm: hs.mitm, ok: true, key_id: hs.keyId });
    drawStatus();
  }

  async function receive(p, pk, meta, ctx) {
    await go(pk, 1, 0, 750);
    const rx = await C.openPacket(S.world, p, Date.now());
    S.checks = rx.checks; drawChecks();
    S.inbox.unshift({ seq: p.h.seq, ok: rx.accepted, text: rx.text, reason: rx.reason }); drawInbox();
    if (rx.accepted) {
      log("receiver", "lg_deliver", { seq: p.h.seq, text: rx.text });
      pk.classList.add("accepted");
      await post("comm_accept", { attack: meta.attack, seq: p.h.seq, key_id: S.keyId });
    } else {
      log("receiver", "lg_reject", { seq: p.h.seq, reason: rx.reason });
      pk.classList.add("rejected");
      const r = await post("comm_reject", { reason: rx.reason, origin: meta.fromAttacker ? "attacker" : "sender", key_id: S.keyId, seq: p.h.seq });
      if ((r.incidents || []).length) ctx.detected = true;
      await applyIncidents(r.incidents);
    }
    await dispose(pk, rx.accepted ? "gone" : "gone");
    return rx;
  }

  async function doSend() {
    const text = $("msg").value.trim();
    if (!text) return;
    S.outcome = null; drawOutcome();
    const ctx = { attack: S.attack, read: null, modified: false, accepted: null, blocked: false, detected: false, delivery: "normal", forgedOrReplayed: false };

    // 1) the gateway checks clear-text traffic (policy rule CR-CM-004)
    if (!S.cfg.encryption) {
      const r = await post("comm_send", { encrypted: false, text: text, signed: S.cfg.signature });
      if (r.outcome === "dropped") { log("cyro", "lg_policy_blocked"); setCfg({ encryption: true }); }
      else if ((r.incidents || []).length) { ctx.policy = r.incidents; }   // a policy finding, not an attack detection
    }
    // 2) make sure a session exists
    if (S.needHS || (S.cfg.encryption && !S.world.session)) await doConnect();
    if (S.cfg.encryption && !S.world.session) { log("sender", "lg_nosession"); return; }
    if (S.cfg.encryption) await post("comm_send", { encrypted: true, signed: S.cfg.signature, key_id: S.keyId });

    // 3) build the real packet and send it
    const pkt = await C.buildPacket(S.world, text, Date.now());
    S.sent++; S.wire = pkt; drawWire(); drawStatus();
    log("sender", "lg_send", { seq: pkt.h.seq, mode: modeOf() });
    const pk = makePkt(pktLabel(pkt), pktCls(pkt), pktIcon(pkt));
    await go(pk, 0.5, 0, 800);

    let delivered = pkt, meta = { attack: S.attack === "eavesdrop" || S.attack === "none" ? "none" : S.attack, fromAttacker: false };
    const atk = S.attack;
    if (atk === "eavesdrop") {
      ctx.read = await C.eavesdrop(S.world, pkt);
      await post("comm_intercept", { readable: ctx.read.readable, how: ctx.read.how });
      const copy = makePkt(pktLabel(pkt), pktCls(pkt), pktIcon(pkt)); placeAt(copy, 0.5, 0);
      await go(copy, 0.5, atkY(), 500);
      log("attacker", ctx.read.readable ? "lg_sniff_plain" : "lg_sniff_enc", { text: ctx.read.text });
      copy.classList.add(ctx.read.readable ? "exposed" : "sealed"); await sleep(500); copy.remove();
    } else if (atk === "tamper" || (atk === "mitm" && !S.mitmActive)) {
      const r = await post("comm_inject", { attack: atk === "mitm" ? "tamper" : atk });
      if (r.outcome === "dropped") { ctx.blocked = true; log("cyro", "lg_blocked", { src: S.src }); }
      else {
        await go(pk, 0.5, atkY(), 450);
        const t = C.tamper(pkt); delivered = t.packet; ctx.modified = true; meta.fromAttacker = true;
        if (atk === "mitm") { ctx.read = await C.eavesdrop(S.world, pkt); await post("comm_intercept", { readable: ctx.read.readable, how: ctx.read.how }); log("attacker", "lg_sniff_plain", { text: ctx.read.text }); }
        log("attacker", "lg_tamper", { change: t.change });
        label(pk, pktLabel(delivered), "pkt " + pktCls(delivered) + " tampered");
        await go(pk, 0.5, 0, 450);
      }
    } else if (atk === "mitm" && S.mitmActive) {
      const r = await post("comm_inject", { attack: "mitm" });
      if (r.outcome === "dropped") { ctx.blocked = true; S.needHS = true; S.mitmActive = false; log("cyro", "lg_blocked", { src: S.src }); log("sender", "lg_nosession"); await dispose(pk); S.outcome = { attack: atk, res: "blocked", conf: "protected", integ: "intact", delivery: "blocked", detected: ctx.detected }; drawOutcome(); return; }
      await go(pk, 0.5, atkY(), 450);
      const m = await C.mitmRelay(S.world, pkt, true); ctx.read = m.read; delivered = m.packet; ctx.modified = true; meta.fromAttacker = true;
      await post("comm_intercept", { readable: m.read.readable, how: m.read.how });
      log("attacker", m.read.how === "plaintext" ? "lg_sniff_plain" : "lg_sniff_mitm", { text: m.read.text });
      label(pk, pktLabel(delivered), "pkt " + pktCls(delivered) + " tampered");
      await go(pk, 0.5, 0, 450);
    }

    const rx = await receive(delivered, pk, meta, ctx);
    ctx.accepted = rx.accepted; ctx.rx = rx;
    if (atk === "tamper" || atk === "mitm") ctx.delivery = ctx.blocked ? "blocked" : rx.accepted ? (ctx.modified ? "accepted_mod" : "normal") : "rejected";

    // 4) replay and impersonation happen after the genuine message
    if (atk === "replay" || atk === "impersonate") {
      await sleep(700);
      if (atk === "replay") log("attacker", "lg_replay_cap");
      await sleep(500);
      const r = await post("comm_inject", { attack: atk });
      if (r.outcome === "dropped") { ctx.blocked = true; ctx.delivery = "blocked"; log("cyro", "lg_blocked", { src: S.src }); }
      else {
        const fake = atk === "replay" ? C.replay(pkt) : await C.forge(S.world, "Transfer 9999 to attacker account", Date.now());
        log("attacker", atk === "replay" ? "lg_replay_send" : "lg_forge");
        S.wire = fake; drawWire();
        const ap = makePkt(pktLabel(fake), (pktCls(fake)) + (atk === "replay" ? " replay" : " forged"), "spy");
        placeAt(ap, 0.5, atkY()); await go(ap, 0.5, 0, 450);
        const rx2 = await receive(fake, ap, { attack: atk, fromAttacker: true }, ctx);
        ctx.accepted = rx2.accepted; ctx.forgedOrReplayed = true; ctx.delivery = rx2.accepted ? (atk === "replay" ? "accepted_replay" : "accepted_forged") : "rejected";
      }
    } else if (atk === "eavesdrop") ctx.delivery = "normal";

    // 5) outcome indicators
    if (ctx.policy) await applyIncidents(ctx.policy);
    let res = "failed";
    if (atk === "eavesdrop") res = ctx.read && ctx.read.readable ? "success" : "failed";
    else if (atk === "tamper") res = ctx.accepted && ctx.modified ? "success" : "failed";
    else if (atk === "replay" || atk === "impersonate") res = ctx.forgedOrReplayed && ctx.accepted ? "success" : "failed";
    else if (atk === "mitm") res = ctx.accepted && ctx.modified ? "success" : ctx.read && ctx.read.readable ? "partial" : "failed";
    else res = "none";
    if (ctx.blocked) res = "blocked";
    S.outcome = { attack: atk, res: res, conf: atk === "none" ? "na" : (ctx.read && ctx.read.readable ? "exposed" : "protected"),
                  integ: atk === "none" || atk === "eavesdrop" ? "na" : ((ctx.accepted && (ctx.modified || ctx.forgedOrReplayed)) ? "compromised" : "intact"),
                  delivery: ctx.delivery, detected: ctx.detected };
    drawOutcome();
    if (S.rotate) { S.rotate = false; S.needHS = true; log("cyro", "lg_keys_rotated"); await doConnect(); }
  }

  async function guarded(fn) {
    if (S.busy) return;
    S.busy = true; drawStatus();
    try { await fn(); } catch (e) { console.error(e); } finally { S.busy = false; drawStatus(); }
  }

  async function reset() {
    await guarded(async function () {
      await CG.api("/api/comm/reset", { session: S.session });
      zone.querySelectorAll(".pkt").forEach(function (p) { p.remove(); });
      S.session = newSession(); S.world = await C.createWorld(S.cfg);
      Object.assign(S, { needHS: true, hsState: S.cfg.encryption ? "idle" : "plain", keyId: null, mitmActive: false, sent: 0, blocked: false, src: null,
                         logs: [], incs: new Map(), outcome: null, inbox: [], checks: null, wire: null, rotate: false });
      $("defList").replaceChildren(); drawAll(); log("cyro", "lg_reset");
    });
  }

  function drawAll() { drawStatus(); drawAttackPick(); drawWire(); drawChecks(); drawInbox(); drawOutcome(); drawDefense(); drawLog(); }

  // ---------- wiring ----------
  $("tEnc").addEventListener("change", function () { setCfg({ encryption: $("tEnc").checked }); });
  $("tSig").addEventListener("change", function () { setCfg({ signature: $("tSig").checked }); });
  $("tAuth").addEventListener("change", function () { setCfg({ authHandshake: $("tAuth").checked }); });
  $("tReplay").addEventListener("change", function () { setCfg({ antiReplay: $("tReplay").checked }); });
  document.querySelectorAll("[data-preset]").forEach(function (b) { b.addEventListener("click", function () { if (!S.busy) setCfg(C.PRESETS[b.dataset.preset]); }); });
  $("bSend").addEventListener("click", function () { guarded(doSend); });
  $("bConnect").addEventListener("click", function () { guarded(async function () { S.needHS = true; await doConnect(); }); });
  $("bReset").addEventListener("click", reset);
  document.addEventListener("cg:lang", drawAll);

  (async function init() {
    CG.apply();
    $("msg").value = CG.lang === "ar" ? "حوّل 100 إلى الحساب 4521" : "Transfer 100 to account 4521";
    S.world = await C.createWorld(S.cfg);
    $("fpSender").textContent = "ID " + S.world.sender.fp.slice(0, 8); $("fpReceiver").textContent = "ID " + S.world.receiver.fp.slice(0, 8);
    $("fpSender").title = $("fpReceiver").title = S.world.sender.fp;
    S.hsState = "plain"; syncToggles(); drawAll();
  })();
})();
