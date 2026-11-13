"""Security awareness quiz. Answers are scored on the server."""

# (id, category, q_ar, q_en, [options_ar], [options_en], correct_index, expl_ar, expl_en)
Q = [
 ("p1", "phishing",
  "وصلتك رسالة من «البنك» تطلب تأكيد بياناتك عبر رابط خلال ساعة. ما التصرف الأصح؟",
  "A message from “your bank” asks you to confirm your data via a link within an hour. What is the best action?",
  ["أضغط الرابط وأؤكد بسرعة", "أفتح تطبيق البنك أو موقعه الرسمي بنفسي وأتحقق", "أرسل الرسالة لأصدقائي ليتحققوا"],
  ["Click the link and confirm quickly", "Open the bank's official app or site myself and check", "Forward it to friends to check"],
  1, "الاستعجال علامة تصيد. ادخل دائمًا من القناة الرسمية التي تعرفها لا من الرابط.",
  "Urgency is a phishing sign. Always go through the official channel you know, not the link."),
 ("p2", "phishing",
  "أي مما يلي أقوى مؤشر على أن الرابط مزيف؟",
  "Which is the strongest sign that a link is fake?",
  ["يبدأ بـ https", "paypal.com.account-verify.xyz", "يحتوي على أرقام"],
  ["It starts with https", "paypal.com.account-verify.xyz", "It contains numbers"],
  1, "النطاق الحقيقي هو آخر جزء قبل الامتداد (account-verify.xyz) وليس paypal.com. وhttps وحده لا يعني الأمان.",
  "The real domain is the last part before the extension (account-verify.xyz), not paypal.com. https alone does not mean safe."),
 ("p3", "phishing",
  "ما الذي تفعله الجهات الموثوقة عادة؟",
  "What do trustworthy organizations typically do?",
  ["تطلب كلمة المرور عبر رسالة للتحقق", "لا تطلب كلمة المرور أو رمز التحقق عبر الرسائل", "ترسل روابط تسجيل دخول لكل عميل يوميًا"],
  ["Ask for your password by message to verify you", "Never ask for your password or code by message", "Send login links to every customer daily"],
  1, "لا يطلب أي موظف شرعي كلمة مرورك أو رمز التحقق أبدًا.",
  "No legitimate employee will ever ask for your password or verification code."),
 ("s1", "social",
  "اتصل شخص يدّعي أنه من الدعم الفني ويطلب رمزًا وصلك للتو برسالة. ماذا تفعل؟",
  "Someone claiming to be tech support asks for a code you just received by SMS. What do you do?",
  ["أعطيه الرمز ليساعدني", "أنهي المكالمة ولا أشاركه أبدًا", "أعطيه نصف الرمز فقط"],
  ["Give it so they can help", "Hang up and never share it", "Give only half of the code"],
  1, "الرمز مفتاح حسابك. المهاجم يطلبه بعد أن يبدأ دخولًا فعليًا إلى حسابك.",
  "The code is the key to your account. The attacker asks for it while actually logging in to it."),
 ("s2", "social",
  "وجدت فلاشة USB في موقف سيارات الشركة. الأفضل:",
  "You find a USB drive in the company car park. Best action:",
  ["أوصلها بجهازي لمعرفة صاحبها", "أسلّمها لقسم الأمن دون توصيلها", "أستخدمها لأن مساحتها مفيدة"],
  ["Plug it in to find the owner", "Hand it to security without plugging it in", "Use it, the space is handy"],
  1, "الأجهزة المتروكة أسلوب هجوم شائع (USB drop) وقد تنفّذ برمجيات خبيثة تلقائيًا.",
  "Abandoned drives are a common attack (USB drop) and can run malware automatically."),
 ("w1", "passwords",
  "أي كلمة مرور هي الأقوى؟",
  "Which password is strongest?",
  ["P@ssw0rd2024", "قطار-نهر-سحاب-٤٧-جبل", "Mohammed1990"],
  ["P@ssw0rd2024", "train-river-cloud-47-mountain", "Mohammed1990"],
  1, "العبارة الطويلة العشوائية أقوى من كلمة قصيرة بتعديلات متوقعة مثل @ و0.",
  "A long random passphrase beats a short word with predictable tweaks like @ and 0."),
 ("w2", "passwords",
  "ما أفضل ممارسة لكلمات المرور؟",
  "What is the best password practice?",
  ["كلمة واحدة قوية لكل الحسابات", "كلمة مختلفة لكل حساب مع مدير كلمات مرور", "تغييرها كل يوم بتعديل رقم واحد"],
  ["One strong password for everything", "A different password per account plus a password manager", "Change it daily by one digit"],
  1, "إعادة استخدام كلمة المرور تجعل تسريب موقع واحد يكشف بقية حساباتك.",
  "Reusing passwords means one site's breach exposes your other accounts."),
 ("w3", "passwords",
  "ما فائدة المصادقة الثنائية (2FA)؟",
  "What is two-factor authentication (2FA) for?",
  ["تغني عن كلمة المرور", "تضيف حاجزًا ثانيًا حتى لو سُرقت كلمة المرور", "تسرّع تسجيل الدخول"],
  ["It replaces the password", "Adds a second barrier even if the password is stolen", "Makes login faster"],
  1, "تطبيقات المصادقة ومفاتيح الأمان أفضل من الرسائل النصية.",
  "Authenticator apps and security keys are better than SMS codes."),
 ("n1", "network",
  "أنت في مقهى بشبكة Wi-Fi مفتوحة. ما الأحوط؟",
  "You are in a café on open Wi-Fi. What is safest?",
  ["أدخل لحسابي البنكي مباشرة", "أتجنب العمليات الحساسة أو أستخدم VPN موثوقًا أو بيانات الجوال", "أعطل جدار الحماية ليعمل الإنترنت أسرع"],
  ["Log in to my bank directly", "Avoid sensitive actions or use a trusted VPN or mobile data", "Turn off the firewall for speed"],
  1, "الشبكات المفتوحة قد تُراقب أو تُنتحل (Evil Twin).",
  "Open networks can be monitored or spoofed (Evil Twin)."),
 ("n2", "network",
  "ماذا يعني القفل بجانب عنوان الموقع؟",
  "What does the padlock next to a site address mean?",
  ["الموقع آمن وصادق دائمًا", "الاتصال مشفّر، لكن الموقع قد يكون مزيفًا", "الموقع خالٍ من الفيروسات"],
  ["The site is always safe and honest", "The connection is encrypted, but the site may still be fake", "The site is virus-free"],
  1, "مواقع التصيد كثيرًا ما تستخدم HTTPS. القفل يثبت التشفير لا هوية صاحب الموقع.",
  "Phishing sites often use HTTPS. The padlock proves encryption, not who runs the site."),
 ("g1", "general",
  "ما أهم فائدة للتحديثات الأمنية؟",
  "What is the main value of security updates?",
  ["تغيير شكل النظام", "سد ثغرات معروفة يستغلها المهاجمون", "زيادة مساحة التخزين"],
  ["Changing how the system looks", "Closing known holes attackers exploit", "Freeing storage"],
  1, "معظم الاختراقات الناجحة تستغل ثغرات لها تصحيحات متاحة أصلًا.",
  "Most successful breaches exploit holes that already have patches."),
 ("g2", "general",
  "ما الذي يحميك من برامج الفدية بأكبر قدر؟",
  "What protects you most against ransomware damage?",
  ["دفع الفدية بسرعة", "نسخ احتياطية منتظمة مفصولة عن الجهاز", "إخفاء الملفات المهمة"],
  ["Paying the ransom quickly", "Regular backups kept separate from the device", "Hiding important files"],
  1, "النسخة الاحتياطية المنفصلة تتيح لك الاستعادة دون الدفع.",
  "A separate backup lets you recover without paying."),
]


# Spread the correct answer across positions so it is not predictable.
_T = [1, 0, 2, 2, 0, 1, 2, 0, 1, 2, 0, 1]


def _arrange(q, target):
    ar, en = list(q[4]), list(q[5])
    for opts in (ar, en):
        opts.insert(target, opts.pop(q[6]))
    return q[:4] + (ar, en, target) + q[7:]


Q = [_arrange(q, t) for q, t in zip(Q, _T)]


def public():
    return [{"id": q[0], "cat": q[1], "q": {"ar": q[2], "en": q[3]},
             "options": {"ar": q[4], "en": q[5]}} for q in Q]


def level(pct):
    return "excellent" if pct >= 85 else "good" if pct >= 60 else "fair" if pct >= 40 else "low"


def score(answers):
    """answers: {question_id: chosen_index}. Returns result dict or None if invalid."""
    if not isinstance(answers, dict):
        return None
    review, right = [], 0
    for q in Q:
        pick = answers.get(q[0])
        if not isinstance(pick, int) or isinstance(pick, bool) or not 0 <= pick < len(q[4]):
            pick = None
        ok = pick == q[6]
        right += ok
        review.append({"id": q[0], "picked": pick, "correct": q[6], "ok": ok,
                       "explain": {"ar": q[7], "en": q[8]}})
    pct = round(100 * right / len(Q))
    return {"score": right, "total": len(Q), "percent": pct, "level": level(pct), "review": review}
