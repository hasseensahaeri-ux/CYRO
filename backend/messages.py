"""Bilingual (ar/en) text for every finding the scanners can produce.
Tuple order: ar_title, ar_why, en_title, en_why."""

M = {
    # ---- URL ----
    "assumed_scheme": ("لم يُحدَّد البروتوكول", "أُضيف http:// تلقائيًا لإجراء التحليل.",
                       "No protocol given", "http:// was added automatically for analysis."),
    "no_https": ("الرابط لا يستخدم HTTPS", "البيانات تنتقل دون تشفير، ويسهل اعتراضها أو التلاعب بها.",
                 "Link does not use HTTPS", "Data travels unencrypted and can be intercepted or altered."),
    "ip_host": ("العنوان رقم IP بدل اسم نطاق", "المواقع الشرعية نادرًا ما تستخدم رقم IP مباشرة؛ يُستخدم ذلك لإخفاء هوية الموقع.",
                "Address is an IP instead of a domain", "Legitimate sites rarely use a raw IP; it hides who runs the site."),
    "at_sign": ("الرابط يحتوي على الرمز @", "ما قبل @ يتجاهله المتصفح، فيُستخدم لعرض اسم موثوق بينما الوجهة مختلفة.",
                "Link contains @", "Browsers ignore everything before @, so a trusted name can hide the real destination."),
    "punycode": ("نطاق بأحرف مموَّهة (Punycode/IDN)", "قد يستخدم أحرفًا تشبه الحروف اللاتينية لانتحال موقع معروف.",
                 "Look-alike characters in domain (Punycode/IDN)", "May use characters that resemble Latin letters to imitate a known site."),
    "many_subdomains": ("عدد كبير من النطاقات الفرعية ({n})", "تُستخدم لدفن الاسم الحقيقي للنطاق في نهاية طويلة مربكة.",
                        "Many subdomains ({n})", "Used to bury the real domain inside a long confusing name."),
    "long_url": ("رابط طويل جدًا ({n} حرفًا)", "الروابط الطويلة تُخفي الوجهة الفعلية وتُستخدم في التصيد.",
                 "Very long URL ({n} characters)", "Long URLs hide the real destination and are common in phishing."),
    "long_host": ("اسم نطاق طويل جدًا", "أسماء النطاقات الطويلة شائعة في المواقع المنتحلة.",
                  "Very long domain name", "Long domain names are common in impersonation sites."),
    "many_hyphens": ("شرطات كثيرة في النطاق", "أنماط مثل secure-login-bank شائعة في النطاقات المزيفة.",
                     "Many hyphens in domain", "Patterns like secure-login-bank are common in fake domains."),
    "susp_tld": ("امتداد نطاق عالي الاستخدام في الإساءة (.{tld})", "هذه الامتدادات رخيصة أو مجانية وتكثر فيها المواقع المسيئة، وليست خطرًا بذاتها.",
                 "TLD often abused (.{tld})", "These TLDs are cheap or free and often abused; not dangerous by themselves."),
    "brand_abuse": ("قد ينتحل علامة «{brand}»", "اسم العلامة يظهر في النطاق لكن النطاق الرئيسي ليس لها: {reg}.",
                    "May imitate brand “{brand}”", "The brand name appears in the domain but the main domain is not theirs: {reg}."),
    "brand_leet": ("أرقام تحاكي حروف علامة «{brand}»", "استبدال الحروف بأرقام (مثل 0 بدل o) أسلوب معروف للانتحال.",
                   "Digits mimic brand “{brand}”", "Swapping letters for digits (like 0 for o) is a known impersonation trick."),
    "keywords": ("كلمات حساسة في الرابط: {items}", "كلمات مثل login وverify تظهر في روابط التصيد لدفعك لإدخال بياناتك.",
                 "Sensitive words in link: {items}", "Words like login or verify appear in phishing links to push you to enter data."),
    "shortener": ("رابط مختصر", "الاختصار يخفي الوجهة الحقيقية؛ افتح الرابط الأصلي بحذر.",
                  "Shortened link", "Shortening hides the real destination; be careful opening it."),
    "odd_port": ("منفذ غير معتاد ({port})", "المواقع العادية تستخدم 80 أو 443 غالبًا.",
                 "Unusual port ({port})", "Normal sites usually use 80 or 443."),
    "redirect_param": ("الرابط يحمل رابطًا آخر كمعامل", "قد يعيد توجيهك إلى موقع مختلف بعد فتحه.",
                       "Link carries another URL as a parameter", "It may redirect you to a different site."),
    "dns_fail": ("تعذر حل اسم النطاق", "النطاق غير موجود أو غير متاح حاليًا.",
                 "Domain could not be resolved", "The domain does not exist or is currently unavailable."),
    "cert_invalid": ("شهادة HTTPS غير صالحة", "تعذر التحقق من الشهادة: {reason}.",
                     "Invalid HTTPS certificate", "Certificate could not be verified: {reason}."),
    "cert_ok": ("شهادة HTTPS صالحة", "أصدرتها: {issuer}، وتنتهي بعد {days} يومًا. الشهادة تثبت التشفير لا حسن النية.",
                "Valid HTTPS certificate", "Issued by {issuer}, expires in {days} days. A certificate proves encryption, not good intent."),
    "tls_unreachable": ("تعذر فحص شهادة HTTPS", "لم يتجاوب الخادم على المنفذ 443 خلال المهلة.",
                        "HTTPS certificate not checked", "The server did not answer on port 443 in time."),
    "blocklisted": ("النطاق في قائمة التهديدات المحلية", "النطاق مسجَّل في قائمة تهديدات معروفة (URLhaus).",
                    "Domain is in the local threat list", "The domain is listed in a known threat feed (URLhaus)."),
    # ---- Phishing text ----
    "urgency": ("لغة استعجال", "الاستعجال يمنعك من التفكير والتحقق. العبارات: {items}",
                "Urgency language", "Urgency stops you from thinking and verifying. Phrases: {items}"),
    "threat": ("تهديد بإيقاف أو إغلاق", "يُخيفك المهاجم بخسارة حسابك لتتصرف بسرعة. العبارات: {items}",
               "Threat of suspension or closure", "Attackers scare you with losing access so you act fast. Phrases: {items}"),
    "credentials": ("طلب بيانات دخول أو رموز تحقق", "الجهات الموثوقة لا تطلب كلمة المرور أو رمز التحقق عبر الرسائل. العبارات: {items}",
                    "Asks for login data or codes", "Trusted organizations do not ask for passwords or codes by message. Phrases: {items}"),
    "financial": ("طلب بيانات مالية أو دفع", "بيانات البطاقة والحسابات هدف رئيسي للتصيد. العبارات: {items}",
                  "Asks for financial data or payment", "Card and account data are prime phishing targets. Phrases: {items}"),
    "lure": ("إغراء بجائزة أو استرداد", "العروض المغرية تُستخدم لجذب الضحية. العبارات: {items}",
             "Prize or refund lure", "Tempting offers are used to hook victims. Phrases: {items}"),
    "generic_greeting": ("تحية عامة", "الرسائل الشرعية غالبًا تذكر اسمك. العبارات: {items}",
                         "Generic greeting", "Legitimate messages usually use your name. Phrases: {items}"),
    "click_prompt": ("حثّ على الضغط على رابط", "طلب الضغط المباشر شائع في رسائل التصيد. العبارات: {items}",
                     "Pushes you to click a link", "Direct click requests are common in phishing. Phrases: {items}"),
    "link_mismatch": ("نص الرابط لا يطابق وجهته", "النص المعروض يشير إلى {shown} لكن الرابط يذهب إلى {real}.",
                      "Link text does not match its target", "Displayed text points to {shown} but the link goes to {real}."),
    "risky_links": ("روابط ذات مؤشرات خطورة داخل الرسالة", "تحليل الروابط المحلي وجد مؤشرات في {n} رابط.",
                    "Risky links inside the message", "Local link analysis found indicators in {n} link(s)."),
    "shouting": ("أسلوب صياح (أحرف كبيرة أو علامات تعجب)", "المبالغة في التأكيد أسلوب لإثارة القلق.",
                 "Shouting style (capitals or exclamation marks)", "Excessive emphasis is used to create anxiety."),
    "combo": ("استعجال مع طلب بيانات حساسة", "اجتماع الاستعجال وطلب بيانات الدخول هو النمط الكلاسيكي للتصيد.",
              "Urgency combined with a request for sensitive data", "Urgency plus a credentials request is the classic phishing pattern."),
    # ---- File ----
    "disguised_exe": ("ملف تنفيذي بامتداد مختلف", "محتوى الملف برنامج تنفيذي لكن امتداده ({ext}) يوحي بغير ذلك.",
                      "Executable with a different extension", "The content is an executable program but the extension ({ext}) suggests otherwise."),
    "type_mismatch": ("الامتداد لا يطابق المحتوى", "الامتداد .{ext} لكن المحتوى يبدو: {kind}.",
                      "Extension does not match content", "Extension is .{ext} but content looks like: {kind}."),
    "risky_ext": ("نوع ملف قابل للتنفيذ", "الامتداد .{ext} يمكنه تشغيل أوامر. لا تفتحه إلا من مصدر موثوق.",
                  "Executable file type", "The .{ext} extension can run commands. Open only from a trusted source."),
    "double_ext": ("امتداد مزدوج مخادع", "الاسم يوهم بملف عادي بينما ينتهي بامتداد قابل للتنفيذ (.{ext}).",
                   "Deceptive double extension", "The name looks like a normal file but ends with an executable extension (.{ext})."),
    "eicar_test": ("ملف اختبار مضادات الفيروسات (EICAR)", "نمط اختبار قياسي غير ضار تتعرف عليه برامج الحماية، ويُستخدم لتجربة أنظمة الكشف.",
                   "Antivirus test file (EICAR)", "A standard harmless test pattern recognised by security software, used to test detection systems."),
}


def build(code, points, sev=None, **p):
    t = M[code]
    if sev is None:
        sev = "info" if points <= 0 else "high" if points >= 20 else "medium" if points >= 10 else "low"
    f = lambda s: s.format(**p)
    return {"code": code, "points": points, "severity": sev,
            "title": {"ar": f(t[0]), "en": f(t[2])},
            "why": {"ar": f(t[1]), "en": f(t[3])}}


def verdict(score):
    return "dangerous" if score >= 50 else "suspicious" if score >= 20 else "safe"
