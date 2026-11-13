"""Detection rules. Each rule has an ID, name, description, human-readable conditions,
severity and the parameters the detector really uses (thresholds are lab-scaled)."""
import hashlib
from dataclasses import dataclass, field


def bi(ar, en):
    return {"ar": ar, "en": en}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    name: dict
    description: dict
    conditions: dict
    params: dict = field(default_factory=dict)


# Harmless test indicator used by the malware demo (hash of a synthetic sample, not real malware).
TEST_IOC_HASHES = {hashlib.sha256(b"CYRO-SIM-SAMPLE-1").hexdigest()}

RULES = [
    Rule("CR-BF-001", "brute_force", "high",
         bi("هجوم تخمين كلمات المرور", "Brute-force login attack"),
         bi("تكرار محاولات تسجيل الدخول الفاشلة من مصدر واحد خلال فترة قصيرة.",
            "Repeated failed logins from a single source in a short time."),
         bi("5 محاولات دخول فاشلة أو أكثر من المصدر نفسه خلال 60 ثانية.",
            "5 or more failed logins from the same source within 60 seconds."),
         {"threshold": 5, "window": 60}),
    Rule("CR-PS-001", "port_scan", "high",
         bi("فحص منافذ", "Port scan"),
         bi("اتصالات متكررة من مصدر واحد بمنافذ مختلفة لاستكشاف الخدمات المفتوحة.",
            "Repeated connections from one source to many different ports to discover open services."),
         bi("محاولات اتصال بـ 8 منافذ مختلفة أو أكثر من المصدر نفسه خلال 10 ثوانٍ.",
            "Connection attempts to 8 or more distinct ports from the same source within 10 seconds."),
         {"distinct_ports": 8, "window": 10}),
    Rule("CR-ST-001", "traffic", "high",
         bi("ارتفاع غير طبيعي في الاتصالات من مصدر", "Abnormal traffic from one source"),
         bi("معدل طلبات أو حجم بيانات من مصدر واحد يتجاوز الحد المسموح.",
            "Request rate or data volume from one source exceeds the allowed limit."),
         bi("أكثر من 100 طلب أو أكثر من 50 ميغابايت من المصدر نفسه خلال 10 ثوانٍ.",
            "More than 100 requests or 50 MB from the same source within 10 seconds."),
         {"requests": 100, "bytes": 50_000_000, "window": 10}),
    Rule("CR-ST-002", "ddos", "critical",
         bi("إغراق موزَّع للخدمة (DDoS)", "Distributed flood (DDoS)"),
         bi("طوفان طلبات نحو هدف واحد من مصادر متعددة في آن واحد.",
            "A flood of requests toward one target from many sources at once."),
         bi("120 طلبًا أو أكثر نحو الهدف نفسه من 8 مصادر مختلفة أو أكثر خلال 5 ثوانٍ.",
            "120 or more requests to the same target from 8 or more distinct sources within 5 seconds."),
         {"requests": 120, "sources": 8, "window": 5}),
    Rule("CR-PH-001", "phishing", "high",
         bi("رسالة تصيد", "Phishing message"),
         bi("رسالة تحمل مؤشرات تصيد (استعجال، طلب بيانات، روابط مشبوهة).",
            "A message carrying phishing indicators (urgency, credential requests, suspicious links)."),
         bi("درجة تحليل الرسالة 50 فأكثر (خطيرة جدًا من 80).", "Message analysis score of 50 or more (critical from 80)."),
         {"score": 50, "critical": 80}),
    Rule("CR-UR-001", "url", "high",
         bi("رابط خطير", "Dangerous link"),
         bi("رابط حصل في الفحص على درجة خطورة مرتفعة.", "A link whose scan produced a high risk score."),
         bi("درجة فحص الرابط 50 فأكثر (خطير جدًا من 80).", "Link scan score of 50 or more (critical from 80)."),
         {"score": 50, "critical": 80}),
    Rule("CR-ML-001", "malware", "high",
         bi("مؤشرات ملف مشبوه", "Suspicious file indicators"),
         bi("ملف يطابق مؤشرات اختبارية: توقيع EICAR، تنفيذي متنكر، امتداد مزدوج، أو Hash معروف للاختبار.",
            "A file matching test indicators: EICAR signature, disguised executable, double extension, or a known test hash."),
         bi("أي من: توقيع EICAR، ملف تنفيذي بامتداد مختلف، امتداد مزدوج، Hash ضمن قائمة المؤشرات التجريبية.",
            "Any of: EICAR signature, executable with another extension, double extension, hash in the test indicator list."),
         {}),
    Rule("CR-CM-001", "comm_integrity", "high",
         bi("فشل سلامة أو أصالة رسالة", "Message integrity or authenticity failure"),
         bi("رفض المستقبل رسالة لأن وسم التشفير أو التوقيع الرقمي لا يطابق محتواها.",
            "The receiver rejected a message because its encryption tag or digital signature does not match the content."),
         bi("حزمة مرفوضة بسبب بصمة تشفير (GCM) أو توقيع (ECDSA) غير صالح، وهو مؤشر تعديل أو انتحال. (حد المختبر: حدث واحد)",
            "A packet rejected for an invalid encryption tag (GCM) or signature (ECDSA), a sign of tampering or impersonation. (Lab threshold: one event)"),
         {"threshold": 1}),
    Rule("CR-CM-002", "comm_replay", "high",
         bi("هجوم إعادة إرسال", "Replay attack"),
         bi("إعادة إرسال رسالة سليمة سبق التقاطها لتنفيذها مرة ثانية.", "Re-sending a previously captured valid message to make it run again."),
         bi("حزمة مرفوضة لأن رقمها التسلسلي قديم أو ختمها الزمني خارج نافذة 30 ثانية.",
            "A packet rejected because its sequence number is old or its timestamp is outside the 30-second window."),
         {"window_s": 30}),
    Rule("CR-CM-003", "comm_mitm", "critical",
         bi("العبث بتبادل المفاتيح (احتمال وسيط MITM)", "Key-exchange tampering (possible MITM)"),
         bi("طرف ثالث استبدل مفتاح أحد الطرفين أثناء إنشاء الجلسة.", "A third party replaced one party's key while the session was being set up."),
         bi("توقيع مفتاح المصافحة لا يطابق الهوية الموثّقة مسبقًا للطرف الآخر.",
            "The handshake key signature does not match the other party's pre-pinned identity."), {}),
    Rule("CR-CM-004", "comm_policy", "medium",
         bi("بيانات حساسة عبر قناة غير مشفرة", "Sensitive data over an unencrypted channel"),
         bi("رسالة تحمل مؤشرات بيانات حساسة تنتقل نصًا صريحًا يستطيع أي طرف على القناة قراءته.",
            "A message with sensitive-data indicators travelling in clear text that anyone on the channel can read."),
         bi("رسالة بلا تشفير تحتوي كلمة مرور أو رمز تحقق أو بطاقة أو حسابًا أو رقمًا طويلًا.",
            "An unencrypted message containing a password, verification code, card, account or a long number."), {}),
]
BY_ID = {r.id: r for r in RULES}
