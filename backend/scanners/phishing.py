"""Rule-based phishing message analysis (Arabic + English). No ML is claimed."""
import re
from urllib.parse import urlsplit

import config
from ..messages import build, verdict
from . import url_scanner

_AR_MARKS = re.compile(r"[\u064B-\u0652\u0640]")
_AR_MAP = str.maketrans("أإآٱىةئؤ", "اااايهيو")


def norm(s):
    return _AR_MARKS.sub("", s.lower()).translate(_AR_MAP)


CATEGORIES = {
    "urgency": (15, ["urgent", "immediately", "within 24 hours", "act now", "final notice", "last warning",
                     "expires today", "right away", "asap", "عاجل", "فورا", "خلال 24 ساعة", "اخر تحذير",
                     "في اقرب وقت", "الان", "ينتهي اليوم", "قبل فوات الاوان"]),
    "threat": (20, ["suspended", "locked", "will be closed", "terminated", "legal action", "unauthorized",
                    "deactivated", "restricted", "تعليق حسابك", "ايقاف حسابك", "سيتم اغلاق", "حظر حسابك",
                    "اجراء قانوني", "نشاط مشبوه", "تم تقييد", "تم ايقاف"]),
    "credentials": (25, ["password", "verify your account", "confirm your identity", "sign in", "log in",
                         "login", "otp", "verification code", "security code", "كلمه المرور", "كلمه السر",
                         "رمز التحقق", "رمز otp", "تاكيد هويتك", "تحقق من حسابك", "تسجيل الدخول",
                         "الرقم السري"]),
    "financial": (25, ["credit card", "card number", "cvv", "bank account", "iban", "wire transfer",
                       "gift card", "bitcoin", "payment details", "بطاقه ائتمان", "رقم البطاقه",
                       "الحساب البنكي", "ايبان", "تحويل مبلغ", "بطاقات هدايا", "بيانات الدفع"]),
    "lure": (15, ["you won", "winner", "prize", "claim your", "refund", "inheritance", "congratulations",
                  "لقد فزت", "مبروك", "جايزه", "استرداد", "ميراث", "هديه مجانيه"]),
    "generic_greeting": (8, ["dear customer", "dear user", "dear client", "dear account holder",
                             "عزيزي العميل", "عزيزي المستخدم", "عزيزتي العميله"]),
    "click_prompt": (8, ["click here", "click the link", "click below", "اضغط هنا", "انقر هنا",
                         "اضغط على الرابط", "افتح الرابط"]),
}
_PATTERNS = {k: re.compile(r"(?<![a-z0-9\u0600-\u06FF])[وبلفك]?(?:%s)(?![a-z0-9\u0600-\u06FF])" % "|".join(re.escape(norm(w)) for w in v[1]))
             for k, v in CATEGORIES.items()}

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'\)\]]+", re.I)
ANCHOR_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)
TAG_RE = re.compile(r"<[^>]+>")
SHOWN_RE = re.compile(r"^(?:https?://)?([\w-]+(?:\.[\w-]+)+)", re.I)


def _host(u):
    try:
        return (urlsplit(u if "://" in u else "http://" + u).hostname or "").lower()
    except ValueError:
        return ""


def analyze(text):
    text = (text or "").strip()
    if not text:
        raise url_scanner.ScanError("empty")
    if len(text) > config.MAX_TEXT_CHARS:
        raise url_scanner.ScanError("too_long")
    findings, n = [], norm(text)

    hit = {}
    for cat, (pts, _) in CATEGORIES.items():
        found = list(dict.fromkeys(m.group(0) for m in _PATTERNS[cat].finditer(n)))
        if found:
            hit[cat] = True
            findings.append(build(cat, pts, items=" / ".join(found[:5])))
    if hit.get("urgency") and hit.get("credentials"):
        findings.append(build("combo", 10))

    for href, label in ANCHOR_RE.findall(text):
        m = SHOWN_RE.match(TAG_RE.sub("", label).strip())
        real = _host(href)
        if m and real and m.group(1).lower().removeprefix("www.") != real.removeprefix("www."):
            findings.append(build("link_mismatch", 25, shown=m.group(1).lower(), real=real))
            break

    links, seen = [], set()
    for u in URL_RE.findall(text):
        u = u.rstrip(".,;:!?")
        if u in seen or len(links) >= 10:
            continue
        seen.add(u)
        try:
            r = url_scanner.analyze(u, network=False)
            links.append({"url": r["url"], "score": r["score"], "verdict": r["verdict"],
                          "findings": [f for f in r["findings"] if f["points"] > 0][:3]})
        except url_scanner.ScanError:
            continue
    risky = [l for l in links if l["score"] >= 20]
    if risky:
        findings.append(build("risky_links", min(30, int(max(l["score"] for l in risky) * 0.5)), n=len(risky)))

    letters = [c for c in text if c.isalpha() and c.isascii()]
    if text.count("!") >= 3 or (len(letters) >= 20 and sum(c.isupper() for c in letters) / len(letters) > 0.5):
        findings.append(build("shouting", 5))

    score = min(100, sum(f["points"] for f in findings))
    findings.sort(key=lambda f: -f["points"])
    return {"score": score, "verdict": verdict(score), "findings": findings, "links": links,
            "chars": len(text)}
