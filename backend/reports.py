"""PDF report generation (Arabic RTL + English) using reportlab only.
Arabic text is reshaped and each *wrapped line* is bidi-reordered, which keeps long lines correct."""
import io
from datetime import datetime
from pathlib import Path

import arabic_reshaper
from bidi.algorithm import get_display
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

FONT_DIR = Path(__file__).parent / "fonts"
WIN = Path("C:/Windows/Fonts")
_ready = False

BLUE, TEXT, MUTED = HexColor("#1F8BFF"), HexColor("#111827"), HexColor("#6B7280")
VCOL = {"safe": HexColor("#15803D"), "suspicious": HexColor("#B45309"), "dangerous": HexColor("#B91C1C")}

T = {
    "ar": {"gen": "تاريخ إنشاء الملف", "created": "تاريخ إنشاء التقرير", "count": "عدد عمليات الفحص",
           "summary": "الملخص", "details": "تفاصيل عمليات الفحص", "score": "درجة الخطورة",
           "safe": "لا مؤشرات خطورة", "suspicious": "مشبوه", "dangerous": "خطير",
           "url": "فحص رابط", "phishing": "تحليل رسالة", "file": "فحص ملف", "chars": "رسالة نصية ({n} حرفًا)",
           "none": "لم تُكتشف مؤشرات بالقواعد المستخدمة.", "indicators": "مؤشرات الخطورة",
           "quiz": "اختبار الوعي الأمني: {a} محاولة، أفضل نتيجة {b}%، آخر نتيجة {c}%.",
           "method": "التحليل قائم على قواعد محلية معلنة. غياب المؤشرات لا يعني أن العنصر آمن بشكل مؤكد، "
                     "والـ Hash يتحقق من سلامة المحتوى ولا يكشف البرمجيات الخبيثة.",
           "page": "صفحة"},
    "en": {"gen": "File generated", "created": "Report created", "count": "Number of scans",
           "summary": "Summary", "details": "Scan details", "score": "Risk score",
           "safe": "No risk indicators", "suspicious": "Suspicious", "dangerous": "Dangerous",
           "url": "URL scan", "phishing": "Message analysis", "file": "File check", "chars": "Text message ({n} chars)",
           "none": "No indicators found by the rules used.", "indicators": "Risk indicators",
           "quiz": "Awareness quiz: {a} attempt(s), best {b}%, latest {c}%.",
           "method": "Analysis uses declared local rules. No indicators does not guarantee an item is safe, "
                     "and a hash verifies content integrity only; it does not detect malware.",
           "page": "Page"},
}


def _register():
    global _ready
    if _ready:
        return
    pick = lambda names: next((p for p in names if p.exists()), None)
    reg = pick([FONT_DIR / "DejaVuSans.ttf", WIN / "tahoma.ttf", WIN / "arial.ttf"])
    bold = pick([FONT_DIR / "DejaVuSans-Bold.ttf", WIN / "tahomabd.ttf", WIN / "arialbd.ttf"]) or reg
    if not reg:
        raise RuntimeError("No Unicode font available for PDF reports")
    pdfmetrics.registerFont(TTFont("CG", str(reg)))
    pdfmetrics.registerFont(TTFont("CG-B", str(bold)))
    _ready = True


class _Doc:
    def __init__(self, lang):
        _register()
        self.lang, self.ar = lang, lang == "ar"
        self.buf = io.BytesIO()
        self.c = canvas.Canvas(self.buf, pagesize=A4)
        self.w, self.h = A4
        self.m = 42
        self.page = 0
        self.new_page()

    def new_page(self):
        if self.page:
            self.c.showPage()
        self.page += 1
        c = self.c
        c.setFillColor(BLUE)
        c.rect(0, self.h - 30, self.w, 30, stroke=0, fill=1)
        c.setFillColorRGB(1, 1, 1)
        c.setFont("CG-B", 11)
        c.drawString(self.m, self.h - 20, "CYRO")
        c.setFont("CG", 8)
        c.drawRightString(self.w - self.m, self.h - 20, "Intelligent Cybersecurity Platform")
        c.setFillColor(MUTED)
        c.setFont("CG", 8)
        label = f"{T[self.lang]['page']} {self.page}"
        c.drawCentredString(self.w / 2, 22, get_display(arabic_reshaper.reshape(label), base_dir="R") if self.ar else label)
        self.y = self.h - 62

    def _shape(self, s):
        return arabic_reshaper.reshape(s) if self.ar else s

    def _wrap(self, text, font, size, maxw):
        words, lines, cur = self._shape(text).split(" "), [], ""
        for wd in words:
            while pdfmetrics.stringWidth(wd, font, size) > maxw:       # break very long tokens
                k = len(wd)
                while k > 1 and pdfmetrics.stringWidth(wd[:k], font, size) > maxw:
                    k -= 1
                if cur:
                    lines.append(cur); cur = ""
                lines.append(wd[:k]); wd = wd[k:]
            trial = (cur + " " + wd).strip()
            if cur and pdfmetrics.stringWidth(trial, font, size) > maxw:
                lines.append(cur); cur = wd
            else:
                cur = trial
        if cur:
            lines.append(cur)
        return lines or [""]

    def text(self, s, size=10, bold=False, color=TEXT, indent=0, gap=0):
        font = "CG-B" if bold else "CG"
        lead = size * 1.45
        for line in self._wrap(str(s), font, size, self.w - 2 * self.m - indent):
            if self.y < 50:
                self.new_page()
            self.c.setFont(font, size)
            self.c.setFillColor(color)
            if self.ar:
                self.c.drawRightString(self.w - self.m - indent, self.y, get_display(line, base_dir="R"))
            else:
                self.c.drawString(self.m + indent, self.y, line)
            self.y -= lead
        self.y -= gap

    def rule(self):
        self.c.setStrokeColor(HexColor("#D1D5DB"))
        self.c.line(self.m, self.y + 4, self.w - self.m, self.y + 4)
        self.y -= 8

    def need(self, h):
        if self.y < 50 + h:
            self.new_page()


def _when(ts):
    return str(ts).replace("T", " ")[:16]


def build_pdf(data, lang):
    d, tr = _Doc(lang), T[lang]
    rep, scans, quiz = data["report"], data["scans"], data["quiz"]
    d.text(rep["title"], 20, True, gap=6)
    d.text(f"{tr['created']}: {_when(rep['created_at'])}", 9, color=MUTED)
    d.text(f"{tr['gen']}: {datetime.now().strftime('%Y-%m-%d %H:%M')}", 9, color=MUTED)
    d.text(f"{tr['count']}: {len(scans)}", 9, color=MUTED, gap=8)

    d.text(tr["summary"], 13, True, BLUE, gap=2)
    for v in ("safe", "suspicious", "dangerous"):
        n = sum(s["verdict"] == v for s in scans)
        d.text(f"{tr[v]}: {n}", 10, color=VCOL[v])
    d.text("  |  ".join(f"{tr[t]}: {sum(s['type'] == t for s in scans)}" for t in ("url", "phishing", "file")), 10, gap=2)
    if quiz["attempts"]:
        d.text(tr["quiz"].format(a=quiz["attempts"], b=quiz["best"], c=quiz["latest"]), 10)
    d.text(tr["method"], 8.5, color=MUTED, gap=6)
    d.rule()

    d.text(tr["details"], 13, True, BLUE, gap=4)
    for s in scans:
        d.need(70)
        target = tr["chars"].format(n=s["target"]) if s["type"] == "phishing" else s["target"]
        d.text(f"#{s['id']}  {tr[s['type']]}  -  {target}", 10.5, True)
        d.text(f"{tr[s['verdict']]}   |   {tr['score']}: {s['score']}/100   |   {_when(s['created_at'])}",
               9, color=VCOL[s["verdict"]])
        active = [f for f in s["findings"] if f["points"] > 0 or f["severity"] == "ok"]
        if not active:
            d.text(tr["none"], 9, color=MUTED, indent=10)
        for f in active:
            d.text("•  " + f["title"][lang] + (f"  (+{f['points']})" if f["points"] > 0 else ""), 9.5, True, indent=10)
            d.text(f["why"][lang], 8.5, color=MUTED, indent=22)
        d.y -= 6
        d.rule()
    d.c.save()
    return d.buf.getvalue()


IT = {
    "ar": {"title": "تقرير حادثة أمنية", "id": "رقم الحادثة", "sev": "الخطورة", "status": "الحالة", "rule": "قاعدة الكشف",
           "source": "المصدر", "created": "وقت الإنشاء", "summary": "ملخص التحليل", "cond": "شروط القاعدة", "evidence": "الأدلة",
           "timeline": "الخط الزمني للحادثة", "actions": "الإجراءات الدفاعية", "verified": "تم التحقق", "notverified": "لم يتم التحقق",
           "conclusion": "الخلاصة", "events": "الأحداث المرتبطة",
           "sev_low": "منخفضة", "sev_medium": "متوسطة", "sev_high": "عالية", "sev_critical": "حرجة",
           "st_detected": "مكتشفة", "st_responding": "قيد الاستجابة", "st_mitigated": "تم احتواؤها", "st_failed": "فشل التحقق", "st_closed": "مغلقة",
           "c_ok": "تم كشف التهديد واحتواؤه، وتأكد النظام من فعالية كل إجراء دفاعي بإرسال محاولات اختبار رُفضت.",
           "c_bad": "لم يكتمل التحقق من الاستجابة. تحتاج الحادثة إلى متابعة يدوية.",
           "c_active": "الحادثة ما زالت قيد المعالجة.",
           "stages": {"detection": "كشف", "analysis": "تحليل", "incident": "حادثة", "response": "استجابة", "verification": "تحقق",
                      "mitigated": "احتواء", "failed": "فشل", "report": "تقرير", "closed": "إغلاق"}},
    "en": {"title": "Security Incident Report", "id": "Incident ID", "sev": "Severity", "status": "Status", "rule": "Detection rule",
           "source": "Source", "created": "Created", "summary": "Analysis summary", "cond": "Rule conditions", "evidence": "Evidence",
           "timeline": "Incident timeline", "actions": "Defensive actions", "verified": "verified", "notverified": "not verified",
           "conclusion": "Conclusion", "events": "Related events",
           "sev_low": "Low", "sev_medium": "Medium", "sev_high": "High", "sev_critical": "Critical",
           "st_detected": "Detected", "st_responding": "Responding", "st_mitigated": "Mitigated", "st_failed": "Verification failed", "st_closed": "Closed",
           "c_ok": "The threat was detected and mitigated, and every defensive action was verified by test attempts that were rejected.",
           "c_bad": "Response verification did not complete. The incident needs manual follow-up.",
           "c_active": "The incident is still being handled.",
           "stages": {"detection": "Detection", "analysis": "Analysis", "incident": "Incident", "response": "Response",
                      "verification": "Verification", "mitigated": "Mitigated", "failed": "Failed", "report": "Report", "closed": "Closed"}},
}
SEV_COL = {"low": HexColor("#1769FF"), "medium": HexColor("#B45309"), "high": HexColor("#B91C1C"), "critical": HexColor("#7F1D1D")}


def build_incident_pdf(inc, rule, lang):
    d, tr = _Doc(lang), IT[lang]
    d.text(f"{tr['title']} #{inc['id']}", 19, True, gap=4)
    d.text(inc["title"][lang], 12, True, color=BLUE, gap=6)
    d.text(f"{tr['sev']}: {tr['sev_' + inc['severity']]}", 10.5, True, SEV_COL.get(inc["severity"], TEXT))
    d.text(f"{tr['status']}: {tr['st_' + inc['status']]}", 10)
    d.text(f"{tr['rule']}: {inc['rule_id']}" + (f" - {rule.name[lang]}" if rule else ""), 10)
    d.text(f"{tr['source']}: {inc['source']}", 10)
    d.text(f"{tr['created']}: {_when(inc['created_at'])}", 10, gap=6)
    d.rule()
    d.text(tr["summary"], 13, True, BLUE, gap=2)
    d.text(inc["analysis"]["summary"][lang], 10, gap=4)
    if rule:
        d.text(tr["cond"], 11, True)
        d.text(rule.conditions[lang], 9.5, color=MUTED, gap=4)
    ev = inc["analysis"].get("evidence", {})
    if ev:
        d.text(tr["evidence"], 11, True)
        for k, v in ev.items():
            d.text(f"{k}: {', '.join(map(str, v)) if isinstance(v, list) else v}", 9, color=MUTED, indent=8)
        d.y -= 4
    d.rule()
    d.text(tr["timeline"], 13, True, BLUE, gap=2)
    for t in inc["timeline"]:
        stamp = datetime.fromtimestamp(t["ts"]).strftime("%H:%M:%S")
        d.need(30)
        d.text(f"{stamp}  [{tr['stages'].get(t['stage'], t['stage'])}]  {t['message'][lang]}", 9.5, indent=4)
    d.y -= 4
    d.rule()
    d.text(tr["actions"], 13, True, BLUE, gap=2)
    for a in inc["actions"]:
        ok = bool(a["verified"])
        d.text(f"{a['action']}  ->  {a['target']}  ({tr['verified'] if ok else tr['notverified']})", 9.5, color=VCOL["safe"] if ok else VCOL["dangerous"], indent=4)
    d.y -= 4
    d.rule()
    d.text(tr["conclusion"], 13, True, BLUE, gap=2)
    done = inc["status"] in ("mitigated", "closed")
    d.text(tr["c_ok"] if done else tr["c_bad"] if inc["status"] == "failed" else tr["c_active"], 10, gap=4)
    d.text(f"{tr['events']}: {len(inc['events'])}", 9, color=MUTED)
    d.c.save()
    return d.buf.getvalue()
