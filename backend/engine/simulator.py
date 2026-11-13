"""Local attack simulation lab. Nothing leaves this process: scenarios only create events that are
pushed through the same detection/defense engine. Sources use RFC 5737 documentation addresses
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), which are reserved and never routable."""
import hashlib
import logging
import random
import threading
import time

import config
from .. import db
from . import bus, core, store
from .rules import bi
from ..scanners import file_check

log = logging.getLogger("cyberguard.lab")
LEGIT_USER, ATTACKER_1, ATTACKER_2 = "198.51.100.10", "203.0.113.45", "198.51.100.77"


def _s(at, kind, source, target, details, ar, en, actor="attacker"):
    return {"at": round(at, 3), "kind": kind, "source": source, "target": target,
            "details": details, "note": bi(ar, en), "actor": actor}


# Illustrative origins for SIMULATED sources. They are labelled SIM-NN on purpose: the documentation
# addresses used here have no real location, and no real country is implied or accused.
NODES = [("SIM-01", 40.7, -74.0), ("SIM-02", 34.0, -118.2), ("SIM-03", -23.5, -46.6), ("SIM-04", 51.5, -0.1),
         ("SIM-05", 48.9, 2.3), ("SIM-06", 55.7, 37.6), ("SIM-07", 35.7, 139.7), ("SIM-08", 1.35, 103.8),
         ("SIM-09", 28.6, 77.2), ("SIM-10", -33.9, 151.2), ("SIM-11", -1.3, 36.8), ("SIM-12", 6.5, 3.4),
         ("SIM-13", 39.9, 116.4), ("SIM-14", 19.4, -99.1), ("SIM-15", -34.6, -58.4), ("SIM-16", 41.0, 29.0)]
GEO_KINDS = {"login_failed", "login_success", "conn_attempt", "request", "message"}


def geo_for(source, actor):
    """Deterministic illustrative location: attackers map to a SIM node, normal users sit near the lab server."""
    h = int(hashlib.sha256(str(source).encode()).hexdigest(), 16)
    if actor == "legit":
        lat, lon = config.LAB_SERVER_GEO
        return {"geo": [round(lat + ((h % 1000) / 1000 - 0.5) * 3, 2), round(lon + (((h // 1000) % 1000) / 1000 - 0.5) * 3, 2)],
                "origin": "LOCAL"}
    code, la, lo = NODES[h % len(NODES)]
    return {"geo": [la, lo], "origin": code}


# ---------------- scenario plans ----------------
def _brute_force(rng):
    steps, t = [], 0.0
    for k, ar, en in (("login_failed", "سارة تخطئ في كلمة المرور (سلوك طبيعي)", "Sara mistypes her password (normal behavior)"),
                      ("login_failed", "سارة تخطئ مرة ثانية", "Sara mistypes again"),
                      ("login_success", "سارة تدخل بنجاح، ولا يجب أن يصدر أي تنبيه", "Sara logs in successfully; no alert expected")):
        steps.append(_s(t, k, LEGIT_USER, "sara", {"client": "browser"}, ar, en, "legit")); t += 1.0
    accounts = ["admin", "root", "administrator", "admin"]
    for n in range(1, 15):
        acc = accounts[n % 4]
        steps.append(_s(t, "login_failed", ATTACKER_1, acc, {"method": "password_guess", "attempt": n},
                        f"المهاجم يجرّب تخمينًا رقم {n} على الحساب {acc}", f"Attacker tries guess #{n} on account {acc}"))
        t += 0.7
    return steps


def _port_scan(rng):
    steps, t = [], 0.0
    for i in range(3):
        steps.append(_s(t, "conn_attempt", LEGIT_USER, "lab-server", {"port": 443, "service": "https"},
                        "مستخدم عادي يتصل بخدمة HTTPS (منفذ واحد)", "Normal user connects to HTTPS (a single port)", "legit")); t += 0.8
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 8080]
    names = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 135: "rpc", 139: "netbios",
             143: "imap", 443: "https", 445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgres", 8080: "http-alt"}
    t += 0.5
    for p in ports:
        steps.append(_s(t, "conn_attempt", ATTACKER_2, "lab-server", {"port": p, "service": names[p], "flags": "SYN"},
                        f"المهاجم يطرق المنفذ {p} ({names[p]})", f"Attacker probes port {p} ({names[p]})"))
        t += 0.3
    return steps


def _ddos(rng):
    steps, t = [], 0.0
    for i in range(8):
        steps.append(_s(t, "request", f"198.51.100.{20 + i % 3}", "web-frontend", {"bytes": rng.randint(600, 1200)},
                        "طلب طبيعي من عميل", "Normal client request", "legit")); t += 0.4
    bots = [f"203.0.113.{100 + i}" for i in range(14)]
    t += 0.6
    for i in range(240):
        b = bots[i % 14]
        steps.append(_s(t, "request", b, "web-frontend", {"bytes": rng.randint(400, 900), "flood": True},
                        f"طلب من مصدر موزَّع {b}", f"Request from distributed source {b}"))
        t += 0.03
    return steps


PHISH_MSGS = [
    ("legit", "colleague@university.edu",
     "Hi team, the cybersecurity expo rehearsal moved to 3pm tomorrow in room B12. Please bring your demo laptops.",
     "رسالة عادية من زميل عن موعد بروفة", "A normal message from a colleague about a rehearsal"),
    ("attacker", "security@bank-verify-alerts.top",
     "عاجل: تم تعليق حسابك المصرفي. لتفادي إغلاق الحساب خلال 24 ساعة أدخل كلمة المرور ورمز التحقق على الرابط "
     "http://secure-login.bank-verify-alerts.top/verify",
     "رسالة تصيد عربية تنتحل مصرفًا", "Arabic phishing message impersonating a bank"),
    ("legit", "newsletter@library.edu", "Weekly library newsletter: new e-books and opening hours for the exam period.",
     "نشرة بريدية عادية من المكتبة", "A normal newsletter from the library"),
    ("attacker", "no-reply@paypa1-support.xyz",
     "URGENT: Your account will be suspended. Confirm your identity and card number now: "
     "http://paypal.com.account-check.paypa1-support.xyz/login",
     "رسالة تصيد إنجليزية بتهديد الإيقاف", "English phishing message threatening suspension"),
    ("attacker", "prizes@win-gift.click",
     "Congratulations! You won a gift card. Click here to claim your prize and enter your bank account IBAN: "
     "http://win-gift.click/claim?id=77",
     "رسالة إغراء بجائزة", "Prize lure message"),
]


def _phishing(rng):
    steps, t = [], 0.0
    for actor, sender, text, ar, en in PHISH_MSGS:
        steps.append(_s(t, "message", sender, "inbox", {"sender": sender, "text": text}, ar, en, actor))
        t += 2.0
        if sender.startswith("security@"):          # user reacts to the first phishing message
            steps.append(_s(t, "url_click", "user-workstation", "secure-login.bank-verify-alerts.top", {},
                            "المستخدم يضغط الرابط بعد الاستجابة: يجب أن يُحجب", "User clicks the link after the response: must be blocked", "legit"))
            t += 1.5
    return steps


def _malware(rng):
    eicar = b"X5O!P%@AP-" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" + b"!$H+H*"   # built at runtime; not the full AV string
    samples = [("meeting-notes.txt", b"Agenda: expo rehearsal at 3pm.\n", "ملف نصي عادي", "A normal text file", "legit"),
               ("team-photo.jpg", b"\xff\xd8\xff\xe0" + b"\0" * 64, "صورة عادية", "A normal image", "legit"),
               ("invoice_2026.pdf.exe", b"MZ" + b"\x90\x00" * 32, "ملف تنفيذي متنكر بامتداد مزدوج", "Executable disguised with a double extension", "attacker"),
               ("eicar-test.txt", eicar, "ملف اختبار مضادات الفيروسات (EICAR)", "Antivirus test file (EICAR)", "attacker"),
               ("sample.bin", b"CYRO-SIM-SAMPLE-1", "عينة تطابق Hash اختباري معروف", "Sample matching a known test hash", "attacker")]
    steps, t, hashes = [], 0.0, {}
    for name, data, ar, en, actor in samples:
        r = file_check.analyze_bytes(name, data)            # real analyzer on in-memory bytes; nothing is executed or saved
        hashes[name] = r["sha256"]
        steps.append(_s(t, "file", name, name, {"name": name, "size": r["size"], "sha256": r["sha256"],
                                                "codes": [f["code"] for f in r["findings"] if f["points"] > 0],
                                                "eicar": r["eicar"]}, ar, en, actor))
        t += 1.8
    for name in ("invoice_2026.pdf.exe", "sample.bin"):
        steps.append(_s(t, "file_open", "workstation-07", name, {"sha256": hashes[name]},
                        f"محاولة فتح الملف {name} بعد العزل: يجب أن تُرفض", f"Attempt to open {name} after quarantine: must be rejected", "legit"))
        t += 1.0
    return steps


SCENARIOS = {
    "brute_force": {
        "name": bi("هجوم تخمين كلمات المرور", "Brute-force attack"), "builder": _brute_force, "rules": ["CR-BF-001"],
        "description": bi("مهاجم يجرّب كلمات مرور كثيرة على حسابات النظام حتى يصيب الصحيح.", "An attacker tries many passwords on system accounts until one works."),
        "how": bi("يرسل المهاجم محاولات دخول متتالية بسرعة تفوق قدرة الإنسان، غالبًا على حسابات شائعة مثل admin.",
                  "The attacker sends rapid login attempts, faster than a human could, usually against common accounts like admin."),
        "goal": bi("فهم لماذا يُعدّ تكرار الفشل من مصدر واحد مؤشر خطر، وكيف يفرّق النظام بينه وبين خطأ المستخدم العادي.",
                   "Learn why repeated failures from one source are a risk signal, and how a system tells them apart from a normal typo."),
    },
    "port_scan": {
        "name": bi("فحص المنافذ", "Port scanning"), "builder": _port_scan, "rules": ["CR-PS-001"],
        "description": bi("مهاجم يستكشف الخدمات المفتوحة على خادم بالاتصال بمنافذ كثيرة.", "An attacker discovers open services on a server by connecting to many ports."),
        "how": bi("يطرق المهاجم منافذ مختلفة تباعًا ويلاحظ أيها يستجيب، فيعرف الخدمات والثغرات المحتملة.",
                  "The attacker knocks on different ports in turn and notes which answer, revealing services and possible weaknesses."),
        "goal": bi("فهم أن الاتصال بمنفذ واحد طبيعي بينما الاتصال بمنافذ متعددة في ثوانٍ مؤشر استطلاع.",
                   "Understand that one port is normal while many distinct ports within seconds signals reconnaissance."),
    },
    "ddos": {
        "name": bi("محاكاة هجوم DDoS", "DDoS simulation"), "builder": _ddos, "rules": ["CR-ST-002"],
        "description": bi("طوفان طلبات من مصادر كثيرة نحو خدمة واحدة لإبطائها أو إيقافها (محاكاة محلية فقط).",
                         "A flood of requests from many sources toward one service to slow or stop it (local simulation only)."),
        "how": bi("تتصرف أجهزة مخترقة كشبكة واحدة وترسل طلبات في آن واحد؛ كل جهاز يبدو هادئًا لكن المجموع ضخم.",
                  "Compromised machines act as one network and send requests together; each looks quiet but the total is huge."),
        "goal": bi("فهم لماذا لا يكفي مراقبة كل مصدر منفردًا، وأهمية تجميع الحركة نحو الهدف.",
                   "Understand why watching each source alone is not enough, and why traffic toward the target must be aggregated."),
    },
    "phishing": {
        "name": bi("هجوم التصيد", "Phishing attack"), "builder": _phishing, "rules": ["CR-PH-001"],
        "description": bi("رسائل تنتحل جهات موثوقة لسرقة كلمات المرور والبيانات المالية.", "Messages impersonating trusted parties to steal passwords and financial data."),
        "how": bi("تجمع الرسالة بين الاستعجال والتهديد وطلب البيانات ورابط مزيف، بينما تمر الرسائل العادية بسلام.",
                  "A message combines urgency, threats, a data request and a fake link, while normal messages pass untouched."),
        "goal": bi("التعرف على مؤشرات التصيد، ورؤية كيف يعزل النظام الرسالة ويحجب النطاق قبل أن ينقر المستخدم.",
                   "Recognise phishing indicators and see the system quarantine the message and block the domain before a user clicks."),
    },
    "malware": {
        "name": bi("محاكاة كشف الملفات المشبوهة", "Malware detection simulation"), "builder": _malware, "rules": ["CR-ML-001"],
        "description": bi("ملفات مشبوهة تصل إلى الجهاز، ويفحصها المحرك بمؤشرات اختبارية دون تنفيذها.",
                          "Suspicious files arrive and the engine checks them with test indicators without running them."),
        "how": bi("تُفحص عينات داخل الذاكرة فقط: توقيع EICAR، تنفيذي متنكر بامتداد مزدوج، وHash معروف للاختبار.",
                  "Samples are checked in memory only: EICAR signature, executable disguised by a double extension, and a known test hash."),
        "goal": bi("فهم أن الكشف يعتمد على مؤشرات قابلة للتحقق، وكيف يمنع العزل فتح الملف لاحقًا. لا يُنفَّذ أي ملف.",
                   "Learn that detection relies on checkable indicators and how quarantine prevents opening the file later. Nothing is executed."),
    },
}


def catalog():
    out = []
    for sid, s in SCENARIOS.items():
        plan = s["builder"](random.Random(1))
        out.append({"id": sid, "name": s["name"], "description": s["description"], "how": s["how"], "goal": s["goal"],
                    "rules": s["rules"], "steps": len(plan), "duration_s": round(plan[-1]["at"])})
    return out


# ---------------- runner ----------------
class Lab:
    def __init__(self, owner):
        self.owner = owner
        self.lock = threading.RLock()
        self._stop, self._pause = threading.Event(), threading.Event()
        self.thread = None
        self._clear()

    def _clear(self):
        self.state, self.scenario, self.session = "idle", None, None
        self.step = self.total = 0
        self.t0 = self.attack_at = None
        self.speed, self.result = 1.0, None

    def status(self):
        return {"state": self.state, "scenario": self.scenario, "session": self.session, "step": self.step,
                "total": self.total, "t0": self.t0, "speed": self.speed, "result": self.result}

    def _publish_state(self):
        bus.publish("sim", {"type": "state", **self.status()})

    def start(self, scenario, speed):
        with self.lock:
            if self.state in ("running", "paused"):
                return "busy"
            if scenario not in SCENARIOS:
                return "unknown"
            plan = SCENARIOS[scenario]["builder"](random.Random())
            self._stop.clear(); self._pause.clear()
            self.session = f"sim-{int(time.time())}"
            self.scenario, self.speed, self.result = scenario, speed, None
            self.step, self.total, self.t0 = 0, len(plan), time.time()
            self.attack_at = next((s["at"] for s in plan if s["actor"] == "attacker"), 0.0)
            self.state = "running"
            self.thread = threading.Thread(target=self._run, args=(plan, self.session, speed, self.t0), daemon=True)
            self._publish_state()
            self.thread.start()
            return "ok"

    def pause(self):
        with self.lock:
            if self.state != "running":
                return False
            self._pause.set(); self.state = "paused"; self._publish_state()
            return True

    def resume(self):
        with self.lock:
            if self.state != "paused":
                return False
            self._pause.clear(); self.state = "running"; self._publish_state()
            return True

    def stop(self):
        with self.lock:
            if self.state not in ("running", "paused"):
                return False
            self._stop.set(); self._pause.clear(); self.state = "stopped"
            return True

    def reset(self):
        self.stop()
        t = self.thread
        if t and t.is_alive():
            t.join(timeout=12)
            if t.is_alive():
                return False
        with self.lock:
            sess = self.session
            if sess:
                core.reset_session(sess)
            self._clear()
            self._publish_state()
        return True

    def _sleep(self, seconds):
        left = seconds
        while True:
            if self._stop.is_set():
                return False
            if self._pause.is_set():
                time.sleep(0.05)
                continue
            if left <= 0:
                return True
            d = min(0.05, left)
            time.sleep(d); left -= d

    def _run(self, plan, session, speed, t0):
        owner_token = db.set_owner(self.owner)
        # ContextVars do not automatically inherit Flask's request context in a new
        # worker thread. Initialize this visitor's database after restoring its owner.
        db.init_db()
        completed = False
        try:
            prev = 0.0
            for i, st in enumerate(plan):
                if not self._sleep((st["at"] - prev) / speed):
                    break
                prev = st["at"]
                self.step = i + 1
                bus.publish("sim", {"type": "step", "session": session, "step": i + 1, "total": len(plan),
                                    "at": st["at"], "kind": st["kind"], "source": st["source"], "target": st["target"],
                                    "actor": st["actor"], "note": st["note"]})
                extra = geo_for(st["source"], st["actor"]) if st["kind"] in GEO_KINDS else {}
                core.ingest(st["kind"], st["source"], st["target"], dict(st["details"], sim_step=i + 1, **extra),
                            session=session, ts=t0 + st["at"], delay=min(0.6, 0.6 / speed))
            else:
                completed = True
        except Exception:
            log.exception("simulation crashed")
        finally:
            with self.lock:
                if session == self.session:
                    self.result = self._summary(session)
                    if completed and self.state in ("running", "paused"):
                        self.state = "finished"
                    elif self.state in ("running", "paused"):
                        self.state = "stopped"
                    self._publish_state()
            db.reset_owner(owner_token)

    def _summary(self, session):
        session = core.scoped_session(session)
        alerts = store.list_alerts(session, 200)
        incs = store.list_incidents(session, 200)
        counts = store.session_counts(session)
        expected = set(SCENARIOS[self.scenario]["rules"])
        got = {a["rule_id"] for a in alerts}
        resp = []
        for i in incs:
            tl = {t["stage"]: t["ts"] for t in (store.get_incident(i["id"]) or {}).get("timeline", [])}
            if "detection" in tl and ("mitigated" in tl or "failed" in tl):
                resp.append(tl.get("mitigated", tl.get("failed")) - tl["detection"])
        first = min((a["ts"] for a in alerts), default=None)
        return {"expected_rules": sorted(expected), "detected": expected <= got and bool(alerts),
                "alerts": len(alerts), "incidents": [{"id": i["id"], "severity": i["severity"], "status": i["status"]} for i in incs],
                "mitigated": sum(i["status"] in ("mitigated", "closed") for i in incs),
                "failed": sum(i["status"] == "failed" for i in incs),
                "time_to_detect_s": round(first - (self.t0 + self.attack_at), 2) if first is not None else None,
                "response_s": round(sum(resp) / len(resp), 2) if resp else None,
                "events": counts["events"], "blocked_attempts": counts["blocked"]}


_labs = {}
_labs_lock = threading.Lock()


def get_lab():
    owner = db.current_owner_session()
    if owner is None:
        owner = "local-development"
    with _labs_lock:
        if owner not in _labs:
            _labs[owner] = Lab(owner)
        return _labs[owner]
