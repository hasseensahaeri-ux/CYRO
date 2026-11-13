"""Event ingestion -> detection -> analysis -> incident -> automated response -> verification -> report.
All state changes are real: events are stored, rules analyse them, defenses change a
firewall-like state table, and verification probes send new events through the same filter."""
import logging
import re
import threading
import time
from collections import defaultdict, deque
from urllib.parse import urlsplit

from . import bus, rules, store
from .rules import bi
from ..scanners import phishing

log = logging.getLogger("cyberguard.engine")
_lock = threading.RLock()
_win = defaultdict(deque)     # sliding windows, key[0] is always the session
_fired = set()                # (session, rule, key): one incident per attack until reset
_state = {}                   # session -> {(kind, value)} loaded lazily from defense_state

SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
PLAYBOOK = {"brute_force": ["block_source", "lock_account"], "port_scan": ["block_source"],
            "traffic": ["block_source"], "ddos": ["block_source"],
            "phishing": ["quarantine_message", "block_domain"], "url": ["block_domain"],
            "malware": ["quarantine_file"],
            "comm_integrity": ["block_source"], "comm_replay": ["block_source", "rotate_keys"],
            "comm_mitm": ["block_source"], "comm_policy": ["enforce_encryption"]}
STATE_KIND = {"block_source": "source", "lock_account": "account", "block_domain": "domain",
              "quarantine_message": "message", "quarantine_file": "file_hash",
              "rotate_keys": "session_key", "enforce_encryption": "policy"}
ACTION_TEXT = {
    "block_source": bi("حظر المصدر {t} في جدار الحماية المحلي", "Blocked source {t} in the local firewall"),
    "lock_account": bi("قفل الحساب {t} مؤقتًا", "Temporarily locked account {t}"),
    "block_domain": bi("حظر النطاق {t}", "Blocked domain {t}"),
    "quarantine_message": bi("عزل الرسالة {t}", "Quarantined message {t}"),
    "quarantine_file": bi("عزل الملف (Hash) {t}", "Quarantined file (hash) {t}"),
    "rotate_keys": bi("إبطال مفتاح الجلسة {t} وفرض مفاتيح جديدة", "Revoked session key {t} and forced new keys"),
    "enforce_encryption": bi("فرض التشفير على القناة (منع الإرسال النصي الصريح)", "Enforced encryption on the channel (clear-text sends blocked)"),
}


# ---------------- defense state ----------------
def _st(session):
    if session not in _state:
        _state[session] = store.load_state(session)
    return _state[session]


def denied(session, kind, source, target, details):
    st = _st(session)
    if kind in ("login_failed", "login_success", "conn_attempt", "request", "comm_inject", "comm_packet") and ("source", str(source)) in st:
        return True
    if kind == "comm_packet" and ("session_key", str(details.get("key_id", ""))) in st:
        return True
    if kind == "comm_send" and not details.get("encrypted") and ("policy", "require_encryption") in st:
        return True
    if kind in ("login_failed", "login_success") and ("account", str(target)) in st:
        return True
    if kind == "url_click" and ("domain", str(target)) in st:
        return True
    if kind == "file_open" and ("file_hash", str(details.get("sha256", ""))) in st:
        return True
    return False

ACTION_NAME = {"block_source": bi("حظر المصدر", "Source block"), "lock_account": bi("قفل الحساب", "Account lock"),
               "block_domain": bi("حظر النطاق", "Domain block"), "quarantine_message": bi("عزل الرسالة", "Message quarantine"),
               "quarantine_file": bi("عزل الملف", "File quarantine"), "rotate_keys": bi("تدوير المفاتيح", "Key rotation"),
               "enforce_encryption": bi("فرض التشفير", "Encryption policy")}


# ---------------- detection ----------------
def _det(rule, e, source, evidence, event_ids, severity=None, sources=None):
    return {"rule": rule, "session": e["session"], "source": source, "target": e["target"],
            "severity": severity or rule.severity, "evidence": evidence, "event_ids": event_ids,
            "ts": e["ts"], "sources": sources or [source]}


def _prune(dq, now, window):
    while dq and dq[0][0] < now - window:
        dq.popleft()


def _bf(e):
    r = rules.BY_ID["CR-BF-001"]; p = r.params
    dq = _win[(e["session"], "bf", e["source"])]
    dq.append((e["ts"], e["id"], e["target"]))
    _prune(dq, e["ts"], p["window"])
    key = (e["session"], r.id, e["source"])
    if len(dq) >= p["threshold"] and key not in _fired:
        _fired.add(key)
        return [_det(r, e, e["source"], {"attempts": len(dq), "window_s": p["window"],
                                         "accounts": sorted({t for _, _, t in dq})[:5]}, [i for _, i, _ in dq])]
    return []


def _ps(e):
    r = rules.BY_ID["CR-PS-001"]; p = r.params
    dq = _win[(e["session"], "ps", e["source"])]
    dq.append((e["ts"], e["id"], e["details"].get("port")))
    _prune(dq, e["ts"], p["window"])
    ports = sorted({x[2] for x in dq if x[2] is not None})
    key = (e["session"], r.id, e["source"])
    if len(ports) >= p["distinct_ports"] and key not in _fired:
        _fired.add(key)
        return [_det(r, e, e["source"], {"ports": ports[:20], "port_count": len(ports), "window_s": p["window"]},
                     [x[1] for x in dq])]
    return []


def _traffic(e):
    out, s, now = [], e["session"], e["ts"]
    r1 = rules.BY_ID["CR-ST-001"]; p1 = r1.params
    dq = _win[(s, "rate", e["source"])]
    dq.append((now, e["id"], int(e["details"].get("bytes") or 0)))
    _prune(dq, now, p1["window"])
    total = sum(x[2] for x in dq)
    k1 = (s, r1.id, e["source"])
    if (len(dq) > p1["requests"] or total > p1["bytes"]) and k1 not in _fired:
        _fired.add(k1)
        out.append(_det(r1, e, e["source"], {"requests": len(dq), "bytes": total, "window_s": p1["window"]},
                        [x[1] for x in dq]))
    r2 = rules.BY_ID["CR-ST-002"]; p2 = r2.params
    fq = _win[(s, "flood", e["target"])]
    fq.append((now, e["source"], e["id"]))
    _prune(fq, now, p2["window"])
    srcs = sorted({x[1] for x in fq})
    k2 = (s, r2.id, e["target"])
    if len(fq) >= p2["requests"] and len(srcs) >= p2["sources"] and k2 not in _fired:
        _fired.add(k2)
        out.append(_det(r2, e, "distributed", {"requests": len(fq), "distinct_sources": len(srcs),
                                               "window_s": p2["window"], "target": e["target"]},
                        [x[2] for x in fq], sources=srcs))
    return out


def _phish_features(d):
    score, codes, domains = d.get("score"), d.get("codes"), d.get("domains")
    if score is None and d.get("text"):
        try:
            r = phishing.analyze(d["text"])
        except Exception:
            return None, [], []
        score = r["score"]
        codes = [f["code"] for f in r["findings"] if f["points"] > 0]
        domains = sorted({(urlsplit(l["url"] if "://" in l["url"] else "http://" + l["url"]).hostname or "")
                          for l in r["links"] if l["score"] >= 20} - {""})
    return score, codes or [], domains or []


def _phish(e):
    r = rules.BY_ID["CR-PH-001"]
    score, codes, domains = _phish_features(e["details"])
    if score is None or score < r.params["score"]:
        return []
    sev = "critical" if score >= r.params["critical"] else r.severity
    return [_det(r, e, e["details"].get("sender") or e["source"],
                 {"score": score, "indicators": codes, "domains": domains}, [e["id"]], severity=sev)]


def _url(e):
    r = rules.BY_ID["CR-UR-001"]
    score = e["details"].get("score")
    key = (e["session"], r.id, e["source"])
    if score is None or score < r.params["score"] or key in _fired:
        return []
    _fired.add(key)
    sev = "critical" if score >= r.params["critical"] else r.severity
    return [_det(r, e, e["source"], {"score": score, "indicators": e["details"].get("codes", []),
                                     "domains": [e["source"]]}, [e["id"]], severity=sev)]


def _file(e):
    r, d = rules.BY_ID["CR-ML-001"], e["details"]
    codes, hits = set(d.get("codes") or []), []
    if d.get("sha256") in rules.TEST_IOC_HASHES:
        hits.append(("ioc_hash", "critical"))
    if d.get("eicar") or "eicar_test" in codes:
        hits.append(("eicar", "medium"))
    if "disguised_exe" in codes:
        hits.append(("disguised_exe", "high"))
    if "double_ext" in codes:
        hits.append(("double_ext", "high"))
    key = (e["session"], r.id, d.get("sha256") or e["source"])
    if not hits or key in _fired:
        return []
    _fired.add(key)
    sev = max((h[1] for h in hits), key=SEV_RANK.get)
    return [_det(r, e, d.get("name") or e["source"], {"hits": [h[0] for h in hits], "name": d.get("name"),
                                                      "sha256": d.get("sha256"), "size": d.get("size")},
                 [e["id"]], severity=sev)]


COMM_REASON = {"integrity": "CR-CM-001", "bad_signature": "CR-CM-001", "replay": "CR-CM-002", "handshake_auth": "CR-CM-003"}


def _comm_reject(e):
    d = e["details"]
    rid = COMM_REASON.get(d.get("reason"))
    if not rid:
        return []
    key = (e["session"], rid, e["source"])
    if key in _fired:
        return []
    _fired.add(key)
    return [_det(rules.BY_ID[rid], e, e["source"], {"reason": d["reason"], "key_id": d.get("key_id") or "none", "seq": d.get("seq")}, [e["id"]])]


def _comm_send(e):
    d, r = e["details"], rules.BY_ID["CR-CM-004"]
    key = (e["session"], r.id, "policy")
    if d.get("encrypted") or not d.get("sensitive") or key in _fired:
        return []
    _fired.add(key)
    return [_det(r, e, "sender", {"sensitive_hits": d.get("sensitive_hits", 1), "channel": "cleartext"}, [e["id"]])]


DETECTORS = {"comm_reject": _comm_reject, "comm_send": _comm_send, "login_failed": _bf, "conn_attempt": _ps, "request": _traffic, "message": _phish,
             "url_scan": _url, "file": _file}


# ---------------- analysis ----------------
def _analysis(det):
    ev, r, cat = det["evidence"], det["rule"], det["rule"].category
    src = det["source"]
    j = lambda x: ", ".join(str(i) for i in x) or "-"
    if cat == "brute_force":
        s = bi(f"رُصدت {ev['attempts']} محاولات دخول فاشلة من {src} خلال {ev['window_s']} ثانية، الحسابات المستهدفة: {j(ev['accounts'])}.",
               f"{ev['attempts']} failed logins from {src} within {ev['window_s']} s; targeted accounts: {j(ev['accounts'])}.")
    elif cat == "port_scan":
        s = bi(f"المصدر {src} حاول الاتصال بـ {ev['port_count']} منفذًا مختلفًا خلال {ev['window_s']} ثانية (المنافذ: {j(ev['ports'])}).",
               f"Source {src} tried {ev['port_count']} distinct ports within {ev['window_s']} s (ports: {j(ev['ports'])}).")
    elif cat == "traffic":
        mb = round(ev["bytes"] / 1e6, 1)
        s = bi(f"المصدر {src} أرسل {ev['requests']} طلبًا ({mb} MB) خلال {ev['window_s']} ثانية وتجاوز الحد المسموح.",
               f"Source {src} sent {ev['requests']} requests ({mb} MB) within {ev['window_s']} s, above the allowed limit.")
    elif cat == "ddos":
        s = bi(f"{ev['requests']} طلبًا من {ev['distinct_sources']} مصدرًا مختلفًا نحو {ev['target']} خلال {ev['window_s']} ثوانٍ.",
               f"{ev['requests']} requests from {ev['distinct_sources']} distinct sources toward {ev['target']} within {ev['window_s']} s.")
    elif cat == "phishing":
        s = bi(f"درجة الرسالة {ev['score']}/100. المؤشرات: {j(ev['indicators'])}. النطاقات المشبوهة: {j(ev['domains'])}.",
               f"Message score {ev['score']}/100. Indicators: {j(ev['indicators'])}. Suspicious domains: {j(ev['domains'])}.")
    elif cat == "url":
        s = bi(f"الرابط {src} حصل على درجة {ev['score']}/100. المؤشرات: {j(ev['indicators'])}.",
               f"Link {src} scored {ev['score']}/100. Indicators: {j(ev['indicators'])}.")
    elif cat in ("comm_integrity", "comm_replay", "comm_mitm"):
        why = {"integrity": ("وسم التشفير GCM لا يطابق", "the GCM encryption tag does not match"),
               "bad_signature": ("التوقيع الرقمي غير صالح", "the digital signature is invalid"),
               "replay": ("الرقم التسلسلي أو الختم الزمني قديم", "the sequence number or timestamp is stale"),
               "handshake_auth": ("توقيع مفتاح المصافحة لا يطابق الهوية الموثّقة", "the handshake key signature does not match the pinned identity")}[ev["reason"]]
        s = bi(f"رفض المستقبل حزمة قادمة من {src}: {why[0]}.", f"The receiver rejected a packet from {src}: {why[1]}.")
    elif cat == "comm_policy":
        s = bi(f"رسالة تحمل {ev['sensitive_hits']} مؤشر بيانات حساسة أُرسلت نصًا صريحًا دون تشفير.",
               f"A message with {ev['sensitive_hits']} sensitive-data indicator(s) was sent in clear text without encryption.")
    else:
        s = bi(f"الملف {ev['name']} يطابق المؤشرات: {j(ev['hits'])}.", f"File {ev['name']} matches indicators: {j(ev['hits'])}.")
    return {"attack_type": r.name, "summary": s, "rule_id": r.id, "severity": det["severity"],
            "playbook": PLAYBOOK[cat], "evidence": ev}


# ---------------- response ----------------
def _targets(action, det):
    ev, cat = det["evidence"], det["rule"].category
    if action == "block_source":
        return det["sources"][:50]
    if action == "lock_account":
        return ev.get("accounts", [])[:5]
    if action == "block_domain":
        return (ev.get("domains") or [])[:5]
    if action == "quarantine_message":
        return [f"message#{det['event_ids'][-1]}"]
    if action == "quarantine_file":
        return [ev.get("sha256") or det["source"]]
    if action == "rotate_keys":
        return [str(ev.get("key_id") or "none")]
    if action == "enforce_encryption":
        return ["require_encryption"]
    return []


def _probe(session, kind, source, target, details):
    """Verification probe: a new event pushed through the same filter; never triggers detection."""
    ts = time.time()
    with _lock:
        out = "dropped" if denied(session, kind, source, target, details) else "allowed"
        eid = store.add_event(session, kind, source, target, details, ts, out)
    bus.publish("event", _ev_payload({"id": eid, "ts": ts, "session": session, "kind": kind, "source": source,
                                      "target": target, "details": details}, out))
    return out


def _verify(action, target, session):
    if action == "block_source":
        return _probe(session, "request", target, "verification", {"probe": True}) == "dropped"
    if action == "lock_account":
        return _probe(session, "login_failed", "verification-probe", target, {"probe": True}) == "dropped"
    if action == "block_domain":
        return _probe(session, "url_click", "verification-probe", target, {"probe": True}) == "dropped"
    if action == "quarantine_file":
        return _probe(session, "file_open", "verification-probe", target, {"probe": True, "sha256": target}) == "dropped"
    if action == "rotate_keys":
        return _probe(session, "comm_packet", "verification-probe", "receiver", {"probe": True, "key_id": target}) == "dropped"
    if action == "enforce_encryption":
        return _probe(session, "comm_send", "verification-probe", "receiver", {"probe": True, "encrypted": False}) == "dropped"
    if action == "quarantine_message":
        return store.has_state(session, "message", target)          # read back from the database
    return False


def _respond(det, delay=0.0):
    r, s = det["rule"], det["session"]
    sleep = (lambda: time.sleep(delay)) if delay > 0 else (lambda: None)
    title = bi(f"{r.name['ar']} — {det['source']}", f"{r.name['en']} — {det['source']}")

    t_det = time.time()
    alert_id = store.add_alert(s, r.id, det["severity"], title, det["source"], det["event_ids"], det["evidence"], det["ts"])
    bus.publish("alert", {"id": alert_id, "session": s, "rule_id": r.id, "severity": det["severity"],
                          "title": title, "source": det["source"], "ts": det["ts"]})
    sleep()
    t_an = time.time()
    analysis = _analysis(det)
    iid = store.add_incident(alert_id, s, r.id, r.category, det["severity"], det["source"], title, analysis, t_an)

    def tl(stage, message, t=None):
        t = t or time.time()
        store.add_timeline(iid, stage, message, t)
        bus.publish("timeline", {"incident_id": iid, "session": s, "stage": stage, "message": message, "ts": t})

    def status(st):
        store.set_incident_status(iid, st, time.time())
        bus.publish("incident", {"id": iid, "session": s, "status": st, "severity": det["severity"],
                                 "rule_id": r.id, "category": r.category, "title": title, "source": det["source"]})

    tl("detection", bi(f"القاعدة {r.id} كشفت نشاطًا يطابق شروطها.", f"Rule {r.id} matched the activity."), t_det)
    tl("analysis", analysis["summary"], t_an)
    sleep()
    tl("incident", bi(f"أُنشئت الحادثة #{iid} بخطورة {det['severity']}.", f"Incident #{iid} created with severity {det['severity']}."))
    status("detected")
    sleep()
    status("responding")

    applied, n = [], 0
    for action in PLAYBOOK[r.category]:
        for target in _targets(action, det):
            if n < 3:
                sleep()          # animate the first few, then act at full speed
            n += 1
            with _lock:
                _st(s).add((STATE_KIND[action], str(target)))
                store.set_state(s, STATE_KIND[action], target, iid, time.time())
            aid = store.add_action(iid, s, action, target, "applied", False, {}, time.time())
            t = ACTION_TEXT[action]
            tl("response", bi(t["ar"].format(t=target), t["en"].format(t=target)))
            bus.publish("action", {"incident_id": iid, "session": s, "action": action, "target": target})
            applied.append((aid, action, target))

    sleep()
    all_ok = bool(applied)
    for aid, action, target in applied:
        ok = _verify(action, target, s)
        store.set_action_verified(aid, ok)
        all_ok = all_ok and ok
        nm = ACTION_NAME[action]
        tl("verification", bi(f"التحقق من «{nm['ar']}» على {target}: {'نجح' if ok else 'فشل'}.",
                              f"Verification of “{nm['en']}” on {target}: {'passed' if ok else 'failed'}."))
    if all_ok:
        tl("mitigated", bi("تم احتواء التهديد وتأكدنا من فعالية الإجراءات.", "Threat mitigated and the actions were verified."))
        status("mitigated")
    else:
        tl("failed", bi("لم يكتمل التحقق من الاستجابة؛ تحتاج الحادثة إلى متابعة.", "Response could not be fully verified; the incident needs follow-up."))
        status("failed")
    tl("report", bi("تم إعداد تقرير الحادثة.", "The incident report has been prepared."))
    return iid


# ---------------- public API ----------------
def _ev_payload(e, outcome):
    small = {k: v for k, v in (e.get("details") or {}).items() if k != "text" and len(str(v)) < 200}
    return {"id": e["id"], "ts": e["ts"], "session": e["session"], "kind": e["kind"], "source": e["source"],
            "target": e["target"], "outcome": outcome, "details": small}


def ingest(kind, source, target="", details=None, session="live", ts=None, delay=0.0):
    details, ts = details or {}, ts or time.time()
    with _lock:
        drop = denied(session, kind, source, target, details)
        outcome = "dropped" if drop else "allowed"
        eid = store.add_event(session, kind, source, target, details, ts, outcome)
        e = {"id": eid, "ts": ts, "session": session, "kind": kind, "source": str(source)[:200],
             "target": str(target)[:300], "details": details}
        dets = [] if (drop or details.get("probe")) else (DETECTORS.get(kind, lambda _: [])(e))
    bus.publish("event", _ev_payload(e, outcome))
    return {"event_id": eid, "outcome": outcome, "incidents": [_respond(d, delay) for d in dets]}


def reset_session(session):
    with _lock:
        for k in [k for k in _win if k[0] == session]:
            del _win[k]
        for k in [k for k in _fired if k[0] == session]:
            _fired.discard(k)
        _state.pop(session, None)
        store.clear_session(session)
    bus.publish("reset", {"session": session})


def ingest_scan(kind, result):
    """Feed a real tool scan into the engine. Never raises: tools must keep working if the engine fails."""
    try:
        codes = [f["code"] for f in result["findings"] if f["points"] > 0]
        if kind == "url":
            ingest("url_scan", result["host"], result["url"],
                   {"score": result["score"], "verdict": result["verdict"], "codes": codes})
        elif kind == "phishing":
            domains = sorted({(urlsplit(l["url"] if "://" in l["url"] else "http://" + l["url"]).hostname or "")
                              for l in result["links"] if l["score"] >= 20} - {""})
            ingest("message", "local-message", str(result["chars"]),
                   {"score": result["score"], "verdict": result["verdict"], "codes": codes, "domains": domains})
        elif kind == "file":
            ingest("file", result["name"], result["name"],
                   {"name": result["name"], "size": result["size"], "sha256": result["sha256"],
                    "codes": codes, "eicar": result.get("eicar", False)})
    except Exception:
        log.exception("engine ingest failed")


def system_status():
    active = [i for i in store.list_incidents(limit=200) if i["status"] in ("detected", "responding", "failed")]
    if any(i["severity"] == "critical" or i["status"] == "failed" for i in active):
        return "critical"
    return "elevated" if active else "secure"


def stats():
    s = store.stats()
    s["system_status"] = system_status()
    s["trends"] = store.trends()
    return s


# ---------------- communication lab helpers ----------------
_SENSITIVE = re.compile(r"(?<![a-z0-9\u0600-\u06FF])(password|passcode|otp|pin|cvv|card|iban|account|ssn|login|"
                        r"كلمه المرور|كلمه السر|رمز|بطاقه|حساب|ايبان|الرقم السري)(?![a-z0-9\u0600-\u06FF])|\d{6,}")


def sensitive_hits(text):
    """How many sensitive-data indicators a clear-text message carries (Arabic and English)."""
    return len(_SENSITIVE.findall(phishing.norm(text or "")))
