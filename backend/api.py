"""JSON API. Every route is CSRF-checked (POST) and rate-limited."""
from flask import Blueprint, Response, jsonify, request, stream_with_context

import config
import hashlib
import json
import logging
import queue
import re
import sqlite3

from . import db, quiz
from .engine import bus, simulator, core as engine, rules as engine_rules, store as engine_store
from .scanners import file_check, phishing, url_scanner
from .scanners.url_scanner import ScanError
from .security import api_error, protected

bp = Blueprint("api", __name__, url_prefix="/api")
log = logging.getLogger("cyberguard")


def _save(kind, result):
    """Persist a scan; a storage failure must not hide the scan result."""
    try:
        result["saved"] = bool(db.record_scan(kind, result))
    except sqlite3.Error:
        log.exception("could not save scan")
        result["saved"] = False
    engine.ingest_scan(kind, result)      # real scan -> security event -> detection


def _json_text(field):
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get(field), str):
        return None
    return body[field]


@bp.post("/scan/url")
@protected
def scan_url():
    raw = _json_text("url")
    if raw is None:
        return api_error("invalid_json")
    try:
        result = url_scanner.analyze(raw)
    except ScanError as e:
        return api_error(e.code)
    _save("url", result)
    return jsonify({"ok": True, "result": result})


@bp.post("/scan/phishing")
@protected
def scan_phishing():
    text = _json_text("text")
    if text is None:
        return api_error("invalid_json")
    try:
        result = phishing.analyze(text)
    except ScanError as e:
        return api_error(e.code)
    _save("phishing", result)
    return jsonify({"ok": True, "result": result})


@bp.post("/scan/file")
@protected
def scan_file():
    f1, f2 = request.files.get("file"), request.files.get("file2")
    if not f1 or not f1.filename:
        return api_error("no_file")
    expected = None
    if request.form.get("expected", "").strip():
        expected = file_check.valid_hash(request.form["expected"])
        if not expected:
            return api_error("invalid_hash")
    try:
        results = [file_check.analyze(f1)]
        if f2 and f2.filename:
            results.append(file_check.analyze(f2))
    except ScanError as e:
        return api_error(e.code)
    for r, field in zip(results, ("modified", "modified2")):
        _save("file", r)
        try:
            ms = int(request.form.get(field, ""))
        except ValueError:
            ms = None
        try:
            r["history"] = db.record_file_history(r["name"], r["size"], r["sha256"], ms)
        except sqlite3.Error:
            log.exception("could not log file history")
    compare = None
    if len(results) == 2:
        compare = {"against": "file", "match": results[0]["sha256"] == results[1]["sha256"]}
    elif expected:
        compare = {"against": "hash", "match": results[0]["sha256"] == expected}
    return jsonify({"ok": True, "files": results, "compare": compare})


@bp.get("/quiz")
@protected
def quiz_questions():
    return jsonify({"ok": True, "questions": quiz.public()})


@bp.post("/quiz/submit")
@protected
def quiz_submit():
    body = request.get_json(silent=True)
    result = quiz.score(body.get("answers") if isinstance(body, dict) else None)
    if result is None:
        return api_error("invalid_json")
    try:
        db.record_quiz(result)
    except sqlite3.Error:
        log.exception("could not save quiz result")
    return jsonify({"ok": True, "result": result})


# ---------- dashboard & reports ----------
def _db_call(fn, *a):
    try:
        return fn(*a), None
    except sqlite3.Error:
        log.exception("database error")
        return None, api_error("db", 500)


@bp.get("/stats")
@protected
def stats():
    data, err = _db_call(db.stats)
    return err or jsonify(data)


@bp.get("/scans")
@protected
def scans():
    data, err = _db_call(db.list_scans, 50)
    return err or jsonify({"ok": True, "scans": data})


@bp.get("/reports")
@protected
def reports_list():
    data, err = _db_call(db.list_reports)
    return err or jsonify({"ok": True, "reports": data})


@bp.post("/reports")
@protected
def reports_create():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("invalid_json")
    title = str(body.get("title") or "").strip()[:100] or "Security report"
    limit = body.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500):
        return api_error("invalid_json")
    rid, err = _db_call(db.create_report, title, limit)
    if err:
        return err
    if rid is None:
        return api_error("no_scans")
    return jsonify({"ok": True, "id": rid})


@bp.get("/reports/<int:rid>/pdf")
@protected
def report_pdf(rid):
    from flask import Response
    from . import reports
    data, err = _db_call(db.get_report, rid)
    if err:
        return err
    if not data:
        return api_error("not_found", 404)
    lang = "ar" if request.args.get("lang") == "ar" else "en"
    try:
        pdf = reports.build_pdf(data, lang)
    except Exception:
        log.exception("pdf generation failed")
        return api_error("server", 500)
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="cyro-report-{rid}-{lang}.pdf"'})


# ---------- security engine (events, alerts, incidents, rules) ----------
def _int(name, default, lo=1, hi=500):
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except ValueError:
        return default


def _session():
    # This is only a display/query filter inside the already isolated visitor DB;
    # it is never used to authorize access to another visitor's records.
    value = request.args.get("session", "")
    return value if value and len(value) <= 128 and re.fullmatch(r"[A-Za-z0-9:_-]+", value) else None


def _engine_call(fn, *a, **kw):
    try:
        return fn(*a, **kw), None
    except sqlite3.Error:
        log.exception("engine database error")
        return None, api_error("db", 500)


@bp.get("/file-history")
@protected
def file_history():
    data, err = _db_call(db.list_file_history, _int("limit", 30))
    return err or jsonify({"ok": True, "history": data})


@bp.get("/engine/stats")
@protected
def engine_stats():
    d, err = _engine_call(engine.stats)
    return err or jsonify({"ok": True, **d})


@bp.get("/engine/timeline")
@protected
def engine_timeline():
    span, bucket = _int("span", 3600, 60, 86400), _int("bucket", 300, 5, 3600)
    d, err = _engine_call(engine_store.timeline_buckets, span, bucket, _session())
    return err or jsonify({"ok": True, "buckets": d, "bucket_s": bucket})


@bp.get("/engine/rules")
@protected
def engine_rules_list():
    counts, err = _engine_call(engine_store.rule_counts)
    if err:
        return err
    return jsonify({"ok": True, "rules": [
        {"id": r.id, "category": r.category, "severity": r.severity, "name": r.name, "description": r.description,
         "conditions": r.conditions, "params": r.params, "alerts": counts.get(r.id, 0)} for r in engine_rules.RULES]})


@bp.get("/engine/events")
@protected
def engine_events():
    kind = request.args.get("kind")
    outcome = request.args.get("outcome")
    if (kind and (len(kind) > 30 or not kind.replace("_", "").isalnum())) or outcome not in (None, "", "allowed", "dropped"):
        return api_error("invalid_json")
    d, err = _engine_call(engine_store.list_events, _session(), _int("limit", 100), _int("after", 0, 0, 10**9),
                          kind or None, outcome or None, request.args.get("probes") != "1")
    return err or jsonify({"ok": True, "events": d})


@bp.get("/engine/map")
@protected
def engine_map():
    d, err = _engine_call(engine_store.map_events, _session(), _int("limit", 300))
    return err or jsonify({"ok": True, "events": d})


@bp.get("/engine/top-sources")
@protected
def engine_top_sources():
    d, err = _engine_call(engine_store.top_sources, _int("limit", 5, 1, 20))
    return err or jsonify({"ok": True, "sources": d})


@bp.get("/engine/sessions")
@protected
def engine_sessions():
    d, err = _engine_call(engine_store.recent_sessions)
    return err or jsonify({"ok": True, "sessions": d})


@bp.get("/engine/alerts")
@protected
def engine_alerts():
    d, err = _engine_call(engine_store.list_alerts, _session(), _int("limit", 100), request.args.get("status"))
    return err or jsonify({"ok": True, "alerts": d})


@bp.get("/engine/incidents")
@protected
def engine_incidents():
    d, err = _engine_call(engine_store.list_incidents, _session(), _int("limit", 100), request.args.get("status"))
    return err or jsonify({"ok": True, "incidents": d})


@bp.get("/engine/incidents/<int:iid>")
@protected
def engine_incident(iid):
    d, err = _engine_call(engine_store.get_incident, iid)
    if err:
        return err
    return jsonify({"ok": True, "incident": d}) if d else api_error("not_found", 404)


# ---------- live stream (Server-Sent Events) ----------
@bp.get("/stream")
@protected
def stream():
    q = bus.subscribe(db.current_owner_session())

    def gen():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    m = q.get(timeout=15)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                yield f"event: {m['topic']}\ndata: {json.dumps(m['data'], ensure_ascii=False)}\n\n"
        finally:
            bus.unsubscribe(q)
    return Response(stream_with_context(gen()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ---------- attack simulation lab ----------
@bp.get("/lab/scenarios")
@protected
def lab_scenarios():
    return jsonify({"ok": True, "scenarios": simulator.catalog()})


@bp.get("/lab/status")
@protected
def lab_status():
    return jsonify({"ok": True, **simulator.get_lab().status()})


@bp.post("/lab/<action>")
@protected
def lab_control(action):
    lab = simulator.get_lab()
    if action == "start":
        body = request.get_json(silent=True) or {}
        speed = body.get("speed", 1)
        if speed not in (0.5, 1, 2, 4):
            return api_error("invalid_json")
        res = lab.start(body.get("scenario"), float(speed))
        if res == "busy":
            return api_error("lab_busy", 409)
        if res == "unknown":
            return api_error("invalid_json")
    elif action in ("pause", "resume", "stop"):
        if not getattr(lab, action)():
            return api_error("lab_state", 409)
    elif action == "reset":
        if not lab.reset():
            return api_error("lab_busy", 409)
    else:
        return api_error("not_found", 404)
    return jsonify({"ok": True, **lab.status()})


@bp.post("/engine/alerts/<int:aid>/status")
@protected
def alert_status(aid):
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    if status not in ("open", "acknowledged", "resolved"):
        return api_error("invalid_json")
    n, err = _engine_call(engine_store.set_alert_status, aid, status)
    if err:
        return err
    return jsonify({"ok": True}) if n else api_error("not_found", 404)


@bp.post("/engine/incidents/<int:iid>/close")
@protected
def incident_close(iid):
    from .engine.rules import bi
    res, err = _engine_call(engine_store.close_incident, iid, bi("أغلق المحلل الحادثة بعد المراجعة.", "The analyst closed the incident after review."))
    if err:
        return err
    if res == "missing":
        return api_error("not_found", 404)
    if res == "active":
        return api_error("incident_active", 409)
    engine.bus.publish("incident", {"id": iid, "session": None, "status": "closed"})
    return jsonify({"ok": True})


@bp.get("/engine/incidents/<int:iid>/pdf")
@protected
def incident_pdf(iid):
    from . import reports
    inc, err = _engine_call(engine_store.get_incident, iid)
    if err:
        return err
    if not inc:
        return api_error("not_found", 404)
    lang = "ar" if request.args.get("lang") == "ar" else "en"
    try:
        pdf = reports.build_incident_pdf(inc, engine_rules.BY_ID.get(inc["rule_id"]), lang)
    except Exception:
        log.exception("incident pdf failed")
        return api_error("server", 500)
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="cyro-incident-{iid}-{lang}.pdf"'})


# ---------- Secure Communication Lab ----------
COMM_KINDS = {"comm_send", "comm_inject", "comm_reject", "comm_accept", "comm_intercept", "comm_handshake"}
COMM_ATTACKS = {"none", "eavesdrop", "tamper", "replay", "impersonate", "mitm"}
COMM_REASONS = {"integrity", "bad_signature", "replay", "handshake_auth"}
COMM_HOW = {"plaintext", "mitm_key", "ciphertext_only", "lucky"}
_SESSION_RE = re.compile(r"^comm-[a-z0-9]{6,16}$")


def _attacker_addr(session):
    return "203.0.113." + str(1 + int(hashlib.sha256(session.encode()).hexdigest(), 16) % 254)


def _clean_comm(kind, d):
    """Whitelist and validate lab event details. Returns (details, error_code)."""
    if not isinstance(d, dict):
        return None, "invalid_json"
    out = {}
    key_id = d.get("key_id")
    if key_id not in (None, "") and not (isinstance(key_id, str) and re.fullmatch(r"[0-9a-f]{1,16}", key_id)):
        return None, "invalid_json"
    out["key_id"] = key_id or None
    seq = d.get("seq")
    if seq is not None and (not isinstance(seq, int) or isinstance(seq, bool) or not 0 <= seq <= 10**6):
        return None, "invalid_json"
    out["seq"] = seq
    for flag in ("encrypted", "signed", "readable", "auth", "mitm", "ok"):
        if flag in d:
            out[flag] = bool(d[flag])
    if "attack" in d:
        if d["attack"] not in COMM_ATTACKS:
            return None, "invalid_json"
        out["attack"] = d["attack"]
    if "reason" in d:
        if d["reason"] not in COMM_REASONS:
            return None, "invalid_json"
        out["reason"] = d["reason"]
    if "how" in d:
        if d["how"] not in COMM_HOW:
            return None, "invalid_json"
        out["how"] = d["how"]
    out["origin_actor"] = "attacker" if d.get("origin") == "attacker" else "sender"
    if kind == "comm_send" and not out.get("encrypted"):
        text = d.get("text")
        if not isinstance(text, str) or len(text) > 500:
            return None, "too_long"
        hits = engine.sensitive_hits(text)              # the text itself is never stored
        out["sensitive"], out["sensitive_hits"], out["length"] = hits > 0, hits, len(text)
    return out, None


@bp.post("/comm/event")
@protected
def comm_event():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return api_error("invalid_json")
    session, kind = body.get("session"), body.get("kind")
    if not isinstance(session, str) or not _SESSION_RE.match(session) or kind not in COMM_KINDS:
        return api_error("invalid_json")
    details, err = _clean_comm(kind, body.get("details", {}))
    if err:
        return api_error(err)
    attacker_side = kind in ("comm_inject", "comm_intercept") or (kind == "comm_reject" and details["origin_actor"] == "attacker")
    if attacker_side:
        source = _attacker_addr(session)
        details.update(simulator.geo_for(source, "attacker"))
    else:
        source = "receiver" if kind == "comm_accept" else "sender"
    target = "sender" if kind == "comm_intercept" else "receiver"
    try:
        res = engine.ingest(kind, source, target, details, session=session, delay=0.2)
        incidents = []
        for iid in res["incidents"]:
            inc = engine_store.get_incident(iid)
            incidents.append({"id": iid, "rule_id": inc["rule_id"], "severity": inc["severity"], "status": inc["status"], "title": inc["title"],
                              "actions": [{"action": a["action"], "target": a["target"], "verified": bool(a["verified"])} for a in inc["actions"]]})
    except sqlite3.Error:
        log.exception("comm event failed")
        return api_error("db", 500)
    return jsonify({"ok": True, "outcome": res["outcome"], "source": source, "incidents": incidents})


@bp.post("/comm/reset")
@protected
def comm_reset():
    body = request.get_json(silent=True) or {}
    session = body.get("session")
    if not isinstance(session, str) or not _SESSION_RE.match(session):
        return api_error("invalid_json")
    engine.reset_session(session)
    return jsonify({"ok": True})
