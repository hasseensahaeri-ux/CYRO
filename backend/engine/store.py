"""SQL for the engine. Every statement is parameterised."""
import json
import time

from .. import db


def _txt(ts=None):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts if ts else time.time()))


def _j(o):
    return json.dumps(o, ensure_ascii=False)


def _run(fn):
    con = db.connect()
    try:
        with con:
            return fn(con)
    finally:
        con.close()


def _row(r, *json_fields):
    d = dict(r)
    for f in json_fields:
        d[f.removesuffix("_json")] = json.loads(d.pop(f))
    return d


# ---------- writes ----------
def add_event(session, kind, source, target, details, ts, outcome):
    return _run(lambda c: c.execute(
        "INSERT INTO events(ts,created_at,session,kind,source,target,outcome,details_json) VALUES(?,?,?,?,?,?,?,?)",
        (ts, _txt(ts), session, kind, str(source)[:200], str(target)[:300], outcome, _j(details))).lastrowid)


def add_alert(session, rule_id, severity, title, source, event_ids, evidence, ts):
    return _run(lambda c: c.execute(
        "INSERT INTO alerts(session,rule_id,severity,title_json,source,event_ids_json,evidence_json,ts,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (session, rule_id, severity, _j(title), str(source)[:200], _j(event_ids[-50:]), _j(evidence), ts, _txt(ts))).lastrowid)


def add_incident(alert_id, session, rule_id, category, severity, source, title, analysis, ts):
    return _run(lambda c: c.execute(
        "INSERT INTO incidents(alert_id,session,rule_id,category,severity,source,title_json,status,analysis_json,created_at,updated_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (alert_id, session, rule_id, category, severity, str(source)[:200], _j(title), "detected", _j(analysis),
         _txt(ts), _txt(ts))).lastrowid)


def set_incident_status(iid, status, ts, analysis=None):
    def go(c):
        c.execute("UPDATE incidents SET status=?, updated_at=?, mitigated_at=CASE WHEN ?='mitigated' THEN ? ELSE mitigated_at END "
                  "WHERE id=?", (status, _txt(ts), status, _txt(ts), iid))
        if analysis is not None:
            c.execute("UPDATE incidents SET analysis_json=? WHERE id=?", (_j(analysis), iid))
    _run(go)


def add_timeline(iid, stage, message, ts):
    return _run(lambda c: c.execute("INSERT INTO incident_timeline(incident_id,ts,stage,message_json) VALUES(?,?,?,?)",
                                    (iid, ts, stage, _j(message))).lastrowid)


def add_action(iid, session, action, target, result, verified, detail, ts):
    return _run(lambda c: c.execute(
        "INSERT INTO defense_actions(incident_id,session,action,target,result,verified,detail_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
        (iid, session, action, str(target)[:300], result, 1 if verified else 0, _j(detail), _txt(ts))).lastrowid)


def set_action_verified(action_id, verified):
    _run(lambda c: c.execute("UPDATE defense_actions SET verified=? WHERE id=?", (1 if verified else 0, action_id)))


def set_state(session, kind, value, incident_id, ts):
    _run(lambda c: c.execute("INSERT OR REPLACE INTO defense_state(session,kind,value,incident_id,since) VALUES(?,?,?,?,?)",
                             (session, kind, str(value)[:300], incident_id, _txt(ts))))


def has_state(session, kind, value):
    return _run(lambda c: c.execute("SELECT 1 FROM defense_state WHERE session=? AND kind=? AND value=?",
                                    (session, kind, str(value))).fetchone() is not None)


def load_state(session):
    return _run(lambda c: {(r[0], r[1]) for r in c.execute(
        "SELECT kind,value FROM defense_state WHERE session=?", (session,))})


def set_alert_status(alert_id, status):
    return _run(lambda c: c.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id)).rowcount)


def clear_session(session):
    def go(c):
        c.execute("DELETE FROM incidents WHERE session=?", (session,))      # cascades timeline + actions
        for t in ("alerts", "events", "defense_state"):
            c.execute(f"DELETE FROM {t} WHERE session=?", (session,))
    _run(go)


# ---------- reads ----------
def list_events(session=None, limit=100, after_id=0, kind=None, outcome=None, hide_probes=False):
    def go(c):
        q, a = "SELECT * FROM events WHERE id>?", [after_id]
        for col, val in (("session", session), ("kind", kind), ("outcome", outcome)):
            if val:
                q += f" AND {col}=?"; a.append(val)
        if hide_probes:
            q += " AND details_json NOT LIKE '%\"probe\": true%'"
        rows = c.execute(q + " ORDER BY id DESC LIMIT ?", a + [max(1, min(limit, 500))]).fetchall()
        return [_row(r, "details_json") for r in rows]
    return _run(go)


def list_alerts(session=None, limit=100, status=None):
    def go(c):
        q, a, w = "SELECT * FROM alerts", [], []
        if session: w.append("session=?"); a.append(session)
        if status: w.append("status=?"); a.append(status)
        rows = c.execute(q + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY id DESC LIMIT ?",
                         a + [max(1, min(limit, 500))]).fetchall()
        return [_row(r, "title_json", "event_ids_json", "evidence_json") for r in rows]
    return _run(go)


def list_incidents(session=None, limit=100, status=None):
    def go(c):
        q, a, w = "SELECT * FROM incidents", [], []
        if session: w.append("session=?"); a.append(session)
        if status: w.append("status=?"); a.append(status)
        rows = c.execute(q + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY id DESC LIMIT ?",
                         a + [max(1, min(limit, 500))]).fetchall()
        return [_row(r, "title_json", "analysis_json") for r in rows]
    return _run(go)


def get_incident(iid):
    def go(c):
        r = c.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
        if not r:
            return None
        inc = _row(r, "title_json", "analysis_json")
        inc["timeline"] = [_row(t, "message_json") for t in c.execute(
            "SELECT ts,stage,message_json FROM incident_timeline WHERE incident_id=? ORDER BY id", (iid,))]
        inc["actions"] = [_row(a, "detail_json") for a in c.execute(
            "SELECT id,action,target,result,verified,detail_json,created_at FROM defense_actions WHERE incident_id=? ORDER BY id", (iid,))]
        al = c.execute("SELECT * FROM alerts WHERE id=?", (inc["alert_id"],)).fetchone()
        inc["alert"] = _row(al, "title_json", "event_ids_json", "evidence_json") if al else None
        ids = inc["alert"]["event_ids"] if al else []
        inc["events"] = [_row(e, "details_json") for e in c.execute(
            f"SELECT * FROM events WHERE id IN ({','.join('?' * len(ids)) or 'NULL'}) ORDER BY id", ids)]
        return inc
    return _run(go)


def rule_counts():
    return _run(lambda c: {r[0]: r[1] for r in c.execute("SELECT rule_id, COUNT(*) FROM alerts GROUP BY rule_id")})


def stats(session=None):
    """Aggregates computed from stored events/alerts/incidents."""
    def go(c):
        w, a = ("WHERE session=?", [session]) if session else ("", [])
        and_ = (" AND session=?" if session else "")
        one = lambda sql, extra=(): c.execute(sql, extra).fetchone()[0]
        q = lambda table, cond="": one(f"SELECT COUNT(*) FROM {table} " + (w if not cond else (w + " AND " + cond if w else "WHERE " + cond)), a)
        by_cat = {r[0]: r[1] for r in c.execute(f"SELECT category, COUNT(*) FROM incidents {w} GROUP BY category", a)}
        sev = {r[0]: r[1] for r in c.execute(f"SELECT severity, COUNT(*) FROM alerts {w} GROUP BY severity", a)}
        return {
            "events": q("events", "details_json NOT LIKE '%\"probe\": true%'"),
            "dropped": q("events", "outcome='dropped'"),
            "alerts": q("alerts"),
            "critical_alerts": q("alerts", "severity='critical' AND status!='resolved'"),
            "incidents": q("incidents"),
            "active_incidents": q("incidents", "status IN ('detected','analyzing','responding','failed')"),
            "mitigated": q("incidents", "status IN ('mitigated','closed')"),
            "failed": q("incidents", "status='failed'"),
            "by_category": by_cat,
            "by_severity": {k: sev.get(k, 0) for k in ("low", "medium", "high", "critical")},
        }
    return _run(go)


def timeline_buckets(span_s, bucket_s, session=None, now=None):
    """Event and alert counts per time bucket (oldest first)."""
    now = now or time.time()
    start = now - span_s
    n = int(span_s // bucket_s)

    def go(c):
        out = [{"t": start + i * bucket_s, "events": 0, "alerts": 0} for i in range(n)]
        for table, key in (("events", "events"), ("alerts", "alerts")):
            q, a = f"SELECT CAST((ts-?)/? AS INTEGER) b, COUNT(*) FROM {table} WHERE ts>=?", [start, bucket_s, start]
            if session:
                q += " AND session=?"; a.append(session)
            for b, cnt in c.execute(q + " GROUP BY b", a):
                if 0 <= b < n:
                    out[b][key] = cnt
        return out
    return _run(go)


def session_counts(session):
    """Non-probe event counts for a session: total and rejected by active defenses."""
    def go(c):
        base = "SELECT COUNT(*) FROM events WHERE session=? AND details_json NOT LIKE '%\"probe\": true%'"
        return {"events": c.execute(base, (session,)).fetchone()[0],
                "blocked": c.execute(base + " AND outcome='dropped'", (session,)).fetchone()[0]}
    return _run(go)


def close_incident(iid, message):
    """Analyst closes a handled incident. Returns 'ok', 'missing' or 'active'."""
    def go(c):
        r = c.execute("SELECT status FROM incidents WHERE id=?", (iid,)).fetchone()
        if not r:
            return "missing"
        if r[0] in ("detected", "responding"):
            return "active"
        now = time.time()
        c.execute("UPDATE incidents SET status='closed', updated_at=? WHERE id=?", (_txt(now), iid))
        c.execute("INSERT INTO incident_timeline(incident_id,ts,stage,message_json) VALUES(?,?,?,?)",
                  (iid, now, "closed", _j(message)))
        return "ok"
    return _run(go)


def recent_sessions(limit=10):
    return _run(lambda c: [r[0] for r in c.execute(
        "SELECT session FROM events GROUP BY session ORDER BY MAX(id) DESC LIMIT ?", (limit,))])


def map_events(session=None, limit=300):
    """Recent events that carry an (illustrative) origin, reduced to what the map needs."""
    def go(c):
        q, a = "SELECT id,ts,session,kind,source,target,outcome,details_json FROM events WHERE details_json LIKE '%\"geo\"%'", []
        if session:
            q += " AND session=?"; a.append(session)
        rows = c.execute(q + " ORDER BY id DESC LIMIT ?", a + [max(1, min(limit, 500))]).fetchall()
        out = []
        for r in reversed(rows):
            d = json.loads(r["details_json"])
            out.append({"id": r["id"], "ts": r["ts"], "session": r["session"], "kind": r["kind"], "source": r["source"],
                        "target": r["target"], "outcome": r["outcome"], "details": {"geo": d.get("geo"), "origin": d.get("origin")}})
        return out
    return _run(go)


def top_sources(limit=5):
    """Sources the defense blocked, ranked by how many events they produced."""
    return _run(lambda c: [dict(r) for r in c.execute(
        "SELECT d.value AS source, d.session AS session, COUNT(e.id) AS events, COALESCE(SUM(e.outcome='dropped'),0) AS blocked "
        "FROM defense_state d LEFT JOIN events e ON e.source=d.value AND e.session=d.session "
        "AND e.details_json NOT LIKE '%\"probe\": true%' WHERE d.kind='source' "
        "GROUP BY d.session, d.value ORDER BY events DESC LIMIT ?", (max(1, min(limit, 20)),))])


def trends(now=None, window=3600):
    """Counts for the last window vs the window before it (events, alerts, blocked)."""
    now = now or time.time()
    probe = "details_json NOT LIKE '%\"probe\": true%'"

    def go(c):
        def two(table, cond):
            q = (f"SELECT COALESCE(SUM(ts>=?),0), COALESCE(SUM(ts<?),0) FROM {table} WHERE ts>=? AND {cond}")
            a, b = c.execute(q, (now - window, now - window, now - 2 * window)).fetchone()
            return {"now": a, "prev": b}
        return {"events": two("events", probe), "alerts": two("alerts", "1=1"), "dropped": two("events", probe + " AND outcome='dropped'")}
    return _run(go)
