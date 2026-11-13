"""SQLite storage. All queries are parameterised. Passwords are never stored."""
import hashlib
import json
import sqlite3
import threading
from contextvars import ContextVar
from datetime import date, timedelta
from urllib.parse import urlsplit

import config

NOW = "strftime('%Y-%m-%dT%H:%M:%S','now','localtime')"

# Each anonymous browser receives a physically separate SQLite database.
_OWNER = ContextVar("cyro_visitor_owner", default=None)
_INIT_LOCK = threading.Lock()
_INITIALIZED = set()


def set_owner(owner):
    return _OWNER.set(owner)


def reset_owner(token):
    _OWNER.reset(token)


def current_owner_session():
    return _OWNER.get()


def _database_path():
    owner = _OWNER.get()
    if not owner:
        return config.DB_PATH
    digest = hashlib.sha256(owner.encode("utf-8")).hexdigest()
    return config.BASE_DIR / "data" / "visitors" / (digest + ".sqlite3")

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL CHECK(type IN ('url','phishing','file')),
  target TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK(verdict IN ('safe','suspicious','dangerous')),
  score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),
  created_at TEXT NOT NULL DEFAULT ({NOW}));
CREATE TABLE IF NOT EXISTS scan_results(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  code TEXT NOT NULL, severity TEXT NOT NULL, points INTEGER NOT NULL,
  detail_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  scan_count INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT ({NOW}));
CREATE TABLE IF NOT EXISTS report_scans(
  report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  PRIMARY KEY(report_id, scan_id));
CREATE TABLE IF NOT EXISTS quiz_results(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  score INTEGER NOT NULL, total INTEGER NOT NULL, percent INTEGER NOT NULL, level TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT ({NOW}));
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL, created_at TEXT NOT NULL,
  session TEXT NOT NULL DEFAULT 'live',
  kind TEXT NOT NULL, source TEXT NOT NULL, target TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL DEFAULT 'allowed' CHECK(outcome IN ('allowed','dropped')),
  details_json TEXT NOT NULL DEFAULT '{{}}');
CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session, ts);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session TEXT NOT NULL, rule_id TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
  title_json TEXT NOT NULL, source TEXT NOT NULL,
  event_ids_json TEXT NOT NULL DEFAULT '[]', evidence_json TEXT NOT NULL DEFAULT '{{}}',
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','acknowledged','resolved')),
  ts REAL NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session, ts);
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER NOT NULL REFERENCES alerts(id),
  session TEXT NOT NULL, rule_id TEXT NOT NULL, category TEXT NOT NULL,
  severity TEXT NOT NULL, source TEXT NOT NULL, title_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('detected','analyzing','responding','mitigated','failed','closed')),
  analysis_json TEXT NOT NULL DEFAULT '{{}}',
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, mitigated_at TEXT);
CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session, status);
CREATE TABLE IF NOT EXISTS incident_timeline(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  ts REAL NOT NULL, stage TEXT NOT NULL, message_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS defense_actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  session TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
  result TEXT NOT NULL CHECK(result IN ('applied','failed')),
  verified INTEGER NOT NULL DEFAULT 0, detail_json TEXT NOT NULL DEFAULT '{{}}',
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS defense_state(
  session TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
  incident_id INTEGER, since TEXT NOT NULL,
  PRIMARY KEY(session, kind, value));
CREATE TABLE IF NOT EXISTS file_history(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL, modified_at TEXT,
  status TEXT NOT NULL CHECK(status IN ('new','unchanged','changed')),
  previous_sha256 TEXT,
  checked_at TEXT NOT NULL DEFAULT ({NOW}));
CREATE INDEX IF NOT EXISTS idx_fh_name ON file_history(name, id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_results_scan ON scan_results(scan_id);
"""


def _connect_raw():
    """Open SQLite without triggering schema initialization (used only by init_db)."""
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def connect():
    # Every consumer gets a fully initialized owner-scoped database, including
    # background workers and code paths that do not pass through Flask startup.
    init_db()
    return _connect_raw()


def init_db():
    path = _database_path()
    if path in _INITIALIZED:
        return
    with _INIT_LOCK:
        if path in _INITIALIZED:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        con = _connect_raw()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.executescript(SCHEMA)
            con.commit()
            _INITIALIZED.add(path)
        finally:
            con.close()


def safe_target(kind, result):
    """Privacy: URLs lose query/fragment, messages are stored as a length only."""
    if kind == "url":
        p = urlsplit(result["url"])
        return (p.scheme + "://" + p.netloc + p.path)[:200]
    if kind == "phishing":
        return str(result["chars"])
    return result["name"][:120]


def record_scan(kind, result):
    con = connect()
    try:
        with con:
            cur = con.execute("INSERT INTO scans(type,target,verdict,score) VALUES(?,?,?,?)",
                              (kind, safe_target(kind, result), result["verdict"], result["score"]))
            sid = cur.lastrowid
            con.executemany("INSERT INTO scan_results(scan_id,code,severity,points,detail_json) VALUES(?,?,?,?,?)",
                            [(sid, f["code"], f["severity"], f["points"], json.dumps(f, ensure_ascii=False))
                             for f in result["findings"]])
        return sid
    finally:
        con.close()


def record_quiz(r):
    con = connect()
    try:
        with con:
            con.execute("INSERT INTO quiz_results(score,total,percent,level) VALUES(?,?,?,?)",
                        (r["score"], r["total"], r["percent"], r["level"]))
    finally:
        con.close()


def _rows(con, sql, args=()):
    return [dict(r) for r in con.execute(sql, args).fetchall()]


def stats():
    con = connect()
    try:
        one = lambda sql, a=(): con.execute(sql, a).fetchone()[0]
        last = _rows(con, "SELECT verdict FROM scans ORDER BY id DESC LIMIT 50")
        protection = round(100 * sum(r["verdict"] == "safe" for r in last) / len(last)) if last else None
        days = [(date.today() - timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
        counts = dict(con.execute("SELECT date(created_at), COUNT(*) FROM scans WHERE date(created_at)>=? GROUP BY 1",
                                  (days[0],)).fetchall())
        return {
            "total_scans": one("SELECT COUNT(*) FROM scans"),
            "threats": one("SELECT COUNT(*) FROM scans WHERE verdict='dangerous'"),
            "suspicious_urls": one("SELECT COUNT(*) FROM scans WHERE type='url' AND verdict!='safe'"),
            "files_analyzed": one("SELECT COUNT(*) FROM scans WHERE type='file'"),
            "protection": protection,
            "activity": [{"day": d, "count": counts.get(d, 0)} for d in days],
            "recent": _rows(con, "SELECT type,target,verdict,created_at AS time FROM scans ORDER BY id DESC LIMIT 8"),
            "alerts": [{"level": "danger" if r["verdict"] == "dangerous" else "warn", "type": r["type"],
                        "target": r["target"], "time": r["time"]}
                       for r in _rows(con, "SELECT type,target,verdict,created_at AS time FROM scans "
                                           "WHERE verdict!='safe' ORDER BY id DESC LIMIT 8")],
        }
    finally:
        con.close()


def list_scans(limit=50):
    con = connect()
    try:
        return _rows(con, "SELECT id,type,target,verdict,score,created_at FROM scans ORDER BY id DESC LIMIT ?",
                     (max(1, min(int(limit), 500)),))
    finally:
        con.close()


def create_report(title, limit):
    """Snapshot the latest `limit` scans (None = all) into a report."""
    con = connect()
    try:
        with con:
            sql = "SELECT id FROM scans ORDER BY id DESC" + (" LIMIT ?" if limit else "")
            ids = [r[0] for r in con.execute(sql, (limit,) if limit else ()).fetchall()]
            if not ids:
                return None
            rid = con.execute("INSERT INTO reports(title,scan_count) VALUES(?,?)", (title, len(ids))).lastrowid
            con.executemany("INSERT INTO report_scans(report_id,scan_id) VALUES(?,?)", [(rid, i) for i in ids])
        return rid
    finally:
        con.close()


def list_reports():
    con = connect()
    try:
        return _rows(con, "SELECT id,title,scan_count,created_at FROM reports ORDER BY id DESC LIMIT 100")
    finally:
        con.close()


def get_report(rid):
    con = connect()
    try:
        rep = con.execute("SELECT id,title,scan_count,created_at FROM reports WHERE id=?", (rid,)).fetchone()
        if not rep:
            return None
        scans = _rows(con, "SELECT s.id,s.type,s.target,s.verdict,s.score,s.created_at FROM scans s "
                           "JOIN report_scans rs ON rs.scan_id=s.id WHERE rs.report_id=? ORDER BY s.id DESC", (rid,))
        for s in scans:
            s["findings"] = [json.loads(r[0]) for r in con.execute(
                "SELECT detail_json FROM scan_results WHERE scan_id=? ORDER BY points DESC", (s["id"],))]
        quiz = con.execute("SELECT COUNT(*), MAX(percent), "
                           "(SELECT percent FROM quiz_results ORDER BY id DESC LIMIT 1) FROM quiz_results").fetchone()
        return {"report": dict(rep), "scans": scans,
                "quiz": {"attempts": quiz[0], "best": quiz[1], "latest": quiz[2]}}
    finally:
        con.close()


def record_file_history(name, size, sha256, modified_ms):
    """Log a file check and compare with the previous check of the same file name."""
    from datetime import datetime
    mod = None
    if isinstance(modified_ms, int) and 0 < modified_ms < 4_102_444_800_000:
        mod = datetime.fromtimestamp(modified_ms / 1000).strftime("%Y-%m-%dT%H:%M:%S")
    con = connect()
    try:
        with con:
            prev = con.execute("SELECT sha256 FROM file_history WHERE name=? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
            status = "new" if not prev else "unchanged" if prev[0] == sha256 else "changed"
            con.execute("INSERT INTO file_history(name,size,sha256,modified_at,status,previous_sha256) VALUES(?,?,?,?,?,?)",
                        (name, size, sha256, mod, status, prev[0] if prev and status == "changed" else None))
        return {"status": status, "modified_at": mod, "previous_sha256": prev[0] if prev and status == "changed" else None}
    finally:
        con.close()


def list_file_history(limit=30):
    con = connect()
    try:
        return _rows(con, "SELECT id,name,size,sha256,modified_at,status,previous_sha256,checked_at FROM file_history "
                          "ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 200)),))
    finally:
        con.close()
