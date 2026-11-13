"""Anonymous visitor isolation regression tests."""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import config

config.DB_PATH = pathlib.Path(tempfile.mkdtemp()) / "shared-default.sqlite3"
from app import create_app
from backend import db
from backend.engine import bus, core, simulator, store


class VisitorIsolationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        cls.a = cls.app.test_client()
        cls.b = cls.app.test_client()
        cls.a.get("/")
        cls.b.get("/")
        with cls.a.session_transaction() as s:
            cls.owner_a = s["visitor_id"]
        with cls.b.session_transaction() as s:
            cls.owner_b = s["visitor_id"]

    def test_each_browser_has_a_different_signed_visitor_identity(self):
        self.assertNotEqual(self.owner_a, self.owner_b)

    def test_csrf_tokens_cannot_be_reused_between_visitors(self):
        with self.a.session_transaction() as sa:
            token_a = sa["csrf_token"]
        with self.b.session_transaction() as sb:
            token_b = sb["csrf_token"]
        self.assertNotEqual(token_a, token_b)
        response = self.b.post("/api/comm/reset", json={"session": "comm-private01"},
                               headers={"X-CSRF-Token": token_a})
        self.assertEqual(response.status_code, 403)

    def test_scans_and_reports_are_not_shared(self):
        token = db.set_owner(self.owner_a)
        try:
            db.init_db()
            result = {"url": "https://example.com/", "verdict": "safe", "score": 0, "findings": []}
            db.record_scan("url", result)
            rid = db.create_report("private report", None)
            db.record_quiz({"score": 1, "total": 1, "percent": 100, "level": "test"})
            db.record_file_history("private.txt", 10, "a" * 64, None)
            self.assertIsNotNone(rid)
        finally:
            db.reset_owner(token)

        self.assertEqual(len(self.a.get("/api/scans").get_json()["scans"]), 1)
        self.assertEqual(len(self.b.get("/api/scans").get_json()["scans"]), 0)
        self.assertEqual(len(self.a.get("/api/reports").get_json()["reports"]), 1)
        self.assertEqual(len(self.b.get("/api/reports").get_json()["reports"]), 0)
        self.assertEqual(self.b.get(f"/api/reports/{rid}/pdf").status_code, 404)
        token = db.set_owner(self.owner_b)
        try:
            self.assertEqual(db.list_file_history(), [])
        finally:
            db.reset_owner(token)


    def test_soc_events_alerts_and_incidents_are_not_shared(self):
        token = db.set_owner(self.owner_a)
        try:
            core.reset_session("private-soc-test")
            results = [core.ingest("login_failed", "203.0.113.91", "admin", {},
                                   session="private-soc-test", ts=1_700_000_000 + i)
                       for i in range(5)]
            self.assertTrue(results[-1]["incidents"])
            incident_id = results[-1]["incidents"][0]
        finally:
            db.reset_owner(token)

        token = db.set_owner(self.owner_b)
        try:
            self.assertIsNone(store.get_incident(incident_id))
            self.assertEqual(store.list_events(None, 100), [])
            self.assertEqual(store.list_alerts(None, 100), [])
        finally:
            db.reset_owner(token)

    def test_event_bus_never_delivers_to_another_visitor(self):
        ta = db.set_owner(self.owner_a)
        try:
            qa = bus.subscribe()
        finally:
            db.reset_owner(ta)
        tb = db.set_owner(self.owner_b)
        try:
            bus.publish("event", {"secret": "visitor-b"})
        finally:
            db.reset_owner(tb)
        self.assertTrue(qa.empty())
        bus.unsubscribe(qa)

    def test_simulation_labs_are_distinct_per_visitor(self):
        ta = db.set_owner(self.owner_a)
        try:
            lab_a = simulator.get_lab()
        finally:
            db.reset_owner(ta)
        tb = db.set_owner(self.owner_b)
        try:
            lab_b = simulator.get_lab()
        finally:
            db.reset_owner(tb)
        self.assertIsNot(lab_a, lab_b)


if __name__ == "__main__":
    unittest.main(verbosity=2)
