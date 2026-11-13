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
from backend.engine import bus, simulator


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

    def test_scans_and_reports_are_not_shared(self):
        token = db.set_owner(self.owner_a)
        try:
            db.init_db()
            result = {"url": "https://example.com/", "verdict": "safe", "score": 0, "findings": []}
            db.record_scan("url", result)
            rid = db.create_report("private report", None)
            self.assertIsNotNone(rid)
        finally:
            db.reset_owner(token)

        self.assertEqual(len(self.a.get("/api/scans").get_json()["scans"]), 1)
        self.assertEqual(len(self.b.get("/api/scans").get_json()["scans"]), 0)
        self.assertEqual(len(self.a.get("/api/reports").get_json()["reports"]), 1)
        self.assertEqual(len(self.b.get("/api/reports").get_json()["reports"]), 0)
        self.assertEqual(self.b.get(f"/api/reports/{rid}/pdf").status_code, 404)

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
