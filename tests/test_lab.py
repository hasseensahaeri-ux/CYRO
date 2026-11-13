"""Runs every simulation scenario end to end (fast mode) and checks real detection, defense and controls."""
import pathlib
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import config

config.DB_PATH = pathlib.Path(tempfile.mkdtemp()) / "lab.db"
from backend import db                               # noqa: E402
from backend.engine import core, simulator, store          # noqa: E402

# The simulator is owner-scoped; tests without a request context use the
# local-development owner through the public factory.
lab = simulator.get_lab()


def wait_done(timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        if lab.state in ("finished", "stopped"):
            return True
        time.sleep(0.1)
    return False


class LabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Keep the same local-development owner active in the test thread.
        # The simulator worker restores this owner independently because
        # ContextVars are not inherited by newly-created threads.
        cls.owner_token = db.set_owner("local-development")
        db.init_db()

    @classmethod
    def tearDownClass(cls):
        db.reset_owner(cls.owner_token)

    def tearDown(self):
        lab.reset()

    def run_scenario(self, sid):
        self.assertEqual(lab.start(sid, 4), "ok")
        self.assertTrue(wait_done(), "simulation did not finish")
        return lab.status()["result"]

    def test_brute_force(self):
        r = self.run_scenario("brute_force")
        self.assertTrue(r["detected"]); self.assertEqual(r["mitigated"], 1)
        self.assertGreater(r["blocked_attempts"], 0)
        self.assertEqual([a["source"] for a in store.list_alerts(core.scoped_session(lab.session))], [simulator.ATTACKER_1])   # Sara never flagged

    def test_port_scan(self):
        r = self.run_scenario("port_scan")
        self.assertTrue(r["detected"]); self.assertEqual(r["mitigated"], 1); self.assertGreater(r["blocked_attempts"], 0)
        self.assertEqual([a["source"] for a in store.list_alerts(lab.session)], [simulator.ATTACKER_2])

    def test_ddos(self):
        r = self.run_scenario("ddos")
        self.assertTrue(r["detected"]); self.assertEqual(r["mitigated"], 1); self.assertGreater(r["blocked_attempts"], 50)
        self.assertEqual([a["rule_id"] for a in store.list_alerts(lab.session)], ["CR-ST-002"])         # no per-bot false alerts

    def test_phishing(self):
        r = self.run_scenario("phishing")
        self.assertTrue(r["detected"]); self.assertEqual(r["failed"], 0)
        senders = {a["source"] for a in store.list_alerts(lab.session)}
        self.assertNotIn("colleague@university.edu", senders); self.assertNotIn("newsletter@library.edu", senders)
        self.assertGreaterEqual(r["blocked_attempts"], 1)                      # the post-response click was blocked

    def test_malware(self):
        r = self.run_scenario("malware")
        self.assertTrue(r["detected"]); self.assertEqual(r["incidents"].__len__(), 3); self.assertEqual(r["failed"], 0)
        self.assertGreaterEqual(r["blocked_attempts"], 2)
        names = {a["source"] for a in store.list_alerts(lab.session)}
        self.assertNotIn("meeting-notes.txt", names); self.assertNotIn("team-photo.jpg", names)

    def test_map_geo_and_top_sources(self):
        self.run_scenario("ddos")
        ev = store.map_events(core.scoped_session(lab.session), 500)
        self.assertGreater(len(ev), 100)
        attackers = {e["details"]["origin"] for e in ev if e["source"].startswith("203.0.113.")}
        self.assertTrue(all(o.startswith("SIM-") for o in attackers)); self.assertGreater(len(attackers), 4)
        legit = [e for e in ev if e["source"].startswith("198.51.100.")]
        self.assertTrue(legit and all(e["details"]["origin"] == "LOCAL" for e in legit))
        top = store.top_sources(5)
        self.assertEqual(len(top), 5); self.assertTrue(all(t["events"] > 0 for t in top))
        self.assertEqual(top, sorted(top, key=lambda t: -t["events"]))

    def test_controls(self):
        self.assertEqual(lab.start("brute_force", 0.5), "ok")
        self.assertEqual(lab.start("ddos", 1), "busy")
        time.sleep(0.6)
        self.assertTrue(lab.pause()); step = lab.step; time.sleep(1.2)
        self.assertEqual(lab.step, step); self.assertEqual(lab.state, "paused")          # really frozen
        self.assertFalse(lab.pause())
        self.assertTrue(lab.resume()); time.sleep(1.5); self.assertGreater(lab.step, step)
        self.assertTrue(lab.stop()); self.assertTrue(wait_done()); self.assertEqual(lab.state, "stopped")
        sess = lab.session
        self.assertTrue(store.session_counts(core.scoped_session(sess))["events"] > 0)
        self.assertTrue(lab.reset()); self.assertEqual(lab.state, "idle")
        self.assertEqual(store.session_counts(sess)["events"], 0)                         # reset removed the run's data


if __name__ == "__main__":
    unittest.main(verbosity=2)
