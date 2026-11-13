"""Secure Communication Lab backend: detection rules, automated defense, verification and input validation."""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import config

config.DB_PATH = pathlib.Path(tempfile.mkdtemp()) / "comm.db"
from app import create_app            # noqa: E402
from backend import security           # noqa: E402
from backend.engine import store       # noqa: E402


class CommTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.c = cls.app.test_client()
        cls.H = {"X-CSRF-Token": security.CSRF_TOKEN}

    def setUp(self):
        self.s = "comm-" + self._testMethodName.replace("test_", "")[:10].replace("_", "x") + "01"
        self.c.post("/api/comm/reset", json={"session": self.s}, headers=self.H)

    def ev(self, kind, **details):
        r = self.c.post("/api/comm/event", json={"session": self.s, "kind": kind, "details": details}, headers=self.H)
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()

    def test_sensitive_cleartext_triggers_policy_and_enforcement(self):
        ok = self.ev("comm_send", encrypted=False, text="Hi, lunch at 1?")
        self.assertEqual(ok["incidents"], [])                                        # harmless text: no alert
        r = self.ev("comm_send", encrypted=False, text="my card number is 4111111111111111 and the pin is 4821")
        inc = r["incidents"][0]
        self.assertEqual((inc["rule_id"], inc["status"]), ("CR-CM-004", "mitigated"))
        self.assertTrue(all(a["verified"] for a in inc["actions"]))
        self.assertEqual(self.ev("comm_send", encrypted=False, text="hello again")["outcome"], "dropped")   # policy enforced
        self.assertEqual(self.ev("comm_send", encrypted=True)["outcome"], "allowed")                         # encrypted still flows
        stored = " ".join(str(e["details"]) for e in store.list_events(self.s, 100))
        self.assertNotIn("4111", stored)                                              # the message text is never stored

    def test_tamper_rejection_blocks_attacker(self):
        self.assertEqual(self.ev("comm_inject", attack="tamper")["outcome"], "allowed")
        r = self.ev("comm_reject", reason="bad_signature", origin="attacker", key_id="ab12cd34", seq=1)
        inc = r["incidents"][0]
        self.assertEqual((inc["rule_id"], inc["severity"], inc["status"]), ("CR-CM-001", "high", "mitigated"))
        self.assertEqual(self.ev("comm_inject", attack="replay")["outcome"], "dropped")     # attacker now blocked

    def test_replay_rotates_keys(self):
        r = self.ev("comm_reject", reason="replay", origin="attacker", key_id="deadbeef", seq=1)
        inc = r["incidents"][0]
        self.assertEqual(inc["rule_id"], "CR-CM-002")
        self.assertEqual({a["action"] for a in inc["actions"]}, {"block_source", "rotate_keys"})
        self.assertTrue(all(a["verified"] for a in inc["actions"]))

    def test_handshake_tampering_is_critical(self):
        r = self.ev("comm_reject", reason="handshake_auth", origin="attacker")
        inc = r["incidents"][0]
        self.assertEqual((inc["rule_id"], inc["severity"], inc["status"]), ("CR-CM-003", "critical", "mitigated"))

    def test_events_carry_illustrative_geo_and_show_on_map(self):
        self.ev("comm_inject", attack="tamper")
        m = store.map_events(self.s, 50)
        self.assertTrue(m and m[0]["details"]["origin"].startswith("SIM-"))

    def test_validation(self):
        bad = [{"session": "x", "kind": "comm_send", "details": {}},
               {"session": self.s, "kind": "login_failed", "details": {}},
               {"session": self.s, "kind": "comm_reject", "details": {"reason": "<script>"}},
               {"session": self.s, "kind": "comm_send", "details": {"encrypted": False, "text": "a" * 501}},
               {"session": self.s, "kind": "comm_send", "details": {"key_id": "zz"}}]
        for b in bad:
            self.assertEqual(self.c.post("/api/comm/event", json=b, headers=self.H).status_code, 400, b)
        self.assertEqual(self.c.post("/api/comm/event", json={"session": self.s, "kind": "comm_send", "details": {"encrypted": True}}).status_code, 403)  # CSRF


if __name__ == "__main__":
    unittest.main(verbosity=2)
