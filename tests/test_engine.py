"""Engine tests. Synthetic events are used ONLY here to verify the rules; they never appear as real results."""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import config

config.DB_PATH = pathlib.Path(tempfile.mkdtemp()) / "test.db"
from backend import db                               # noqa: E402
from backend.engine import core, rules, store        # noqa: E402
from backend.scanners import file_check               # noqa: E402

T0 = 1_000_000.0


class EngineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        db.init_db()

    def setUp(self):
        self.s = f"t{self._testMethodName[:20]}"
        core.reset_session(self.s)

    def feed(self, kind, source, target="svc", details=None, ts=T0):
        return core.ingest(kind, source, target, details or {}, session=self.s, ts=ts)

    def incidents(self):
        return store.list_incidents(self.s)

    def test_bruteforce_detected_blocked_and_verified(self):
        res = [self.feed("login_failed", "10.9.0.5", "admin", ts=T0 + i) for i in range(6)]
        self.assertEqual([len(r["incidents"]) for r in res], [0, 0, 0, 0, 1, 0])   # fired once, on the 5th
        self.assertEqual(res[5]["outcome"], "dropped")                              # 6th attempt rejected
        inc = store.get_incident(res[4]["incidents"][0])
        self.assertEqual(inc["status"], "mitigated")
        self.assertEqual({a["action"] for a in inc["actions"]}, {"block_source", "lock_account"})
        self.assertTrue(all(a["verified"] for a in inc["actions"]))
        self.assertEqual([t["stage"] for t in inc["timeline"]][:4], ["detection", "analysis", "incident", "response"])
        self.assertEqual(inc["timeline"][-1]["stage"], "report")
        self.assertEqual(self.feed("login_failed", "other", "admin", ts=T0 + 9)["outcome"], "dropped")  # locked account

    def test_slow_or_few_attempts_do_not_alert(self):
        for i in range(4):
            self.feed("login_failed", "10.9.0.6", "bob", ts=T0 + i)
        for i in range(10):                      # one attempt every 30 s never reaches 5 in 60 s
            self.feed("login_failed", "10.9.0.7", "bob", ts=T0 + i * 30)
        self.assertEqual(self.incidents(), [])

    def test_port_scan(self):
        r = [self.feed("conn_attempt", "10.9.0.8", "srv", {"port": p}, ts=T0 + i * 0.2) for i, p in enumerate(range(20, 30))]
        self.assertEqual(sum(len(x["incidents"]) for x in r), 1)
        self.assertEqual(self.incidents()[0]["status"], "mitigated")
        for i in range(30):                      # same port repeatedly is not a scan
            self.feed("conn_attempt", "10.9.0.9", "srv", {"port": 443}, ts=T0 + i * 0.1)
        self.assertEqual(len(self.incidents()), 1)

    def test_rate_and_ddos(self):
        for i in range(101):
            self.feed("request", "10.9.1.1", "web", {"bytes": 1000}, ts=T0 + i * 0.05)
        self.assertEqual([i["rule_id"] for i in self.incidents()], ["CR-ST-001"])
        for i in range(130):                     # 12 sources, low individual rate
            self.feed("request", f"10.9.2.{i % 12}", "api", {"bytes": 500}, ts=T0 + 100 + i * 0.03)
        inc = [i for i in self.incidents() if i["rule_id"] == "CR-ST-002"][0]
        full = store.get_incident(inc["id"])
        self.assertEqual(inc["severity"], "critical")
        self.assertEqual(len([a for a in full["actions"] if a["action"] == "block_source"]), 12)
        self.assertEqual(full["status"], "mitigated")

    def test_phishing_message(self):
        ok = self.feed("message", "friend@mail.com", "m", {"text": "Hi Sara, lunch tomorrow at 1pm?"})
        bad = self.feed("message", "support@paypa1-secure.top", "m", {
            "text": "URGENT: your account is suspended. Verify your password now http://paypal.com.secure-login.top/verify"})
        self.assertEqual(ok["incidents"], [])
        self.assertEqual(len(bad["incidents"]), 1)
        inc = store.get_incident(bad["incidents"][0])
        self.assertEqual(inc["status"], "mitigated")
        self.assertIn("quarantine_message", {a["action"] for a in inc["actions"]})
        self.assertEqual(self.feed("url_click", "u", "paypal.com.secure-login.top")["outcome"], "dropped")

    def test_malware_indicators(self):
        def file_event(name, data):
            r = file_check.analyze_bytes(name, data)
            return self.feed("file", name, name, {"name": name, "size": r["size"], "sha256": r["sha256"],
                                                  "codes": [f["code"] for f in r["findings"] if f["points"] > 0],
                                                  "eicar": r["eicar"]})
        self.assertEqual(file_event("report.pdf", b"%PDF-1.4 hello")["incidents"], [])
        self.assertEqual(len(file_event("invoice.pdf.exe", b"MZ" + b"\0" * 40)["incidents"]), 1)
        self.assertEqual(len(file_event("test.txt", b"X5O!P%@AP-EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")["incidents"]), 1)
        sev = {i["severity"] for i in self.incidents()}
        self.assertEqual(sev, {"high", "medium"})
        ioc = file_event("sample.bin", b"CYRO-SIM-SAMPLE-1")
        self.assertEqual(store.get_incident(ioc["incidents"][0])["severity"], "critical")
        h = list(rules.TEST_IOC_HASHES)[0]
        self.assertEqual(self.feed("file_open", "u", "x", {"sha256": h})["outcome"], "dropped")

    def test_stats_exclude_probes_and_reset(self):
        for i in range(5):
            self.feed("login_failed", "10.9.3.3", "root", ts=T0 + i)
        st = store.stats(self.s)
        self.assertEqual((st["events"], st["alerts"], st["incidents"], st["mitigated"]), (5, 1, 1, 1))
        self.assertGreaterEqual(st["dropped"], 2)             # verification probes were rejected
        core.reset_session(self.s)
        self.assertEqual(store.stats(self.s)["events"], 0)
        self.assertEqual(self.feed("login_failed", "10.9.3.3", "root")["outcome"], "allowed")   # firewall state cleared

    def test_trends_compare_hours(self):
        for i in range(5):
            self.feed("login_failed", "10.9.4.4", "root", ts=T0 + i)             # fires one alert
        for i in range(3):
            self.feed("login_failed", "10.9.4.5", "bob", ts=T0 - 3600 + i)       # previous hour
        tr = store.trends(now=T0 + 100)
        self.assertGreaterEqual(tr["events"]["now"], 5); self.assertGreaterEqual(tr["events"]["prev"], 3)
        self.assertGreaterEqual(tr["alerts"]["now"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
