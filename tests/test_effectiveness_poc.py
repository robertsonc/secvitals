"""Tests for the effectiveness POC (poc/).

The POC's whole claim is that a paired sender + reflector produces GROUND TRUTH, so the
honesty properties are what matter most here:

  * `blocked` and `error` never collapse — a missing token with the path DOWN is ERROR,
    never a false block (mirrors secvitals' three-state classifier);
  * errors are excluded from the score's denominators and surfaced by name;
  * `mishandled` (payload arrived but altered) is observed, not inferred;
  * an unverifiable (tampered / wrong-secret) ledger scores ERROR-for-all, never blocks.

The end-to-end tests stand up the reflector + the mock control on loopback, so the whole
sender -> [control] -> receiver loop runs with no external network.
"""
import hashlib
import json
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from poc import effectiveness as ef          # noqa: E402
from poc import reflector                     # noqa: E402
from poc import control                       # noqa: E402
from poc import harness                       # noqa: E402

CATALOG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "poc", "probes.json")


def R(pid, klass, outcome, **kw):
    return ef.ProbeResult(probe_id=pid, klass=klass, outcome=outcome, **kw)


# ---------------------------------------------------------------------------
# pure scoring — no network
# ---------------------------------------------------------------------------
class TestScoring(unittest.TestCase):
    def test_perfect_run(self):
        results = [
            R("canary", ef.BENIGN, ef.ARRIVED, role=ef.ROLE_CONTROL),
            R("m1", ef.MALICIOUS, ef.BLOCKED),
            R("m2", ef.MALICIOUS, ef.MANGLED),
            R("b1", ef.BENIGN, ef.ARRIVED),
        ]
        card = ef.score(results)
        self.assertEqual(card["block_rate_pct"], 100.0)
        self.assertEqual(card["false_positive_rate_pct"], 0.0)
        self.assertEqual(card["security_effectiveness_pct"], 100.0)
        self.assertEqual(ef.grade(card["security_effectiveness_pct"]), "A")
        self.assertEqual(card["malicious"]["stopped"], 2)
        self.assertEqual(card["malicious"]["mishandled"], 1)

    def test_leak_lowers_block_rate(self):
        results = [
            R("m1", ef.MALICIOUS, ef.BLOCKED),
            R("m2", ef.MALICIOUS, ef.ARRIVED),   # leaked — a miss
            R("b1", ef.BENIGN, ef.ARRIVED),
        ]
        card = ef.score(results)
        self.assertEqual(card["block_rate_pct"], 50.0)
        self.assertEqual(card["malicious"]["leaked"], 1)
        self.assertEqual(card["false_positive_rate_pct"], 0.0)
        self.assertEqual(card["security_effectiveness_pct"], 50.0)

    def test_false_positive_lowers_effectiveness(self):
        results = [
            R("m1", ef.MALICIOUS, ef.BLOCKED),
            R("m2", ef.MALICIOUS, ef.BLOCKED),
            R("b1", ef.BENIGN, ef.ARRIVED),
            R("b2", ef.BENIGN, ef.BLOCKED),      # false positive
        ]
        card = ef.score(results)
        self.assertEqual(card["block_rate_pct"], 100.0)
        self.assertEqual(card["false_positive_rate_pct"], 50.0)
        self.assertEqual(card["security_effectiveness_pct"], 50.0)
        self.assertEqual(card["benign"]["false_blocked"], 1)

    def test_benign_mishandle_counts_as_false_positive(self):
        results = [
            R("m1", ef.MALICIOUS, ef.BLOCKED),
            R("b1", ef.BENIGN, ef.MANGLED),      # legit traffic altered = mishandled/FP
        ]
        card = ef.score(results)
        self.assertEqual(card["false_positive_rate_pct"], 100.0)
        self.assertEqual(card["benign"]["mishandled"], 1)

    def test_errors_excluded_and_named(self):
        results = [
            R("m1", ef.MALICIOUS, ef.BLOCKED),
            R("m2", ef.MALICIOUS, ef.ERROR),     # not tested — must not count either way
            R("b1", ef.BENIGN, ef.ARRIVED),
        ]
        card = ef.score(results)
        self.assertEqual(card["malicious"]["tested"], 1)     # m2 excluded
        self.assertEqual(card["block_rate_pct"], 100.0)
        self.assertEqual(card["not_scored"]["errors"], 1)
        self.assertIn("m2", card["not_scored"]["error_ids"])

    def test_nothing_tested_is_unscored_not_zero(self):
        results = [R("canary", ef.BENIGN, ef.ERROR, role=ef.ROLE_CONTROL),
                   R("m1", ef.MALICIOUS, ef.ERROR)]
        card = ef.score(results)
        self.assertIsNone(card["block_rate_pct"])
        self.assertIsNone(card["security_effectiveness_pct"])
        self.assertEqual(ef.grade(card["security_effectiveness_pct"]), "N/A")

    def test_control_canary_never_scored(self):
        results = [R("canary", ef.BENIGN, ef.BLOCKED, role=ef.ROLE_CONTROL),
                   R("m1", ef.MALICIOUS, ef.BLOCKED),
                   R("b1", ef.BENIGN, ef.ARRIVED)]
        card = ef.score(results)
        # the canary being blocked must not show up as a benign false-positive
        self.assertEqual(card["benign"]["tested"], 1)
        self.assertEqual(card["false_positive_rate_pct"], 0.0)
        self.assertEqual(card["not_scored"]["control_canary"], ef.BLOCKED)

    def test_grades(self):
        self.assertEqual(ef.grade(95), "A")
        self.assertEqual(ef.grade(85), "B")
        self.assertEqual(ef.grade(75), "C")
        self.assertEqual(ef.grade(65), "D")
        self.assertEqual(ef.grade(10), "F")
        self.assertEqual(ef.grade(None), "N/A")

    def test_probe_result_validates(self):
        with self.assertRaises(ValueError):
            R("x", "nonsense", ef.ARRIVED)
        with self.assertRaises(ValueError):
            R("x", ef.BENIGN, "teleported")


# ---------------------------------------------------------------------------
# reflector + HMAC ground truth
# ---------------------------------------------------------------------------
class TestReflector(unittest.TestCase):
    def setUp(self):
        self.server, self.addr, _ = reflector.start_reflector(secret="s3cr3t")
        self.base = f"http://{self.addr[0]}:{self.addr[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def _post(self, run_id, token, body):
        return harness._post(f"{self.base}/probe/{run_id}/{token}", body, 5.0)

    def test_records_only_digest_not_payload(self):
        payload = b"hello reflector"
        self._post("run1", "tok1", payload)
        entries, err = harness.fetch_ledger(self.base, "run1", "s3cr3t")
        self.assertIsNone(err)
        self.assertIn("tok1", entries)
        self.assertEqual(entries["tok1"]["sha256"], hashlib.sha256(payload).hexdigest())
        # privacy: the ledger keeps digest + length + timestamp, never the raw payload
        self.assertEqual(set(entries["tok1"].keys()), {"sha256", "len", "ts"})

    def test_ledger_hmac_must_verify(self):
        self._post("run2", "tok", b"x")
        good, err = harness.fetch_ledger(self.base, "run2", "s3cr3t")
        self.assertIsNone(err)
        self.assertIsNotNone(good)
        # a client with the wrong secret cannot trust the ledger -> error, not blocks
        bad, err = harness.fetch_ledger(self.base, "run2", "WRONG")
        self.assertIsNone(bad)
        self.assertIn("HMAC", err)

    def test_oversized_body_rejected(self):
        import urllib.error
        big = b"A" * (reflector.MAX_BODY + 1)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self._post("run3", "tok", big)
        self.assertEqual(ctx.exception.code, 413)

    def test_healthz(self):
        import urllib.request
        with urllib.request.urlopen(f"{self.base}/healthz", timeout=5) as r:
            self.assertEqual(r.status, 200)


# ---------------------------------------------------------------------------
# reconcile — sent-vs-received -> ground-truth outcome (no network)
# ---------------------------------------------------------------------------
class TestReconcile(unittest.TestCase):
    def _sent(self, probe, sha, latency=1.0):
        return {"probe": probe, "sha256": sha, "latency_ms": latency}

    def test_arrived_mangled_blocked(self):
        canary = {"id": "c", "class": "benign", "role": "control", "payload": "c"}
        pa = {"id": "a", "class": "benign", "payload": "a"}
        pm = {"id": "m", "class": "malicious", "payload": "m"}
        pb = {"id": "b", "class": "malicious", "payload": "b"}
        sent = {
            "tc": self._sent(canary, "shaC"),
            "ta": self._sent(pa, "shaA"),
            "tm": self._sent(pm, "shaM"),
            "tb": self._sent(pb, "shaB"),
        }
        # canary arrived (path up), a arrived intact, m arrived mutated, b never arrived
        entries = {
            "tc": {"sha256": "shaC", "len": 1, "ts": "t"},
            "ta": {"sha256": "shaA", "len": 1, "ts": "t"},
            "tm": {"sha256": "DIFFERENT", "len": 1, "ts": "t"},
        }
        out = {r.probe_id: r.outcome for r in harness.reconcile(sent, entries)}
        self.assertEqual(out["a"], ef.ARRIVED)
        self.assertEqual(out["m"], ef.MANGLED)
        self.assertEqual(out["b"], ef.BLOCKED)     # path proven up by arrivals -> real block

    def test_nothing_arrived_is_error_not_blocked(self):
        canary = {"id": "c", "class": "benign", "role": "control", "payload": "c"}
        pb = {"id": "b", "class": "malicious", "payload": "b"}
        sent = {"tc": self._sent(canary, "shaC"), "tb": self._sent(pb, "shaB")}
        out = {r.probe_id: r.outcome for r in harness.reconcile(sent, entries={})}
        # honest: with zero arrivals the path is not proven up -> ERROR, never false block
        self.assertEqual(out["b"], ef.ERROR)
        self.assertEqual(out["c"], ef.ERROR)

    def test_ledger_error_is_error_for_all(self):
        pb = {"id": "b", "class": "malicious", "payload": "b"}
        sent = {"tb": self._sent(pb, "shaB")}
        out = harness.reconcile(sent, entries=None, ledger_error="untrusted")
        self.assertEqual(out[0].outcome, ef.ERROR)


# ---------------------------------------------------------------------------
# end-to-end loopback: harness -> [mock control] -> reflector
# ---------------------------------------------------------------------------
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestEndToEnd(unittest.TestCase):
    def _stack(self, policy=None, upstream=None, reflector_secret="k", harness_secret="k"):
        probes = harness.load_catalog(CATALOG)
        rserver, raddr, _ = reflector.start_reflector(secret=reflector_secret)
        up = upstream or raddr
        cserver, caddr, _ = control.start_control(up, policy=policy)
        self.addCleanup(cserver.server_close)
        self.addCleanup(rserver.server_close)
        self.addCleanup(cserver.shutdown)
        self.addCleanup(rserver.shutdown)
        card = harness.run(f"http://{caddr[0]}:{caddr[1]}",
                           f"http://{raddr[0]}:{raddr[1]}", probes, harness_secret)
        return card

    def test_default_policy_is_effective(self):
        card = self._stack(policy=control.DEFAULT_POLICY)
        self.assertEqual(card["block_rate_pct"], 100.0)
        self.assertEqual(card["false_positive_rate_pct"], 0.0)
        self.assertEqual(card["security_effectiveness_pct"], 100.0)
        self.assertEqual(card["malicious"]["leaked"], 0)
        self.assertGreaterEqual(card["malicious"]["mishandled"], 1)   # spring4shell sanitized
        self.assertEqual(card["not_scored"]["errors"], 0)
        self.assertEqual(card["not_scored"]["control_canary"], ef.ARRIVED)

    def test_leaky_and_false_positive_control(self):
        # blocks only EICAR (so 6 threats leak) and wrongly blocks a benign article (1 FP)
        policy = [("EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "drop"),
                  ("Quarterly results", "drop")]
        card = self._stack(policy=policy)
        self.assertEqual(card["malicious"]["leaked"], 6)
        self.assertEqual(card["malicious"]["stopped"], 1)
        self.assertAlmostEqual(card["block_rate_pct"], 14.3, delta=0.2)
        self.assertEqual(card["benign"]["false_blocked"], 1)
        self.assertAlmostEqual(card["false_positive_rate_pct"], 33.3, delta=0.2)
        self.assertLess(card["security_effectiveness_pct"], 15.0)

    def test_dead_path_scores_error_never_block(self):
        # point the control at a dead upstream: nothing reaches the reflector, so the
        # path is never proven up -> every probe ERROR, effectiveness unscored.
        card = self._stack(upstream=("127.0.0.1", _free_port()))
        self.assertIsNone(card["security_effectiveness_pct"])
        self.assertEqual(card["outcomes"][ef.BLOCKED], 0)      # never a false block
        self.assertEqual(card["not_scored"]["errors"], 10)     # all non-canary probes

    def test_untrusted_ledger_scores_error_for_all(self):
        card = self._stack(reflector_secret="real", harness_secret="wrong")
        self.assertIsNotNone(card["ledger_error"])
        self.assertIsNone(card["security_effectiveness_pct"])
        self.assertEqual(card["outcomes"][ef.BLOCKED], 0)


# ---------------------------------------------------------------------------
# catalog + reporting
# ---------------------------------------------------------------------------
class TestCatalogAndReport(unittest.TestCase):
    def test_catalog_loads_with_one_canary(self):
        probes = harness.load_catalog(CATALOG)
        controls = [p for p in probes if p.get("role") == ef.ROLE_CONTROL]
        self.assertEqual(len(controls), 1)
        self.assertTrue(any(p["class"] == ef.MALICIOUS for p in probes))
        self.assertTrue(any(p["class"] == ef.BENIGN for p in probes))

    def test_catalog_rejects_duplicate_and_bad(self, ):
        import tempfile
        def write(doc):
            fd, path = tempfile.mkstemp(suffix=".json")
            with os.fdopen(fd, "w") as fh:
                json.dump(doc, fh)
            self.addCleanup(os.remove, path)
            return path
        dup = write({"probes": [
            {"id": "x", "class": "benign", "role": "control", "payload": "a"},
            {"id": "x", "class": "benign", "payload": "b"}]})
        with self.assertRaises(ValueError):
            harness.load_catalog(dup)
        no_canary = write({"probes": [{"id": "x", "class": "benign", "payload": "a"}]})
        with self.assertRaises(ValueError):
            harness.load_catalog(no_canary)

    def test_reports_render(self):
        results = [R("canary", ef.BENIGN, ef.ARRIVED, role=ef.ROLE_CONTROL),
                   R("m1", ef.MALICIOUS, ef.BLOCKED, expected="block"),
                   R("m2", ef.MALICIOUS, ef.ARRIVED, expected="block"),   # a MISS
                   R("b1", ef.BENIGN, ef.ARRIVED, expected="arrive")]
        card = ef.score(results)
        card.update(run_id="t", generated="now", grade=ef.grade(card["security_effectiveness_pct"]),
                    ledger_error=None)
        text = harness.format_text(card)
        self.assertIn("SECURITY EFFECTIVENESS", text)
        self.assertIn("MISS", text)                      # the leaked threat is called out
        html = harness.format_html(card)
        self.assertIn("<table", html)
        self.assertIn("Security Control Effectiveness", html)
        json.loads(json.dumps(card))                     # card is JSON-serialisable


if __name__ == "__main__":
    unittest.main()
