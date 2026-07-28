"""Tests for the known-quantity accounting: true on-wire counts, the dry-run signal
manifest (which must send NOTHING), and the pasteable verification key."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(HERE, "config")


def mk_trigger(runner="curl", commands=None, **kw):
    base = dict(
        id="t", label="t", cls="ns-ids", runner=runner,
        commands=commands or [["curl", "http://x"]],
        flags=[], severity="info", threat_class="", expected_fire="", talking_point="",
        expected_on_allow={}, expected_on_block={}, params=[], timeout=30.0,
    )
    base.update(kw)
    return sv.Trigger(**base)


class TestOnWireCount(unittest.TestCase):
    def test_curl_counts_commands(self):
        t = mk_trigger(commands=[["curl", "http://a"], ["curl", "http://b"]])
        self.assertEqual(t.on_wire_count(sv.Settings(raw={})), 2)

    def test_iprep_expands_to_the_node_sample(self):
        """The whole point: one `iprep` command puts ip_rep_sample probes on the wire,
        so counting commands under-reports it (6x at the default sample)."""
        t = mk_trigger(runner="iprep", cls="ns-iprep", commands=[["iprep"]])
        self.assertEqual(len(t.commands), 1)
        self.assertEqual(t.on_wire_count(sv.Settings(raw={})), 6)          # default sample
        s = sv.Settings(raw={"webcc": {"ip_rep_sample": 12}})
        self.assertEqual(t.on_wire_count(s), 12)

    def test_iprep_never_reports_zero(self):
        s = sv.Settings(raw={"webcc": {"ip_rep_sample": 0}})
        t = mk_trigger(runner="iprep", cls="ns-iprep", commands=[["iprep"]])
        self.assertEqual(t.on_wire_count(s), 1)

    def test_to_public_exposes_both_counts(self):
        t = mk_trigger(runner="iprep", cls="ns-iprep", commands=[["iprep"]])
        pub = t.to_public(sv.Settings(raw={}))
        self.assertEqual(pub["request_count"], 1)          # catalog commands
        self.assertEqual(pub["wire_request_count"], 6)     # what actually goes out
        self.assertIn("console_hint", pub)
        self.assertNotIn("commands", pub)                  # still never leaked


class TestConsoleHint(unittest.TestCase):
    def test_falls_back_to_the_class_default(self):
        t = mk_trigger(cls="ns-ids")
        self.assertEqual(t.console_hint_text(), sv.CLASS_CONSOLE_HINT["ns-ids"])

    def test_catalog_hint_wins(self):
        t = mk_trigger(cls="ns-ids", console_hint="Look in the Foo log")
        self.assertEqual(t.console_hint_text(), "Look in the Foo log")

    def test_every_class_has_a_default(self):
        for cls in sv.CLASSES:
            self.assertIn(cls, sv.CLASS_CONSOLE_HINT, cls)

    def test_bad_hint_rejected_at_load(self):
        base = dict(id="x", label="x", **{"class": "ns-ids"}, runner="curl",
                    commands=[["curl", "http://x"]])
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(dict(base, console_hint=5), 30.0)
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(dict(base, console_hint="x" * 301), 30.0)


class TestSignalManifest(unittest.TestCase):
    def setUp(self):
        self.settings = sv.load_settings(CONFIG)
        self.triggers = sv.load_catalog(CONFIG, self.settings)

    def test_manifest_sends_nothing(self):
        """A dry run must not touch the network — no subprocess, no socket."""
        orig_run, orig_conn, orig_sock = (sv.subprocess.run, sv.socket.create_connection,
                                          sv.socket.socket)

        def boom(*a, **k):
            raise AssertionError("the manifest must not perform any I/O")
        sv.subprocess.run = boom
        sv.socket.create_connection = boom
        sv.socket.socket = boom
        try:
            m = sv.signal_manifest(self.triggers, self.settings)
            sv.format_signal_manifest(m, verbose=True)
        finally:
            sv.subprocess.run, sv.socket.create_connection = orig_run, orig_conn
            sv.socket.socket = orig_sock
        self.assertGreater(m["totals"]["signals"], 0)

    def test_totals_match_the_catalog(self):
        m = sv.signal_manifest(self.triggers, self.settings)
        t = m["totals"]
        self.assertEqual(t["triggers_total"], len(self.triggers))
        # three buckets, not two: runnable, gated off, and never configured here
        self.assertEqual(t["triggers_enabled"] + t["triggers_gated"]
                         + t["triggers_unconfigured"], len(self.triggers))
        # enabled signals are the sum of the enabled triggers' true on-wire counts
        expected = sum(x.on_wire_count(self.settings) for x in self.triggers
                       if not x.unavailable_reason(self.settings))
        self.assertEqual(t["signals"], expected)
        # the gate-on figure counts every trigger the GATE could unlock — it must not
        # promise signals that only site configuration can unlock
        self.assertEqual(t["signals_if_gate_enabled"],
                         sum(x.on_wire_count(self.settings) for x in self.triggers
                             if not x.unconfigured(self.settings)))
        self.assertGreater(t["signals_if_gate_enabled"], t["signals"])
        self.assertEqual(m["profile"], "default")

    def test_lab_profile_enables_everything_the_gate_controls(self):
        lab = sv.Settings(raw={"enable_live_suspect_hosts": True})
        m = sv.signal_manifest(self.triggers, lab)
        self.assertEqual(m["profile"], "lab")
        self.assertEqual(m["totals"]["triggers_gated"], 0)
        # unconfigured triggers stay unavailable: a gate cannot supply a target
        self.assertEqual(m["totals"]["signals"], m["totals"]["signals_if_gate_enabled"])

    def test_iprep_counted_at_full_fan_out(self):
        lab = sv.Settings(raw={"enable_live_suspect_hosts": True})
        m = sv.signal_manifest(self.triggers, lab)
        row = next(r for r in m["triggers"] if r["id"] == "ip-rep-tor")
        self.assertEqual(row["wire_request_count"], lab.ip_rep_sample)
        self.assertGreater(row["wire_request_count"], 1)

    def test_rows_carry_destinations_and_redacted_commands(self):
        m = sv.signal_manifest(self.triggers, self.settings)
        uid = next(r for r in m["triggers"] if r["id"] == "ns-uid")
        self.assertEqual(uid["destinations"], ["testmynids.org:80"])
        self.assertEqual(uid["commands"][0][0], "curl")
        self.assertNotIn(sv.DEVNULL_TOKEN, uid["commands"][0])   # resolved, not raw
        dns = next(r for r in m["triggers"] if r["id"] == "ns-dns")
        self.assertTrue(all("@8.8.8.8:53" in d for d in dns["destinations"]))
        ssh = next(r for r in m["triggers"] if r["id"] == "ns-sshscan")
        self.assertEqual(ssh["destinations"], ["testmynids.org:22"])

    def test_text_render_states_the_total_and_the_gate(self):
        m = sv.signal_manifest(self.triggers, self.settings)
        text = sv.format_signal_manifest(m)
        self.assertIn("TOTAL: %d signals" % m["totals"]["signals"], text)
        self.assertIn("DISABLED", text)
        self.assertNotIn("$ curl", text)                        # commands only when verbose
        self.assertIn("$ curl", sv.format_signal_manifest(m, verbose=True))


class TestVerificationKey(unittest.TestCase):
    def test_key_carries_time_id_expectation_flow_and_state(self):
        t = mk_trigger(id="ns-uid", expected_fire="SID 2100498 — id check returned root")
        flow = sv._flow("TCP", "10.0.0.5", "51000", "93.184.216.34", "80", host="testmynids.org")
        key = sv.verification_key(t, sv.ALLOWED, [flow], when=0)
        self.assertIn("1970-01-01T00:00:00Z", key)
        self.assertIn("ns-uid", key)
        self.assertIn("SID 2100498", key)
        self.assertIn("10.0.0.5:51000 -> 93.184.216.34:80", key)
        self.assertIn("(testmynids.org)", key)
        self.assertIn("local:allowed", key)

    def test_unknown_endpoints_render_as_dashes_never_guesses(self):
        t = mk_trigger(id="x", expected_fire="something")
        key = sv.verification_key(t, sv.ERROR, [sv._flow("TCP")], when=0)
        self.assertIn("—:— -> —:—", key)

    def test_no_flows_still_produces_a_key(self):
        t = mk_trigger(id="x", expected_fire="")
        key = sv.verification_key(t, sv.BLOCKED, [], when=0)
        self.assertIn("x", key)
        self.assertIn("local:blocked", key)

    def test_literal_address_does_not_repeat_as_host(self):
        t = mk_trigger(id="x")
        flow = sv._flow("TCP", "10.0.0.5", "5", "1.2.3.4", "443", host="1.2.3.4")
        self.assertNotIn("(1.2.3.4)", sv.verification_key(t, sv.ALLOWED, [flow], when=0))


if __name__ == "__main__":
    unittest.main()
