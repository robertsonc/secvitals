"""Tests for M4 east–west tier 1: internal segmentation probing.

Two honesty properties carry this milestone, and both are tested against real sockets
rather than mocks:

  1. A REFUSED connection (RST) means the packet ARRIVED and the host answered. It must
     read as REACHABLE. Reporting it as `blocked` would credit the firewall with work the
     host did — a false positive in the product's favour.
  2. If the target host itself does not answer, nothing can be concluded about policy.
     That is `error`, never `blocked`.
"""
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(HERE, "config")

BLACKHOLE = "192.0.2.1"          # TEST-NET-1 (RFC 5737) — never answers


def ew_trigger(tid="ew-t", target="t"):
    return sv.Trigger.from_dict(
        {"id": tid, "label": tid, "class": "ew", "runner": "ew",
         "commands": [["ew-probe", target]]}, 30.0)


def ew_settings(targets, timeout=1):
    return sv.Settings(raw={"east_west": {"probe_timeout_s": timeout, "targets": targets}})


class SocketFixture(unittest.TestCase):
    """A real listening port (SYN-ACK) and a real closed port (RST) on loopback."""

    def setUp(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.open_port = self.listener.getsockname()[1]
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.closed_port = probe.getsockname()[1]
        probe.close()

    def tearDown(self):
        self.listener.close()


class TestConnectOutcome(SocketFixture):
    def test_open_and_refused_are_distinguished(self):
        outcome, _ = sv._tcp_connect_outcome("127.0.0.1", self.open_port, 2)
        self.assertEqual(outcome, sv.EW_OPEN)                   # SYN-ACK
        outcome, _ = sv._tcp_connect_outcome("127.0.0.1", self.closed_port, 2)
        self.assertEqual(outcome, sv.EW_REFUSED)                # RST

    def test_refused_is_never_reported_as_a_drop(self):
        """The load-bearing distinction: an RST proves the packet arrived."""
        outcome, _ = sv._tcp_connect_outcome("127.0.0.1", self.closed_port, 2)
        self.assertNotEqual(outcome, sv.EW_TIMEOUT)
        self.assertEqual(outcome, sv.EW_REFUSED)

    def test_exception_to_outcome_mapping_is_exact(self):
        """Assert the mapping directly rather than trusting a sandbox's treatment of an
        unroutable address: some environments refuse TEST-NET-1 instead of dropping it,
        which would make a network-dependent test lie about what the code does.

        A no-answer TIMEOUT and a no-route ERROR must map to DIFFERENT outcomes: only the
        first is consistent with a policy drop."""
        original = socket.create_connection
        cases = [
            (socket.timeout("timed out"), sv.EW_TIMEOUT),
            (ConnectionRefusedError(111, "refused"), sv.EW_REFUSED),
            (OSError(101, "Network is unreachable"), sv.EW_UNREACHABLE),
            (OSError(113, "No route to host"), sv.EW_UNREACHABLE),
        ]
        try:
            for exc, expected in cases:
                def raiser(*a, **k, ):
                    raise exc
                socket.create_connection = raiser
                outcome, _flow = sv._tcp_connect_outcome("10.0.0.1", 445, 1)
                self.assertEqual(outcome, expected, repr(exc))
        finally:
            socket.create_connection = original
        self.assertNotEqual(sv.EW_TIMEOUT, sv.EW_UNREACHABLE)

    def test_bad_port_does_not_raise(self):
        outcome, _ = sv._tcp_connect_outcome("127.0.0.1", "not-a-port", 1)
        self.assertEqual(outcome, sv.EW_UNREACHABLE)


class TestEwProbe(SocketFixture):
    def _run(self, ports, control=None, host="127.0.0.1"):
        settings = ew_settings({"t": {"label": "T", "host": host,
                                      "control_port": control or self.open_port,
                                      "ports": ports}})
        trigger = ew_trigger()
        return sv.App(settings, [trigger], CONFIG)._run_ew(trigger), settings

    def test_rst_reads_as_reachable_not_blocked(self):
        """A closed port answered — the path is open. This is the finding that matters:
        segmentation is NOT stopping this traffic."""
        out, _ = self._run([self.closed_port])
        self.assertEqual(out["state"], sv.ALLOWED)
        self.assertEqual(out["ratio"],
                         {"blocked": 0, "reached": 1, "unreachable": 0, "total": 1})
        self.assertIn("RST", out["stdout"])
        self.assertIn("not a firewall drop", out["stdout"])

    def test_open_port_reads_as_reachable(self):
        second = socket.socket()
        second.bind(("127.0.0.1", 0))
        second.listen(1)
        try:
            out, _ = self._run([second.getsockname()[1]])
        finally:
            second.close()
        self.assertEqual(out["state"], sv.ALLOWED)
        self.assertIn("SYN-ACK", out["stdout"])

    def test_timeout_with_a_live_control_reads_as_blocked(self):
        """The control proves the host is up, so a timeout is a drop in transit."""
        settings = ew_settings({"t": {"label": "T", "host": "127.0.0.1",
                                      "control_port": self.open_port, "ports": [445]}})
        trigger = ew_trigger()
        app = sv.App(settings, [trigger], CONFIG)
        original = sv._tcp_connect_outcome
        try:
            sv._tcp_connect_outcome = lambda h, p, t: (sv.EW_TIMEOUT, sv._flow("TCP", dst_port=p))
            out = app._run_ew(trigger)
        finally:
            sv._tcp_connect_outcome = original
        self.assertEqual(out["state"], sv.BLOCKED)
        self.assertIn("dropped in transit", out["stdout"])

    def test_dead_host_is_error_never_blocked(self):
        """Without a reachable control port nothing can be concluded about policy."""
        out, _ = self._run([445], control=80, host=BLACKHOLE)
        self.assertEqual(out["state"], sv.ERROR)
        self.assertIn("not a block", out["reason"])
        self.assertIn("UNREACHABLE", out["stdout"])

    def test_mixed_result_shows_the_split(self):
        settings = ew_settings({"t": {"label": "T", "host": "127.0.0.1",
                                      "control_port": self.open_port,
                                      "ports": [self.closed_port, 445]}})
        trigger = ew_trigger()
        app = sv.App(settings, [trigger], CONFIG)
        original = sv._tcp_connect_outcome

        def fake(host, port, timeout):
            if int(port) == 445:
                return sv.EW_TIMEOUT, sv._flow("TCP", dst_port=port)     # dropped
            return sv.EW_REFUSED, sv._flow("TCP", dst_port=port)         # RST
        try:
            sv._tcp_connect_outcome = fake
            out = app._run_ew(trigger)
        finally:
            sv._tcp_connect_outcome = original
        self.assertEqual(out["ratio"],
                         {"blocked": 1, "reached": 1, "unreachable": 0, "total": 2})
        self.assertIn("mixed", out["reason"])

    def test_all_ports_unreachable_is_error_not_blocked(self):
        """No route to any port says nothing about policy, even with a live control."""
        settings = ew_settings({"t": {"label": "T", "host": "127.0.0.1",
                                      "control_port": self.open_port, "ports": [445, 3389]}})
        trigger = ew_trigger()
        app = sv.App(settings, [trigger], CONFIG)
        original = sv._tcp_connect_outcome
        try:
            sv._tcp_connect_outcome = lambda h, p, t: (sv.EW_UNREACHABLE,
                                                       sv._flow("TCP", dst_port=p))
            out = app._run_ew(trigger)
        finally:
            sv._tcp_connect_outcome = original
        self.assertEqual(out["state"], sv.ERROR)
        self.assertIn("environment problem, not a block", out["reason"])

    def test_control_probe_is_not_counted_as_a_signal(self):
        out, settings = self._run([self.closed_port])
        self.assertEqual(out["wire_requests"], 1)      # one port under test, not two


class TestTargetConfiguration(unittest.TestCase):
    def test_absent_targets_is_normal_not_an_error(self):
        self.assertEqual(sv.load_ew_targets(sv.Settings(raw={})), {})

    def test_malformed_targets_are_refused(self):
        for bad in ({"t": {"host": "", "control_port": 443, "ports": [445]}},
                    {"t": {"host": "10.0.0.1", "control_port": 0, "ports": [445]}},
                    {"t": {"host": "10.0.0.1", "control_port": 443, "ports": []}},
                    {"t": {"host": "10.0.0.1", "control_port": 443, "ports": [70000]}},
                    {"t": {"host": "10.0.0.1", "control_port": "https", "ports": [445]}},
                    {"BAD NAME": {"host": "10.0.0.1", "control_port": 443, "ports": [445]}},
                    {"t": ["not a mapping"]}):
            with self.assertRaises(sv.ConfigError, msg=repr(bad)):
                sv.load_ew_targets(ew_settings(bad))

    def test_control_port_may_not_also_be_under_test(self):
        """It is the reachability reference; testing it would make the result circular."""
        with self.assertRaises(sv.ConfigError) as ctx:
            sv.load_ew_targets(ew_settings(
                {"t": {"host": "10.0.0.1", "control_port": 445, "ports": [445, 3389]}}))
        self.assertIn("control_port", str(ctx.exception))

    def test_valid_target_loads(self):
        targets = sv.load_ew_targets(ew_settings(
            {"server-zone": {"label": "Servers", "zone": "srv", "host": "10.20.30.40",
                             "control_port": 443, "ports": [445, 3389]}}))
        target = targets["server-zone"]
        self.assertEqual(target.host, "10.20.30.40")
        self.assertEqual(target.ports, [445, 3389])
        self.assertEqual(target.to_public()["zone"], "srv")


class TestUnconfiguredIsItsOwnAnswer(unittest.TestCase):
    """"We were never told where to probe" is not gated, and not a policy result."""

    def setUp(self):
        self.trigger = ew_trigger("ew-server-zone", "server-zone")
        self.settings = sv.Settings(raw={})

    def test_unconfigured_trigger_reports_invalid_with_a_useful_reason(self):
        app = sv.App(self.settings, [self.trigger], CONFIG)
        _t, out = app.run("ew-server-zone", {})
        self.assertEqual(out["state"], sv.INVALID)
        self.assertIn("east_west.targets", out["reason"])
        self.assertIn("Not a policy result", out["reason"])

    def test_unconfigured_is_distinct_from_gated(self):
        self.assertTrue(self.trigger.unconfigured(self.settings))
        self.assertFalse(self.trigger.gated_disabled(self.settings))

    def test_unconfigured_contributes_no_signals(self):
        self.assertEqual(self.trigger.on_wire_count(self.settings), 0)

    def test_configured_trigger_is_available_again(self):
        settings = ew_settings({"server-zone": {"host": "10.0.0.1", "control_port": 443,
                                                "ports": [445, 3389]}})
        self.assertFalse(self.trigger.unconfigured(settings))
        self.assertIsNone(self.trigger.unavailable_reason(settings))
        self.assertEqual(self.trigger.on_wire_count(settings), 2)

    def test_run_all_and_selection_skip_what_cannot_run(self):
        chosen = sv.select_triggers([self.trigger], "all", self.settings)
        self.assertEqual(chosen, [])

    def test_manifest_separates_unconfigured_from_gated(self):
        settings = sv.load_settings(CONFIG)
        triggers = sv.load_catalog(CONFIG, settings)
        manifest = sv.signal_manifest(triggers, settings)
        self.assertGreaterEqual(manifest["totals"]["triggers_unconfigured"], 3)
        text = sv.format_signal_manifest(manifest)
        self.assertIn("NOT CONFIGURED HERE", text)
        self.assertIn("east_west.targets", text)
        # and an unconfigured trigger is NOT listed under the live-suspect gate
        gated_line = [ln for ln in text.splitlines() if ln.startswith("DISABLED —")][0]
        self.assertNotIn("ew-server-zone", gated_line)

    def test_enabling_the_gate_does_not_pretend_to_fix_it(self):
        """The gate-on figure must not promise signals that configuration alone unlocks."""
        settings = sv.load_settings(CONFIG)
        triggers = sv.load_catalog(CONFIG, settings)
        totals = sv.signal_manifest(triggers, settings)["totals"]
        lab = sv.Settings(raw=dict(settings.raw, enable_live_suspect_hosts=True))
        lab_totals = sv.signal_manifest(triggers, lab)["totals"]
        self.assertEqual(totals["signals_if_gate_enabled"], lab_totals["signals"])


class TestShippedEwCatalog(unittest.TestCase):
    def setUp(self):
        self.settings = sv.load_settings(CONFIG)
        self.triggers = sv.load_catalog(CONFIG, self.settings)
        self.by_id = {t.id: t for t in self.triggers}

    def test_ew_class_is_no_longer_empty(self):
        ew = [t for t in self.triggers if t.cls == "ew"]
        self.assertEqual(len(ew), 3)
        for t in ew:
            self.assertEqual(t.runner, "ew")
            self.assertTrue(t.ew_target_name(), t.id)

    def test_ew_triggers_ship_unconfigured(self):
        """Nothing ships pre-pointed at an address — the site must choose it."""
        for t in self.triggers:
            if t.cls == "ew":
                self.assertTrue(t.unconfigured(self.settings), t.id)

    def test_ew_triggers_carry_a_console_hint_and_talking_point(self):
        for t in self.triggers:
            if t.cls == "ew":
                self.assertTrue(t.talking_point, t.id)
                self.assertTrue(t.console_hint_text(), t.id)

    def test_settings_ships_an_empty_target_map_not_a_fake_one(self):
        targets = sv.load_ew_targets(self.settings)
        self.assertEqual(targets, {})


if __name__ == "__main__":
    unittest.main()


class TestAvailabilityIsConsistent(unittest.TestCase):
    """Every place that asks "can this run?" must use the same broad check.

    A trigger can be unavailable for two different reasons — gated off, or never
    configured for this site. Anywhere that still asked only `gated_disabled` would
    treat an unconfigured east-west trigger as runnable: the header would promise
    signals it cannot fire, the coverage matrix would count it as exercised-able, and
    its card would look clickable until you clicked it."""

    def setUp(self):
        self.settings = sv.load_settings(CONFIG)
        self.triggers = sv.load_catalog(CONFIG, self.settings)
        self.ew = [t for t in self.triggers if t.cls == "ew"]

    def test_the_shipped_ew_triggers_are_unavailable_but_not_gated(self):
        self.assertTrue(self.ew)
        for t in self.ew:
            self.assertTrue(t.unavailable_reason(self.settings), t.id)
            self.assertFalse(t.gated_disabled(self.settings), t.id)

    def test_header_signal_count_excludes_them(self):
        available = [t for t in self.triggers if not t.unavailable_reason(self.settings)]
        self.assertTrue(all(t.cls != "ew" for t in available))
        planned = sum(t.on_wire_count(self.settings) for t in available)
        self.assertEqual(planned, sv.signal_manifest(self.triggers, self.settings)["totals"]["signals"])

    def test_coverage_matrix_does_not_count_them_as_enabled(self):
        """M1's coverage matrix reports what COULD have been exercised; an unconfigured
        trigger could not, and saying otherwise would overstate the session."""
        ledger = sv.RunLedger(CONFIG)
        cov = ledger.coverage_matrix(self.triggers, self.settings)
        for cls, threat in ((t.cls, t.threat_class or "(unclassified)") for t in self.ew):
            cell = cov["cells"][f"{cls}|{threat}"]
            self.assertGreater(cell["catalog"], 0)
            self.assertEqual(cell["enabled"], 0, f"{cls}|{threat}")

    def test_coverage_gaps_name_the_unexercised_ew_class(self):
        ledger = sv.RunLedger(CONFIG)
        gaps = ledger.coverage_matrix(self.triggers, self.settings)["gaps"]
        self.assertTrue(any(g.startswith("ew /") for g in gaps), gaps)
