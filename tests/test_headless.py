"""Tests for headless (pre-brief) mode: trigger selection, honest reporting, and the
policy-neutral exit codes — a `blocked` trigger is the product working, never a failure."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402


def _curl_stub(code, out=""):
    """A fake 'curl': prints the -w line, exits with `code`."""
    return [sys.executable, "-c", "import sys; sys.stdout.write(%r); sys.exit(%d)" % (out, code)]


def mk_trigger(tid, cls="ns-ids", runner="curl", commands=None, flags=None):
    return sv.Trigger(
        id=tid, label=tid, cls=cls, runner=runner,
        commands=commands or [_curl_stub(0, "200|")],
        flags=flags or [], severity="info", threat_class="", expected_fire="SID 1234",
        talking_point="", expected_on_allow={}, expected_on_block={}, params=[],
        timeout=15.0,
    )


def mk_app(triggers, live=False):
    settings = sv.Settings(raw={"enable_live_suspect_hosts": live,
                                "run": {"min_interval_s": 0, "control_host": ""},
                                "evidence": {"log": False}})
    return sv.App(settings, triggers, "."), settings


class TestSelectTriggers(unittest.TestCase):
    def setUp(self):
        self.triggers = [
            mk_trigger("a"), mk_trigger("b", cls="ns-webcc"),
            mk_trigger("gated", flags=["hits_live_suspect_hosts"]),
        ]
        _, self.settings = mk_app(self.triggers)

    def test_all_skips_gated_like_the_window_does(self):
        got = sv.select_triggers(self.triggers, "all", self.settings)
        self.assertEqual([t.id for t in got], ["a", "b"])
        self.assertEqual([t.id for t in sv.select_triggers(self.triggers, None, self.settings)],
                         ["a", "b"])

    def test_all_includes_gated_when_the_gate_is_open(self):
        _, live = mk_app(self.triggers, live=True)
        self.assertEqual([t.id for t in sv.select_triggers(self.triggers, "all", live)],
                         ["a", "b", "gated"])

    def test_explicit_id_is_not_silently_skipped(self):
        # naming a gated trigger must surface its disabled state, not do nothing
        got = sv.select_triggers(self.triggers, "gated", self.settings)
        self.assertEqual([t.id for t in got], ["gated"])

    def test_selection_by_class_and_by_list(self):
        self.assertEqual([t.id for t in sv.select_triggers(self.triggers, "ns-webcc", self.settings)],
                         ["b"])
        self.assertEqual([t.id for t in sv.select_triggers(self.triggers, "b,a", self.settings)],
                         ["a", "b"])                     # catalog order, not argument order

    def test_unknown_name_raises(self):
        with self.assertRaises(ValueError):
            sv.select_triggers(self.triggers, "nope", self.settings)


class TestRunHeadless(unittest.TestCase):
    def _run(self, triggers, selector="all", fmt="text", live=False):
        app, settings = mk_app(triggers, live=live)
        buf = io.StringIO()
        code = sv.run_headless(app, triggers, settings, selector, fmt, out=buf)
        return code, buf.getvalue()

    def test_all_allowed_exits_clean(self):
        code, text = self._run([mk_trigger("a"), mk_trigger("b")])
        self.assertEqual(code, sv.HEADLESS_OK)
        self.assertIn("2 triggers", text)
        self.assertIn("allowed", text)

    def test_blocked_is_not_a_failure(self):
        """The load-bearing exit-code rule: an inline block is the product working."""
        blocked = mk_trigger("blocked", commands=[_curl_stub(28)])
        code, text = self._run([blocked])
        self.assertEqual(code, sv.HEADLESS_OK)
        self.assertIn("blocked", text)

    def test_environment_error_is_a_failure(self):
        broken = mk_trigger("broken", commands=[_curl_stub(6)])     # DNS failure
        code, text = self._run([broken])
        self.assertEqual(code, sv.HEADLESS_PROBLEM)
        self.assertIn("error", text)

    def test_named_gated_trigger_reports_invalid_and_fails(self):
        code, text = self._run([mk_trigger("g", flags=["hits_live_suspect_hosts"])], selector="g")
        self.assertEqual(code, sv.HEADLESS_PROBLEM)
        self.assertIn("invalid", text)

    def test_unknown_selector_is_a_usage_error(self):
        code, _ = self._run([mk_trigger("a")], selector="does-not-exist")
        self.assertEqual(code, sv.HEADLESS_USAGE)

    def test_empty_selection_is_a_usage_error(self):
        # every trigger gated off, so "all" selects nothing runnable
        code, _ = self._run([mk_trigger("g", flags=["hits_live_suspect_hosts"])])
        self.assertEqual(code, sv.HEADLESS_USAGE)

    def test_text_output_carries_the_verification_key(self):
        _, text = self._run([mk_trigger("a")])
        self.assertIn("verify:", text)
        self.assertIn("expect SID 1234", text)
        self.assertIn("signals planned", text)

    def test_json_output_is_one_parseable_document(self):
        code, text = self._run([mk_trigger("a"), mk_trigger("b", commands=[_curl_stub(28)])],
                               fmt="json")
        self.assertEqual(code, sv.HEADLESS_OK)
        doc = json.loads(text)
        self.assertEqual(doc["summary"]["triggers"], 2)
        self.assertEqual(doc["summary"]["signals"], 2)
        self.assertEqual(doc["summary"]["problems"], 0)
        ids = [r["id"] for r in doc["results"]]
        self.assertEqual(ids, ["a", "b"])
        states = {r["id"]: r["state"] for r in doc["results"]}
        self.assertEqual(states, {"a": sv.ALLOWED, "b": sv.BLOCKED})
        for r in doc["results"]:
            self.assertTrue(r["verify_key"])
            self.assertTrue(r["console_hint"])

    def test_signal_count_uses_the_true_on_wire_number(self):
        multi = mk_trigger("multi", commands=[_curl_stub(0, "200|"), _curl_stub(0, "200|")])
        _, text = self._run([multi], fmt="json")
        doc = json.loads(text)
        self.assertEqual(doc["summary"]["signals"], 2)
        self.assertEqual(doc["results"][0]["wire_requests"], 2)


class TestCliWiring(unittest.TestCase):
    def test_flags_parse(self):
        args = sv.parse_args(["--list"])
        self.assertTrue(args.list_triggers)
        self.assertEqual(args.format, "text")
        args = sv.parse_args(["--run", "ns-ids", "--format", "json"])
        self.assertEqual(args.run, "ns-ids")
        self.assertEqual(args.format, "json")
        self.assertTrue(sv.parse_args(["--dry-run"]).dry_run)

    def test_list_main_sends_nothing_and_exits_zero(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        orig = sv.subprocess.run

        def boom(*a, **k):
            raise AssertionError("--list must not run anything")
        sv.subprocess.run = boom
        saved, sys.stdout = sys.stdout, io.StringIO()
        try:
            code = sv.main(["--config-dir", os.path.join(here, "config"), "--list"])
            printed = sys.stdout.getvalue()
        finally:
            sys.stdout = saved
            sv.subprocess.run = orig
        self.assertEqual(code, 0)
        self.assertIn("TOTAL:", printed)

    def test_list_json_is_parseable(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        saved, sys.stdout = sys.stdout, io.StringIO()
        try:
            code = sv.main(["--config-dir", os.path.join(here, "config"),
                            "--list", "--format", "json"])
            printed = sys.stdout.getvalue()
        finally:
            sys.stdout = saved
        self.assertEqual(code, 0)
        doc = json.loads(printed)
        self.assertIn("totals", doc)
        self.assertGreater(doc["totals"]["signals"], 0)


if __name__ == "__main__":
    unittest.main()
