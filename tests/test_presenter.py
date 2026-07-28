"""Tests for M2 presenter experience: demo profiles (validated, ORDERED selections of
existing catalog ids) and the presenter session's pacing, progress and scoreboard.

The property that matters most: a profile SELECTS triggers, it never defines them — so
the fixed-catalog guarantee is untouched — and a bad profile fails loudly at startup
rather than half-way through a demo."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(HERE, "config")


def _stub(code, out=""):
    return [sys.executable, "-c", "import sys; sys.stdout.write(%r); sys.exit(%d)" % (out, code)]


def mk_trigger(tid, cls="ns-ids", commands=None, flags=None, severity="info"):
    return sv.Trigger(
        id=tid, label=tid.upper(), cls=cls, runner="curl",
        commands=commands or [_stub(0, "200|")], flags=flags or [], severity=severity,
        threat_class="recon", expected_fire="SID 1234", talking_point="a point",
        expected_on_allow={}, expected_on_block={}, params=[], timeout=15.0,
    )


def settings_with(profiles_raw, live=False):
    return sv.Settings(raw={"enable_live_suspect_hosts": live,
                            "run": {"min_interval_s": 0, "control_host": ""},
                            "profiles": profiles_raw})


class TestProfileLoading(unittest.TestCase):
    def setUp(self):
        self.triggers = [mk_trigger("a"), mk_trigger("b"), mk_trigger("c", cls="ns-webcc")]

    def test_loads_and_preserves_declared_order(self):
        st = settings_with({"demo": {"label": "Demo", "triggers": ["c", "a", "b"]}})
        profiles = sv.load_profiles(st, self.triggers)
        self.assertEqual(profiles["demo"].trigger_ids, ["c", "a", "b"])
        by_id = {t.id: t for t in self.triggers}
        self.assertEqual([t.id for t in profiles["demo"].triggers(by_id)], ["c", "a", "b"])

    def test_absent_profiles_is_not_an_error(self):
        self.assertEqual(sv.load_profiles(sv.Settings(raw={}), self.triggers), {})

    def test_unknown_trigger_id_fails_loudly_at_load(self):
        st = settings_with({"demo": {"triggers": ["a", "ghost"]}})
        with self.assertRaises(sv.ConfigError) as ctx:
            sv.load_profiles(st, self.triggers)
        self.assertIn("ghost", str(ctx.exception))

    def test_structural_errors_are_rejected(self):
        for bad in ({"demo": {"triggers": []}},
                    {"demo": {"triggers": "a"}},
                    {"demo": {"triggers": [1, 2]}},
                    {"demo": ["a"]},
                    {"BAD NAME": {"triggers": ["a"]}}):
            with self.assertRaises(sv.ConfigError, msg=repr(bad)):
                sv.load_profiles(settings_with(bad), self.triggers)
        with self.assertRaises(sv.ConfigError):
            sv.load_profiles(sv.Settings(raw={"profiles": ["a"]}), self.triggers)

    def test_duplicate_ids_are_collapsed_keeping_first_position(self):
        st = settings_with({"demo": {"triggers": ["b", "a", "b"]}})
        self.assertEqual(sv.load_profiles(st, self.triggers)["demo"].trigger_ids, ["b", "a"])

    def test_profile_only_selects_it_never_defines_a_command(self):
        st = settings_with({"demo": {"triggers": ["a", "b"]}})
        profile = sv.load_profiles(st, self.triggers)["demo"]
        by_id = {t.id: t for t in self.triggers}
        for t in profile.triggers(by_id):
            self.assertIs(t, by_id[t.id])          # the very same catalog object
        self.assertFalse(hasattr(profile, "commands"))

    def test_signal_count_excludes_gated_triggers(self):
        triggers = [mk_trigger("a"), mk_trigger("g", flags=["hits_live_suspect_hosts"])]
        st = settings_with({"demo": {"triggers": ["a", "g"]}})
        profile = sv.load_profiles(st, triggers)["demo"]
        by_id = {t.id: t for t in triggers}
        self.assertEqual(profile.on_wire_count(by_id, st), 1)
        pub = profile.to_public(by_id, st)
        self.assertEqual(pub["gated"], ["g"])
        self.assertEqual(pub["trigger_count"], 2)


class TestShippedProfiles(unittest.TestCase):
    """The profiles shipped in settings.yaml must actually load against the catalog."""

    def test_shipped_profiles_are_valid(self):
        settings = sv.load_settings(CONFIG)
        triggers = sv.load_catalog(CONFIG, settings)
        profiles = sv.load_profiles(settings, triggers)
        self.assertTrue(profiles)
        by_id = {t.id: t for t in triggers}
        for name, profile in profiles.items():
            self.assertTrue(profile.trigger_ids, name)
            self.assertEqual(len(profile.triggers(by_id)), len(profile.trigger_ids), name)
            self.assertGreater(profile.on_wire_count(by_id, settings), 0, name)

    def test_exec_profile_stays_short(self):
        settings = sv.load_settings(CONFIG)
        triggers = sv.load_catalog(CONFIG, settings)
        profile = sv.load_profiles(settings, triggers)["exec-5min"]
        by_id = {t.id: t for t in triggers}
        self.assertLessEqual(profile.on_wire_count(by_id, settings), 12)


class TestSelection(unittest.TestCase):
    def test_profile_order_beats_catalog_order(self):
        triggers = [mk_trigger("a"), mk_trigger("b"), mk_trigger("c")]
        st = settings_with({"demo": {"triggers": ["c", "a"]}})
        profile = sv.load_profiles(st, triggers)["demo"]
        chosen = sv.select_triggers(triggers, "all", st, profile)
        self.assertEqual([t.id for t in chosen], ["c", "a"])

    def test_profile_still_skips_gated(self):
        triggers = [mk_trigger("a"), mk_trigger("g", flags=["hits_live_suspect_hosts"])]
        st = settings_with({"demo": {"triggers": ["g", "a"]}})
        profile = sv.load_profiles(st, triggers)["demo"]
        self.assertEqual([t.id for t in sv.select_triggers(triggers, "all", st, profile)],
                         ["a"])

    def test_without_a_profile_behaviour_is_unchanged(self):
        triggers = [mk_trigger("a"), mk_trigger("b")]
        st = settings_with({})
        self.assertEqual([t.id for t in sv.select_triggers(triggers, "all", st, None)],
                         ["a", "b"])


class TestPresenterSession(unittest.TestCase):
    def setUp(self):
        self.settings = sv.Settings(raw={})
        self.triggers = [
            mk_trigger("a"),
            mk_trigger("b", cls="ns-webcc"),
            mk_trigger("c", commands=[_stub(0, "200|"), _stub(0, "200|")]),
        ]
        self.session = sv.PresenterSession(self.triggers, self.settings, label="Demo")

    def test_starts_at_the_first_trigger(self):
        self.assertEqual(self.session.current.id, "a")
        self.assertEqual(self.session.progress(), (1, 3))
        self.assertFalse(self.session.done)

    def test_walks_forward_and_back_without_running_off_the_ends(self):
        self.session.back()
        self.assertEqual(self.session.current.id, "a")        # clamped at the start
        for expected in ("b", "c"):
            self.assertEqual(self.session.advance().id, expected)
        self.assertIsNone(self.session.advance())             # past the end
        self.assertTrue(self.session.done)
        self.session.advance()                                # stays done, no crash
        self.assertTrue(self.session.done)
        self.assertEqual(self.session.back().id, "c")

    def test_progress_is_one_based_and_clamped(self):
        self.session.goto(99)
        self.assertEqual(self.session.progress(), (3, 3))

    def test_planned_signals_uses_the_true_on_wire_count(self):
        self.assertEqual(self.session.planned_signals(), 4)   # 1 + 1 + 2
        self.assertEqual(self.session.fired_signals(), 0)
        self.session.record("c", sv.ALLOWED)
        self.assertEqual(self.session.fired_signals(), 2)

    def test_scoreboard_tallies_by_state_and_class(self):
        self.session.record("a", sv.ALLOWED)
        self.session.record("b", sv.BLOCKED)
        board = self.session.scoreboard()
        self.assertEqual(board["states"], {sv.ALLOWED: 1, sv.BLOCKED: 1})
        self.assertEqual(board["fired"], 2)
        self.assertEqual(board["remaining"], 1)
        self.assertEqual(board["classes"]["ns-ids"]["fired"], 1)
        self.assertEqual(board["classes"]["ns-webcc"]["states"], {sv.BLOCKED: 1})

    def test_rerunning_a_trigger_replaces_rather_than_double_counts(self):
        self.session.record("a", sv.ERROR)
        self.session.record("a", sv.ALLOWED)
        self.assertEqual(self.session.scoreboard()["states"], {sv.ALLOWED: 1})
        self.assertEqual(self.session.scoreboard()["fired"], 1)

    def test_summary_line_reports_triggers_and_signals(self):
        self.session.record("a", sv.BLOCKED)
        line = self.session.summary_line()
        self.assertIn("1/3 triggers", line)
        self.assertIn("1/4 signals", line)
        self.assertIn("1 blocked", line)

    def test_empty_session_does_not_divide_by_zero(self):
        empty = sv.PresenterSession([], self.settings)
        self.assertEqual(empty.progress(), (0, 0))
        self.assertTrue(empty.done)
        self.assertIsNone(empty.current)
        self.assertEqual(empty.planned_signals(), 0)
        self.assertIn("nothing fired yet", sv._presenter_board(empty))

    def test_board_renders_per_class_only_once_fired(self):
        self.assertIn("nothing fired yet", sv._presenter_board(self.session))
        self.session.record("a", sv.ALLOWED)
        board = sv._presenter_board(self.session)
        self.assertIn("ns-ids", board)
        self.assertNotIn("ns-webcc", board)      # not fired yet, so not claimed


class TestProfileCli(unittest.TestCase):
    def test_flags_parse(self):
        args = sv.parse_args(["--profile", "exec-5min", "--run", "all"])
        self.assertEqual(args.profile, "exec-5min")
        self.assertTrue(sv.parse_args(["--profiles"]).profiles)

    def test_profiles_listing_exits_clean(self):
        saved, sys.stdout = sys.stdout, io.StringIO()
        try:
            code = sv.main(["--config-dir", CONFIG, "--profiles"])
            printed = sys.stdout.getvalue()
        finally:
            sys.stdout = saved
        self.assertEqual(code, 0)
        self.assertIn("exec-5min", printed)
        self.assertIn("signals", printed)

    def test_profiles_listing_as_json(self):
        saved, sys.stdout = sys.stdout, io.StringIO()
        try:
            sv.main(["--config-dir", CONFIG, "--profiles", "--format", "json"])
            doc = json.loads(sys.stdout.getvalue())
        finally:
            sys.stdout = saved
        names = {p["name"] for p in doc}
        self.assertIn("swg-story", names)
        for p in doc:
            self.assertGreater(p["signals"], 0)

    def test_unknown_profile_is_a_usage_error(self):
        err, sys.stderr = sys.stderr, io.StringIO()
        try:
            code = sv.main(["--config-dir", CONFIG, "--profile", "nope", "--list"])
        finally:
            sys.stderr = err
        self.assertEqual(code, 2)

    def test_profile_scopes_the_manifest(self):
        saved, sys.stdout = sys.stdout, io.StringIO()
        try:
            code = sv.main(["--config-dir", CONFIG, "--profile", "exec-5min", "--list"])
            printed = sys.stdout.getvalue()
        finally:
            sys.stdout = saved
        self.assertEqual(code, 0)
        self.assertIn("5-minute exec demo", printed)
        self.assertIn("ns-uid", printed)
        self.assertNotIn("ns-pdfembed", printed)      # outside the profile

    def test_empty_profiles_listing_says_so(self):
        text = sv.format_profiles({}, {}, sv.Settings(raw={}))
        self.assertIn("No demo profiles are defined", text)


class TestHeadlessWithProfile(unittest.TestCase):
    def test_runs_in_profile_order_and_reports_it(self):
        triggers = [mk_trigger("a"), mk_trigger("b"), mk_trigger("c")]
        st = settings_with({"demo": {"label": "Demo Story", "triggers": ["c", "a"]}})
        profile = sv.load_profiles(st, triggers)["demo"]
        app = sv.App(st, triggers, ".")
        buf = io.StringIO()
        code = sv.run_headless(app, triggers, st, "all", "json", out=buf, profile=profile)
        self.assertEqual(code, sv.HEADLESS_OK)
        doc = json.loads(buf.getvalue())
        self.assertEqual([r["id"] for r in doc["results"]], ["c", "a"])
        self.assertEqual(doc["summary"]["demo_profile"], "demo")

    def test_text_output_names_the_profile(self):
        triggers = [mk_trigger("a")]
        st = settings_with({"demo": {"label": "Demo Story", "triggers": ["a"]}})
        profile = sv.load_profiles(st, triggers)["demo"]
        buf = io.StringIO()
        sv.run_headless(sv.App(st, triggers, "."), triggers, st, "all", "text",
                        out=buf, profile=profile)
        self.assertIn("Profile: Demo Story", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
