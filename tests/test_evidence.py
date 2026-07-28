"""Tests for M1 run evidence: the hash-chained ledger, the expected/observed/confirmed
scorecard, the policy-coverage matrix, the exports, and the local evidence log.

The load-bearing properties here are honesty properties: the chain must detect tampering
with an observation, the presenter's attestation must stay OUTSIDE the chain and must
never overwrite what the host observed, and nothing may leave the machine."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(HERE, "config")


def _stub(code, out=""):
    return [sys.executable, "-c", "import sys; sys.stdout.write(%r); sys.exit(%d)" % (out, code)]


def mk_trigger(tid, cls="ns-ids", commands=None, threat="recon", severity="info", flags=None):
    return sv.Trigger(
        id=tid, label=tid.upper(), cls=cls, runner="curl",
        commands=commands or [_stub(0, "200|")], flags=flags or [], severity=severity,
        threat_class=threat, expected_fire="SID 2100498 — id check returned root",
        talking_point="", expected_on_allow={}, expected_on_block={}, params=[], timeout=15.0,
    )


class LedgerFixture(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sv-ev-")
        self.settings = sv.Settings(raw={
            "run": {"min_interval_s": 0, "control_host": ""},
            "evidence": {"log": False, "dir": self.dir},
        })

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_all(self, triggers):
        app = sv.App(self.settings, triggers, CONFIG)
        for t in triggers:
            app.run(t.id, {})
        return app


class TestHashChain(LedgerFixture):
    def test_chain_verifies_and_detects_tampering(self):
        app = self.run_all([mk_trigger("a"), mk_trigger("b", commands=[_stub(28)]),
                            mk_trigger("c")])
        led = app.ledger
        self.assertEqual(len(led.records), 3)
        self.assertEqual(led.verify_chain(), (True, None))

        original = led.records[1]["state"]
        self.assertEqual(original, sv.BLOCKED)
        led.records[1]["state"] = sv.ALLOWED          # rewrite an observation
        ok, bad = led.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(bad, 2)
        led.records[1]["state"] = original
        self.assertEqual(led.verify_chain(), (True, None))

    def test_tampering_with_an_early_record_is_caught_at_that_record(self):
        app = self.run_all([mk_trigger("a"), mk_trigger("b"), mk_trigger("c")])
        app.ledger.records[0]["reason"] = "something else entirely"
        ok, bad = app.ledger.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    def test_records_are_linked_not_merely_self_hashed(self):
        app = self.run_all([mk_trigger("a"), mk_trigger("b")])
        led = app.ledger
        self.assertEqual(led.records[0]["prev_hash"], "")
        self.assertEqual(led.records[1]["prev_hash"], led.records[0]["hash"])


class TestAttestation(LedgerFixture):
    def test_presenter_attestation_does_not_break_the_chain(self):
        """The human annotation is evidence of a different kind and lives outside the
        chain — otherwise ticking a box would look like tampering."""
        app = self.run_all([mk_trigger("a"), mk_trigger("b")])
        app.ledger.set_confirmed(1, sv.CONFIRMED_YES)
        app.ledger.set_confirmed(2, sv.CONFIRMED_NO)
        self.assertEqual(app.ledger.verify_chain(), (True, None))
        self.assertEqual(app.ledger.records[0]["confirmed"], sv.CONFIRMED_YES)

    def test_attestation_never_overwrites_the_observation(self):
        app = self.run_all([mk_trigger("blocked", commands=[_stub(28)])])
        app.ledger.set_confirmed(1, sv.CONFIRMED_NO)   # "I didn't see it on the console"
        rec = app.ledger.records[0]
        self.assertEqual(rec["state"], sv.BLOCKED)     # the local observation is unchanged
        self.assertEqual(rec["confirmed"], sv.CONFIRMED_NO)

    def test_defaults_to_unset_and_rejects_junk(self):
        app = self.run_all([mk_trigger("a")])
        self.assertEqual(app.ledger.records[0]["confirmed"], sv.CONFIRMED_UNSET)
        with self.assertRaises(ValueError):
            app.ledger.set_confirmed(1, "probably?")
        self.assertIsNone(app.ledger.set_confirmed(99, sv.CONFIRMED_YES))


class TestLedgerContent(LedgerFixture):
    def test_every_outcome_is_recorded_including_failures(self):
        app = self.run_all([mk_trigger("ok"), mk_trigger("dropped", commands=[_stub(28)]),
                            mk_trigger("broken", commands=[_stub(6)])])
        self.assertEqual(app.ledger.state_counts(),
                         {sv.ALLOWED: 1, sv.BLOCKED: 1, sv.ERROR: 1})

    def test_gated_trigger_is_recorded_as_invalid(self):
        gated = mk_trigger("g", flags=["hits_live_suspect_hosts"])
        app = self.run_all([gated])
        self.assertEqual(app.ledger.records[0]["state"], sv.INVALID)

    def test_unknown_trigger_is_not_recorded(self):
        app = sv.App(self.settings, [mk_trigger("a")], CONFIG)
        trigger, out = app.run("nope", {})
        self.assertIsNone(trigger)
        self.assertEqual(app.ledger.records, [])

    def test_signal_count_uses_the_true_on_wire_number(self):
        multi = mk_trigger("m", commands=[_stub(0, "200|"), _stub(0, "200|")])
        app = self.run_all([multi])
        self.assertEqual(app.ledger.signals_fired(), 2)

    def test_result_carries_the_ledger_seq_back_to_the_caller(self):
        app = sv.App(self.settings, [mk_trigger("a"), mk_trigger("b")], CONFIG)
        self.assertEqual(app.run("a", {})[1]["seq"], 1)
        self.assertEqual(app.run("b", {})[1]["seq"], 2)


class TestScorecardAndCoverage(LedgerFixture):
    def test_scorecard_keeps_the_three_columns_separate(self):
        app = self.run_all([mk_trigger("a")])
        app.ledger.set_confirmed(1, sv.CONFIRMED_YES)
        row = app.ledger.scorecard()[0]
        self.assertIn("SID 2100498", row["expected"])   # catalog says
        self.assertEqual(row["observed"], sv.ALLOWED)   # host saw
        self.assertEqual(row["confirmed"], sv.CONFIRMED_YES)  # human attested

    def test_coverage_matrix_names_the_gaps(self):
        triggers = [mk_trigger("fired", cls="ns-ids", threat="recon"),
                    mk_trigger("never", cls="ns-webcc", threat="policy")]
        app = sv.App(self.settings, triggers, CONFIG)
        app.run("fired", {})
        cov = app.ledger.coverage_matrix(triggers, self.settings)
        self.assertEqual(cov["cells"]["ns-ids|recon"]["result"], 1)
        self.assertEqual(cov["cells"]["ns-webcc|policy"]["fired"], 0)
        self.assertTrue(any("ns-webcc / policy" in g for g in cov["gaps"]))
        # a class with no catalog entries at all is named too
        self.assertTrue(any(g.startswith("ew:") for g in cov["gaps"]), cov["gaps"])

    def test_errored_trigger_counts_as_fired_but_not_as_a_result(self):
        triggers = [mk_trigger("broken", commands=[_stub(6)])]
        app = self.run_all(triggers)
        cov = app.ledger.coverage_matrix(triggers, self.settings)
        cell = cov["cells"]["ns-ids|recon"]
        self.assertEqual(cell["fired"], 1)
        self.assertEqual(cell["result"], 0)      # an environment error proves nothing


class TestExports(LedgerFixture):
    def setUp(self):
        super().setUp()
        self.triggers = [mk_trigger("a"), mk_trigger("b", cls="ns-webcc",
                                                     commands=[_stub(28)], threat="policy")]
        self.app = self.run_all(self.triggers)

    def test_json_round_trips_and_reports_chain_status(self):
        doc = json.loads(self.app.ledger.to_json(self.triggers, self.settings))
        self.assertEqual(doc["summary"]["triggers"], 2)
        self.assertTrue(doc["summary"]["chain_ok"])
        self.assertIn("coverage", doc)
        self.assertEqual(doc["provenance"]["version"], sv.__version__)
        self.assertEqual(len(doc["provenance"]["catalog_sha256"]), 64)

    def test_csv_has_a_header_and_one_row_per_trigger(self):
        lines = [ln for ln in self.app.ledger.to_csv().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith("seq,ts,run_id,id,label"))

    def test_html_is_self_contained_and_escaped(self):
        evil = mk_trigger("x", cls="ns-ids")
        evil.label = "<script>alert(1)</script>"
        app = self.run_all([evil])
        html = app.ledger.to_html([evil], self.settings)
        self.assertIn("<!doctype html>", html)
        self.assertNotIn("<script>alert(1)</script>", html)   # escaped, not injected
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn("<script", html.lower())             # no scripts at all
        self.assertNotIn("src=\"http", html)                  # no external resources
        self.assertNotIn("<link", html.lower())

    def test_export_picks_the_format_from_the_extension(self):
        for ext, probe in ((".json", "\"summary\""), (".csv", "seq,ts,run_id"),
                           (".html", "<!doctype html>")):
            path = os.path.join(self.dir, "report" + ext)
            written = sv.export_ledger(self.app.ledger, path, self.triggers, self.settings)
            self.assertEqual(written, path)
            with open(path, encoding="utf-8") as fh:
                self.assertIn(probe, fh.read())

    def test_report_states_error_is_not_a_policy_result(self):
        html = self.app.ledger.to_html(self.triggers, self.settings)
        self.assertIn("Not a policy result", html)
        self.assertIn("Never read this as a block", html)


class TestEvidenceLog(LedgerFixture):
    def test_append_and_read_back(self):
        path = os.path.join(self.dir, "evidence.jsonl")
        self.assertTrue(sv.append_jsonl(path, {"run_id": "r1", "seq": 1}))
        self.assertTrue(sv.append_jsonl(path, {"run_id": "r1", "seq": 2}))
        self.assertEqual(len(sv.read_jsonl(path)), 2)

    def test_malformed_lines_are_skipped_not_fatal(self):
        path = os.path.join(self.dir, "evidence.jsonl")
        sv.append_jsonl(path, {"run_id": "r1", "seq": 1})
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("{not json\n\n")
        sv.append_jsonl(path, {"run_id": "r1", "seq": 2})
        self.assertEqual(len(sv.read_jsonl(path)), 2)

    def test_last_session_returns_only_the_most_recent_run(self):
        path = os.path.join(self.dir, "evidence.jsonl")
        for seq in (1, 2):
            sv.append_jsonl(path, {"run_id": "old", "seq": seq})
        for seq in (1, 2, 3):
            sv.append_jsonl(path, {"run_id": "new", "seq": seq})
        recs = sv.last_session_records(path)
        self.assertEqual(len(recs), 3)
        self.assertTrue(all(r["run_id"] == "new" for r in recs))

    def test_missing_log_is_not_an_error(self):
        self.assertEqual(sv.read_jsonl(os.path.join(self.dir, "nope.jsonl")), [])
        self.assertEqual(sv.last_session_records(os.path.join(self.dir, "nope.jsonl")), [])

    def test_rotation_keeps_the_log_bounded(self):
        path = os.path.join(self.dir, "evidence.jsonl")
        sv.append_jsonl(path, {"run_id": "r", "seq": 1}, max_bytes=1)
        sv.append_jsonl(path, {"run_id": "r", "seq": 2}, max_bytes=1)
        self.assertTrue(os.path.exists(path + ".1"))

    def test_app_writes_to_the_configured_directory_only(self):
        settings = sv.Settings(raw={"run": {"min_interval_s": 0, "control_host": ""},
                                    "evidence": {"log": True, "dir": self.dir}})
        app = sv.App(settings, [mk_trigger("a")], CONFIG)
        app.run("a", {})
        self.assertEqual(os.path.dirname(app.evidence_path), self.dir)
        self.assertEqual(len(sv.read_jsonl(app.evidence_path)), 1)

    def test_logging_can_be_turned_off(self):
        app = sv.App(self.settings, [mk_trigger("a")], CONFIG)   # evidence.log False
        app.run("a", {})
        self.assertFalse(os.path.exists(app.evidence_path))


class TestCorrelationHeader(LedgerFixture):
    def test_off_by_default_so_the_wire_is_unchanged(self):
        self.assertFalse(sv.Settings(raw={}).correlation_header)
        self.assertEqual(sv._curl_flow_argv(["curl", "http://x"], None).count("-H"), 0)

    def test_header_added_only_when_enabled(self):
        argv = sv._curl_flow_argv(["curl", "-w", "%{http_code}|", "http://x"], "abc123")
        self.assertIn("-H", argv)
        self.assertIn(f"{sv.CORRELATION_HEADER}: abc123", argv)
        self.assertIn(sv.FLOW_MARK, argv[argv.index("-w") + 1])   # write-out still intact

    def test_displayed_command_is_still_the_catalogs(self):
        settings = sv.Settings(raw={"run": {"min_interval_s": 0, "control_host": "",
                                            "correlation_header": True},
                                    "evidence": {"log": False, "dir": self.dir}})
        t = mk_trigger("a")
        app = sv.App(settings, [t], CONFIG)
        _, out = app.run("a", {})
        self.assertNotIn(sv.CORRELATION_HEADER, out["stdout"])


class TestCliEvidence(LedgerFixture):
    def test_headless_export_writes_and_reports_the_path(self):
        import io
        triggers = [mk_trigger("a"), mk_trigger("b", commands=[_stub(28)])]
        app = sv.App(self.settings, triggers, CONFIG)
        target = os.path.join(self.dir, "run.html")
        buf = io.StringIO()
        code = sv.run_headless(app, triggers, self.settings, "all", "text", out=buf,
                               export=target)
        self.assertEqual(code, sv.HEADLESS_OK)
        self.assertTrue(os.path.exists(target))
        self.assertIn("Evidence written to", buf.getvalue())

    def test_headless_json_export_is_announced_in_the_document(self):
        import io
        triggers = [mk_trigger("a")]
        app = sv.App(self.settings, triggers, CONFIG)
        target = os.path.join(self.dir, "run.json")
        buf = io.StringIO()
        sv.run_headless(app, triggers, self.settings, "all", "json", out=buf, export=target)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["export"], target)

    def test_unwritable_export_is_a_usage_error_not_a_crash(self):
        import io
        triggers = [mk_trigger("a")]
        app = sv.App(self.settings, triggers, CONFIG)
        # a regular file used as a directory component — makedirs must fail
        blocker = os.path.join(self.dir, "blocker")
        with open(blocker, "w", encoding="utf-8") as fh:
            fh.write("not a directory")
        bad = os.path.join(blocker, "run.json")
        code = sv.run_headless(app, triggers, self.settings, "all", "text",
                               out=io.StringIO(), export=bad)
        self.assertEqual(code, sv.HEADLESS_USAGE)
        self.assertEqual(len(app.ledger.records), 1)   # the run itself still happened

    def test_cli_flags_parse(self):
        args = sv.parse_args(["--run", "all", "--export", "r.html"])
        self.assertEqual(args.export, "r.html")
        self.assertTrue(sv.parse_args(["--last-session"]).last_session)

    def test_last_session_with_no_log_exits_clean(self):
        import io
        saved, sys.stdout = sys.stdout, io.StringIO()
        try:
            code = sv.main(["--config-dir", CONFIG, "--last-session"])
            printed = sys.stdout.getvalue()
        finally:
            sys.stdout = saved
        self.assertEqual(code, 0)
        self.assertTrue(printed.strip())

    def test_scorecard_text_renders_all_three_columns(self):
        app = self.run_all([mk_trigger("a")])
        app.ledger.set_confirmed(1, sv.CONFIRMED_YES)
        text = sv.format_scorecard(app.ledger.scorecard())
        self.assertIn("OBSERVED", text)
        self.assertIn("CONFIRMED", text)
        self.assertIn("expected:", text)
        self.assertIn("confirmed on console", text)
        self.assertEqual(sv.format_scorecard([]), "No triggers have been fired yet.")


class TestProvenance(unittest.TestCase):
    def test_digests_cover_code_and_config(self):
        prov = sv.provenance(CONFIG)
        self.assertEqual(prov["version"], sv.__version__)
        for key in ("code_sha256", "catalog_sha256", "settings_sha256"):
            self.assertEqual(len(prov[key]), 64, key)

    def test_missing_config_does_not_raise(self):
        prov = sv.provenance("/nonexistent/dir")
        self.assertEqual(prov["catalog_sha256"], "")
        self.assertEqual(len(prov["code_sha256"]), 64)

    def test_run_ids_are_unique(self):
        self.assertEqual(len({sv.new_run_id() for _ in range(200)}), 200)


if __name__ == "__main__":
    unittest.main()
