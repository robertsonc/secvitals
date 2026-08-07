"""Tests for the measurement-mode ('assurance tier') label threaded through the catalog,
the signal manifest, and the run evidence.

Every shipping trigger is BEST-EFFORT (single-ended, public origin, a heuristic local
read). GROUND-TRUTH (dual-ended over a reflector you control — the poc/) is a distinct
tier the schema can carry so the two are shown side by side and never confused. The
mode never affects what is sent; it only labels what a result can prove."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(HERE, "config")


def mk_trigger(tid="t", mode=None, **kw):
    base = dict(
        id=tid, label=tid, cls="ns-ids", runner="curl",
        commands=[["curl", "http://x"]], flags=[], severity="info", threat_class="",
        expected_fire="", talking_point="", expected_on_allow={}, expected_on_block={},
        params=[], timeout=30.0,
    )
    base.update(kw)
    t = sv.Trigger(**base)
    if mode is not None:
        t.mode = mode
    return t


def from_dict(**kw):
    base = dict(id="t", **{"class": "ns-ids"}, runner="curl", commands=[["curl", "http://x"]])
    base.update(kw)
    return sv.Trigger.from_dict(base, 30.0)


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------
class TestSchema(unittest.TestCase):
    def test_default_mode_is_best_effort(self):
        self.assertEqual(from_dict().mode, "best-effort")
        self.assertEqual(sv.DEFAULT_MODE, "best-effort")

    def test_ground_truth_is_accepted(self):
        self.assertEqual(from_dict(mode="ground-truth").mode, "ground-truth")

    def test_unknown_mode_is_rejected(self):
        with self.assertRaises(sv.ConfigError):
            from_dict(mode="best_effort")          # underscore, not the hyphen spelling
        with self.assertRaises(sv.ConfigError):
            from_dict(mode="proven")

    def test_to_public_carries_mode(self):
        self.assertEqual(mk_trigger().to_public(sv.Settings(raw={}))["mode"], "best-effort")
        self.assertEqual(mk_trigger(mode="ground-truth").to_public(sv.Settings(raw={}))["mode"],
                         "ground-truth")

    def test_the_shipping_catalog_is_all_best_effort(self):
        settings = sv.load_settings(CONFIG)
        triggers = sv.load_catalog(CONFIG, settings)
        self.assertTrue(triggers)
        self.assertTrue(all(t.mode == "best-effort" for t in triggers),
                        "every shipping trigger should be best-effort")


# ---------------------------------------------------------------------------
# signal manifest
# ---------------------------------------------------------------------------
class TestManifest(unittest.TestCase):
    def setUp(self):
        self.settings = sv.Settings(raw={})

    def test_manifest_groups_by_mode(self):
        triggers = [mk_trigger("a"), mk_trigger("b"),
                    mk_trigger("g", mode="ground-truth")]
        modes = {m["mode"]: m for m in sv.signal_manifest(triggers, self.settings)["modes"]}
        self.assertEqual(modes["best-effort"]["triggers"], 2)
        self.assertEqual(modes["ground-truth"]["triggers"], 1)

    def test_format_shows_both_tiers_and_the_caveat(self):
        text = sv.format_signal_manifest(
            sv.signal_manifest([mk_trigger("a")], self.settings))
        self.assertIn("MEASUREMENT MODE", text)
        self.assertIn("best-effort", text)
        self.assertIn("ground-truth", text)
        self.assertIn("MAY OR MAY NOT", text)           # the best-effort caveat
        # with no ground-truth triggers, the manifest points at where that tier lives
        self.assertIn("poc/harness.py --manifest", text)

    def test_manifest_sends_nothing(self):
        # signal_manifest only reads catalog metadata; a trigger whose command would fail
        # loudly if executed still produces a manifest, proving nothing ran.
        t = mk_trigger("x", commands=[["curl", "http://x"]])
        self.assertIn("mode", sv.signal_manifest([t], self.settings)["triggers"][0])


# ---------------------------------------------------------------------------
# run evidence (ledger / scorecard / exports)
# ---------------------------------------------------------------------------
class TestEvidence(unittest.TestCase):
    def setUp(self):
        self.settings = sv.Settings(raw={})
        self.led = sv.RunLedger(run_id="r")
        self.out = {"state": sv.ALLOWED, "reason": "ok", "wire_requests": 1,
                    "expected_fire": "SID 1"}

    def test_record_and_scorecard_carry_mode(self):
        self.led.add(mk_trigger("a"), self.out, self.settings)
        self.led.add(mk_trigger("g", mode="ground-truth"), self.out, self.settings)
        self.assertEqual([r["mode"] for r in self.led.records],
                         ["best-effort", "ground-truth"])
        self.assertEqual([r["mode"] for r in self.led.scorecard()],
                         ["best-effort", "ground-truth"])

    def test_chain_still_verifies_with_mode_in_the_record(self):
        self.led.add(mk_trigger("a"), self.out, self.settings)
        self.led.add(mk_trigger("b"), self.out, self.settings)
        self.assertEqual(self.led.verify_chain(), (True, None))

    def test_csv_has_a_mode_column(self):
        self.led.add(mk_trigger("g", mode="ground-truth"), self.out, self.settings)
        csv = self.led.to_csv()
        header = csv.splitlines()[0]
        self.assertIn("mode", header.split(","))
        self.assertIn("ground-truth", csv)

    def test_html_report_labels_mode(self):
        self.led.add(mk_trigger("g", mode="ground-truth"), self.out, self.settings)
        html = self.led.to_html()
        self.assertIn("<th>Mode</th>", html)
        self.assertIn("ground-truth", html)


if __name__ == "__main__":
    unittest.main()
