"""Tests for catalog/settings loading and validation."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLoad(unittest.TestCase):
    def test_load_real(self):
        settings = sv.load_settings(os.path.join(HERE, "config"))
        self.assertEqual(settings.wsl_python, "python3")
        self.assertFalse(settings.enable_live_suspect_hosts)
        triggers = sv.load_catalog(os.path.join(HERE, "config"), settings)
        self.assertTrue(any(t.id == "ns-uid" for t in triggers))
        uid = next(t for t in triggers if t.id == "ns-uid")
        self.assertEqual(uid.argv, ["tmNIDS", "-1"])
        self.assertEqual(uid.cls, "ns-ids")
        self.assertEqual(uid.runner, "tmnids")

    def test_full_catalog(self):
        settings = sv.load_settings(os.path.join(HERE, "config"))
        triggers = sv.load_catalog(os.path.join(HERE, "config"), settings)
        by_class = {}
        for t in triggers:
            by_class.setdefault(t.cls, []).append(t)

        # 15 tmNIDS signatures, selectors -1..-15
        tmnids = [t for t in triggers if t.runner == "tmnids"]
        self.assertEqual(len(tmnids), 15)
        self.assertEqual(sorted(int(t.argv[1].lstrip("-")) for t in tmnids), list(range(1, 16)))
        for t in tmnids:
            self.assertEqual(t.cls, "ns-ids")
            self.assertEqual(t.argv[0], "tmNIDS")

        # Phase 3: 10 WebCC (curl) + 1 IP-rep (iprep)
        self.assertEqual(len(by_class.get("ns-webcc", [])), 10)
        self.assertEqual(len(by_class.get("ns-iprep", [])), 1)
        for t in by_class["ns-webcc"]:
            self.assertEqual(t.runner, "curl")
            self.assertEqual(t.argv[0], "curl")
        self.assertEqual(by_class["ns-iprep"][0].runner, "iprep")

        # live-suspect triggers gated off by default
        gated = {t.id for t in triggers if t.gated_disabled(settings)}
        self.assertEqual(gated, {"ns-badcert", "ns-tor", "web-cat-p2p", "ip-rep-tor"})


class TestTriggerValidation(unittest.TestCase):
    def base(self, **kw):
        d = dict(id="ns-uid", label="x", **{"class": "ns-ids"}, runner="tmnids",
                 argv=["tmNIDS", "-1"], expected_on_allow={"rc": 0},
                 expected_on_block={"rc_nonzero": True})
        d.update(kw)
        return d

    def test_ok(self):
        t = sv.Trigger.from_dict(self.base(), 30.0)
        self.assertEqual(t.id, "ns-uid")

    def test_bad_id(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(id="Bad Id!"), 30.0)

    def test_bad_class(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(**{"class": "nope"}), 30.0)

    def test_bad_runner(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(runner="rm"), 30.0)

    def test_bad_argv(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(argv=[]), 30.0)
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(argv="tmNIDS -1"), 30.0)

    def test_bad_flag(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(flags=["do_something_evil"]), 30.0)

    def test_param_without_allow_or_pattern_fails_closed(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(argv=["curl", "{t}"], params=[{"name": "t"}]), 30.0)

    def test_argv_references_undeclared_param(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(argv=["curl", "{missing}"], params=[]), 30.0)

    def test_bad_predicate_type_rejected(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(expected_on_allow={"rc": "zero"}), 30.0)
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(expected_on_block={"http_code_in": "403"}), 30.0)
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(expected_on_allow={"unknown_key": 1}), 30.0)
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(expected_on_block={"rc_nonzero": "yes"}), 30.0)

    def test_bad_regex_pattern_rejected(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(argv=["curl", "{t}"],
                                           params=[{"name": "t", "pattern": "("}]), 30.0)


class TestGating(unittest.TestCase):
    def _settings(self, enabled):
        return sv.Settings(raw={"enable_live_suspect_hosts": enabled})

    def test_gated_when_disabled(self):
        t = sv.Trigger.from_dict(
            dict(id="ns-tor", label="tor", **{"class": "ns-ids"}, runner="tmnids",
                 argv=["tmNIDS", "-5"], flags=["hits_live_suspect_hosts"]), 30.0)
        self.assertTrue(t.gated_disabled(self._settings(False)))
        self.assertFalse(t.gated_disabled(self._settings(True)))

    def test_not_gated_without_flag(self):
        t = sv.Trigger.from_dict(
            dict(id="ns-uid", label="uid", **{"class": "ns-ids"}, runner="tmnids",
                 argv=["tmNIDS", "-1"]), 30.0)
        self.assertFalse(t.gated_disabled(self._settings(False)))

    def test_public_shape(self):
        t = sv.Trigger.from_dict(
            dict(id="ns-uid", label="uid", **{"class": "ns-ids"}, runner="tmnids",
                 argv=["tmNIDS", "-1"], flags=["needs_internet"]), 30.0)
        pub = t.to_public(self._settings(False))
        self.assertEqual(pub["class"], "ns-ids")
        self.assertNotIn("argv", pub)   # never leak the argv template to the client catalog
        self.assertIn("expected_fire", pub)


if __name__ == "__main__":
    unittest.main()
