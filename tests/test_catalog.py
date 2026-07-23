"""Tests for catalog/settings loading and validation (native `commands` schema)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestLoad(unittest.TestCase):
    def test_load_real(self):
        settings = sv.load_settings(os.path.join(HERE, "config"))
        self.assertFalse(settings.enable_live_suspect_hosts)
        self.assertEqual(settings.control_host, "1.1.1.1")
        triggers = sv.load_catalog(os.path.join(HERE, "config"), settings)
        uid = next(t for t in triggers if t.id == "ns-uid")
        self.assertEqual(uid.cls, "ns-ids")
        self.assertEqual(uid.runner, "curl")                  # native curl, not a tmNIDS binary
        self.assertEqual(uid.commands[0][0], "curl")
        self.assertTrue(any("testmynids.org/uid" in tok for tok in uid.commands[0]))

    def test_full_catalog(self):
        settings = sv.load_settings(os.path.join(HERE, "config"))
        triggers = sv.load_catalog(os.path.join(HERE, "config"), settings)
        by_class = {}
        for t in triggers:
            by_class.setdefault(t.cls, []).append(t)

        # 15 north-south IDS signatures, reproduced natively (curl / dns / tcp — no tmNIDS binary).
        ns_ids = by_class["ns-ids"]
        self.assertEqual(len(ns_ids), 15)
        self.assertTrue(all(t.runner in ("curl", "dns", "tcp") for t in ns_ids))
        self.assertEqual({t.runner for t in ns_ids}, {"curl", "dns", "tcp"})

        # 10 WebCC (curl) + 1 IP-rep (iprep)
        self.assertEqual(len(by_class.get("ns-webcc", [])), 10)
        self.assertEqual(len(by_class.get("ns-iprep", [])), 1)
        for t in by_class["ns-webcc"]:
            self.assertEqual(t.runner, "curl")
            self.assertEqual(t.commands[0][0], "curl")
        self.assertEqual(by_class["ns-iprep"][0].runner, "iprep")

        # multi-request triggers reproduce every request the tmNIDS test sends
        malua = next(t for t in triggers if t.id == "ns-malua")
        self.assertEqual(len(malua.commands), 5)

        # live-suspect triggers gated off by default
        gated = {t.id for t in triggers if t.gated_disabled(settings)}
        self.assertEqual(gated, {"ns-badcert", "ns-tor", "web-cat-p2p", "ip-rep-tor"})

    def test_devnull_token_is_allowed(self):
        settings = sv.load_settings(os.path.join(HERE, "config"))
        triggers = sv.load_catalog(os.path.join(HERE, "config"), settings)
        # every curl command uses the {devnull} token and it loads without a param error
        curls = [c for t in triggers if t.runner == "curl" for c in t.commands]
        self.assertTrue(any(sv.DEVNULL_TOKEN in c for c in curls))


class TestTriggerValidation(unittest.TestCase):
    def base(self, **kw):
        d = dict(id="ns-uid", label="x", **{"class": "ns-ids"}, runner="curl",
                 commands=[["curl", "-s", "http://x"]])
        d.update(kw)
        return d

    def test_ok(self):
        t = sv.Trigger.from_dict(self.base(), 30.0)
        self.assertEqual(t.id, "ns-uid")
        self.assertEqual(t.commands, [["curl", "-s", "http://x"]])

    def test_argv_back_compat(self):
        # a single `argv` is normalized to one command
        t = sv.Trigger.from_dict(self.base(commands=None, argv=["curl", "http://y"]), 30.0)
        self.assertEqual(t.commands, [["curl", "http://y"]])

    def test_bad_id(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(id="Bad Id!"), 30.0)

    def test_bad_class(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(**{"class": "nope"}), 30.0)

    def test_bad_runner(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(runner="rm"), 30.0)

    def test_bad_commands(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(commands=[]), 30.0)
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(commands=["curl", "http://x"]), 30.0)   # not a list of lists
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(commands=[[]]), 30.0)

    def test_bad_flag(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(flags=["do_something_evil"]), 30.0)

    def test_param_without_allow_or_pattern_fails_closed(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(commands=[["curl", "{t}"]], params=[{"name": "t"}]), 30.0)

    def test_commands_reference_undeclared_param(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(commands=[["curl", "{missing}"]], params=[]), 30.0)

    def test_devnull_token_needs_no_param(self):
        t = sv.Trigger.from_dict(self.base(commands=[["curl", "-o", sv.DEVNULL_TOKEN, "http://x"]]), 30.0)
        self.assertIn(sv.DEVNULL_TOKEN, t.commands[0])

    def test_bad_regex_pattern_rejected(self):
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(self.base(commands=[["curl", "{t}"]],
                                           params=[{"name": "t", "pattern": "("}]), 30.0)


class TestGating(unittest.TestCase):
    def _settings(self, enabled):
        return sv.Settings(raw={"enable_live_suspect_hosts": enabled})

    def test_gated_when_disabled(self):
        t = sv.Trigger.from_dict(
            dict(id="ns-tor", label="tor", **{"class": "ns-ids"}, runner="dns",
                 commands=[["dns", "x.onion", "@8.8.8.8"]], flags=["hits_live_suspect_hosts"]), 30.0)
        self.assertTrue(t.gated_disabled(self._settings(False)))
        self.assertFalse(t.gated_disabled(self._settings(True)))

    def test_not_gated_without_flag(self):
        t = sv.Trigger.from_dict(
            dict(id="ns-uid", label="uid", **{"class": "ns-ids"}, runner="curl",
                 commands=[["curl", "http://x"]]), 30.0)
        self.assertFalse(t.gated_disabled(self._settings(False)))

    def test_public_shape(self):
        t = sv.Trigger.from_dict(
            dict(id="ns-malua", label="uid", **{"class": "ns-ids"}, runner="curl",
                 commands=[["curl", "-A", "a", "http://x"], ["curl", "-A", "b", "http://x"]],
                 flags=["needs_internet"]), 30.0)
        pub = t.to_public(self._settings(False))
        self.assertEqual(pub["class"], "ns-ids")
        self.assertNotIn("commands", pub)   # never leak the command templates to a catalog view
        self.assertEqual(pub["request_count"], 2)
        self.assertIn("expected_fire", pub)


if __name__ == "__main__":
    unittest.main()
