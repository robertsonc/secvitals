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

        # North-south IDS: the 15 tmNIDS signatures + the modern-exploit pack + the
        # DNS-security pack and the IPv6 parity twin, all reproduced natively.
        ns_ids = by_class["ns-ids"]
        self.assertEqual(len(ns_ids), 23)
        self.assertTrue(all(t.runner in ("curl", "dns", "tcp") for t in ns_ids))
        self.assertEqual({t.runner for t in ns_ids}, {"curl", "dns", "tcp"})

        # WebCC (curl) + DLP (curl) + 1 IP-rep (iprep)
        self.assertEqual(len(by_class.get("ns-webcc", [])), 20)
        self.assertEqual(len(by_class.get("ns-dlp", [])), 3)
        self.assertEqual(len(by_class.get("ns-iprep", [])), 4)
        for t in by_class["ns-webcc"] + by_class["ns-dlp"]:
            self.assertEqual(t.runner, "curl")
            self.assertEqual(t.commands[0][0], "curl")
        for t in by_class["ns-iprep"]:
            self.assertEqual(t.runner, "iprep")
        # east-west tier 1 fills the previously empty `ew` class
        self.assertEqual(len(by_class.get("ew", [])), 3)
        for t in by_class["ew"]:
            self.assertEqual(t.runner, "ew")
        self.assertEqual(len(triggers), 53)

        # multi-request triggers reproduce every request the tmNIDS test sends
        malua = next(t for t in triggers if t.id == "ns-malua")
        self.assertEqual(len(malua.commands), 5)

        # live-suspect triggers gated off by default
        gated = {t.id for t in triggers if t.gated_disabled(settings)}
        self.assertEqual(gated, {"ns-badcert", "ns-tor", "web-cat-p2p",
                                 "web-cat-hacking", "web-cat-adult", "ip-rep-tor",
                                 "ip-rep-botnet", "ip-rep-scanner", "ip-rep-spammer"})

    def test_exploit_payloads_are_inert_literals(self):
        """The modern-exploit pack must carry FIXED literal payloads aimed at the benign
        origin, and must never point a JNDI/LDAP reference at a resolvable name."""
        settings = sv.load_settings(os.path.join(HERE, "config"))
        triggers = sv.load_catalog(os.path.join(HERE, "config"), settings)
        by_id = {t.id: t for t in triggers}
        for tid in ("ns-log4shell", "ns-shellshock", "ns-spring4shell", "ns-scanner-ua"):
            t = by_id[tid]
            self.assertEqual(t.cls, "ns-ids")
            self.assertEqual(t.runner, "curl")
            self.assertFalse(t.params, f"{tid} must take no runtime params")
            for cmd in t.commands:
                url = [tok for tok in cmd if tok.startswith("http")]
                self.assertTrue(url, f"{tid} has a command with no URL")
                self.assertTrue(all("testmynids.org" in u for u in url),
                                f"{tid} must only target the benign test origin")
        # every JNDI reference points at the RFC 2606 reserved .invalid TLD
        jndi = [tok for cmd in by_id["ns-log4shell"].commands for tok in cmd if "jndi" in tok]
        self.assertTrue(jndi)
        self.assertTrue(all(".invalid/" in tok for tok in jndi), jndi)

    def test_dlp_payloads_are_synthetic(self):
        """DLP bodies must use the publicly documented test values, never real data."""
        settings = sv.load_settings(os.path.join(HERE, "config"))
        triggers = sv.load_catalog(os.path.join(HERE, "config"), settings)
        dlp = {t.id: t for t in triggers if t.cls == "ns-dlp"}
        bodies = " ".join(tok for t in dlp.values() for cmd in t.commands for tok in cmd)
        self.assertIn("4111111111111111", bodies)      # universal Visa test PAN
        self.assertIn("666-12-3456", bodies)           # SSA never issues area 666
        self.assertIn("AKIAIOSFODNN7EXAMPLE", bodies)  # AWS documentation example key
        for t in dlp.values():
            for cmd in t.commands:
                self.assertIn("-X", cmd)
                self.assertEqual(cmd[cmd.index("-X") + 1], "POST")
                self.assertTrue(any("testmynids.org" in tok for tok in cmd))

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


class TestSettingsAccessors(unittest.TestCase):
    """Every Settings config accessor must be a @property.

    Regression guard for a merge hazard: two branches each added a property to this
    class, sharing the leading `@property` line as context. Concatenating both sides
    left the second `def` undecorated — so `settings.evidence_log_enabled` returned a
    bound method, which is always truthy, silently re-enabling evidence logging that an
    operator had turned OFF. A decorator lost this way changes a default without
    changing a single line of visible logic, so it is asserted rather than eyeballed."""

    def test_no_config_accessor_is_left_undecorated(self):
        settings = sv.Settings(raw={})
        offenders = []
        for name in dir(sv.Settings):
            if name.startswith("_"):
                continue
            attr = getattr(sv.Settings, name, None)
            if callable(attr) and not isinstance(attr, property):
                continue                       # a genuine method, not an accessor
            if isinstance(attr, property):
                value = getattr(settings, name)
                if callable(value):
                    offenders.append(name)     # a property returning a callable is a smell
        self.assertEqual(offenders, [])

    def test_known_toggles_evaluate_to_real_booleans(self):
        """A bound method is truthy, so `if settings.x:` would pass either way."""
        settings = sv.Settings(raw={"evidence": {"log": False}})
        for name in ("enable_live_suspect_hosts", "evidence_log_enabled",
                     "correlation_header", "check_update_on_start"):
            if hasattr(sv.Settings, name):
                value = getattr(settings, name)
                self.assertIsInstance(value, bool, f"{name} is {type(value).__name__}")
        self.assertFalse(settings.evidence_log_enabled)   # the setting is honoured
