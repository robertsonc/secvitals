"""Tests for M3 coverage breadth: DNS query types and the DNS-security pack, the named
IP-reputation feeds, and the transport-capability gate behind the IPv6/HTTP-3 twins.

The honesty property under test: a transport this host cannot use must report `error`,
NEVER `blocked`. `curl -6` on a host with no IPv6 exits 7, which the classifier would
otherwise read as an inline drop — crediting the customer's stack with a block it never
made."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(HERE, "config")


class FakeProc:
    def __init__(self, rc=0, stdout=b""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = b""


def mk_trigger(tid="t", runner="curl", commands=None, requires=None, cls="ns-ids"):
    return sv.Trigger(
        id=tid, label=tid, cls=cls, runner=runner,
        commands=commands or [["curl", "http://x"]], flags=[], severity="info",
        threat_class="recon", expected_fire="", talking_point="",
        expected_on_allow={}, expected_on_block={}, params=[], timeout=15.0,
        requires=requires or [],
    )


class TestDnsQueryTypes(unittest.TestCase):
    def test_type_token_is_parsed_and_allowlisted(self):
        sub = sv._run_dns(["dns", "x.example", "@192.0.2.1", "type=TXT"], 1.0)
        self.assertIsNone(sub.error_reason)          # ran (and timed out) — not rejected
        bad = sv._run_dns(["dns", "x.example", "type=EVIL"], 1.0)
        self.assertIn("unsupported query type", bad.error_reason)
        self.assertIn("TXT", bad.error_reason)       # tells the author what is allowed

    def test_defaults_to_a_record(self):
        ok, detail, err, _flow = sv._dns_query("x.example", "192.0.2.1", 0.5)
        self.assertFalse(ok)                          # TEST-NET-1 never answers
        self.assertIsNone(err)                        # a timeout is not an env error
        self.assertIn("A", detail)

    def test_qtype_appears_in_the_detail_line(self):
        _ok, detail, _err, _flow = sv._dns_query("x.example", "192.0.2.1", 0.5, "TXT")
        self.assertIn("TXT", detail)

    def test_every_shipped_qtype_has_a_wire_code(self):
        for name, code in sv.DNS_QTYPES.items():
            self.assertIsInstance(code, int, name)
            self.assertTrue(0 < code < 65536, name)

    def test_oversized_label_is_an_error_not_a_silent_truncation(self):
        ok, _d, err, _f = sv._dns_query("a" * 64 + ".example.com", "192.0.2.1", 0.5)
        self.assertFalse(ok)
        self.assertIn("63", err)

    def test_missing_query_name_is_an_error(self):
        self.assertIn("no query name", sv._run_dns(["dns", "@8.8.8.8"], 1.0).error_reason)


class TestTransportRequirements(unittest.TestCase):
    def setUp(self):
        sv.reset_capability_cache()
        self.settings = sv.Settings(raw={"run": {"ipv6_control_url": "https://[2001:db8::1]/"}})

    def tearDown(self):
        sv.reset_capability_cache()

    def test_requires_is_validated_against_a_fixed_allowlist(self):
        base = dict(id="x", label="x", **{"class": "ns-ids"}, runner="curl",
                    commands=[["curl", "http://x"]])
        self.assertEqual(sv.Trigger.from_dict(dict(base, requires=["ipv6"]), 30.0).requires,
                         ["ipv6"])
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(dict(base, requires=["telepathy"]), 30.0)
        with self.assertRaises(sv.ConfigError):
            sv.Trigger.from_dict(dict(base, requires="ipv6"), 30.0)

    def test_no_requirements_means_no_gate(self):
        self.assertIsNone(sv.unmet_requirement(mk_trigger(), self.settings))

    def test_missing_ipv6_egress_is_an_error_never_a_block(self):
        """The load-bearing test: curl -6 exits 7 without IPv6, which maps to BLOCKED.
        The gate must catch that before the trigger ever runs."""
        sv.ipv6_egress_ok(self.settings, _runner=lambda: FakeProc(rc=7))   # prime: no v6
        trigger = mk_trigger(requires=["ipv6"])
        reason = sv.unmet_requirement(trigger, self.settings)
        self.assertIsNotNone(reason)
        self.assertIn("IPv6", reason)
        self.assertIn("not a policy result", reason)
        result = sv.run_trigger(trigger, {}, self.settings)
        self.assertEqual(sv.classify(trigger, result)[0], sv.ERROR)   # not BLOCKED
        self.assertEqual(result.subs, [])                             # nothing was sent

    def test_working_ipv6_lets_the_trigger_run(self):
        sv.ipv6_egress_ok(self.settings, _runner=lambda: FakeProc(rc=0))
        self.assertIsNone(sv.unmet_requirement(mk_trigger(requires=["ipv6"]), self.settings))

    def test_unconfigured_ipv6_control_is_an_error_not_a_guess(self):
        settings = sv.Settings(raw={"run": {"ipv6_control_url": ""}})
        reason = sv.unmet_requirement(mk_trigger(requires=["ipv6"]), settings)
        self.assertIn("could not be told apart from a policy block", reason)

    def test_missing_http3_support_is_an_error(self):
        sv.curl_features(_runner=lambda: FakeProc(stdout=b"Features: alt-svc HTTP2 SSL\n"))
        reason = sv.unmet_requirement(mk_trigger(requires=["http3"]), self.settings)
        self.assertIn("HTTP/3", reason)
        self.assertIn("not a policy result", reason)

    def test_present_http3_support_lets_the_trigger_run(self):
        sv.curl_features(_runner=lambda: FakeProc(stdout=b"Features: alt-svc HTTP2 HTTP3 SSL\n"))
        self.assertIsNone(sv.unmet_requirement(mk_trigger(requires=["http3"]), self.settings))

    def test_absent_curl_reports_no_features_rather_than_crashing(self):
        def boom():
            raise OSError("no curl here")
        self.assertEqual(sv.curl_features(_runner=boom), set())

    def test_capability_answers_are_cached(self):
        calls = {"n": 0}

        def counting():
            calls["n"] += 1
            return FakeProc(stdout=b"Features: HTTP3\n")
        sv.curl_features(_runner=counting)
        sv.curl_features(_runner=counting)
        self.assertEqual(calls["n"], 1)


class TestReputationFeeds(unittest.TestCase):
    def _settings(self, feeds=None, tor_url="https://example.invalid/tor.txt"):
        raw = {"webcc": {"tor_list_url": tor_url}}
        if feeds is not None:
            raw["webcc"]["reputation_feeds"] = feeds
        return sv.Settings(raw=raw)

    def test_tor_is_always_available_from_the_legacy_setting(self):
        feeds = sv.load_reputation_feeds(self._settings())
        self.assertIn("tor", feeds)
        self.assertEqual(feeds["tor"].port, 443)

    def test_extra_feeds_load_with_their_own_port(self):
        feeds = sv.load_reputation_feeds(self._settings({
            "botnet-c2": {"label": "C2", "url": "https://example.invalid/c2.txt", "port": 8080}}))
        self.assertEqual(feeds["botnet-c2"].port, 8080)
        self.assertEqual(feeds["botnet-c2"].label, "C2")

    def test_non_https_feed_is_refused(self):
        with self.assertRaises(sv.ConfigError):
            sv.load_reputation_feeds(self._settings({"x": {"url": "http://example.invalid/a"}}))

    def test_structural_errors_are_refused(self):
        for bad in ({"x": {"url": "https://a.invalid", "port": 0}},
                    {"x": {"url": "https://a.invalid", "port": "http"}},
                    {"BAD": {"url": "https://a.invalid"}},
                    {"x": ["not a mapping"]}):
            with self.assertRaises(sv.ConfigError, msg=repr(bad)):
                sv.load_reputation_feeds(self._settings(bad))

    def test_ip_list_parsing_is_strict(self):
        text = "# comment\n1.2.3.4\n  10.0.0.1  \n192.168.0.0/16\n999.1.1.1\nnot-an-ip\n8.8.8.8\n"
        # CIDR ranges and junk are skipped rather than guessed at
        self.assertEqual(sv._parse_ip_list(text), ["1.2.3.4", "10.0.0.1", "8.8.8.8"])

    def test_legacy_names_still_resolve(self):
        self.assertIs(sv._parse_tor_ips, sv._parse_ip_list)
        self.assertIs(sv.TorNodeCache, sv.IpFeedCache)

    def test_catalog_rejects_an_unknown_feed_at_load(self):
        settings = sv.load_settings(CONFIG)
        triggers = sv.load_catalog(CONFIG, settings)
        bad = dict(id="ip-rep-x", label="x", **{"class": "ns-iprep"}, runner="iprep",
                   commands=[["iprep", "no-such-feed"]])
        # the loader resolves feed names, so a typo fails at startup
        with self.assertRaises(sv.ConfigError):
            trig = sv.Trigger.from_dict(bad, 30.0)
            feeds = sv.load_reputation_feeds(settings)
            if trig.commands[0][1] not in feeds:
                raise sv.ConfigError("unknown reputation feed")
        self.assertTrue(any(t.id == "ip-rep-botnet" for t in triggers))

    def test_app_caches_one_fetch_per_feed_url(self):
        settings = sv.Settings(raw={"webcc": {"tor_list_url": "https://a.invalid/t.txt"}})
        app = sv.App(settings, [], CONFIG)
        first = app.feed_cache(app.feeds["tor"])
        self.assertIs(first, app.feed_cache(app.feeds["tor"]))

    def test_unknown_feed_at_run_time_is_an_error_not_a_verdict(self):
        settings = sv.Settings(raw={"run": {"control_host": "1.1.1.1"},
                                    "webcc": {"tor_list_url": "https://a.invalid/t.txt"}})
        trig = mk_trigger("ip-rep-x", runner="iprep", cls="ns-iprep",
                          commands=[["iprep", "ghost"]])
        app = sv.App(settings, [trig], CONFIG)
        out = app._run_iprep(trig)
        self.assertEqual(out["state"], sv.ERROR)
        self.assertIn("unknown reputation feed", out["reason"])


class TestShippedCatalog(unittest.TestCase):
    def setUp(self):
        self.settings = sv.load_settings(CONFIG)
        self.triggers = sv.load_catalog(CONFIG, self.settings)
        self.by_id = {t.id: t for t in self.triggers}

    def test_new_packs_are_present(self):
        for tid in ("ns-dns-dga", "ns-dns-tunnel", "ns-doh",
                    "ip-rep-botnet", "ip-rep-scanner", "ip-rep-spammer",
                    "ns-uid-v6", "web-cat-social-v6", "web-cat-social-h3"):
            self.assertIn(tid, self.by_id, tid)

    def test_every_reputation_trigger_is_gated(self):
        """These reach real suspect addresses — they must never fire by default."""
        for t in self.triggers:
            if t.cls == "ns-iprep":
                self.assertIn("hits_live_suspect_hosts", t.flags, t.id)
                self.assertTrue(t.gated_disabled(self.settings), t.id)

    def test_parity_twins_declare_their_transport(self):
        self.assertEqual(self.by_id["ns-uid-v6"].requires, ["ipv6"])
        self.assertEqual(self.by_id["web-cat-social-v6"].requires, ["ipv6"])
        self.assertEqual(self.by_id["web-cat-social-h3"].requires, ["http3"])
        # and they actually use the matching curl flag
        self.assertIn("-6", self.by_id["ns-uid-v6"].commands[0])
        self.assertIn("--http3", self.by_id["web-cat-social-h3"].commands[0])

    def test_ipv6_twin_mirrors_its_ipv4_original(self):
        """A parity test is only meaningful if the payload is identical."""
        v4 = [tok for tok in self.by_id["ns-uid"].commands[0] if tok.startswith("http")]
        v6 = [tok for tok in self.by_id["ns-uid-v6"].commands[0] if tok.startswith("http")]
        self.assertEqual(v4, v6)

    def test_dns_pack_uses_the_builtin_probe_and_allowed_types(self):
        tunnel = self.by_id["ns-dns-tunnel"]
        self.assertEqual(tunnel.runner, "dns")
        types = [tok.split("=", 1)[1] for cmd in tunnel.commands for tok in cmd
                 if tok.startswith("type=")]
        self.assertTrue(types)
        for qtype in types:
            self.assertIn(qtype, sv.DNS_QTYPES)

    def test_dns_labels_stay_within_the_protocol_limit(self):
        for tid in ("ns-dns-dga", "ns-dns-tunnel"):
            for cmd in self.by_id[tid].commands:
                name = cmd[1]
                for label in name.split("."):
                    self.assertLessEqual(len(label), 63, f"{tid}: {label}")

    def test_doh_targets_are_https_provider_endpoints(self):
        for cmd in self.by_id["ns-doh"].commands:
            url = [t for t in cmd if t.startswith("http")][0]
            self.assertTrue(url.startswith("https://"), url)

    def test_signal_totals_are_countable(self):
        manifest = sv.signal_manifest(self.triggers, self.settings)
        self.assertEqual(manifest["totals"]["triggers_total"], len(self.triggers))
        self.assertGreater(manifest["totals"]["signals_if_gate_enabled"],
                           manifest["totals"]["signals"])


if __name__ == "__main__":
    unittest.main()
