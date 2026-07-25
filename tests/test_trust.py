"""Tests for M5 trust & robustness: multi-endpoint control probing, catalog signing,
pre-flight readiness, graceful curl-absent handling, and ERROR-only origin failover.

Each of these touches the honesty boundary, so the assertions are about what the app
refuses to claim: a control probe that no longer masks real blocks, a readiness check
that never predicts policy, and a failover that never launders a policy result."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(HERE, "config")
HAVE_OPENSSL = shutil.which("openssl") is not None


class FakeProc:
    def __init__(self, rc=0, stdout=b""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = b""


def _stub(code, out=""):
    return [sys.executable, "-c", "import sys; sys.stdout.write(%r); sys.exit(%d)" % (out, code)]


def mk_trigger(tid="t", runner="curl", commands=None):
    return sv.Trigger(
        id=tid, label=tid, cls="ns-ids", runner=runner,
        commands=commands or [["curl", "http://x"]], flags=[], severity="info",
        threat_class="recon", expected_fire="", talking_point="",
        expected_on_allow={}, expected_on_block={}, params=[], timeout=15.0,
    )


class TestControlEndpoints(unittest.TestCase):
    def setUp(self):
        self.original = sv._tcp_probe

    def tearDown(self):
        sv._tcp_probe = self.original

    def test_legacy_single_host_still_works(self):
        settings = sv.Settings(raw={"run": {"control_host": "1.1.1.1", "control_port": 443}})
        self.assertEqual(settings.control_endpoints, [("tcp", "1.1.1.1", 443)])
        self.assertTrue(settings.control_enabled)

    def test_disabled_when_nothing_configured(self):
        settings = sv.Settings(raw={"run": {"control_host": ""}})
        self.assertEqual(settings.control_endpoints, [])
        self.assertFalse(settings.control_enabled)
        ok, detail = sv.probe_control(settings)
        self.assertIsNone(ok)
        self.assertIn("no control endpoint", detail)

    def test_one_filtered_endpoint_no_longer_masks_real_blocks(self):
        """The whole point: a customer denying 1.1.1.1 must not turn every inline block
        into an `error`."""
        settings = sv.Settings(raw={"run": {"control_endpoints": [
            {"host": "1.1.1.1", "port": 443},
            {"host": "9.9.9.9", "port": 443},
        ]}})
        sv._tcp_probe = lambda h, p, t: h == "9.9.9.9"      # first is filtered
        ok, detail = sv.probe_control(settings)
        self.assertTrue(ok)
        self.assertIn("9.9.9.9", detail)

    def test_all_failing_means_egress_is_broken(self):
        settings = sv.Settings(raw={"run": {"control_endpoints": [
            {"host": "1.1.1.1", "port": 443}, {"host": "9.9.9.9", "port": 443}]}})
        sv._tcp_probe = lambda h, p, t: False
        ok, detail = sv.probe_control(settings)
        self.assertFalse(ok)
        self.assertIn("all control endpoints failed", detail)

    def test_transport_matching_prefers_the_right_kind(self):
        """A network permitting DNS but denying TCP/443 must not fail a DNS trigger."""
        settings = sv.Settings(raw={"run": {"control_endpoints": [
            {"host": "1.1.1.1", "port": 443, "kind": "tcp"},
            {"host": "8.8.8.8", "port": 53, "kind": "dns"},
        ]}})
        tried = []
        sv._tcp_probe = lambda h, p, t: tried.append(("tcp", h)) or False
        original_dns = sv._dns_query
        try:
            sv._dns_query = lambda n, s, t: (tried.append(("dns", s)) or (True, "ok", None, None))
            ok, detail = sv.probe_control(settings, prefer_kind="dns")
        finally:
            sv._dns_query = original_dns
        self.assertTrue(ok)
        self.assertEqual(tried[0][0], "dns")        # DNS was tried FIRST
        self.assertIn("8.8.8.8", detail)

    def test_malformed_endpoints_are_skipped_not_fatal(self):
        settings = sv.Settings(raw={"run": {"control_endpoints": [
            {"host": ""}, {"port": 443}, "nonsense", {"host": "9.9.9.9", "port": 70000},
            {"host": "1.1.1.1", "port": 443}]}})
        self.assertEqual(settings.control_endpoints, [("tcp", "1.1.1.1", 443)])

    def test_probe_result_is_recorded_for_the_details_pane(self):
        trigger = mk_trigger("dnst", runner="dns",
                             commands=[["dns", "example.com", "@192.0.2.1"]])
        settings = sv.Settings(raw={"run": {"control_host": "1.1.1.1"}})
        sv._tcp_probe = lambda h, p, t: True
        result = sv.run_trigger(trigger, {}, settings)
        self.assertTrue(result.control_ok)
        self.assertIn("egress confirmed", result.control_detail)
        self.assertEqual(sv.classify(trigger, result)[0], sv.BLOCKED)


class TestCatalogSignature(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sv-cat-")
        self.cfg = os.path.join(self.dir, "config")
        os.makedirs(self.cfg)
        shutil.copy(os.path.join(CONFIG, "catalog.yaml"),
                    os.path.join(self.cfg, "catalog.yaml"))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_unsigned_is_reported_not_refused(self):
        """Existing installs have no signature and must keep working."""
        status, detail = sv.catalog_signature_status(self.cfg)
        self.assertEqual(status, sv.CATALOG_UNSIGNED)
        self.assertIn("not authenticated", detail)

    def test_missing_catalog_is_reported(self):
        status, _ = sv.catalog_signature_status(os.path.join(self.dir, "nope"))
        self.assertEqual(status, sv.CATALOG_MODIFIED)

    def test_garbage_signature_does_not_verify(self):
        with open(os.path.join(self.cfg, "catalog.yaml.sig"), "wb") as fh:
            fh.write(b"not a signature")
        status, _ = sv.catalog_signature_status(self.cfg)
        self.assertEqual(status, sv.CATALOG_MODIFIED)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not available")
    def test_sign_verify_and_tamper_round_trip(self):
        priv = os.path.join(self.dir, "k_priv.pem")
        pub = os.path.join(self.dir, "k_pub.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", priv],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub],
                       check=True, capture_output=True)
        pubkey = open(pub, encoding="utf-8").read()
        catalog = os.path.join(self.cfg, "catalog.yaml")
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv,
                        "-out", catalog + ".sig", catalog], check=True, capture_output=True)

        self.assertEqual(sv.catalog_signature_status(self.cfg, pubkey)[0], sv.CATALOG_VERIFIED)
        # a single appended byte must invalidate it
        with open(catalog, "a", encoding="utf-8") as fh:
            fh.write("\n# tampered\n")
        self.assertEqual(sv.catalog_signature_status(self.cfg, pubkey)[0], sv.CATALOG_MODIFIED)

    @unittest.skipUnless(HAVE_OPENSSL, "openssl not available")
    def test_a_different_key_does_not_verify(self):
        catalog = os.path.join(self.cfg, "catalog.yaml")
        priv = os.path.join(self.dir, "other_priv.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", priv],
                       check=True, capture_output=True)
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv,
                        "-out", catalog + ".sig", catalog], check=True, capture_output=True)
        # signed with a key the app does not trust
        self.assertEqual(sv.catalog_signature_status(self.cfg)[0], sv.CATALOG_MODIFIED)

    def test_strict_mode_refuses_an_unsigned_catalog(self):
        shutil.copy(os.path.join(CONFIG, "settings.yaml"),
                    os.path.join(self.cfg, "settings.yaml"))
        code = sv.main(["--config-dir", self.cfg, "--strict-catalog", "--list"])
        self.assertEqual(code, 2)

    def test_default_mode_starts_with_an_unsigned_catalog(self):
        import io
        shutil.copy(os.path.join(CONFIG, "settings.yaml"),
                    os.path.join(self.cfg, "settings.yaml"))
        saved, sys.stdout = sys.stdout, io.StringIO()
        try:
            code = sv.main(["--config-dir", self.cfg, "--list"])
        finally:
            sys.stdout = saved
        self.assertEqual(code, 0)


class TestCurlAbsent(unittest.TestCase):
    def setUp(self):
        sv.reset_environment_cache()

    def tearDown(self):
        sv.reset_environment_cache()

    def test_missing_curl_reports_invalid_with_a_fix_not_a_wall_of_errors(self):
        sv.curl_present(_runner=lambda: FakeProc(rc=127))
        app = sv.App(sv.Settings(raw={"run": {"min_interval_s": 0}}), [mk_trigger("a")], CONFIG)
        _t, out = app.run("a", {})
        self.assertEqual(out["state"], sv.INVALID)
        self.assertIn("curl was not found", out["reason"])
        self.assertIn("not a policy result", out["reason"])

    def test_present_curl_does_not_gate_anything(self):
        sv.curl_present(_runner=lambda: FakeProc(rc=0, stdout=b"curl 8.5.0\n"))
        settings = sv.Settings(raw={"run": {"min_interval_s": 0, "control_host": ""}})
        app = sv.App(settings, [mk_trigger("a", commands=[_stub(0, "200|")])], CONFIG)
        _t, out = app.run("a", {})
        self.assertEqual(out["state"], sv.ALLOWED)

    def test_curl_absence_is_cached(self):
        calls = {"n": 0}

        def counting():
            calls["n"] += 1
            return FakeProc(rc=0, stdout=b"curl 8.5.0\n")
        sv.curl_present(_runner=counting)
        sv.curl_present(_runner=counting)
        self.assertEqual(calls["n"], 1)

    def test_exec_failure_is_not_fatal(self):
        def boom():
            raise OSError("nope")
        present, detail = sv.curl_present(_runner=boom)
        self.assertFalse(present)
        self.assertTrue(detail)


class TestPreflight(unittest.TestCase):
    def setUp(self):
        sv.reset_environment_cache()
        self.original = sv._tcp_probe

    def tearDown(self):
        sv.reset_environment_cache()
        sv._tcp_probe = self.original

    def test_ready_when_curl_and_egress_are_fine(self):
        sv.curl_present(_runner=lambda: FakeProc(rc=0, stdout=b"curl 8.5.0\n"))
        sv._tcp_probe = lambda h, p, t: True
        report = sv.environment_report(sv.Settings(raw={"run": {"control_host": "1.1.1.1"}}))
        self.assertTrue(report["ready"])
        self.assertIn("Ready", report["verdict"])

    def test_not_ready_when_curl_is_missing(self):
        sv.curl_present(_runner=lambda: FakeProc(rc=127))
        sv._tcp_probe = lambda h, p, t: True
        report = sv.environment_report(sv.Settings(raw={"run": {"control_host": "1.1.1.1"}}))
        self.assertFalse(report["ready"])
        curl_check = [c for c in report["checks"] if c["name"] == "curl"][0]
        self.assertFalse(curl_check["ok"])

    def test_report_never_predicts_policy(self):
        """A readiness gate that implied a verdict would put a guess on stage next to
        real results."""
        sv.curl_present(_runner=lambda: FakeProc(rc=0, stdout=b"curl 8.5.0\n"))
        sv._tcp_probe = lambda h, p, t: True
        report = sv.environment_report(sv.Settings(raw={"run": {"control_host": "1.1.1.1"}}))
        text = sv.format_environment_report(report)
        self.assertIn("says nothing about whether any trigger will be allowed or blocked",
                      report["note"])
        self.assertIn("readiness check only", text)
        for word in ("will be blocked", "predicts", "expect a block"):
            self.assertNotIn(word, text)

    def test_exit_code_reflects_readiness_only(self):
        sv.curl_present(_runner=lambda: FakeProc(rc=127))
        sv._tcp_probe = lambda h, p, t: True
        import io
        saved, sys.stdout = sys.stdout, io.StringIO()
        try:
            code = sv.main(["--config-dir", CONFIG, "--preflight"])
        finally:
            sys.stdout = saved
        self.assertEqual(code, 1)          # not ready
        self.assertTrue(sv.parse_args(["--preflight"]).preflight)


class TestOriginFailover(unittest.TestCase):
    def test_off_by_default(self):
        self.assertEqual(sv.Settings(raw={}).origin_failover, {})

    def test_swap_rewrites_only_the_host(self):
        argv = ["curl", "-A", "http://not-a-url-agent", "-H", "Host: keepme",
                "http://origin.example/uid/index.html?a=b"]
        out = sv._swap_url_host(argv, "origin.example", "alt.example")
        self.assertEqual(out[-1], "http://alt.example/uid/index.html?a=b")
        self.assertEqual(out[1:5], argv[1:5])        # headers and UA untouched
        self.assertEqual(out[2], "http://not-a-url-agent")   # non-matching host untouched

    def test_swap_preserves_port_and_userinfo(self):
        out = sv._swap_url_host(["curl", "https://u:p@origin.example:8443/x"],
                                "origin.example", "alt.example")
        self.assertEqual(out[1], "https://u:p@alt.example:8443/x")

    def test_failover_only_fires_on_an_environment_error(self):
        settings = sv.Settings(raw={"run": {"origin_failover": {"origin.example": "alt.example"}}})
        calls = []
        original = sv._run_curl

        def fake(argv, timeout):
            calls.append(argv)
            host, _ = sv._url_endpoint(argv)
            if host == "origin.example":
                return sv.SubResult(argv=argv, rc=6)          # DNS failure -> ERROR
            return sv.SubResult(argv=argv, rc=0, http_code=200)
        try:
            sv._run_curl = fake
            sub = sv._run_curl_with_failover(["curl", "http://origin.example/x"], 5, settings)
        finally:
            sv._run_curl = original
        self.assertEqual(len(calls), 2)
        self.assertEqual(sub.failover_from, "origin.example")
        self.assertEqual(sub.rc, 0)

    def test_a_blocked_result_is_never_laundered_through_a_failover(self):
        """A policy outcome is the answer; retrying it elsewhere would hide it."""
        settings = sv.Settings(raw={"run": {"origin_failover": {"origin.example": "alt.example"}}})
        calls = []
        original = sv._run_curl
        try:
            sv._run_curl = lambda argv, timeout: (calls.append(argv)
                                                  or sv.SubResult(argv=argv, rc=28))
            sub = sv._run_curl_with_failover(["curl", "http://origin.example/x"], 5, settings)
        finally:
            sv._run_curl = original
        self.assertEqual(len(calls), 1)          # no retry
        self.assertEqual(sub.rc, 28)
        self.assertEqual(sub.failover_from, "")

    def test_a_failing_failover_keeps_the_original_error(self):
        settings = sv.Settings(raw={"run": {"origin_failover": {"origin.example": "alt.example"}}})
        original = sv._run_curl
        try:
            sv._run_curl = lambda argv, timeout: sv.SubResult(argv=argv, rc=6)
            sub = sv._run_curl_with_failover(["curl", "http://origin.example/x"], 5, settings)
        finally:
            sv._run_curl = original
        self.assertEqual(sub.rc, 6)
        self.assertEqual(sub.failover_from, "")   # nothing to claim

    def test_failover_is_visible_in_the_details(self):
        sub = sv.SubResult(argv=["curl", "http://alt.example/x"], rc=0, http_code=200,
                           failover_from="origin.example")
        text = sv._format_subs([sub])
        self.assertIn("ORIGIN FAILOVER", text)
        self.assertIn("verify the alternate serves the same content", text)


if __name__ == "__main__":
    unittest.main()
