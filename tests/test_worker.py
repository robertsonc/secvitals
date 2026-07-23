"""Worker + runner tests for the Tkinter build.

The console (Windows Python / Tkinter) fires each trigger by shelling ONE worker into
WSL and parsing a single framed JSON result line. These tests exercise that whole path
WITHOUT Windows or WSL, by using the LocalRunner (same code, local Python) and curl
against a closed port for a deterministic `blocked` verdict (rc 7). The security-relevant
re-validation (Trigger.from_dict in the worker) and the base64url/framing contract are
covered directly."""
import base64
import json
import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402

HAVE_CURL = shutil.which("curl") is not None

# A closed loopback port: curl exits 7 (couldn't connect) -> BLOCKED_RC -> blocked. No
# network, no external dependency, and it never collapses into `error`.
CURL_TRIGGER = {
    "id": "t-curl", "label": "closed port", "class": "ns-webcc", "runner": "curl",
    "argv": ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}|", "--max-time", "5",
             "http://127.0.0.1:1/"],
    "flags": [], "severity": "info",
    "expected_on_allow": {"rc": 0}, "expected_on_block": {"rc_nonzero": True},
}


def _spec(trigger=None, params=None, settings=None):
    return {"trigger": trigger or CURL_TRIGGER,
            "params": params or {},
            "settings": settings if settings is not None else {"run": {"control_host": ""}}}


class TestSpecFraming(unittest.TestCase):
    def test_spec_b64_is_url_safe_and_roundtrips(self):
        spec = _spec()
        tok = sv._spec_b64(spec)
        self.assertRegex(tok, r"^[A-Za-z0-9_\-=]+$")   # argv/shell-safe: no spaces or quotes
        back = json.loads(base64.urlsafe_b64decode(tok.encode()).decode())
        self.assertEqual(back, spec)

    def test_extract_result_finds_marker(self):
        out = sv.RESULT_MARKER + '{"state":"blocked","reason":"x"}'
        self.assertEqual(sv._extract_result("banner\n" + out + "\n")["state"], "blocked")

    def test_extract_result_missing_marker_raises(self):
        with self.assertRaises(sv.RunnerError):
            sv._extract_result("just some distro banner\n")

    def test_extract_result_bad_json_raises(self):
        with self.assertRaises(sv.RunnerError):
            sv._extract_result(sv.RESULT_MARKER + "{not json}")


class TestWorkerRun(unittest.TestCase):
    @unittest.skipUnless(HAVE_CURL, "curl not available")
    def test_blocked_is_not_error(self):
        out = sv._worker_run(_spec())
        self.assertEqual(out["state"], sv.BLOCKED)
        self.assertEqual(out["rc"], 7)

    def test_bad_spec_returns_error_not_crash(self):
        self.assertEqual(sv._worker_run("nope")["state"], sv.ERROR)
        self.assertEqual(sv._worker_run({})["state"], sv.ERROR)

    def test_worker_revalidates_catalog_entry(self):
        # A spec whose trigger declares a runner outside the fixed allowlist must be
        # refused by the worker (Trigger.from_dict re-validation), not executed.
        bad = dict(CURL_TRIGGER, runner="bash", argv=["bash", "-c", "echo pwned"])
        out = sv._worker_run(_spec(trigger=bad))
        self.assertEqual(out["state"], sv.ERROR)
        self.assertIn("invalid trigger spec", out["reason"])

    def test_worker_main_emits_single_framed_line(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = sv.worker_main(sv._spec_b64(_spec()))
        self.assertEqual(rc, 0)
        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(sv.RESULT_MARKER))


class TestRunners(unittest.TestCase):
    @unittest.skipUnless(HAVE_CURL, "curl not available")
    def test_local_runner_end_to_end(self):
        out = sv.LocalRunner().run(_spec(), timeout=30)
        self.assertEqual(out["state"], sv.BLOCKED)

    def test_make_runner_is_local_off_windows(self):
        if sys.platform == "win32":
            self.skipTest("runs on non-Windows")
        self.assertIsInstance(sv.make_runner(sv.Settings(raw={})), sv.LocalRunner)

    def test_wsl_runner_argv_uses_e_and_streams_stdin(self):
        r = sv.WslRunner(distro="Ubuntu-22.04", python="python3", source=b"x")
        self.assertEqual(r._argv("TOKEN"),
                         ["wsl.exe", "-d", "Ubuntu-22.04", "-e", "python3", "-", "worker", "TOKEN"])
        # default distro -> no -d
        self.assertEqual(sv.WslRunner(source=b"x")._argv("T"),
                         ["wsl.exe", "-e", "python3", "-", "worker", "T"])

    def test_wsl_runner_without_source_fails_cleanly(self):
        with self.assertRaises(sv.RunnerError):
            sv.WslRunner(source=b"").run(_spec(), timeout=5)

    def test_outer_timeout_scales_iprep(self):
        s = sv.Settings(raw={"webcc": {"ip_rep_sample": 6, "node_probe_timeout_s": 5}})
        self.assertGreater(sv._outer_timeout(s, {"runner": "iprep", "timeout_s": 5}),
                           sv._outer_timeout(s, {"runner": "curl", "timeout_s": 5}))


class TestToSpecRoundTrip(unittest.TestCase):
    def test_trigger_to_spec_revalidates(self):
        t = sv.Trigger.from_dict(CURL_TRIGGER, 30.0)
        t2 = sv.Trigger.from_dict(t.to_spec(), 30.0)
        self.assertEqual(t2.argv, t.argv)
        self.assertEqual(t2.expected_on_allow, t.expected_on_allow)
        self.assertEqual(t2.timeout, t.timeout)


if __name__ == "__main__":
    unittest.main()
