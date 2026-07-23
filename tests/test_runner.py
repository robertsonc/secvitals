"""Tests for the runner: argv construction (allowlist) and subprocess execution."""
import os
import socket
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402


def mk_trigger(**kw):
    base = dict(
        id="t", label="t", cls="ns-ids", runner="tmnids", argv=["tmNIDS", "-1"],
        flags=[], severity="info", threat_class="", expected_fire="", talking_point="",
        expected_on_allow={"rc": 0, "body_contains": "uid=0"},
        expected_on_block={"rc_nonzero": True}, params=[], timeout=30.0,
    )
    base.update(kw)
    return sv.Trigger(**base)


class FakeCache:
    def __init__(self, path=None, err=None):
        self._path = path
        self._err = err

    def ensure(self):
        if self._err:
            raise sv.TmnidsError(self._err)
        return self._path


class TestBuildArgv(unittest.TestCase):
    def test_fixed_argv_no_params(self):
        t = mk_trigger(argv=["tmNIDS", "-1"], params=[])
        self.assertEqual(sv.build_argv(t, {}), ["tmNIDS", "-1"])

    def test_allowlist_param(self):
        t = mk_trigger(runner="curl", argv=["curl", "{target}"],
                       params=[{"name": "target", "allow": ["a.example", "b.example"]}])
        self.assertEqual(sv.build_argv(t, {"target": "a.example"}), ["curl", "a.example"])
        with self.assertRaises(sv.ParamError):
            sv.build_argv(t, {"target": "evil.example"})

    def test_pattern_param(self):
        t = mk_trigger(runner="tmnids", argv=["tmNIDS", "{sel}"],
                       params=[{"name": "sel", "pattern": r"-\d+"}])
        self.assertEqual(sv.build_argv(t, {"sel": "-3"}), ["tmNIDS", "-3"])
        with self.assertRaises(sv.ParamError):
            sv.build_argv(t, {"sel": "; rm -rf /"})

    def test_missing_required_param(self):
        t = mk_trigger(runner="curl", argv=["curl", "{target}"],
                       params=[{"name": "target", "allow": ["a"]}])
        with self.assertRaises(sv.ParamError):
            sv.build_argv(t, {})

    def test_unknown_param_rejected(self):
        t = mk_trigger(params=[])
        with self.assertRaises(sv.ParamError):
            sv.build_argv(t, {"surprise": "x"})

    def test_non_string_param_rejected(self):
        t = mk_trigger(runner="curl", argv=["curl", "{target}"],
                       params=[{"name": "target", "allow": ["a"]}])
        with self.assertRaises(sv.ParamError):
            sv.build_argv(t, {"target": 5})


class TestRunTrigger(unittest.TestCase):
    def _stub(self, body, code):
        fd, path = tempfile.mkstemp(prefix="stub-", suffix=".py")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env python3\n")
            fh.write("import sys\n")
            fh.write("sys.stdout.write(%r)\n" % body)
            fh.write("sys.exit(%d)\n" % code)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IRUSR)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def test_tmnids_allowed(self):
        stub = self._stub("uid=0(root) gid=0(root)\n", 0)
        t = mk_trigger(runner="tmnids", argv=["tmNIDS", "-1"])
        r = sv.run_trigger(t, {}, sv.Settings(raw={}), FakeCache(path=stub))
        self.assertEqual(r.rc, 0)
        self.assertIn("uid=0", r.stdout)
        self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)
        # the resolved argv[0] is the stub, not the literal "tmNIDS"
        self.assertEqual(r.argv[0], stub)

    def test_tmnids_blocked_predicate_fallback(self):
        # control disabled => deterministic fallback to expected_on_block {rc_nonzero}.
        stub = self._stub("", 7)
        t = mk_trigger(runner="tmnids", argv=["tmNIDS", "-1"])
        noctrl = sv.Settings(raw={"run": {"control_host": ""}})
        r = sv.run_trigger(t, {}, noctrl, FakeCache(path=stub))
        self.assertEqual(r.rc, 7)
        self.assertIsNone(r.control_ok)   # probe not run
        self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED)

    def test_tmnids_binary_unavailable_is_error(self):
        t = mk_trigger(runner="tmnids", argv=["tmNIDS", "-1"])
        r = sv.run_trigger(t, {}, sv.Settings(raw={}), FakeCache(err="download failed"))
        self.assertIsNotNone(r.error_reason)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_tmnids_selector_guard(self):
        t = mk_trigger(runner="tmnids", argv=["tmNIDS", "-999"])
        r = sv.run_trigger(t, {}, sv.Settings(raw={}), FakeCache(path="/nonexistent"))
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_curl_http_code_parsed(self):
        t = mk_trigger(runner="curl", argv=[sys.executable, "-c", "print('200|12|http://x')"],
                       expected_on_allow={}, expected_on_block={})
        r = sv.run_trigger(t, {}, sv.Settings(raw={}), FakeCache())
        self.assertEqual(r.http_code, 200)
        self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)

    def test_curl_blocked_rc(self):
        t = mk_trigger(runner="curl", argv=[sys.executable, "-c", "import sys;sys.exit(28)"],
                       expected_on_allow={}, expected_on_block={})
        r = sv.run_trigger(t, {}, sv.Settings(raw={}), FakeCache())
        self.assertEqual(r.rc, 28)
        self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED)

    def test_curl_broken_rc_is_error(self):
        t = mk_trigger(runner="curl", argv=[sys.executable, "-c", "import sys;sys.exit(6)"],
                       expected_on_allow={}, expected_on_block={})
        r = sv.run_trigger(t, {}, sv.Settings(raw={}), FakeCache())
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_env_error_signature_forces_error(self):
        # tmNIDS stub that "fails to resolve" and exits nonzero must be error, not blocked.
        fd, path = tempfile.mkstemp(prefix="stub-", suffix=".py")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env python3\nimport sys\n")
            fh.write("sys.stderr.write('curl: (6) Could not resolve host: testmynids.org\\n')\n")
            fh.write("sys.exit(6)\n")
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        t = mk_trigger(runner="tmnids", argv=["tmNIDS", "-1"])
        r = sv.run_trigger(t, {}, sv.Settings(raw={}), FakeCache(path=path))
        self.assertIsNotNone(r.error_reason)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_executable_not_found_is_error(self):
        t = mk_trigger(runner="curl", argv=["/nonexistent/binary-xyz"],
                       expected_on_allow={}, expected_on_block={})
        r = sv.run_trigger(t, {}, sv.Settings(raw={}), FakeCache())
        self.assertIsNotNone(r.error_reason)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)


class TestTcpProbe(unittest.TestCase):
    def test_open_port_true(self):
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        port = ls.getsockname()[1]
        try:
            self.assertTrue(sv._tcp_probe("127.0.0.1", port, 2))
        finally:
            ls.close()

    def test_closed_port_false(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()   # nothing listening on `port` now
        self.assertFalse(sv._tcp_probe("127.0.0.1", port, 1))


if __name__ == "__main__":
    unittest.main()
