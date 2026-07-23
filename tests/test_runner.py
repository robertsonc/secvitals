"""Tests for the native runner: command building (allowlist + {devnull}), curl execution
via a stub interpreter, and the dns / tcp stdlib probes with control-probe honesty."""
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402


def mk_trigger(runner="curl", commands=None, params=None, **kw):
    base = dict(
        id="t", label="t", cls="ns-ids", runner=runner,
        commands=commands or [["curl", "http://x"]],
        flags=[], severity="info", threat_class="", expected_fire="", talking_point="",
        expected_on_allow={}, expected_on_block={}, params=params or [], timeout=15.0,
    )
    base.update(kw)
    return sv.Trigger(**base)


class TestBuildCommand(unittest.TestCase):
    def test_devnull_substituted(self):
        argv = sv.build_command(["curl", "-o", sv.DEVNULL_TOKEN, "http://x"], {})
        self.assertEqual(argv, ["curl", "-o", os.devnull, "http://x"])

    def test_resolve_allowlist(self):
        t = mk_trigger(runner="curl", commands=[["curl", "{target}"]],
                       params=[{"name": "target", "allow": ["a.example", "b.example"]}])
        resolved = sv._resolve_params(t, {"target": "a.example"})
        self.assertEqual(sv.build_command(t.commands[0], resolved), ["curl", "a.example"])
        with self.assertRaises(sv.ParamError):
            sv._resolve_params(t, {"target": "evil.example"})

    def test_resolve_pattern(self):
        t = mk_trigger(runner="curl", commands=[["curl", "{sel}"]],
                       params=[{"name": "sel", "pattern": r"-\d+"}])
        self.assertEqual(sv.build_command(t.commands[0], sv._resolve_params(t, {"sel": "-3"})),
                         ["curl", "-3"])
        with self.assertRaises(sv.ParamError):
            sv._resolve_params(t, {"sel": "; rm -rf /"})

    def test_missing_required(self):
        t = mk_trigger(commands=[["curl", "{target}"]],
                       params=[{"name": "target", "allow": ["a"]}])
        with self.assertRaises(sv.ParamError):
            sv._resolve_params(t, {})

    def test_unknown_param(self):
        with self.assertRaises(sv.ParamError):
            sv._resolve_params(mk_trigger(params=[]), {"surprise": "x"})

    def test_non_string_param(self):
        t = mk_trigger(commands=[["curl", "{target}"]], params=[{"name": "target", "allow": ["a"]}])
        with self.assertRaises(sv.ParamError):
            sv._resolve_params(t, {"target": 5})

    def test_unresolved_token_refused(self):
        with self.assertRaises(sv.ParamError):
            sv.build_command(["curl", "{missing}"], {})


def _curl_stub(code, out=""):
    # A fake "curl": prints the -w line, exits with `code`. Used as the command's argv[0..].
    return [sys.executable, "-c", "import sys; sys.stdout.write(%r); sys.exit(%d)" % (out, code)]


class TestRunCurl(unittest.TestCase):
    def _run(self, code, out="", settings=None):
        t = mk_trigger("curl", commands=[_curl_stub(code, out)])
        return t, sv.run_trigger(t, {}, settings or sv.Settings(raw={}))

    def test_http_code_parsed_and_allowed(self):
        t, r = self._run(0, "200|12|http://x")
        self.assertEqual(r.subs[0].http_code, 200)
        self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)

    def test_blocked_rc(self):
        t, r = self._run(28)
        self.assertEqual(r.subs[0].rc, 28)
        self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED)

    def test_broken_rc_is_error(self):
        t, r = self._run(6)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_missing_binary_is_error(self):
        t = mk_trigger("curl", commands=[["/nonexistent/curl-xyz", "http://x"]])
        r = sv.run_trigger(t, {}, sv.Settings(raw={}))
        self.assertIsNotNone(r.subs[0].error_reason)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_multi_command_all_run(self):
        t = mk_trigger("curl", commands=[_curl_stub(0, "200|"), _curl_stub(0, "204|"), _curl_stub(0, "302|")])
        r = sv.run_trigger(t, {}, sv.Settings(raw={}))
        self.assertEqual(len(r.subs), 3)
        self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)


class TestCurlFlowCapture(unittest.TestCase):
    def test_marker_parsed_and_stripped(self):
        # The stub prints curl's http_code line plus our injected 5-tuple marker line.
        out = "200|\n%s|10.0.0.5|51000|93.184.216.34|80" % sv.FLOW_MARK
        t = mk_trigger("curl", commands=[_curl_stub(0, out)])
        r = sv.run_trigger(t, {}, sv.Settings(raw={}))
        s = r.subs[0]
        self.assertEqual(s.http_code, 200)
        self.assertNotIn(sv.FLOW_MARK, s.stdout)            # marker never reaches the details pane
        self.assertEqual(s.flow, {"proto": "TCP", "src_ip": "10.0.0.5", "src_port": "51000",
                                  "dst_ip": "93.184.216.34", "dst_port": "80", "host": ""})

    def test_flow_argv_extends_writeout(self):
        argv = sv._curl_flow_argv(["curl", "-w", "%{http_code}|", "http://x"])
        self.assertIn(sv.FLOW_MARK, argv[argv.index("-w") + 1])
        added = sv._curl_flow_argv(["curl", "http://x"])     # no -w in the command
        self.assertEqual(added[-2], "-w")
        self.assertIn(sv.FLOW_MARK, added[-1])

    def test_format_flows_hides_all_empty(self):
        self.assertEqual(sv._format_flows([sv._flow("TCP")]), "")
        table = sv._format_flows([sv._flow("TCP", "10.0.0.1", "5000", "1.2.3.4", "80", host="x.example")])
        self.assertIn("SRC-PORT", table)
        self.assertIn("1.2.3.4", table)


class TestDnsProbe(unittest.TestCase):
    def test_no_response_needs_control(self):
        # 192.0.2.1 is TEST-NET-1 (RFC5737) — guaranteed no DNS reply, so the probe times
        # out. With egress control OK that reads as blocked; with control broken, error.
        t = mk_trigger("dns", commands=[["dns", "example.com", "@192.0.2.1"]], timeout=2.0)
        orig = sv._tcp_probe
        try:
            sv._tcp_probe = lambda h, p, to: True                 # egress control OK
            self.assertEqual(sv.classify(t, sv.run_trigger(t, {}, sv.Settings(raw={})))[0], sv.BLOCKED)
            sv._tcp_probe = lambda h, p, to: False                # egress broken
            self.assertEqual(sv.classify(t, sv.run_trigger(t, {}, sv.Settings(raw={})))[0], sv.ERROR)
        finally:
            sv._tcp_probe = orig

    def test_control_disabled_no_probe(self):
        t = mk_trigger("dns", commands=[["dns", "example.com", "@192.0.2.1"]], timeout=2.0)
        r = sv.run_trigger(t, {}, sv.Settings(raw={"run": {"control_host": ""}}))
        self.assertIsNone(r.control_ok)


class TestTcpProbe(unittest.TestCase):
    def test_connect_reached_is_allowed(self):
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        port = ls.getsockname()[1]
        try:
            t = mk_trigger("tcp", commands=[["tcp-connect", "127.0.0.1", str(port)]])
            r = sv.run_trigger(t, {}, sv.Settings(raw={}))
            self.assertTrue(r.subs[0].ok)
            self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)
        finally:
            ls.close()

    def test_refused_needs_control(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        t = mk_trigger("tcp", commands=[["tcp-connect", "127.0.0.1", str(port)]])
        orig = sv._tcp_probe
        try:
            sv._tcp_probe = lambda h, p, to: True
            self.assertEqual(sv.classify(t, sv.run_trigger(t, {}, sv.Settings(raw={})))[0], sv.BLOCKED)
        finally:
            sv._tcp_probe = orig

    def test_tcp_probe_helper(self):
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        port = ls.getsockname()[1]
        try:
            self.assertTrue(sv._tcp_probe("127.0.0.1", port, 2))
        finally:
            ls.close()


if __name__ == "__main__":
    unittest.main()
