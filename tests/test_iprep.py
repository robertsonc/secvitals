"""Tests for the IP-reputation runner: control probe, ratio reporting, fail-closed."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402


class FakeTor:
    def __init__(self, ips):
        self.ips = ips

    def get(self):
        return self.ips


def mk_app(control_host="1.1.1.1", sample=3):
    settings = sv.Settings(raw={"run": {"control_host": control_host, "control_port": 443},
                                "webcc": {"ip_rep_sample": sample, "node_probe_timeout_s": 1},
                                "evidence": {"log": False}})
    trig = sv.Trigger.from_dict({"id": "ip-rep-tor", "label": "tor", "class": "ns-iprep",
                                 "runner": "iprep", "argv": ["iprep"],
                                 "flags": ["needs_internet"]}, 30.0)
    return sv.App(settings, [trig], "."), trig


class TestParseIps(unittest.TestCase):
    def test_parse(self):
        text = "# comment\n1.2.3.4\n  10.0.0.1  \nnot-an-ip\n999.1.1.1\n8.8.8.8\n"
        self.assertEqual(sv._parse_tor_ips(text), ["1.2.3.4", "10.0.0.1", "8.8.8.8"])


class TestIprep(unittest.TestCase):
    def setUp(self):
        self._orig_probe = sv._tcp_probe
        self._orig_probe_flow = sv._tcp_probe_flow

    def tearDown(self):
        sv._tcp_probe = self._orig_probe
        sv._tcp_probe_flow = self._orig_probe_flow

    def test_control_disabled_is_error(self):
        app, trig = mk_app(control_host="")
        out = app._run_iprep(trig)
        self.assertEqual(out["state"], sv.ERROR)

    def test_control_fail_is_invalid_not_blocked(self):
        app, trig = mk_app()
        sv._tcp_probe = lambda h, p, t: False   # control (and everything) fails
        out = app._run_iprep(trig)
        self.assertEqual(out["state"], sv.INVALID)   # NOT blocked — egress is broken

    def test_ratio(self):
        app, trig = mk_app(sample=4)
        app.tor_cache = FakeTor(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        seq = {"n": 0}

        def fake(host, port, timeout):
            if host == "1.1.1.1":
                return True                  # control OK
            seq["n"] += 1
            return seq["n"] > 3              # first 3 nodes blocked, 4th reached
        sv._tcp_probe = fake
        sv._tcp_probe_flow = lambda h, p, to: (fake(h, p, to), sv._flow("TCP", dst_ip=h, dst_port=p))
        out = app._run_iprep(trig)
        self.assertEqual(out["state"], sv.RATIO)
        self.assertEqual(out["ratio"], {"blocked": 3, "reached": 1, "total": 4})
        self.assertIn("3 of 4", out["reason"])

    def test_tor_fetch_failure_is_error(self):
        app, trig = mk_app()

        class BadTor:
            def get(self):
                raise OSError("no network")
        app.tor_cache = BadTor()
        sv._tcp_probe = lambda h, p, t: True   # control OK
        out = app._run_iprep(trig)
        self.assertEqual(out["state"], sv.ERROR)

    def test_empty_node_list_is_error(self):
        app, trig = mk_app()
        app.tor_cache = FakeTor([])
        sv._tcp_probe = lambda h, p, t: True
        out = app._run_iprep(trig)
        self.assertEqual(out["state"], sv.ERROR)

    def test_iprep_gated_by_default_via_app_run(self):
        # ip-rep-tor carries hits_live_suspect_hosts; with the gate off it must not run.
        settings = sv.Settings(raw={"enable_live_suspect_hosts": False,
                                    "run": {"control_host": "1.1.1.1"},
                                    "evidence": {"log": False}})
        trig = sv.Trigger.from_dict({"id": "ip-rep-tor", "label": "tor", "class": "ns-iprep",
                                     "runner": "iprep", "argv": ["iprep"],
                                     "flags": ["needs_internet", "hits_live_suspect_hosts"]}, 30.0)
        app = sv.App(settings, [trig], ".")
        sv._tcp_probe = lambda h, p, t: True
        _, out = app.run("ip-rep-tor", {})
        self.assertEqual(out["state"], sv.INVALID)
        self.assertIn("disabled", out["reason"])


if __name__ == "__main__":
    unittest.main()
