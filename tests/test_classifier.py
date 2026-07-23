"""Tests for the three-state classifier — `blocked` and `error` must never collapse.
Covers curl exit-code mapping, the native dns/tcp control-probe disambiguation, and the
multi-request aggregation (blocked only when EVERY reachable request was dropped)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secvitals as sv  # noqa: E402


def mk_trigger(runner="curl", commands=None, **kw):
    base = dict(
        id="t", label="t", cls="ns-ids", runner=runner,
        commands=commands or [["curl", "http://x"]],
        flags=[], severity="info", threat_class="", expected_fire="", talking_point="",
        expected_on_allow={}, expected_on_block={}, params=[], timeout=30.0,
    )
    base.update(kw)
    return sv.Trigger(**base)


def curl_sub(rc, http):
    return sv.SubResult(argv=["curl", "http://x"], rc=rc, http_code=http)


def probe_sub(ok, err=None):
    return sv.SubResult(argv=["dns", "x", "@8.8.8.8"], ok=ok, error_reason=err)


class TestCurlClassifier(unittest.TestCase):
    def test_allowed_and_block_pages(self):
        self.assertEqual(sv.classify_curl(0, 200), sv.ALLOWED)
        self.assertEqual(sv.classify_curl(0, 403), sv.BLOCKED)
        self.assertEqual(sv.classify_curl(0, 451), sv.BLOCKED)

    def test_blocked_rc_are_blocked(self):
        for rc in (28, 7, 56):
            self.assertEqual(sv.classify_curl(rc, None), sv.BLOCKED, rc)

    def test_broken_rc_are_error_not_blocked(self):
        for rc in (6, 5, 35, 60, 77):
            self.assertEqual(sv.classify_curl(rc, None), sv.ERROR, rc)

    def test_unknown_rc_is_error(self):
        self.assertEqual(sv.classify_curl(99, None), sv.ERROR)
        self.assertEqual(sv.classify_curl(1, None), sv.ERROR)

    def test_rc0_unparsed_code_is_error(self):
        self.assertEqual(sv.classify_curl(0, None), sv.ERROR)


class TestSingleRequestClassify(unittest.TestCase):
    def test_curl_allowed(self):
        t = mk_trigger("curl")
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[curl_sub(0, 200)]))[0], sv.ALLOWED)

    def test_curl_blocked(self):
        t = mk_trigger("curl")
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[curl_sub(7, None)]))[0], sv.BLOCKED)

    def test_curl_broken_is_error(self):
        t = mk_trigger("curl")
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[curl_sub(6, None)]))[0], sv.ERROR)

    def test_trigger_level_error_wins(self):
        t = mk_trigger("curl")
        self.assertEqual(sv.classify(t, sv.RunResult(error_reason="invalid parameters"))[0], sv.ERROR)

    def test_timeout_is_error(self):
        t = mk_trigger("curl")
        s = sv.SubResult(argv=["curl"], timed_out=True)
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[s]))[0], sv.ERROR)


class TestProbeClassify(unittest.TestCase):
    def test_probe_reached_is_allowed(self):
        t = mk_trigger("dns")
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[probe_sub(True)]))[0], sv.ALLOWED)

    def test_probe_failed_control_ok_is_blocked(self):
        # the probe didn't complete but general egress works -> dropped inline.
        t = mk_trigger("dns")
        r = sv.RunResult(subs=[probe_sub(False)], control_ok=True)
        self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED)

    def test_probe_failed_control_broken_is_error(self):
        # egress itself is broken -> environment, never a false blocked.
        t = mk_trigger("dns")
        r = sv.RunResult(subs=[probe_sub(False)], control_ok=False)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_probe_env_error_is_error(self):
        t = mk_trigger("tcp")
        r = sv.RunResult(subs=[probe_sub(False, err="could not resolve host")], control_ok=True)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)


class TestMultiRequestAggregate(unittest.TestCase):
    def test_all_allowed(self):
        t = mk_trigger("curl")
        r = sv.RunResult(subs=[curl_sub(0, 200), curl_sub(0, 200), curl_sub(0, 302)])
        self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)

    def test_all_blocked(self):
        t = mk_trigger("curl")
        r = sv.RunResult(subs=[curl_sub(28, None), curl_sub(7, None)])
        state, reason = sv.classify(t, r)
        self.assertEqual(state, sv.BLOCKED)
        self.assertIn("2 blocked", reason)

    def test_all_env_error(self):
        t = mk_trigger("curl")
        r = sv.RunResult(subs=[curl_sub(6, None), curl_sub(60, None)])
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)   # not a false blocked

    def test_mixed_never_hides_the_split(self):
        # 1 allowed + 1 blocked: reported honestly with the breakdown, not a clean block.
        t = mk_trigger("curl")
        r = sv.RunResult(subs=[curl_sub(0, 200), curl_sub(7, None)])
        state, reason = sv.classify(t, r)
        self.assertIn("1 allowed / 1 blocked", reason)
        self.assertIn(state, (sv.ALLOWED, sv.BLOCKED))

    def test_blocked_only_when_all_reachable_dropped(self):
        # 1 env-error + 1 blocked: the reachable one was dropped -> blocked (error excluded).
        t = mk_trigger("curl")
        r = sv.RunResult(subs=[curl_sub(6, None), curl_sub(28, None)])
        self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED)


if __name__ == "__main__":
    unittest.main()
