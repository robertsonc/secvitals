"""Tests for the three-state classifier — `blocked` and `error` must never collapse."""
import os
import sys
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


class TestCurlClassifier(unittest.TestCase):
    def test_allowed_and_block_pages(self):
        self.assertEqual(sv.classify_curl(0, 200), sv.ALLOWED)
        self.assertEqual(sv.classify_curl(0, 403), sv.BLOCKED)
        self.assertEqual(sv.classify_curl(0, 451), sv.BLOCKED)

    def test_blocked_rc_are_blocked(self):
        for rc in (28, 7, 56):
            self.assertEqual(sv.classify_curl(rc, None), sv.BLOCKED, rc)

    def test_broken_rc_are_error_not_blocked(self):
        # The whole point: environment failures must not read as policy blocks.
        for rc in (6, 5, 35, 60, 77):
            self.assertEqual(sv.classify_curl(rc, None), sv.ERROR, rc)

    def test_unknown_rc_is_error(self):
        self.assertEqual(sv.classify_curl(99, None), sv.ERROR)
        self.assertEqual(sv.classify_curl(1, None), sv.ERROR)

    def test_rc0_unparsed_code_is_error(self):
        # rc==0 but http_code couldn't be parsed: can't confirm a pass — fail honest.
        self.assertEqual(sv.classify_curl(0, None), sv.ERROR)


class TestTmnidsClassifier(unittest.TestCase):
    def test_allowed(self):
        t = mk_trigger()
        r = sv.RunResult(rc=0, stdout="uid=0(root) gid=0(root)")
        self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)

    def test_blocked_on_nonzero(self):
        t = mk_trigger()
        r = sv.RunResult(rc=7, stdout="")
        self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED)

    def test_error_reason_wins(self):
        t = mk_trigger()
        r = sv.RunResult(rc=0, stdout="uid=0", error_reason="tmNIDS binary unavailable")
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_ambiguous_is_error_not_blocked(self):
        # rc==0 but the canary body never came back — honest: error, not allowed/blocked.
        t = mk_trigger()
        r = sv.RunResult(rc=0, stdout="some other page")
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_timeout_is_error(self):
        t = mk_trigger()
        r = sv.RunResult(rc=None, timed_out=True)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_control_ok_true_is_blocked(self):
        # egress works but the trigger's response didn't return -> flow dropped inline.
        t = mk_trigger()
        r = sv.RunResult(rc=7, stdout="", control_ok=True)
        self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED)

    def test_control_ok_false_is_error_not_blocked(self):
        # egress itself is broken -> environment error, never a false blocked.
        t = mk_trigger()
        r = sv.RunResult(rc=7, stdout="", control_ok=False)
        self.assertEqual(sv.classify(t, r)[0], sv.ERROR)

    def test_control_ok_true_still_allowed_when_expected_body_present(self):
        # a successful detect (uid=0 came back) is allowed regardless of the control probe.
        t = mk_trigger()
        r = sv.RunResult(rc=0, stdout="uid=0(root)", control_ok=True)
        self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)


class TestPredMatch(unittest.TestCase):
    def test_rc_and_body(self):
        r = sv.RunResult(rc=0, stdout="x uid=0 y")
        self.assertTrue(sv._pred_match({"rc": 0, "body_contains": "uid=0"}, r))
        self.assertFalse(sv._pred_match({"rc": 0, "body_contains": "nope"}, r))
        self.assertFalse(sv._pred_match({"rc": 1}, r))

    def test_rc_nonzero(self):
        self.assertTrue(sv._pred_match({"rc_nonzero": True}, sv.RunResult(rc=7)))
        self.assertFalse(sv._pred_match({"rc_nonzero": True}, sv.RunResult(rc=0)))
        self.assertFalse(sv._pred_match({"rc_nonzero": True}, sv.RunResult(rc=None)))

    def test_empty_pred_never_matches(self):
        self.assertFalse(sv._pred_match({}, sv.RunResult(rc=0)))


if __name__ == "__main__":
    unittest.main()
