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


class TestPredicateRefinement(unittest.TestCase):
    """expected_on_allow / expected_on_block refine a COMPLETED request only.

    The gap they close: a gateway that serves a block page at HTTP 200 (or redirects to
    one) looks like `allowed` to the exit-code mapping alone. The rule that must never
    break: refinement can only reclassify a request that actually completed, so an
    environment failure can never be promoted to `blocked`."""

    def sub(self, rc, http=None, stdout=""):
        return sv.SubResult(argv=["curl", "http://x"], rc=rc, http_code=http, stdout=stdout)

    def test_block_page_served_at_200_is_caught(self):
        t = mk_trigger("curl", expected_on_block={"body_contains": "Access Denied"})
        r = sv.RunResult(subs=[self.sub(0, 200, "200|\nAccess Denied by policy")])
        state, reason = sv.classify(t, r)
        self.assertEqual(state, sv.BLOCKED)
        self.assertIn("expected_on_block", reason)

    def test_redirect_to_a_block_page_is_caught(self):
        t = mk_trigger("curl", expected_on_block={"http_code_in": [302, 307]})
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[self.sub(0, 302)]))[0], sv.BLOCKED)
        # a 200 with the same predicate stays allowed
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[self.sub(0, 200)]))[0], sv.ALLOWED)

    def test_expected_on_allow_confirms_a_pass(self):
        t = mk_trigger("curl", expected_on_allow={"http_code": 200})
        state, reason = sv.classify(t, sv.RunResult(subs=[self.sub(0, 200)]))
        self.assertEqual(state, sv.ALLOWED)
        self.assertIn("expected_on_allow", reason)

    def test_block_predicate_wins_over_allow_predicate(self):
        t = mk_trigger("curl", expected_on_allow={"rc": 0},
                       expected_on_block={"body_contains": "denied"})
        r = sv.RunResult(subs=[self.sub(0, 200, "200|\ndenied")])
        self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED)

    def test_never_promotes_an_environment_error_to_blocked(self):
        """The load-bearing safety property."""
        t = mk_trigger("curl", expected_on_block={"rc_nonzero": True})
        for rc in (6, 35, 60, 77, 99):
            r = sv.RunResult(subs=[self.sub(rc)])
            self.assertEqual(sv.classify(t, r)[0], sv.ERROR, rc)

    def test_never_demotes_a_real_drop_to_allowed(self):
        t = mk_trigger("curl", expected_on_allow={"rc_nonzero": True})
        for rc in (28, 7, 56):
            r = sv.RunResult(subs=[self.sub(rc)])
            self.assertEqual(sv.classify(t, r)[0], sv.BLOCKED, rc)

    def test_predicates_are_inert_when_undeclared(self):
        t = mk_trigger("curl")
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[self.sub(0, 200)]))[0], sv.ALLOWED)
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[self.sub(0, 403)]))[0], sv.BLOCKED)

    def test_a_non_matching_predicate_falls_back_to_the_default(self):
        t = mk_trigger("curl", expected_on_block={"body_contains": "never appears"})
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[self.sub(0, 200)]))[0], sv.ALLOWED)
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[self.sub(0, 451)]))[0], sv.BLOCKED)

    def test_error_reason_and_timeout_still_short_circuit(self):
        t = mk_trigger("curl", expected_on_block={"rc": 0})
        s = sv.SubResult(argv=["curl"], rc=0, http_code=200, error_reason="curl not found")
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[s]))[0], sv.ERROR)
        s2 = sv.SubResult(argv=["curl"], timed_out=True)
        self.assertEqual(sv.classify(t, sv.RunResult(subs=[s2]))[0], sv.ERROR)

    def test_pred_matches_requires_every_key(self):
        s = self.sub(0, 200, "hello")
        self.assertTrue(sv._pred_matches({"rc": 0, "http_code": 200}, s))
        self.assertFalse(sv._pred_matches({"rc": 0, "http_code": 404}, s))
        self.assertFalse(sv._pred_matches({}, s))                 # empty is inert
        self.assertFalse(sv._pred_matches({"unknown_key": 1}, s))  # fails closed
        self.assertTrue(sv._pred_matches({"rc_nonzero": False}, s))
        self.assertTrue(sv._pred_matches({"body_contains": "ell"}, s))
        self.assertFalse(sv._pred_matches({"http_code_in": []}, s))

    def test_probe_runners_are_not_refined(self):
        # dns/tcp have no http code or body; predicates must not disturb them
        t = mk_trigger("dns", expected_on_block={"rc_nonzero": True})
        r = sv.RunResult(subs=[probe_sub(True)])
        self.assertEqual(sv.classify(t, r)[0], sv.ALLOWED)


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
