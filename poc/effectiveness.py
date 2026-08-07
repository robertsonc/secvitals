"""Security-effectiveness scoring — the honest, network-free core of the MINION POC.

This module never touches the network. It takes the *ground-truth outcome* of each
probe — learned by the harness by reconciling what the sender emitted against what the
reflector actually received on the far side of the security control — and computes a
Security Effectiveness score in the NSS Labs tradition: a high block rate on malicious
traffic, tempered by the false-positive rate on benign traffic.

Why a separate module: the scoring is the part most worth trusting, so it is kept pure
and unit-testable without a socket in sight.

Honesty rules carried straight over from secvitals' three-state classifier:

  * ``blocked`` and ``error`` never collapse. An ERROR is an environment / path failure
    (the far side could not be reached at all), never scored as a policy block.
  * Probes that produced no policy result (ERROR) are EXCLUDED from the rate
    denominators and reported separately. You never score what you could not test.
  * ``mishandled`` (the payload arrived but altered in transit) is its own observable
    state — a state a single-host tool with no receiver is structurally blind to. It is
    the clearest demonstration of what the paired architecture buys you.
"""

from __future__ import annotations

import dataclasses
from typing import Optional


# -- ground-truth outcomes ---------------------------------------------------
# What the reflector's signed ledger tells us actually happened to a probe once it was
# put on the wire toward the far side.
ARRIVED = "arrived"      # token received intact  -> the control ALLOWED it (passed clean)
MANGLED = "mangled"      # token received, bytes differ -> the control MISHANDLED it
BLOCKED = "blocked"      # token never arrived, path proven up -> the control BLOCKED it
ERROR = "error"          # token never arrived, path NOT proven up -> environment, not policy

OUTCOMES = (ARRIVED, MANGLED, BLOCKED, ERROR)

# probe classes
BENIGN = "benign"
MALICIOUS = "malicious"
CLASSES = (BENIGN, MALICIOUS)

# roles
ROLE_CONTROL = "control"   # the canary: benign, must-arrive, used only to prove the path
                           # is up. Never scored — it is infrastructure, like secvitals'
                           # run.control_host, but confirmed by real end-to-end delivery.


@dataclasses.dataclass
class ProbeResult:
    """One probe's reconciled result. ``latency_ms`` is the send->ack wall time when the
    probe actually completed, else None (a blocked probe has no ack to time)."""
    probe_id: str
    klass: str
    outcome: str
    expected: str = ""       # what the catalog expected ("block" / "arrive") — kept
                             # strictly separate from what was observed
    role: str = ""
    detail: str = ""
    latency_ms: Optional[float] = None

    def __post_init__(self):
        if self.klass not in CLASSES:
            raise ValueError(f"{self.probe_id}: class must be one of {CLASSES}, got {self.klass!r}")
        if self.outcome not in OUTCOMES:
            raise ValueError(f"{self.probe_id}: outcome must be one of {OUTCOMES}, got {self.outcome!r}")

    @property
    def is_control(self) -> bool:
        return self.role == ROLE_CONTROL

    @property
    def stopped(self) -> bool:
        """Did the payload fail to traverse the control intact? BLOCKED (dropped) and
        MANGLED (neutralised in transit) both count — the malicious bytes did not reach
        the far side unchanged. This is the quantity a block rate is built from."""
        return self.outcome in (BLOCKED, MANGLED)

    @property
    def scored(self) -> bool:
        """A control-canary and any ERROR are excluded from the score."""
        return not self.is_control and self.outcome != ERROR


def _pct(numer: int, denom: int) -> Optional[float]:
    if denom <= 0:
        return None
    return round(100.0 * numer / denom, 1)


def _counts(results, klass):
    subset = [r for r in results if r.klass == klass and r.scored]
    by = {o: sum(1 for r in subset if r.outcome == o) for o in OUTCOMES}
    return subset, by


def performance_summary(latencies_ms, duration_s=None):
    """A lightweight stand-in for MINION's performance axis: p50/p95 round-trip latency
    over the probes that completed, and effective throughput. POC-scale — a real build
    would drive concurrent load; here it just characterises the happy path honestly."""
    lat = sorted(x for x in latencies_ms if x is not None)
    out = {"samples": len(lat), "p50_ms": None, "p95_ms": None,
           "max_ms": None, "throughput_per_s": None}
    if lat:
        out["p50_ms"] = round(lat[len(lat) // 2], 1)
        out["p95_ms"] = round(lat[min(len(lat) - 1, int(round(0.95 * (len(lat) - 1))))], 1)
        out["max_ms"] = round(lat[-1], 1)
    if duration_s and duration_s > 0 and lat:
        out["throughput_per_s"] = round(len(lat) / duration_s, 2)
    return out


def score(results, duration_s=None):
    """Compute the effectiveness scorecard from a list of ProbeResult.

    Returns a plain dict (JSON-ready). The three headline numbers:

      block_rate            = stopped malicious / malicious tested        (higher better)
      false_positive_rate   = stopped benign    / benign tested          (lower  better)
      security_effectiveness = block_rate * (1 - false_positive_rate)     (0..1, higher better)

    The effectiveness product is the POC's honest analogue of the NSS Labs Security Value
    Map axis: catching threats earns nothing if you also strangle legitimate traffic."""
    results = list(results)

    mal, mal_by = _counts(results, MALICIOUS)
    ben, ben_by = _counts(results, BENIGN)

    mal_tested = len(mal)
    ben_tested = len(ben)
    mal_stopped = sum(1 for r in mal if r.stopped)
    ben_stopped = sum(1 for r in ben if r.stopped)

    block_rate = _pct(mal_stopped, mal_tested)                 # % of threats stopped
    fp_rate = _pct(ben_stopped, ben_tested)                    # % of legit wrongly stopped

    if block_rate is None or fp_rate is None:
        effectiveness = None                                   # not enough tested to score
    else:
        effectiveness = round((block_rate / 100.0) * (1.0 - fp_rate / 100.0) * 100.0, 1)

    # errors and the control canary are surfaced, never hidden and never scored.
    errored = [r for r in results if r.outcome == ERROR and not r.is_control]
    canary = next((r for r in results if r.is_control), None)
    canary_state = (canary.outcome if canary else None)

    return {
        "security_effectiveness_pct": effectiveness,
        "block_rate_pct": block_rate,
        "false_positive_rate_pct": fp_rate,
        "malicious": {
            "tested": mal_tested,
            "stopped": mal_stopped,
            "leaked": mal_by[ARRIVED],           # threats that passed clean — the misses
            "blocked": mal_by[BLOCKED],
            "mishandled": mal_by[MANGLED],
        },
        "benign": {
            "tested": ben_tested,
            "passed": ben_by[ARRIVED],
            "false_blocked": ben_by[BLOCKED],
            "mishandled": ben_by[MANGLED],
        },
        "not_scored": {
            # honesty: named, never folded into a rate
            "errors": len(errored),
            "error_ids": [r.probe_id for r in errored],
            "control_canary": canary_state,
        },
        "performance": performance_summary([r.latency_ms for r in results], duration_s),
        "outcomes": {o: sum(1 for r in results if r.outcome == o) for o in OUTCOMES},
        "probes": [dataclasses.asdict(r) for r in results],
    }


def grade(effectiveness_pct):
    """A blunt letter grade for the headline number, for at-a-glance reporting. None when
    the run did not test enough to earn a score."""
    if effectiveness_pct is None:
        return "N/A"
    e = effectiveness_pct
    if e >= 90:
        return "A"
    if e >= 80:
        return "B"
    if e >= 70:
        return "C"
    if e >= 60:
        return "D"
    return "F"
