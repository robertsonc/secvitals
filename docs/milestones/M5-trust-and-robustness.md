# M5 — Trust & Robustness

*Roadmap milestone 5 of 5. Version `0.6.0`. Branch `claude/m5-trust-and-robustness`.*

Four of these five items exist because of the same worry: the console can be *honest
about what it observed* and still mislead, if the thing it observed was decided by
something nobody checked. M5 hardens the parts around the classifier.

---

## What shipped

| Roadmap item | What it is |
|---|---|
| **Multi-endpoint control probe** | An ordered, transport-matched list; egress counts as up if **any** endpoint answers. |
| **Catalog signing** | `catalog.yaml.sig`, verified with the same RSA verifier as the updater, plus `--strict-catalog`. |
| **Pre-flight check** | `--preflight` — a readiness gate, explicitly **not** a policy predictor. |
| **Graceful curl-absent** | One `invalid` with a fix, instead of a wall of identical `error` cards. |
| **ERROR-only origin failover** | Opt-in, never past a policy result, always marked. |

## Multi-endpoint control probe

The blocked-vs-error decision for every native `dns`/`tcp` probe rested on **one** host
(`1.1.1.1:443`). If a customer's policy happened to deny it, every real inline block
silently degraded to `error` — the tool would under-report the product.

```yaml
run:
  control_endpoints:
    - {host: "1.1.1.1", port: 443, kind: tcp}
    - {host: "9.9.9.9", port: 443, kind: tcp}
    - {host: "8.8.8.8", port: 53,  kind: dns}
```

- Egress counts as up if **any** endpoint answers.
- `kind` makes it **transport-matched**: a DNS trigger prefers a DNS control, because a
  network that permits DNS while denying outbound TCP/443 would otherwise produce a
  false `error`.
- Falls back to `control_host`/`control_port`, so existing installs are unchanged.
- Which endpoint answered is recorded and shown in the details pane.

## Catalog signing

The update channel authenticates `secvitals.py` but **not the catalog** — and the catalog
is what decides where traffic goes. Anyone able to write the config directory could point
a trigger elsewhere while every other guardrail (argv-only, no shell, validated params)
still held.

```bash
tools/sign_catalog.sh config/catalog.yaml ~/.config/secvitals/secvitals_release_priv.pem
```

Verification reuses `verify_rsa_sha256` — the same implementation the updater trusts, so
there is one signature path to review, not two. Status is one of **verified**,
**unsigned**, or **modified**, and it is reported on every start and by `--preflight`.

**Fail-visible, not fail-closed, by default.** Existing installs have no signature and
must keep working, so an unsigned catalog is *reported* rather than refused. `--strict-catalog`
(or `run.strict_catalog`) refuses to start unless verified — and it gates **every** path
including `--list`, because an untrusted catalog should not even be enumerated.

The signing script verifies its own output against an independent public key **file**
before leaving a signature in place, for the same reason `sign_release.sh` does: signing
with the wrong key produces a perfectly well-formed signature that every client rejects.

## Pre-flight — a readiness gate, and nothing more

```bash
py secvitals.py --preflight          # exit 0 ready, 1 not ready
py secvitals.py --preflight --format json
```

It answers exactly one question: *can this console run its triggers from here?* It checks
curl, egress control, and the catalog — and it says, in the output itself:

> This is a readiness check only. It says nothing about whether any trigger will be
> allowed or blocked — that is what firing them is for.

That wording is deliberate and load-bearing. A readiness check that implied a verdict
would put a guess on stage next to real results, and there is a test asserting the report
contains no predictive language.

## Graceful curl-absent

Previously a missing `curl.exe` produced an identical `error` on every HTTP trigger, and
the presenter had to decode a wall of them. Now the check runs once (cached) and each
affected trigger reports **`invalid`** with the fix: *"curl was not found on PATH… Windows
10 1803+ ships curl.exe… This is not a policy result."*

## ERROR-only origin failover — opt-in, and here's why

If `testmynids.org` is down, ~9 IDS triggers can't fire and the signal count silently
shrinks. Failover retries against an alternate origin:

```yaml
run:
  origin_failover: {}      # e.g. {"testmynids.org": "alt-origin.example"}
```

Three rules keep it honest:

1. **Only on an environment error** (curl rc in the DNS/TLS set). Never past a `blocked`
   or `allowed` — a policy outcome is the answer, and retrying it elsewhere would launder
   it.
2. **Only the host is rewritten.** Headers, user-agents and payload bodies are untouched,
   so the signal itself is unchanged; only where it is sent differs.
3. **If the failover also fails, the original error stands.** Nothing is claimed that
   wasn't observed.

> **It ships empty on purpose.** An alternate that does not serve the same content can
> turn a real signal into a benign request that trips nothing — and `ns-uid` in particular
> matches on the *response body*, so a 404 from an alternate would read as `allowed`
> while proving nothing. Any result reached this way is marked **ORIGIN FAILOVER** in the
> details with a reminder to verify the alternate. Enable it only with an origin you
> control and have checked.

## Guardrails

All seven hold, and two are strengthened: the catalog is now authenticatable (closing a
real gap in **G1**), and the control probe is no longer a single point of failure for
**G4**.

## Tests

29 new tests (`tests/test_trust.py`); suite now **167 total**. Notable:

- one filtered control endpoint no longer masks a real block;
- DNS-kind controls are tried **first** for DNS triggers;
- sign → verify → tamper round-trip (a single appended byte invalidates it);
- a catalog signed with an untrusted key does **not** verify;
- strict mode refuses even `--list`;
- the pre-flight report contains no predictive language;
- a `blocked` result is never retried through a failover, and a failed failover keeps the
  original error.
