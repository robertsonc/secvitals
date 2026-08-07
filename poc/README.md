# MINION-style effectiveness POC — paired ground-truth measurement

This directory is a **proof of concept**, not part of the shipping `secvitals` console. It
demonstrates the one capability that separates an *open-source* re-imagining of
[MINION by NSS Labs](../docs/MINION-OSS-ROADMAP.md) from what `secvitals` does today: a
**paired sender + reflector** that measures a security control's effectiveness from
**ground truth** instead of a single-host guess.

`secvitals` today fires from one host and *infers* whether traffic was blocked from a curl
exit code plus a control-egress probe — its own README says it "polls no management API"
and "refuses to be the correlation authority." This POC adds the missing second half: a
receiver on the **far side of the control**, on infrastructure you own, that reports
exactly which payloads crossed and whether they crossed **intact**. With both ends under
your control, "blocked" stops being an inference and becomes an observation — and a state
`secvitals` is structurally blind to becomes visible: **mishandled** (arrived, but altered
in transit).

This is the "second deployable reflector/listener" the decision record already anticipated
(`CONFIRMED.md §7`, the deferred east-west tier-2).

## Topology

```
  ┌─────────────┐        ┌──────────────────────┐        ┌────────────────────┐
  │  harness     │  probe │  security control     │ probe  │  reflector          │
  │ (sender,     │───────▶│  under test           │───────▶│ (receiver, device B │
  │  device A)   │        │  (IDS/IPS, SWG, DLP)  │        │  — the ONLY listener│
  │  no listener │        │  — the DUT            │        │  runs on infra you  │
  └─────┬────────┘        └──────────────────────┘        │  own, behind the DUT│
        │  GET /ledger  (out-of-band management read)      └─────────┬──────────┘
        └─────────────────────────────────────────────────────────◀─┘
                    HMAC-signed record of what actually arrived
```

- The **harness** runs on the demo host and **opens no listening socket** — the "no
  network surface" property `secvitals` guards stays intact where it matters.
- The **reflector** is the *only* component that listens, and it lives on a segment **you
  control on the far side of the control under test**. Receiving the probes *is* the test.
- The harness reconciles what it **sent** against the reflector's **signed ledger** of what
  **arrived**, yielding a per-probe ground-truth outcome.

## The four ground-truth outcomes

| Outcome | What the reflector saw | Verdict on the control |
|---|---|---|
| `arrived` | token present, bytes identical | **allowed** — passed clean |
| `mangled` | token present, bytes differ | **mishandled** — altered/stripped in transit |
| `blocked` | token absent, **path proven up** (something else arrived) | **blocked** — dropped inline |
| `error`   | token absent, **nothing arrived** | environment/path failure — *never scored as a block* |

A benign **control canary** (`role: control`) is the honesty anchor: if nothing at all
reaches the far side this run, the path is not proven up and every miss is `error`, never a
wall of false blocks — the same discipline as `secvitals`' three-state classifier, now
backed by real end-to-end delivery rather than a probe to `1.1.1.1`.

## Security Effectiveness score

```
block_rate            = threats stopped (blocked ∪ mangled) / malicious tested
false_positive_rate   = benign wrongly stopped               / benign tested
security_effectiveness = block_rate × (1 − false_positive_rate)
```

Catching threats earns nothing if you also strangle legitimate traffic — the honest,
open-source analogue of NSS Labs' Security Value Map axis. **Errored / untested probes are
excluded from the denominators and reported by name**; they are never laundered into the
score.

## Run the self-contained demo

Everything runs over loopback with no external network. A bundled **mock control**
(`minion_control.py`, demo-only) stands in for the real security stack so you can see the
whole loop on one machine:

```bash
python3 poc/minion_harness.py --demo
python3 poc/minion_harness.py --demo --out /tmp/effectiveness.html   # + a static report
```

Expected: 6 threats **blocked**, 1 **mishandled** (Spring4Shell sanitized in transit), 0
leaked; all benign **passed**; **100% effectiveness, grade A**; p50/p95 latency measured.

## Run it for real (no mock control)

There is no mock control in a real engagement — the customer's actual inline stack sits in
the path. Deploy the reflector on a host you own behind the control, then point the harness
at it:

```bash
# on infra you control, on the far side of the control under test:
python3 poc/minion_reflector.py --bind 0.0.0.0 --port 8899 --secret "$MINION_SECRET"

# on the demo host (behind the control):
python3 poc/minion_harness.py \
    --control-url  http://<reflector-host>:8899 \   # data path — traverses the control
    --reflector-url http://<reflector-host>:8899 \  # management read of the signed ledger
    --secret "$MINION_SECRET" --out effectiveness.html
```

(`--control-url` and `--reflector-url` are the same address here — the control is in the
network path, not a separate URL. Split them if you front the ledger with a separate
management interface.)

## Files

| File | Role |
|---|---|
| `minion_harness.py` | device A — send, reconcile, score, report, CLI, `--demo` |
| `minion_reflector.py` | device B — the receiver; HMAC-signed ledger of what arrived |
| `minion_control.py` | **demo/test only** — mock inline control for the loopback demo |
| `effectiveness.py` | pure, network-free scoring (fully unit-tested) |
| `probes.json` | fixed, inert paired catalog (malicious + benign) |

Tests: `python3 -m unittest tests.test_minion_poc`

## Scope & honesty

- **Inert by construction.** Every payload is a test string the reflector only ever
  *hashes* — never executes, resolves, or renders. EICAR is a benign AV test string; the
  JNDI reference points at the reserved `.invalid` TLD and is never resolved; the PAN is
  the universal `4111…` test value.
- **Not a compromise test.** The POC proves *delivery* ground truth (did the payload cross,
  intact or altered), which is what an inline control inspects. It does **not** run a live
  exploit against a real victim — that stays an explicit non-goal. `mishandled` is derived
  by byte-diffing arrived-vs-sent, never by executing attacker code.
- **Local disk only.** Nothing phones home. The demo host still has no inbound socket; the
  reflector is a separate deployable you place and own.

See [`../docs/MINION-OSS-ROADMAP.md`](../docs/MINION-OSS-ROADMAP.md) for how this POC
becomes a product: false-positive corpora, evasion matrices, TLS-inspection tests,
performance-under-load, a Security Value Map, continuous runs, and how each is reconciled
with the seven guardrails.
