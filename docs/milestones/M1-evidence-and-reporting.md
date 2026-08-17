# M1 — Evidence & Reporting

*Roadmap milestone 1 of 5. Version `0.2.0`. Branch `claude/m1-evidence-and-reporting`.*

Security Vitals could already fire a known quantity of signals and report each one
honestly. What it could not do was **leave anything behind**. A demo ended when the
window closed: no record of what was fired, no artifact the customer could reconcile
against their own console afterwards, and nothing to show that the record hadn't been
massaged on the way out.

M1 closes that gap — **on local disk only**. Nothing is uploaded, there is still no
listening socket, and there is no telemetry of any kind.

---

## What shipped

| Roadmap item | What it is |
|---|---|
| **Per-run signal ledger** | Every fired trigger is recorded in order: local verdict, reason, rc/HTTP, duration, true on-wire signal count, the 5-tuples, the verification key. |
| **Hash-chained evidence** | Each record commits to the one before it, so a report can be shown not to have been quietly edited. |
| **Provenance stamp** | Every report carries SHA-256 digests of the code, the catalog, and the settings that decided what was sent. |
| **Expected vs Observed vs Confirmed scorecard** | Three columns that are never merged — what the catalog *expected* to fire, what this host *observed*, and what the presenter *attested* on the customer's console. |
| **Policy-coverage matrix** | Class × threat grid of what was exercised, and an explicit list of what was **not**. |
| **Exports** | JSON, CSV, and a self-contained HTML leave-behind (no scripts, no external resources, everything escaped). |
| **Local evidence log** | Append-only, size-rotated JSONL, plus `--last-session` to re-read the most recent run without firing anything. |
| **Per-run correlation ID** | Optional `X-SecVitals-Run` header so the customer's console can be filtered to exactly this run. **Off by default** — see below. |

## Using it

### In the window

- **Save report** writes `.html`, `.json`, and `.csv` into the evidence directory and
  tells you exactly where they went. It never opens a browser or uploads anything —
  what happens to the file is the presenter's decision.
- Each fired card grows a **Console:** button that cycles
  *not marked → confirmed ✓ → not seen*. That is the presenter's own attestation; it is
  stored beside the machine's observation, never on top of it.

### From the command line

```bash
py secvitals.py --run all --export demo.html   # fire, then write the leave-behind
py secvitals.py --run all --export run.json    # or .csv / .json
py secvitals.py --last-session                 # re-read the last run, fire nothing
py secvitals.py --last-session --format json
```

`--export` picks its format from the file extension. Exit codes are unchanged and still
policy-neutral: a `blocked` trigger exits 0.

## The three columns, and why they stay separate

The whole product rests on not overstating what it knows. The report therefore keeps
three different kinds of evidence in three different columns:

| Column | Source | Authority |
|---|---|---|
| **Expected to fire** | The fixed catalog (`expected_fire`) | What *should* happen if the control is enforcing |
| **Observed locally** | This host's own three-state classifier | Honest, but only about what *this host* saw |
| **Confirmed on console** | The presenter ticking a box | A human attestation, not a measurement |

Merging any two of these would let the tool imply it knows something it doesn't. In
particular, Security Vitals still **polls no management API** and is still not the
authority on whether the customer's stack caught anything.

## The hash chain — what it does and doesn't prove

Each record's digest covers the record's observed facts **plus the previous record's
digest**. Re-running `verify_chain()` re-derives every digest and reports the first
record that doesn't match.

- Editing an observation after the fact (say, changing an `error` to a `blocked`)
  **invalidates that record and every record after it**, and the HTML report says so in
  red.
- The presenter's **`confirmed` annotation is deliberately outside the chain** — it is
  added by a human after the run, so including it would make honest note-taking look
  like tampering.

This is tamper-*evidence*, not tamper-*proofing*: anyone who can edit the file can also
recompute the chain. It raises the cost of quiet edits and makes casual ones obvious. It
is not a cryptographic signature and is not presented as one.

## Correlation header: off by default, on purpose

`run.correlation_header` stamps `X-SecVitals-Run: <run id>` on curl triggers so the
customer can filter their console to exactly this run. It ships **disabled**, because it
adds a header to traffic whose entire job is to reproduce a signature faithfully, and it
marks that traffic as synthetic. That trade belongs to the operator, not to us. Like the
5-tuple write-out, it is applied **in code** rather than in the catalog, so a self-update
(which ships `secvitals.py` alone) can't leave an install without it.

The **displayed** command stays exactly what the catalog declares.

## Configuration

```yaml
run:
  correlation_header: false   # stamp X-SecVitals-Run (default off)
evidence:
  log: true                   # append each run to the local JSONL log
  dir: ""                     # "" = per-user default location
```

Default evidence directory: `%LOCALAPPDATA%\SecVitals\runs` on Windows,
`~/.local/share/secvitals/runs` elsewhere.

## Guardrails

All seven hold. Specifically:

- **No network surface** — evidence is written with `open()`; nothing listens, nothing
  uploads, and no browser is launched on the user's behalf.
- **Honest classifier untouched** — M1 records verdicts, it never computes them. An
  `error` is recorded as an `error`, and the report states in plain language that an
  error is *not* a policy result and must never be read as a block.
- **Stdlib only** — `csv`, `html`, and `io` are imported locally inside the export
  functions; no third-party dependency was added.

## Tests

39 new tests (`tests/test_evidence.py`, plus a report-dialog GUI smoke), suite now
**177 total**. The load-bearing ones assert honesty properties rather than formatting:

- the chain detects a rewritten observation, and names the first bad record;
- a presenter attestation does **not** break the chain and does **not** overwrite the
  observation;
- an errored trigger counts as *fired* but never as a *result* in the coverage matrix;
- the HTML report escapes hostile trigger labels and contains no scripts or external
  resources;
- the evidence log survives malformed lines, rotates, and can be disabled;
- the correlation header is absent unless explicitly enabled.
