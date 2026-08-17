# M2 — Presenter Experience

*Roadmap milestone 2 of 5. Version `0.3.0`. Branch `claude/m2-presenter-experience`.*

Security Vitals could fire 55 signals and count them precisely. But "Run all enabled"
is **catalog order**, which is an inventory, not a story — and 35 cards scrolling past
is the wrong shape for a five-minute executive slot.

M2 adds the two things a presenter actually needs: a way to **curate and order** what
gets fired, and a way to **present it one trigger at a time** with the talk track in
large type and a live scoreboard.

---

## What shipped

| Roadmap item | What it is |
|---|---|
| **Demo profiles / playlists** | Named, ordered run-sets defined in `settings.yaml`, validated against the catalog at startup. |
| **Deterministic pre-run plan** | Every profile states its exact signal count before anything is fired. |
| **Presenter mode** | A big-type window that walks one trigger at a time — expected SID, talking point, where to look on the console — with a persistent scoreboard by state and by class. |

## Profiles

A profile **selects existing catalog ids and puts them in an order**. It never defines a
command, so the fixed-catalog guarantee is untouched. Every referenced id is validated
against the catalog when the app starts: a typo fails loudly at launch, not half-way
through a demo.

Five profiles ship in `config/settings.yaml`:

| Profile | Signals | The story |
|---|---:|---|
| `exec-5min` | 6 | One signal per control, worst-first. |
| `ids-story` | 21 | Recon → policy → malware → C2, the escalation narrative. |
| `swg-story` | 9 | Acceptable-use categories first, then the threat categories. |
| `data-protection` | 5 | Synthetic PII, then credentials. |
| `modern-cve` | 6 | The marquee CVEs a customer expects their IPS to catch. |

```yaml
profiles:
  exec-5min:
    label: "5-minute exec demo"
    description: "One signal per control, worst-first. The short story."
    triggers:
      - ns-uid
      - ns-c2
      - web-rep-phishing-gsb
      - web-cat-social
      - dlp-pan
```

> **Vendored-YAML constraint.** The loader supports block sequences and *single-line*
> flow sequences, but not a `[...]` list wrapped across several lines. Use the block form
> above. A wrapped flow list fails at startup with `unterminated flow sequence`.

### From the command line

```bash
py secvitals.py --profiles                       # list profiles + their signal counts
py secvitals.py --profile exec-5min --list       # the plan, scoped to that profile
py secvitals.py --profile exec-5min --dry-run    # every command it would send
py secvitals.py --profile exec-5min --run all    # fire it, in profile order
py secvitals.py --profiles --format json
```

`--profile` scopes `--list`, `--dry-run`, and `--run`. Gated triggers are still skipped,
and the profile's signal count reflects that.

## Presenter mode

Click **Presenter**, pick a profile (or "All enabled triggers"), and present:

- the trigger label in 22pt, the **expected SID** beneath it, then the talking point;
- the **console hint** — where to look on the customer's stack for this class of signal;
- after firing, the observed state in 26pt, colour-coded, with the reason underneath;
- a persistent **scoreboard**: overall tally plus a per-class breakdown, and
  `n/total triggers · n/total signals` in the header;
- **◀ Back / Fire / Next ▶** so the presenter controls the pace, not a timer.

The picker states each option's trigger and signal count **before** anything runs, so the
presenter commits to a number in front of the room.

### The scoreboard says whose observation it is

The tally counts what **this host observed locally**, and the window says so in as many
words directly beneath it. It is never a claim about what the customer's stack did —
Security Vitals still polls no management API, and the customer's console remains
authoritative.

## Design notes

**`PresenterSession` is pure.** All pacing, progress arithmetic, and scoreboard logic
live in a plain object with no Tk dependency, so they are unit-tested without a display.
The window is a thin renderer over it. Re-firing a trigger *replaces* its result rather
than double-counting.

**Profile order beats catalog order.** `select_triggers()` returns catalog order normally,
but a profile's own order when one is active — that ordering *is* the narrative, and
sorting it away would defeat the feature.

**Duplicates collapse, position preserved.** `[b, a, b]` becomes `[b, a]`, so a
copy-paste slip can't silently double a signal count.

## Guardrails

All seven hold. The one worth stating explicitly: **a profile is a selection, not a
definition.** It carries a list of ids and nothing else — no commands, no URLs, no
parameters — and the objects it hands back are the very same `Trigger` instances the
catalog loaded. There is no path from a profile to a new command.

## Tests

29 new tests (`tests/test_presenter.py`) plus a presenter-window GUI smoke; suite now
**168 total**. Notable assertions:

- an unknown trigger id in a profile raises `ConfigError` at load, naming the id;
- the profile's declared order survives selection, and gated triggers are still skipped;
- the profiles shipped in `settings.yaml` actually load against the real catalog;
- the session clamps at both ends, an empty session doesn't divide by zero, and
  re-firing replaces rather than double-counts;
- headless output runs in profile order and names the profile.
