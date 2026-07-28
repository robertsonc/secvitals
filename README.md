# Security Vitals

A local, single-host **security-trigger console** for inline security-stack demos. Fire
security-trigger traffic on a button click and read the **local result** — `allowed`,
`blocked`, or `error` — in a **self-contained window** (Tkinter, like NetVitals — no
browser, no local server). The traffic egresses the network and is inspected by the
inline **IDS/IPS** and **Secure Web Gateway**; **the console polls no management API.**
You verify on the inline stack's management console already on screen. The console just
fires the traffic and honestly reports what it observed locally.

```
  This host  →  IDS/IPS + Secure Web Gateway  →  Internet
```

This build covers **north–south** functions — IDS/IPS, web categorization /
reputation, IP reputation (Tor, botnet-C2, scanner and spammer feeds), DNS security,
and DLP / content inspection — with IPv6 and HTTP/3 parity twins to expose transport
blind spots, plus **east–west tier 1** (internal segmentation probing).

**The known quantity.** The catalog is fixed, so the number of signals a run puts on the
wire is exact and repeatable: **66 signals across 41 triggers** by default, or **100
across 50** once the live-suspect gate is on. Ask for it before you fire — `--list` for
the summary, `--dry-run` for every command that would be sent (both send nothing), or the
**Signal manifest** button in the window.

## How it runs

The console is a **Tkinter window on Windows Python**, and everything runs **natively —
no WSL**. Each trigger reproduces exactly what the corresponding
[tmNIDS](https://github.com/3CORESec/testmynids.org) test sends, using:

- **`curl.exe`** (ships with Windows 10 1803+) for the HTTP signatures — same flags and
  exit codes as Linux curl, so the classifier is unchanged;
- small **built-in stdlib probes** for the rest: a DNS query (`dns`) and a TCP connect /
  banner grab (`tcp`), plus the IP-reputation probe (`iprep`).

So the same IDS/IPS signatures trip, but **nothing downloads or executes a
third-party binary** and there's no distro to depend on. (It also runs natively on Linux
for development.)

## Install (Windows, one-click)

Double-click **`install.bat`**. A per-user setup window (no admin rights) finds a Windows
Python **with Tkinter** (installing one from python.org if needed), confirms `curl.exe` is
present, copies the app, and creates Start Menu / Desktop shortcuts plus a Settings → Apps
entry — the same installer experience as NetVitals. Each app opens in its own window with
its own taskbar icon. See [docs/INSTALL.md](docs/INSTALL.md) for options, silent install,
updating, and uninstalling.

## Run it manually

```bash
py secvitals.py          # Windows (from the install folder)
python3 secvitals.py     # Linux (development)
```

No dependencies beyond Python 3.8+ (standard library only); the Windows Python needs
tcl/tk (Tkinter), and HTTP triggers need `curl.exe`. Useful flags: `--verbose`,
`--config-dir DIR`, `--check-update`, `--update`.

### Preview and headless modes (no window)

```bash
py secvitals.py --list                 # the catalog + the signal count — sends nothing
py secvitals.py --dry-run              # every command that WOULD be sent — sends nothing
py secvitals.py --run all              # fire everything headless and report honestly
py secvitals.py --run ns-dlp,ns-uid    # fire selected classes and/or trigger ids
py secvitals.py --run all --format json
```

`--run` is the **pre-brief**: fire from the customer's network *before* the meeting and
find out that an origin is unreachable or the control probe is down while you can still
fix it. Its exit code is policy-neutral — **0 even when triggers are blocked** (a block is
the inline stack doing its job); non-zero only for `error`/`invalid` or a usage problem.

### Demo profiles and presenter mode

"Run all" is catalog order — an inventory, not a story. A **profile** is a curated,
ordered subset with a committed signal count:

```bash
py secvitals.py --profiles                     # what's available + each one's count
py secvitals.py --profile exec-5min --list     # the plan for that profile
py secvitals.py --profile exec-5min --run all  # fire it, in profile order
```

Five ship in `config/settings.yaml` (`exec-5min`, `ids-story`, `swg-story`,
`data-protection`, `modern-cve`). A profile only ever **selects** existing catalog ids —
it never defines a command — and every id is validated at startup, so a typo fails at
launch rather than on stage.

In the window, **🎤 Presenter mode** walks one trigger at a time in large type: expected
SID, talking point, where to look on the customer's console, then the observed state and
a running scoreboard by state and class. See
[docs/milestones/M2-presenter-experience.md](docs/milestones/M2-presenter-experience.md).

### Leave something behind

```bash
py secvitals.py --run all --export demo.html   # HTML leave-behind (.json / .csv too)
py secvitals.py --last-session                 # re-read the last run, fire nothing
```

Or click **⬇ Save report** in the window. Every run is recorded in a **hash-chained
ledger** stamped with digests of the code and catalog that produced it, so a report can
be shown not to have been quietly edited. The report keeps three columns strictly
separate — what the catalog **expected** to fire, what this host **observed**, and what
the presenter **confirmed** on the customer's console — and names the policy dimensions
the session did *not* exercise.

**Local disk only.** Nothing is uploaded, nothing phones home, and there is still no
listening socket. See [docs/milestones/M1-evidence-and-reporting.md](docs/milestones/M1-evidence-and-reporting.md).

## What the result states mean

| State | What happened locally | Reading it |
|---|---|---|
| **allowed** | the trigger ran and the expected response came back | IDS is in **detect-only** mode, or SWG policy allows the category |
| **blocked** | the flow was dropped inline (reset / timeout / policy deny) | **IPS / SWG enforcement is working** — the money shot |
| **error** | the trigger couldn't run or the environment is broken (DNS, TLS, no route, binary missing) | not a policy result — fix the environment; never read as a block |
| **ratio** | IP reputation reached N-of-M live suspect nodes | a ratio, not a single verdict; the inline IP-reputation stats are authoritative |
| **disabled** | a live-suspect-hosts trigger is gated off | enable it only in a lab (see below) |

`blocked` and `error` are **never** collapsed. An environment failure is reported as
`error`, never as a false `blocked` — a false "blocked" would misrepresent the product.

The classic before/after: run a trigger in IDS mode → `allowed` + an alert on the inline
stack's console. Flip the security policy to inline/IPS and run the same trigger →
`blocked`, same traffic now dropped.

## Configuration (separate from logic)

- **`config/catalog.yaml`** — the fixed trigger catalog. The console acts on a catalog
  `id`; commands are **fixed** here (a list of argv lists per trigger — a trigger may fire
  several requests), never built from free text. Optional params are validated against a
  per-trigger allowlist / pattern before substitution.
- **`config/settings.yaml`** — endpoints and toggles (the control-egress probe, the
  live-suspect-hosts gate, the Tor-list source for IP reputation, and the update source).

### Protocol parity, honestly

`ns-uid-v6`, `web-cat-social-v6` and `web-cat-social-h3` re-send existing payloads over
IPv6 and HTTP/3 to expose a control that inspects IPv4/TCP and ignores the rest. Because
`curl -6` exits 7 on a host with no IPv6 route — which would otherwise read as
`blocked` — these triggers declare `requires: [ipv6]` / `[http3]`, and the transport is
checked **before anything is sent**. If this host can't use the transport, the result is
`error` with a plain reason, and nothing goes on the wire. It is never reported as a
block. See [docs/milestones/M3-coverage-breadth.md](docs/milestones/M3-coverage-breadth.md).

### East–west (internal segmentation)

`ew-server-zone`, `ew-user-zone` and `ew-dmz` probe whether one internal zone can reach
another — the lateral-movement path ransomware actually uses. Tier 1 only: a bare TCP
connect, no payload and no listener needed.

Targets are **your** addresses, so nothing ships pre-filled. Define them under
`east_west.targets` in `settings.yaml`; until then these triggers report *"not
configured"*, which is its own answer — not gated, and not a block.

Reading it: **SYN-ACK or RST both mean reachable** (an RST proves the packet arrived and
the host answered — that is not a firewall drop). Only a **timeout** means dropped in
transit, and only when a control port on the same host confirms the host is up. If the
control is unreachable the result is `error`, never a false `blocked`. See
[docs/milestones/M4-east-west-tier1.md](docs/milestones/M4-east-west-tier1.md).

### Live suspect-infrastructure gate

Some triggers reach **real** suspect hosts, live Tor nodes, or destinations that simply
look odd in a customer's SIEM (bad-cert hosts, `thepiratebay.org`, `.onion` / Tor relays,
live exploit-tooling and adult sites). They are flagged `hits_live_suspect_hosts` and
**disabled by default**, so the console can run on a customer-adjacent network without
originating awkward traffic. Enable them only in a lab you control:

```yaml
# config/settings.yaml
enable_live_suspect_hosts: true
```

### Pre-flight and catalog provenance

```bash
py secvitals.py --preflight        # can this console run its triggers from here?
py secvitals.py --strict-catalog   # refuse to start unless the catalog is signed
```

`--preflight` checks curl, egress control, and the catalog signature. It is a **readiness
gate only** — it says nothing about whether any trigger will be allowed or blocked.

The update channel authenticates `secvitals.py` but not the catalog, and the catalog is
what decides where traffic goes. Sign it with `tools/sign_catalog.sh`; the status
(**verified** / **unsigned** / **modified**) is reported on every start. Unsigned is
reported rather than refused so existing installs keep working — use `--strict-catalog`
to require it. See
[docs/milestones/M5-trust-and-robustness.md](docs/milestones/M5-trust-and-robustness.md).

## Security posture

Because this console executes local commands, it is built defensively:

- **No network surface at all** — there is no HTTP server and no listening socket. The UI
  is an in-process Tkinter window; nothing off-box can reach it.
- **No download-and-execute** — the app runs no third-party binary. Each trigger is an
  explicit, audited command in the fixed catalog. Commands run via `subprocess` with an
  **argv list, never `shell=True`**, with a per-trigger timeout and captured
  stdout/stderr/returncode. Optional params are validated against a **per-trigger
  allowlist / pattern**; the only built-in token is `{devnull}` (the OS null device).
- **No shell anywhere** — HTTP triggers exec `curl.exe` directly; `dns` / `tcp` triggers
  are pure stdlib socket probes. There is no bash, no PowerShell, and no WSL in the path.
- **Self-update is signed and fails closed** — pinned source, offline RSA signature
  verified before anything is written; on Windows the download retries through the system
  certificate store (SChannel) so a TLS-inspecting proxy doesn't break verification. See
  [docs/UPDATE_SECURITY.md](docs/UPDATE_SECURITY.md).

## Tests

```bash
python3 -m unittest discover -s tests
```

The runner (curl via a stub interpreter, the dns/tcp probes, multi-request aggregation),
the three-state classifier, the catalog/YAML loader, the IP-reputation probe, the signed
updater, the signal manifest, and headless mode each have their own suite — all run
natively, no Windows required.

## Provenance

Reuses from the `netvitals` app: the **form factor** — a self-contained Tkinter window
with the shared visual identity (palette, dark theme, EKG heartbeat) — the **installer UI**
(the WinForms setup experience: Windows Python + Tkinter, a `pythonw` shortcut, Add/Remove
Programs), and the **self-update mechanism** (ported and hardened — netvitals' updater had
no authenticity check). Everything else is new. The original demo scripts and cheatsheets
are kept under [`docs/reference/`](docs/reference/) for provenance; the app reimplements
their trigger logic and does not execute them. See [`CONFIRMED.md`](CONFIRMED.md) for the
full decision record.

## Status

- [x] Phase 0 — scope + reuse + execution-path decisions (`CONFIRMED.md`)
- [x] Phase 1 — catalog + runner + three-state classifier
- [x] Hardened self-update channel
- [x] Phase 2 — full N/S IDS catalog (15 signatures) + run-all with rate limiting
- [x] Phase 3 — Secure Web Gateway (category + web-reputation) + IP reputation (control probe + ratio)
- [x] Tkinter window (replaces the loopback web UI)
- [x] Native Windows execution (curl.exe + stdlib dns/tcp probes) — WSL removed
- [x] Roadmap wave 1 — true on-wire signal counts + dry-run manifest, headless pre-brief
      mode, modern-exploit / SWG-category / DLP catalog packs, verification key +
      console hints, and `expected_on_*` classifier refinement
      (see [docs/SOLUTION-AND-ROADMAP.md](docs/SOLUTION-AND-ROADMAP.md))
- [x] E/W tier 1 — internal segmentation probing (`ew` class filled)
- [ ] E/W tier 2 — payload signatures east–west (needs a second deployable; deferred)
