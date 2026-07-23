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

This build covers **north–south** functions: IDS/IPS and web categorization / reputation
and IP reputation. East–west is deferred.

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

### Live suspect-infrastructure gate

Some triggers reach **real** suspect hosts or live Tor nodes (bad-cert hosts,
`thepiratebay.org`, `.onion` / Tor relays). They are flagged
`hits_live_suspect_hosts` and **disabled by default**, so the console can run on a
customer-adjacent network without originating awkward traffic. Enable them only in a lab
you control:

```yaml
# config/settings.yaml
enable_live_suspect_hosts: true
```

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
the three-state classifier, the catalog/YAML loader, the IP-reputation probe, and the
signed updater each have their own suite — all run natively, no Windows required.

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
- [ ] E/W — deferred (schema reserves `ew`; not implemented)
