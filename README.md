# Security Vitals

A local, single-host **security-trigger console** for HPE Aruba EdgeConnect demos. Fire
security-trigger traffic on a button click and read the **local result** — `allowed`,
`blocked`, or `error` — in a **self-contained window** (Tkinter, like NetVitals — no
browser, no local server). The traffic egresses the SD-WAN and is inspected by
EdgeConnect (ECOS Suricata v7) and the SSE Secure Web Gateway / BrightCloud WebCC; **the
console polls no management API.** You verify on the Orchestrator / EC dashboard already
on screen. The console just fires the traffic and honestly reports what it observed
locally.

```
  Source · WSL  →  EdgeConnect · Suricata v7 / WebCC  →  Internet
```

This build covers **north–south** functions: IDS/IPS (tmNIDS) and WebCC / IP reputation.
East–west is deferred.

## How it runs

The console is a **Tkinter window on Windows Python**. Each time you fire a trigger it
runs a short-lived **worker inside WSL** — native `bash` / `curl` / tmNIDS, on the SD-WAN
egress path — and classifies the result. The worker is invoked as:

```
wsl.exe -e python3 - worker <spec>      # this script is streamed to python3 on stdin
```

so **nothing is installed inside the distro** and the security-relevant execution stays
where the Linux tooling and the egress are. `-e python3 -` runs with no login shell, and
the spec travels as one base64url token, so there is no shell-quoting layer to mangle.
Run the app natively on Linux (or in WSL with WSLg) and the worker simply runs in-process.

## Install (Windows, one-click)

Double-click **`install.bat`**. A per-user setup window (no admin rights) finds a Windows
Python **with Tkinter** (installing one from python.org if needed), verifies WSL and adds
`python3` to your distro if it's missing, copies the app, and creates Start Menu / Desktop
shortcuts plus a Settings → Apps entry — the same installer experience as NetVitals. See
[docs/INSTALL.md](docs/INSTALL.md) for options, silent install, updating, and uninstalling.

## Run it manually

```bash
# Windows (from the install folder): opens the window, fires triggers into WSL
py secvitals.py
# Linux / WSLg: opens the window, runs the worker in-process
python3 secvitals.py
```

No dependencies beyond Python 3.8+ (standard library only); the Windows Python needs
tcl/tk (Tkinter). Useful flags: `--verbose`, `--config-dir DIR`, `--check-update`,
`--update`. (`secvitals worker <b64>` is the internal in-WSL execution entry point.)

## What the result states mean

| State | What happened locally | Reading it |
|---|---|---|
| **allowed** | the trigger ran and the expected response came back | IDS is in **detect-only** mode, or WebCC policy allows the category |
| **blocked** | the flow was dropped inline (reset / timeout / policy deny) | **IPS / WebCC enforcement is working** — the money shot |
| **error** | the trigger couldn't run or the environment is broken (DNS, TLS, no route, binary missing) | not a policy result — fix the environment; never read as a block |
| **ratio** | IP reputation reached N-of-M live suspect nodes | a ratio, not a single verdict; the EC IP-rep stats are authoritative |
| **disabled** | a live-suspect-hosts trigger is gated off | enable it only in a lab (see below) |

`blocked` and `error` are **never** collapsed. An environment failure is reported as
`error`, never as a false `blocked` — a false "blocked" would misrepresent the product.

The classic before/after: run a trigger in IDS mode → `allowed` + an alert on the EC
dashboard. Flip the security policy to inline/IPS and run the same trigger → `blocked`,
same traffic now dropped.

## Configuration (separate from logic)

- **`config/catalog.yaml`** — the fixed trigger catalog. The console acts on a catalog
  `id`; a command is never built from free text. The full catalog entry travels to the
  worker, which **re-validates it** (`Trigger.from_dict`) before running it.
- **`config/settings.yaml`** — endpoints and toggles (tmNIDS source + optional SHA-256
  pin, the control-egress probe, the live-suspect-hosts gate, the update source, and the
  `wsl.distro` the worker runs in — empty means wsl.exe's default distro).

### Live suspect-infrastructure gate

Some triggers reach **real** suspect hosts or live Tor nodes (Winnti-adjacent domains,
`thepiratebay.org`, `hidemyass.com`, Tor relays). They are flagged
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
  is an in-process Tkinter window; nothing off-box (or off-loopback) can reach it.
- The console acts on a **fixed catalog**; the worker independently **re-validates** every
  catalog entry it is handed before running anything. Commands run via `subprocess` with
  an **argv list, never `shell=True`**, with a per-trigger timeout and captured
  stdout/stderr/returncode. Optional params are validated against a **per-trigger
  allowlist / pattern**.
- The Windows→WSL bridge passes the run spec as a single **base64url token** to
  `wsl.exe -e python3 -` (no login shell, no shell metacharacters), so the class of
  quote-mangling bug the installer hit with PowerShell cannot recur.
- The tmNIDS binary is **SHA-256 pinned and cached** (verified every run, never
  re-downloaded per click), fetched over pinned TLS. Verification is mandatory and fails
  closed.
- **Self-update is signed and fails closed** — pinned source, offline RSA signature
  verified before anything is written; on Windows the download retries through the system
  certificate store (SChannel) so a TLS-inspecting proxy doesn't break verification. See
  [docs/UPDATE_SECURITY.md](docs/UPDATE_SECURITY.md).

## Tests

```bash
python3 -m unittest discover -s tests
```

The worker/runner path is covered without Windows or WSL (the `LocalRunner` runs the same
worker with the local Python); the engine, classifier, YAML loader, and signed updater
have their own suites.

## Provenance

Reuses from the `netvitals` app: the **form factor** — a self-contained Tkinter window
with the HPE visual identity (palette, dark theme, EKG heartbeat) — the **installer UI**
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
- [x] Phase 2 — full tmNIDS N/S catalog (15 triggers) + run-all with rate limiting
- [x] Phase 3 — WebCC (category + web-reputation) + IP reputation (control probe + ratio)
- [x] Tkinter window (replaces the loopback web UI) + Windows→WSL worker bridge
- [ ] E/W — deferred (schema reserves `ew`; not implemented)
