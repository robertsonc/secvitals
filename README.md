# Security Vitals

A local, single-host **security-trigger console** for HPE Aruba EdgeConnect demos. Fire
security-trigger traffic on a button click and read the **local result** — `allowed`,
`blocked`, or `error` — right in the browser. The traffic egresses the SD-WAN and is
inspected by EdgeConnect (ECOS Suricata v7) and the SSE Secure Web Gateway / BrightCloud
WebCC; **the console polls no management API.** You verify on the Orchestrator / EC
dashboard already on screen. The console just fires the traffic and honestly reports what
it observed locally.

```
  Source · WSL  →  EdgeConnect · Suricata v7 / WebCC  →  Internet
```

This build covers **north–south** functions: IDS/IPS (tmNIDS) and WebCC / IP reputation.
East–west is deferred.

## Run it (inside WSL)

The console runs **inside WSL**, serves on loopback, and you open it in the **Windows
browser**. No dependencies beyond Python 3.8+ (standard library only).

```bash
python3 secvitals.py
# then open the printed URL, e.g. http://127.0.0.1:8787/ , in the Windows browser
```

Useful flags: `--port N`, `--no-browser`, `--verbose`, `--config-dir DIR`,
`--check-update`, `--update`.

## What the result states mean

| State | What happened locally | Reading it |
|---|---|---|
| **sent · allowed** | the trigger ran and the expected response came back | IDS is in **detect-only** mode, or WebCC policy allows the category |
| **sent · blocked** | the flow was dropped inline (reset / timeout / policy deny) | **IPS / WebCC enforcement is working** — the money shot |
| **error** | the trigger couldn't run or the environment is broken (DNS, TLS, no route, binary missing) | not a policy result — fix the environment; never read as a block |
| **disabled** | a live-suspect-hosts trigger is gated off | enable it only in a lab (see below) |

`blocked` and `error` are **never** collapsed. An environment failure is reported as
`error`, never as a false `blocked` — a false "blocked" would misrepresent the product.

The classic before/after: run a trigger in IDS mode → `allowed` + an alert on the EC
dashboard. Flip the security policy to inline/IPS and run the same trigger → `blocked`,
same traffic now dropped.

## Configuration (separate from logic)

- **`config/catalog.yaml`** — the fixed, server-side trigger catalog. The UI sends only a
  trigger `id`; the runner builds the command from this file, never from browser input.
- **`config/settings.yaml`** — endpoints and toggles (port, tmNIDS source + optional
  SHA-256 pin, the live-suspect-hosts gate, the update source).

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

- The HTTP server binds **loopback only** (`127.0.0.1`) — it is not a LAN service.
- Requests are gated by a per-session **CSRF token**, a `Host`-header check
  (DNS-rebinding defense), and a strict Content-Security-Policy.
- Commands run via `subprocess` with an **argv list, never `shell=True`**, with a
  per-trigger timeout and captured stdout/stderr/returncode. Optional params are
  validated against a **per-trigger allowlist**.
- The tmNIDS binary is **cached** (never re-downloaded per click), fetched over pinned
  TLS, with an optional SHA-256 pin.
- **Self-update is signed and fails closed** — pinned source, offline RSA signature
  verified before anything is written. See [docs/UPDATE_SECURITY.md](docs/UPDATE_SECURITY.md).

## Tests

```bash
python3 -m unittest discover -s tests
```

## Provenance

Reuses two things from the `netvitals` app: the **HPE visual identity** (palette, dark
theme, branding) for the UI form factor, and the **self-update mechanism** (ported and
hardened — netvitals' updater had no authenticity check). Everything else is new. The
original demo scripts and cheatsheets are kept under
[`docs/reference/`](docs/reference/) for provenance; the app reimplements their trigger
logic and does not execute them. See [`CONFIRMED.md`](CONFIRMED.md) for the full decision
record.

## Status

- [x] Phase 0 — scope + reuse + execution-path decisions (`CONFIRMED.md`)
- [x] Phase 1 — catalog + runner + three-state classifier + `ns-uid`, in the UI shell
- [x] Hardened self-update channel
- [x] Phase 2 — full tmNIDS N/S catalog (15 triggers) + run-all with rate limiting
- [x] Phase 3 — WebCC (category + web-reputation) + IP reputation (control probe + ratio, Deny notice)
- [ ] E/W — deferred (schema reserves `ew`; not implemented)
