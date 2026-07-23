# Security Vitals — Phase 0 CONFIRMED

Decision record for the Security Vitals local trigger console (`secvitals`).
Written before any feature code, per the Phase 0 gate. Everything below is either
an observed fact about the source material or a recorded build decision.

- **Date:** 2026-07-23
- **Repo:** `robertsonc/secvitals` — branch `claude/security-vitals-trigger-console-g8zdds`
- **Source to reuse from:** `robertsonc/netvitals` @ `1.6.2` (read-only reference)
- **Status of `secvitals`:** empty repo (no commits) — this app is built fresh.

---

## 0. Revisions (newest first)

### 0b. Native execution — WSL removed (supersedes §0a's WSL-worker bridge)

**Date:** 2026-07-23 (same day, after the Tkinter+WSL build was pushed as PR #4).

The presenter asked: *"Is WSL a requirement? Windows has curl and python natively — all we
need is the packets on the wire with the right signatures."* Correct. Reading the upstream
[tmNIDS](https://github.com/3CORESec/testmynids.org) script confirmed it is **33 `curl`
calls** plus a few `dig` / `nc` / `openssl s_client`. So:

- **curl** → `curl.exe` (Windows 10 1803+), identical flags + exit codes;
- **dig** → a built-in stdlib UDP DNS query (`dns` runner);
- **nc** (SSH banner / Tor connect) → a stdlib TCP connect (`tcp` runner) / the existing
  `iprep` probe;
- **openssl s_client** (bad-cert / SNI) → `curl -k https://…` (the handshake + SNI still
  cross the wire, which is what the sensor sees).

**Decision:** drop WSL entirely and run **100% natively** on Windows (and on Linux for
dev). This is *better* than the WSL bridge on every axis that matters: one self-contained
process per app with its own taskbar icon; Windows-origin traffic (more representative);
**no download-and-execute of a third-party binary** (the tmNIDS SHA-pin machinery is gone);
and a simpler install (no distro provisioning).

- **Catalog:** the 15 IDS signatures are reproduced natively as `commands` (a list of
  argv-lists per trigger, so multi-request tests like the 5 malware UAs fire in full).
  Runners are now `curl` / `dns` / `tcp` / `iprep`. The `{devnull}` token maps to the OS
  null device. Fidelity of each reproduced request to its ET/IDS SID is verified on
  the inline stack's management console (the one thing not checkable from a dev box).
- **Removed:** the Worker/Runner/WSL bridge, `TmnidsCache` + the tmNIDS binary pin + the
  `tmnids`/`wsl` settings, `expected_on_allow/block` predicates. Multi-request triggers
  **aggregate honestly** — `blocked` only when every reachable request was dropped; the
  split is always shown. Execution is back **in-process** (`App.run` on a background
  thread). Installer re-based on netvitals' model with **no** WSL step; taskbar icon wired
  via `iconbitmap` + an AppUserModelID.

Non-negotiables still hold: fixed catalog, argv list + no shell, per-trigger timeout,
three-state classifier (`blocked` ≠ `error`, disambiguated by the control probe for
dns/tcp), live-suspect gate, signed fail-closed update. "No network surface" (§0a) is
now joined by "no shell, no WSL, no third-party binary."

### 0a. Pivot to a native Tkinter window (supersedes §2a's web-app decision)

**Date:** 2026-07-23 (post Phases 0–3, after the web build shipped and merged).

The presenter asked: *"Does it have to run in a browser? The Tkinter-contained UI is
preferred."* Confirmed direction: **Windows Tkinter (like NetVitals)** — a self-contained
window on Windows Python, no browser and no local server, working on any Windows + WSL
(no WSLg required).

This resolves the tension §2a flagged: the original non-negotiables read as a web app
(*"bind the local server to loopback"*), but netvitals' actual form factor is a native
Tkinter window, and that is what the presenter wanted. The literal "loopback server"
language is **superseded** — a native window has **no network surface at all**, which is
strictly stronger than a loopback bind + CSRF token.

**New architecture (see README / INSTALL):**

- **Console:** a Tkinter window on **Windows Python** (mirrors netvitals' `run_gui` form
  factor: shared palette, EKG heartbeat, dark cards). Same palette constants as §2b.
- **Execution:** each fired trigger runs a short-lived **worker in WSL** —
  `wsl.exe -e python3 - worker <base64url-spec>`, this script streamed on stdin — so the
  Linux tooling and network egress do the real work and **nothing is installed in the
  distro**. `-e python3 -` uses no login shell; the spec is one base64url token, so no
  shell-quoting layer exists to mangle (the class of bug the installer hit in PR #3).
  On Linux / WSLg the worker runs in-process.
- **Engine unchanged:** the catalog loader, `run_trigger`, three-state classifier,
  control-egress probe, iprep ratio, tmNIDS SHA-256 pin, and signed updater are the exact
  Phase 1–3 code, now driven by the worker instead of the HTTP handler. The worker
  **re-validates** every catalog entry it receives (`Trigger.from_dict`) before running.
- **Removed:** `http.server`, the request `Handler`, the CSRF token, the embedded
  `INDEX_HTML`, `webbrowser`. **Installer** re-based on netvitals' model (Windows Python +
  Tkinter, `pythonw` shortcut, Add/Remove Programs) plus a WSL-worker provisioning step.

Every non-negotiable below still holds; the loopback/CSRF item (§9) is replaced by
"no network surface," and the two reuse pillars (§2) are now satisfied **literally**
(the form factor *is* netvitals' Tkinter window; the self-update is the ported channel).

---

## 1. What Security Vitals is

A local, single-host demo console. The host already sits behind an inline security
stack; traffic egresses the network and is inspected by the inline **IDS/IPS** and
**Secure Web Gateway** (web categorization / reputation). On a
button click the app **fires security-trigger traffic** and **classifies the
local result** (allowed / blocked / error). **It does not poll any management
API** — verification happens on the inline stack's management console already on screen.

Scope this build: **north–south (N/S)** only — IDS/IPS (tmNIDS) + web-categorization/
reputation + IP reputation. **East–west (E/W) is deferred**; only the catalog schema
leaves room for it (see §7).

---

## 2. Reuse from netvitals — exactly two things

### 2a. Form factor  →  **reuse the visual identity; build the shell fresh**

**Finding (important premise correction):** netvitals has **no local HTTP server
and no browser** anywhere. It is a **single-file, native Tkinter desktop app**
(`import tkinter` at `netquality.py:2096/2635/3659`; UI is `run_gui` @ 2095,
`run_mesh_gui` @ 2634, `run_launcher` @ 3653; `root.mainloop()` @ 2628/2820/3998).
Greps for `http.server` / `socketserver` / `flask` / `wsgi` / `webbrowser` return
**zero** hits. The only sockets are the (out-of-scope) UDP/TCP/VXLAN measurement
probes, and they default to the **all-interfaces wildcard** `0.0.0.0`
(`--bind` default, `netquality.py:4071-4072`), not loopback.

So "reuse the local-server + browser pattern" **cannot be a literal code port** —
that pattern does not exist in netvitals. The task's own non-negotiables, however,
are unambiguously a **web app**: *"bind the local server to loopback only,"* *"the
UI sends a trigger id,"* *"presenter opens it in the Windows browser."* A Tkinter
app cannot satisfy *"bind the local server to loopback."*

**Decision:** Build secvitals as a **stdlib `http.server` bound to `127.0.0.1` +
a single-page web UI** the presenter opens in the Windows browser. Reuse
netvitals' **shared visual identity** — the exact palette/font constants at
`netquality.py:1916-1929`:

| token | value | role |
|---|---|---|
| `ACCENT_GREEN` | `#01A982` | signature green / primary accent |
| `ACCENT_GREEN_DK` | `#017a5e` | hover / pressed |
| `BG` | `#1a1d21` | app background |
| `PANEL` | `#23272e` | card/panel |
| `PANEL_HI` | `#2c313a` | raised/hover panel, flat buttons |
| `GRID` | `#363b44` | borders/grid |
| `TXT` | `#f2f4f5` | primary text |
| `TXT_DIM` | `#9aa3ad` | secondary text |
| `FONT` | `Segoe UI` | UI font |
| `STREAM_COLORS` | `#01A982 #FF8300 #00B0E6 #FEC901` | status accents |

These map 1:1 onto CSS custom properties. The two attached cheatsheets
(`ids-demo-cheatsheet.html`, `webcc-demo-cheatsheet.html`) already express this
same design system in HTML/CSS (teal `--accent:#0E8F86`, light+dark tokens,
"field card" layout: header + brand + panels + sticky-header table + callouts) —
they are the visual reference for the UI shell. Branding assets
(`assets/hpe_logo.svg|png`, `netvitals.ico`) are carried over (note: the logos are
currently *unused* by netvitals code — wiring them in is new work).

**Not reused (wrong scope, per the task):** netvitals' traffic-generation,
measurement, timing, correlation, scoring, and all socket/VXLAN code. None of it
is touched.

### 2b. Update capability  →  **port the mechanism/UX, ADD authenticity, fail closed**

**Finding — what netvitals' self-update does today (required Phase 0 report):**

- **Source:** `UPDATE_URL = https://raw.githubusercontent.com/robertsonc/netvitals/main/netquality.py`
  (`netquality.py:53`). This is the **mutable tip of branch `main`** — not a tag,
  commit SHA, or release asset. It is **overridable at runtime via `--update-url`**
  (`4054-4055`) and that override **persists across the post-update relaunch**
  (`4454-4456`, `3986-3988`) — i.e. the update origin is shortcut/argv-controllable.
- **Transport:** `urllib.request.urlopen(url)` → `resp.read()` (`3147-3154`), a
  single HTTP(S) GET of the raw `.py`. Windows cert-failure fallback
  `_download_via_windows_tls` (`3070-3137`) re-downloads via `curl.exe` then
  PowerShell `Invoke-WebRequest` through SChannel (URL/out-path passed via env vars
  to avoid command splicing; TLS verification stays on). `update.bat` just runs
  `python netquality.py --update %*`. `install.ps1` first-install pulls the
  `codeload` branch **zip** of `main` and the python.org CPython installer, both
  with **no hash/Authenticode check**.
- **Verifies before applying:** *nothing authentic.* Only (1) TLS cert = **host**
  auth, (2) an https→http downgrade guard (`3150-3153`), (3) UTF-8 decode
  (`3178`), (4) `compile()` succeeds (`3183`), (5) substring gate
  `"MAGIC"`/`"Network Vitals"` present (`3186`), (6) `__version__` parses (`3188`),
  (7) `remote_v > local_v` (`3254`). **No signature, no checksum** — `hashlib`/
  `hmac` are never imported for updates. Then `install_update` writes over
  `__file__` via `.new` + atomic `os.replace` (keeps `.bak`, `3194-3220`) and
  `relaunch()` spawns the overwritten file (`3223-3239`).
- **Fail posture:** fails **closed** on the weak checks (any raises → exit 1 /
  "Update check failed", install never reached), but **fails OPEN on
  authenticity** — a well-formed hostile payload (valid Python + the two magic
  strings + a higher version) passes **every** gate and executes with user
  privileges. Threat surface: push-to-`main`, a hijacked `--update-url` host with
  a valid cert, or a CDN-edge compromise each own every client.

**Why this matters for secvitals:** secvitals **also runs local commands**, so an
accepted malicious update is **RCE on every SE laptop**. Porting the update path
"as-is" would inherit a fail-open authenticity hole. The task's non-negotiable
overrides "ported as-is": *"Verify signature or checksum before applying, pin the
source, and fail closed… This is not optional ceremony."*

**Decision — hardened update design (see §6).** Port the **mechanism and UX** of
`fetch_update`/`install_update`/`relaunch`/`perform_update` (atomic `.new`→
`os.replace`, `.bak` backup, detached delayed relaunch, "check vs apply" split,
CLI + a themed in-app dialog) and **insert real authenticity**: an offline-signed
release manifest verified with an **embedded public key** before anything is
written, source **pinned and non-overridable**, **fail closed** on any
verification failure.

---

## 3. Host & execution path — DECISION: **app runs inside WSL** (preferred)

`demo-notes.txt` establishes the signal path: **Windows + WSL → inline security stack →
Internet**; WSL2 NATs through the Windows host, so the inline stack's alerts show the host
LAN IP (e.g. `10.13.1.100`) as source, zone Untrust outbound.

**Chosen:** the **preferred** path — the app runs **inside WSL**, serves on
`127.0.0.1`, and the presenter opens it in the **Windows browser**. Traffic path
is unchanged (still NATs through the host onto the network); execution is **native
bash** — no `wsl.exe` shelling, no nested quoting, no CRLF stripping. This is why
the existing `.cmd` files need `tr -d '\r'`: crossing the Windows→WSL boundary is
the thing we avoid by living inside WSL.

**Not built:** the Windows-native fallback (`["wsl.exe","-e","bash","-lc", …]`).
Per the task: *"Do not build both, and do not build an abstraction layer 'in
case.'"* The runner interface stays free of any Windows-vs-WSL assumption so the
fallback could be added later without redesign, but no such layer is written now.

Either way: **`subprocess` with an argv list, never `shell=True`**, per-trigger
timeout, captured stdout/stderr/returncode.

---

## 4. Dependency posture — DECISION: **zero third-party dependencies**

Matches netvitals' self-contained, pip-free install (itself a supply-chain /
attack-surface win for a tool that self-updates *and* runs commands):

- **Server/UI:** stdlib `http.server` on loopback + a static single-page UI.
- **Catalog:** authored in **YAML** (per the task's examples), loaded by a **small
  vendored pure-Python YAML-subset parser** scoped to the catalog's shape (block
  sequences/mappings, flow `{}`/`[]`, scalars, bools/ints, comments). Keeps the
  catalog hand-editable without a PyYAML dependency.
- **Update authenticity:** **pure-stdlib RSA-2048 / SHA-256 detached-signature
  verification** (strict PKCS#1 v1.5, full-block compare). Signing is done offline
  with `openssl`; the private key never ships; the public key is embedded as a
  constant. No `cryptography`/`pynacl` dependency; the verifier interoperates with
  `openssl dgst -sign` output (proven by a round-trip test).

Rejected alternative: PyYAML + `cryptography`/Ed25519 — less in-house code, but
adds pip-install steps on the SE laptop and to the update path.

---

## 5. Trigger catalog & classifier (data, not hardcoded buttons)

- **Fixed server-side catalog** loaded from YAML at startup (enum/allowlist). The
  UI POSTs a **trigger id**; optional params are validated against a **per-trigger
  allowlist**. A command is **never** constructed from client input.
- **Classes:** `ns-ids` (tmNIDS), `ns-webcc` (web category + web reputation),
  `ns-iprep` (IP reputation). `ew` is a **reserved** class value only (deferred).
  (The YAML example's `ns-swg` is superseded by the more specific `ns-webcc` /
  `ns-iprep` from the web-gateway section.)
- **`ns-ids` seed = tmNIDS 15 signatures.** Core invocation = **cached
  `tmNIDS -N`** (binary cached at a fixed path, downloaded once, `chmod +x`, reused
  — never re-downloaded per click). `ns-uid` (tmNIDS `-1`, SID 2100498) is the
  canonical "should fire on ET Open" trigger — **built first** in Phase 1.
- **Flags surfaced in the UI:** `needs_internet`, `needs_et_ruleset`,
  `hits_live_suspect_hosts`.
- **`hits_live_suspect_hosts`** (tmNIDS 4 `example.livehost.live`/Winnti, tmNIDS 5
  live Tor nodes, parts of 11; SWG `thepiratebay.org`, `hidemyass.com`, the Tor
  IP-rep probes): reach real suspect infrastructure. **Decision: disabled by
  default**, visibly flagged in the UI, and **toggleable by config**, so the
  console can run on a customer-adjacent network without originating
  Winnti-adjacent / awkward-SIEM traffic.

### Local result classifier — the one thing worth engineering

Do not merely stream stdout. The **exit code + response body** carry the signal:

| Enforcement state | Local observation | UI state |
|---|---|---|
| IDS (detect only) | command succeeds, response returns | `sent · allowed` |
| IPS (inline drop) | connection reset / timeout / non-zero rc | `sent · blocked` |
| SWG / IP-rep deny | **silent drop** — timeout/reset, no block page | `sent · blocked` |
| Trigger failed | DNS failure, TLS error, no route, binary missing | `error` + reason |

`blocked` and `error` **must never collapse** — that distinction is the whole
demo. Each catalog entry declares `expected_on_allow` / `expected_on_block` for
the classifier to compare against. Three-state curl classifier (fixes the shell
version's "any nonzero rc = BLOCKED" bug, which fails in the dangerous direction):

```
BLOCKED_RC = {28, 7, 56}          # timeout, conn refused, recv reset — a drop
BROKEN_RC  = {6, 5, 35, 60, 77}   # DNS, proxy DNS, TLS handshake, cert — environment
rc == 0            -> "blocked" if http_code in (403,451) else "allowed"
rc in BROKEN_RC    -> "error"     # never render an environment failure as a policy block
rc in BLOCKED_RC   -> "blocked"
otherwise          -> "error"     # unknown rc is an error, not a block — fail toward honest
```

Retain `rc` + stderr in the result object, show on demand; `error` renders
visually distinct from `blocked` (different colour + label).

**Secure Web Gateway specifics:** there is **no block page** — deny = silent drop (timeout/
reset). No block-page/redirect detection, no "blocked by policy" banner implying
a page was served. **Prerequisite surfaced in the UI:** the category/reputation
must be set to **Deny** in policy for a test to block; an `allowed` result most
often means the policy isn't set, not that enforcement failed.
**IP reputation control probe:** before the Tor probes, connect to one known-good
high-reputation IP:443; if the **control fails → egress broken → whole test
`invalid`**, probe nothing else; if it succeeds, run node probes and report a
**ratio** (`4 of 6 blocked`), never a single verdict. Tor node list cached with a
TTL, not fetched per click. **EICAR** is fetched over HTTPS → a block there is
URL/category reputation, **not** file scanning — labelled accordingly.

---

## 6. Hardened self-update design (secvitals)

- **Pinned source (non-overridable):** a fixed HTTPS release location under
  `robertsonc/secvitals` (release assets / tag, not raw `main`). No `--update-url`
  override that can bypass verification; if an override ever exists it is
  host-allowlisted **and** still signature-gated.
- **Signed manifest:** each release publishes `secvitals.py` + `manifest.json`
  (`version`, `sha256` of the artifact) + `manifest.json.sig` (RSA-2048 PKCS#1 v1.5
  / SHA-256 detached signature over the manifest bytes, base64). Public key
  embedded as `UPDATE_PUBKEY` constant; private key offline only.
- **Verify-before-apply (fail closed):** fetch manifest + sig over pinned HTTPS →
  **verify signature with embedded pubkey** (missing/invalid ⇒ refuse) → enforce
  `version > local` (monotonic, no rollback) → fetch artifact → **SHA-256 must
  match manifest** → atomic `.new`→`os.replace` (keep `.bak`, ported UX) →
  **re-verify on-disk hash before relaunch** (closes fetch→exec TOCTOU) → relaunch.
  Any failure aborts and leaves the running version untouched.
- **Ported as-is from netvitals:** the atomic swap + `.bak`, the detached delayed
  relaunch (port-release), the CLI (`--check-update`/`--update`) vs GUI-dialog
  split, and the frozen-`.exe` guard. Kept only as *corruption* checks (never as
  trust): `compile()` and the UTF-8/self-identity sanity gates.
- **tmNIDS binary** is likewise cached (not re-downloaded per click); its pinned
  download is a second code-execution channel and gets an optional configurable
  checksum pin + hard-fail (`error: binary missing/failed`) on download failure.

---

## 7. E/W — deferred (schema room only)

Out of scope for this build; no E/W code, no anticipatory abstractions. Recorded
so the schema doesn't paint us into a corner:
- **Tier 1** (policy/port probe, no listener): SYN to a denied port in another
  zone; timeout = policy drop, RST = allowed-but-closed, SYN-ACK = allowed-open;
  needs a target **IP** + a **control port** to disambiguate timeouts; skip UDP.
- **Tier 2** (payload signature, listener required): IDS content rules carry
  `flow:established,to_server` (confirmed in `trigger_suricata.sh:49`), so payload
  is only evaluated after a completed 3-way handshake — needs a **second
  deployable** reflector/listener with its own update surface. Not until the
  single-artifact update path is hardened.
- **Schema requirement met:** `class` is an open string field with `ew` reserved;
  the runner interface assumes nothing about traffic being internet-bound.

---

## 8. Explicitly NOT ported

- All `.cmd` launchers (`Run-IDS-*.cmd`, `Run-WebCC-*.cmd`) — Windows→WSL launch
  glue, replaced by the app.
- The interactive `menu()` loops in `run-ids-menu.sh` / `webcc-test.sh` — the app
  UI replaces them (the underlying test lists are kept as catalog data).
- The **`local` mode** of `trigger_suricata.sh` / `Trigger-Suricata.ps1` /
  `Trigger-IDPS.ps1` — it `sudo tee -a`'s a rule (sid 9000001) into
  `local.rules` and reloads/restarts the local IDS engine (`trigger_suricata.sh:45-66`).
  Edits rules, needs privilege, targets a self-hosted sensor rather than the inline stack
  under test, foot-gun on stage. Dropped as a button (kept, if at all, only as a separate gated CLI).
- netvitals' `--update-url` override, mutable-`main` source, and version-only
  trust gate — replaced by the pinned + signed design in §6.
- netvitals' traffic/measurement/scoring engine and all its sockets.

---

## 9. Non-negotiables checklist (tracked through the build)

- [x] Fixed server-side catalog (enum/allowlist); UI sends a **trigger id**; params
  validated per-trigger (allowlist/pattern, control-char guard, compiled at load);
  command never built from client input.
- [x] `subprocess` **argv list**, **no `shell=True`**, per-trigger **timeout**,
  captured stdout/stderr/rc; no `eval`/`exec`; no bare `except:`; structured
  logging (the only `print` is the CLI startup banner).
- [x] Update channel verified (RSA signature) + source pinned (non-overridable) +
  **fail closed**.
- [x] tmNIDS binary cached (no per-click re-download) **and pinned** — mandatory
  SHA-256 verification, bounded download, https enforced, fail closed.
- [x] ~~Server bound to **loopback only**~~ → **superseded (§0):** the console is a native
  Tkinter window with **no network surface at all** (no HTTP server, no listening socket) —
  strictly stronger than a loopback bind. Execution is in-process and **native** (§0b): no
  shell (`curl.exe` exec'd directly; dns/tcp are stdlib probes), no WSL, no third-party
  binary. Commands come only from the fixed catalog.
- [x] `local` mode excluded from the buttons.
- [x] Config (catalog + endpoints) separated from logic, in config files.
- [x] `blocked` vs `error` never collapse — three-state classifier; the tmNIDS path
  uses a **control egress probe** so a broken environment reports `error`, never a
  false `blocked`; live-suspect hosts flagged + disable-able (default off).
- [x] *(Phase 3)* three-state **SWG** classifier (curl rc-set); IP-rep control probe
  (fail => whole test `invalid`) + **ratio** reporting (never a single verdict); Tor list
  cached with a TTL; Deny-prerequisite + silent-drop notice in the UI; EICAR labelled as
  URL/category reputation, not file scanning.

Phase 1 was hardened against an adversarial code review (11 confirmed findings: tmNIDS
supply-chain integrity, tmNIDS block-vs-error honesty via the control probe, YAML
same-indent sequences, load-time predicate validation, handler socket timeout, param
hardening, curl-code honesty, and dropping the unimplemented `tcp443` runner).

---

## 10. Phase plan

- **Phase 0 — Confirm** (this doc). ✅
- **Phase 1 — Vertical slice:** catalog loader + runner + **classifier** + `ns-uid`
  end-to-end in the reused UI shell. Prove allow/blocked/error before breadth.
- **Phase 2 — Full N/S catalog:** remaining tmNIDS triggers, flags surfaced,
  "run all" with sane sequencing + rate limiting.
- **Phase 3 — Secure Web Gateway + IP reputation** (last phase): category/web-rep/ip-rep
  triggers, three-state classifier, control probe, Deny-prerequisite notice.
  **E/W deferred — not started.**
- **Phase 4 — Native Tkinter window** (§0a): replace the loopback web UI with a
  self-contained Tkinter window on Windows Python; re-base the installer on netvitals'
  Windows-Python/pythonw model. ✅
- **Phase 5 — Native execution** (§0b): reproduce the tmNIDS catalog as native
  `curl` / `dns` / `tcp` commands, drop WSL and the tmNIDS binary, run in-process, add the
  taskbar icon. ✅

One commit per logical change, noting reused vs added.
