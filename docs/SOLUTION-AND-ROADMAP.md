# Security Vitals — Solution Overview, User Guide & Feature Roadmap

*A field guide to what Security Vitals fires today, how to run it in front of a
customer, and where it should go next.*

Security Vitals (`secvitals`) exists to do one thing well: put a **known,
attributable quantity of high‑quality security signals** on the wire so a
customer's inline security stack has something honest to catch, live, during a
demo. It fires the traffic and reports what it saw **locally** — `allowed`,
`blocked`, or `error` — and never pretends to be the authority. The customer
reads the real verdict on their own management console, already on screen.

Everything in this document is grounded in the code as of version **0.6.0**
(`secvitals.py`, `config/catalog.yaml`, `config/settings.yaml`). It is organized
in three parts:

1. **[Solution Overview](#1-solution-overview)** — what the product is and,
   specifically, the **test cases (demo triggers) it supports today**.
2. **[User Guide](#2-user-guide)** — how to install, run, read results, and get
   a clean before/after out of a live demo.
3. **[Roadmap of Features](#3-roadmap-of-features)** — a vetted plan for what it
   should support tomorrow, centered on generating *more*, *better‑attributed*
   signals without breaking the design's guardrails.

---

## 1. Solution Overview

### 1.1 What it is

A local, single‑host **security‑trigger console**. The host already sits behind
an inline security stack; traffic egresses and is inspected on the way out:

```
  This host  →  IDS / IPS  +  Secure Web Gateway  →  Internet
```

On a button click the app fires trigger traffic and **classifies the local
result**. It **polls no management API** — verification happens on the inline
stack's console. Security Vitals' only job is to fire clean, attributable
traffic and *honestly* report what it observed on this host. This build covers
**north–south** functions (IDS/IPS, web categorization/reputation, IP
reputation, and DLP / content inspection); east–west is deferred (see §1.9).

### 1.2 Architecture at a glance

| Property | Choice | Why it matters for a demo |
|---|---|---|
| **Form factor** | Single‑file, stdlib‑only **Tkinter window** (`secvitals.py`, ~4,400 lines). No browser, no server. | Nothing to stand up on the SE laptop; opens in its own window with its own taskbar icon. |
| **Execution** | **Native** — `curl.exe` (Windows 10 1803+) for HTTP; built‑in stdlib probes for DNS and TCP; a built‑in IP‑reputation probe. **No WSL, no shell, no download‑and‑execute.** | Windows‑origin traffic (representative); the same IDS signatures trip without shipping a third‑party binary. |
| **What fires** | A **fixed catalog** (`config/catalog.yaml`). Commands are argv lists, never built from free text; optional params are allowlist/pattern‑validated. | The signal set is auditable and repeatable — a *known quantity*, not ad‑hoc traffic. |
| **What it reports** | A **three‑state classifier** where `blocked` and `error` never collapse. | A broken environment is reported as `error`, never a false `blocked` that would misrepresent the customer's product. |
| **Attribution** | Every request captures its **5‑tuple** (src/dst IP+port, protocol, host). | The presenter can match a click to the exact flow/event on the customer's console. |
| **Update** | Signed, fail‑closed self‑update from a pinned source. | The tool runs commands, so its update channel is hardened against becoming an RCE vector. |

### 1.3 The test cases it supports today — the trigger catalog

In Security Vitals' vocabulary, a **"test case" is a demo trigger**: a fixed unit
of traffic designed to trip a specific control. There are **53 triggers** across
**five** active classes — the `ew` class, reserved and empty since Phase 0, is now
filled:

| Class | UI label | Triggers | Catalog commands | On‑wire requests |
|---|---|---:|---:|---:|
| `ns-ids` | NORTH‑SOUTH · IDS / IPS | 23 | 52 | 52 |
| `ns-webcc` | NORTH‑SOUTH · WEB CATEGORIES & REPUTATION (SWG) | 20 | 20 | 20 |
| `ns-dlp` | NORTH‑SOUTH · DATA LOSS PREVENTION (content inspection) | 3 | 4 | 4 |
| `ns-iprep` | NORTH‑SOUTH · IP REPUTATION | 4 | 4 | 24 (4 × node sample) |
| `ew` | EAST‑WEST | 3 | 3 | 0 until targets are configured |
| **Total** | | **53** | **83** | **100** |

**66 signals across 41 triggers** by default; **100 across 50** with the
live‑suspect gate on. The three `ew` triggers contribute **0** until a site defines
`east_west.targets` — they are *not configured*, which is deliberately its own
state, distinct from *gated* and emphatically distinct from *blocked* (§1.4).

> #### The "known quantity" — exactly how many signals hit the wire
>
> Several triggers fire more than one request (e.g. `ns-malua` = 5 malware
> user‑agents, `ns-badcert` = 6 hosts, `ns-iplookup` = 6 lookup services). The
> single `ip-rep-tor` trigger expands to **6 live node probes** (`ip_rep_sample`
> in `settings.yaml`) — which is why the console counts *on‑wire requests*, not
> catalog commands. So a full run is a *fixed, countable* set of signals, and the
> count depends on one toggle:
>
> | Profile | Active triggers | IDS | SWG | DLP | IP‑rep | **Signals on the wire** |
> |---|---:|---:|---:|---:|---:|---:|
> | **Default** (live‑suspect gate **off** — customer‑adjacent) | 35 | 36 | 15 | 4 | 0 | **55** |
> | **Lab** (gate **on**, `enable_live_suspect_hosts: true`) | 41 | 43 | 18 | 4 | 6 | **71** |
>
> Out of the box, six triggers are gated off (§1.7), so the default run omits the
> live bad‑cert signals, the `.onion` lookup, the Pirate Bay / exploit‑tooling /
> adult category hits, and **all** IP‑reputation coverage. Enable the gate in a
> lab you control to fire the full 71.
>
> You never have to trust this table: `--list`, `--dry-run`, or the window's
> **Signal manifest** button compute it from the live catalog and send nothing
> (§2.1a).

**The full catalog (all 53 triggers):**

| # | id | Test case | Class | Runner | Req | Threat | Sev | Expected to fire (SID / rule) | Gated |
|--:|---|---|---|---|--:|---|---|---|:--:|
| 1 | `ns-uid` | Linux UID (`uid=0(root)`) | ns-ids | curl | 1 | recon | info | SID 2100498 — GPL id check returned root | — |
| 2 | `ns-basicauth` | HTTP Basic Auth (root:root) | ns-ids | curl | 1 | policy | warn | ET POLICY — Basic Auth base64 creds | — |
| 3 | `ns-malua` | Malware User‑Agents | ns-ids | curl | **5** | malware | crit | ET USER_AGENTS — BlackSun/JEDI‑VCL/… | — |
| 4 | `ns-badcert` | Bad certificates & CAs | ns-ids | curl | **6** | malware | crit | ET/ML TLS 2022134, 2020493, 2029345/6, 2033098, 2054198/200, 2021941 | **●** |
| 5 | `ns-tor` | Tor `.onion` DNS lookup | ns-ids | dns | 1 | policy | warn | ET POLICY — DNS query for a `.onion` | **●** |
| 6 | `ns-peexe` | EXE / DLL download over HTTP | ns-ids | curl | 1 | malware | warn | ET/GPL — Windows PE over cleartext HTTP | — |
| 7 | `ns-pdfembed` | PDF with embedded file | ns-ids | curl | 1 | malware | warn | ET — PDF with an embedded file | — |
| 8 | `ns-sshscan` | Outbound SSH scan (:22) | ns-ids | tcp | 1 | recon | info | ET SCAN — outbound SSH banner grab | — |
| 9 | `ns-dns` | Suspicious domains (sinkhole/DDNS/rare TLD) | ns-ids | dns | **3** | policy | info | ET DNS — sinkhole / DDNS / suspicious TLD | — |
| 10 | `ns-anonfile` | Anonymous filesharing (fromsmash.com) | ns-ids | curl | 1 | policy | warn | ET POLICY — anon file‑sharing (SNI) | — |
| 11 | `ns-iplookup` | External IP‑address lookup | ns-ids | curl | **6** | recon | info | ET POLICY — external IP lookup (ipify/ipinfo/…) | — |
| 12 | `ns-shortener` | URL shorteners | ns-ids | curl | **3** | policy | warn | ET POLICY — shorteners (2038992, 2038568, 2035742) | — |
| 13 | `ns-gaming` | Policy violation — gaming | ns-ids | curl | **2** | policy | warn | ET POLICY — gaming UA/client (2014718, 2013910) | — |
| 14 | `ns-adware` | Adware / PUP | ns-ids | curl | **3** | malware | warn | ET ADWARE_PUP (2003060, 2002001, 2002092) | — |
| 15 | `ns-c2` | Malware C2 beacon | ns-ids | curl | **2** | c2 | crit | ET MALWARE — C2 beacon (2027793, 2016568) | — |
| 15a | `ns-log4shell` | Log4Shell JNDI probe (CVE‑2021‑44228) | ns-ids | curl | 1 | exploit | crit | ET EXPLOIT — Log4j JNDI injection in an HTTP header | — |
| 15b | `ns-shellshock` | Shellshock CGI probe (CVE‑2014‑6271) | ns-ids | curl | 1 | exploit | crit | ET EXPLOIT — Bash function definition in a header | — |
| 15c | `ns-spring4shell` | Spring4Shell class‑loader probe (CVE‑2022‑22965) | ns-ids | curl | 1 | exploit | warn | ET EXPLOIT — Spring class‑loader manipulation | — |
| 15d | `ns-scanner-ua` | Scanner user agents (Nikto/sqlmap/Nmap) | ns-ids | curl | **3** | recon | warn | ET SCAN — scanner user agent observed outbound | — |
| 16 | `web-cat-gambling` | Gambling — bet365.com | ns-webcc | curl | 1 | policy | info | SWG category Gambling · Deny → timeout | — |
| 16a | `ns-dns-dga` | DGA‑style domains (high‑entropy generated names) | ns-ids | dns | **3** | c2 | warn | ET DNS / DGA heuristics — algorithmically generated lookups | — |
| 16b | `ns-dns-tunnel` | DNS tunnelling (long labels, TXT + NULL) | ns-ids | dns | **3** | c2 | crit | ET DNS — tunnelling / exfiltration over TXT and NULL | — |
| 16c | `ns-doh` | DNS‑over‑HTTPS (resolver bypass) | ns-ids | curl | **2** | policy | warn | ET POLICY — DNS over HTTPS (DoH) usage | — |
| 16d | `ns-uid-v6` | Linux UID over **IPv6** (address‑family parity) | ns-ids | curl | 1 | recon | warn | SID 2100498 over IPv6 — same signature on the v6 path | — |
| 17 | `web-cat-social` | Social Networking — facebook.com | ns-webcc | curl | 1 | policy | info | SWG Social Networking · Deny → timeout | — |
| 18 | `web-cat-streaming` | Streaming Media — youtube.com | ns-webcc | curl | 1 | policy | info | SWG Streaming Media · Deny → timeout | — |
| 19 | `web-cat-proxy` | Proxy / Anonymizer — hidemyass.com | ns-webcc | curl | 1 | policy | warn | SWG Proxy Avoidance · Deny → timeout | — |
| 20 | `web-cat-p2p` | Peer‑to‑Peer — thepiratebay.org | ns-webcc | curl | 1 | policy | warn | SWG Peer‑to‑Peer · Deny → timeout | **●** |
| 21 | `web-cat-crypto` | Cryptocurrency — coinbase.com | ns-webcc | curl | 1 | policy | info | SWG Cryptocurrency · Deny → timeout | — |
| 22 | `web-rep-eicar` | EICAR test file (URL/category reputation) | ns-webcc | curl | 1 | malware | crit | Web reputation / SWG · Deny → timeout | — |
| 23 | `web-rep-malware-gsb` | Malware page (Google Safe Browsing test) | ns-webcc | curl | 1 | malware | crit | Web threat (malware) · Deny → timeout | — |
| 24 | `web-rep-phishing-gsb` | Phishing page (GSB test) | ns-webcc | curl | 1 | malware | crit | Web threat (phishing) · Deny → timeout | — |
| 25 | `web-rep-unwanted-gsb` | Unwanted software (GSB test) | ns-webcc | curl | 1 | policy | warn | Web threat (unwanted) · Deny → timeout | — |
| 25a | `web-cat-genai` | Generative AI / Shadow AI — chatgpt.com | ns-webcc | curl | 1 | policy | warn | SWG category Generative AI · Deny → timeout | — |
| 25b | `web-cat-webmail` | Personal webmail — mail.yahoo.com | ns-webcc | curl | 1 | policy | info | SWG category Personal Webmail · Deny → timeout | — |
| 25c | `web-cat-dating` | Dating — match.com | ns-webcc | curl | 1 | policy | info | SWG category Dating · Deny → timeout | — |
| 25d | `web-cat-jobsearch` | Job Search — indeed.com | ns-webcc | curl | 1 | policy | info | SWG category Job Search · Deny → timeout | — |
| 25e | `web-cat-weapons` | Weapons — guns.com | ns-webcc | curl | 1 | policy | info | SWG category Weapons · Deny → timeout | — |
| 25f | `web-cat-drugs` | Marijuana / Drugs — leafly.com | ns-webcc | curl | 1 | policy | info | SWG category Marijuana / Drugs · Deny → timeout | — |
| 25g | `web-cat-hacking` | Hacking / exploit tooling — exploit‑db.com | ns-webcc | curl | 1 | policy | warn | SWG category Hacking · Deny → timeout | **●** |
| 25h | `web-cat-social-v6` | Social Networking over **IPv6** (SWG parity) | ns-webcc | curl | 1 | policy | info | SWG category Social Networking over IPv6 · Deny → timeout | — |
| 25i | `web-cat-social-h3` | Social Networking over **HTTP/3** (QUIC parity) | ns-webcc | curl | 1 | policy | warn | SWG category over HTTP/3 · a UDP/443 flow — no log entry is itself the finding | — |
| 25h | `web-cat-adult` | Adult content — category test | ns-webcc | curl | 1 | policy | warn | SWG category Adult · Deny → timeout | **●** |
| 26 | `ip-rep-tor` | IP Reputation — Tor Proxy nodes (:443) | ns-iprep | iprep | 1* | policy | warn | IP reputation "Tor Proxy" · Deny → timeouts (ratio) | **●** |
| 26a | `ip-rep-botnet` | IP Reputation — botnet C2 (Feodo Tracker) | ns-iprep | iprep | 1 * | c2 | crit | IP reputation 'Botnet C2 / Malware' · Deny → timeouts (ratio) | **●** |
| 26b | `ip-rep-scanner` | IP Reputation — SSH brute‑force sources (:22) | ns-iprep | iprep | 1 * | recon | warn | IP reputation 'Scanner / brute‑force' · Deny → timeouts (ratio) | **●** |
| 26c | `ip-rep-spammer` | IP Reputation — mail‑abuse sources (:25) | ns-iprep | iprep | 1 * | policy | warn | IP reputation 'Spam source' · Deny → timeouts (ratio) | **●** |
| 27 | `dlp-pan` | Credit‑card data (synthetic test PAN) | ns-dlp | curl | 1 | dlp | crit | DLP — credit‑card number in an outbound POST body | — |
| 28 | `dlp-ssn` | Personal data (never‑issued SSN) | ns-dlp | curl | 1 | dlp | crit | DLP — US SSN pattern in an outbound POST body | — |
| 29 | `dlp-secrets` | Credentials & keys (documentation examples) | ns-dlp | curl | **2** | dlp | crit | DLP — cloud access key / private‑key material | — |
| 30 | `ew-server-zone` | Segmentation — workstation → server zone | ew | ew | 1 † | lateral | crit | East–west policy · DENY admin ports (SMB/RDP/SSH/SQL) | ○ |
| 31 | `ew-user-zone` | Segmentation — peer workstation isolation | ew | ew | 1 † | lateral | warn | East–west policy · client isolation between peers | ○ |
| 32 | `ew-dmz` | Segmentation — DMZ → internal pivot | ew | ew | 1 † | lateral | crit | East–west policy · DMZ → internal should DENY | ○ |

<sub>`Req` = number of catalog commands. `*` an `iprep` trigger has one command but probes `ip_rep_sample` (6) live addresses on the wire — 4 feeds × 6 = 24. `†` an `ew` trigger probes one port per entry in its target's `ports` list, and contributes **0** until `east_west.targets` is defined. `●` = gated by `hits_live_suspect_hosts`, off by default. `○` = *not configured* for this site — a different state from gated, and not a policy result. Lettered rows were added in roadmap waves 1 and 2.</sub>

**On the exploit and DLP payloads.** Both packs are built to be *inert by
construction*, because a demo tool must never actually attack anything or leak
real data. The exploit payloads are fixed literal strings sent as headers or
query strings to the same benign tmNIDS origin the rest of the IDS catalog uses;
the JNDI references point at the RFC 2606 reserved `.invalid` TLD and are never
resolved or fetched. The DLP bodies use publicly documented test values — the
universal Visa test PAN, an SSN in the never‑issued 666 area, and AWS's own
documentation example key. The sensor matches the pattern on the wire, which is
the entire point; nothing is exploited and no real data exists to lose.

Each trigger also carries a **talking point** and an **expected‑fire** string
(the SID or rule a presenter can name), both surfaced in the UI.

### 1.4 The honest classifier — the one thing worth engineering

Security Vitals never merely streams stdout. It reads the exit code / response
into one of **five** result states, and it is deliberate about which two must
**never** be confused:

| State | Local observation | How to read it |
|---|---|---|
| **allowed** | The trigger ran; the expected response came back. | IDS is in **detect‑only** mode, or the SWG category is not set to Deny. |
| **blocked** | The flow was dropped inline (reset / timeout / policy deny). | **IPS / SWG enforcement is working** — the money shot. |
| **error** | The trigger couldn't run (DNS, TLS, no route, curl missing). | **Not a policy result.** Fix the environment; never read as a block. |
| **invalid** | A gated live‑suspect trigger is off; the IP‑rep egress control failed; an east‑west target is **not configured** for this site; or `curl` is missing. | Enable the gate in a lab, fix egress, define `east_west.targets`, or install curl. Never a policy result. |
| **ratio** | IP reputation reached N‑of‑M live suspect nodes. | A ratio, not a verdict; the inline IP‑rep stats are authoritative. |

`blocked` and `error` **never collapse** — that distinction is the whole demo.
How each runner decides:

- **curl**: exit codes are mapped explicitly. `28/7/56` (timeout / connection
  refused / recv reset) → **blocked**; `6/5/35/60/77` (DNS, proxy DNS, TLS
  handshake, cert) → **error**; `rc 0` with HTTP `403/451` → **blocked**, else
  **allowed**; `rc 0` with no parseable code → **error**; any unknown code →
  **error** (fail toward honest).
- **Optional per‑trigger refinement**: a gateway that serves a block page at HTTP
  200 (or redirects to one) would look like `allowed` to the exit‑code mapping
  alone. A catalog entry may declare `expected_on_block` / `expected_on_allow`
  (matching on `rc`, `rc_nonzero`, `http_code`, `http_code_in`, `body_contains`)
  to catch that. The refinement is applied **only to a request that actually
  completed** (`rc 0`), so it can never promote an environment failure to
  `blocked` or demote a real inline drop to `allowed`.
- **dns / tcp** probes: a probe that doesn't complete is *ambiguous* — it could
  be an inline drop or a broken network. A **control egress probe** to a
  known‑good host (`1.1.1.1:443` by default) disambiguates: control OK + probe
  failed → **blocked**; control failed → **error**, never a false blocked.
- **Multi‑request triggers aggregate honestly**: `blocked` only when *every
  reachable* request was dropped; the per‑request split is always shown.
- **IP reputation** runs the control probe first (fail → whole test `invalid`),
  then reports **N‑of‑M blocked** as a ratio — never a single verdict, because a
  lone reach may be a live relay and a lone block may be an offline node.

### 1.5 Attribution: the 5‑tuple

Every request records the exact **5‑tuple** it put on the wire — source and
destination IP and port, protocol, and the dialed hostname. For curl this comes
back through an injected `--write-out` marker (`SECV-5TUPLE`, added *in code* so
the displayed command stays exactly what the catalog declares); for the stdlib
probes it comes from the live socket's `getsockname()`/`getpeername()`. Unknown
fields render as `—`, never a plausible‑looking guess. This is what lets a
presenter jump from "I clicked Fire" to the precise flow row on the customer's
console.

### 1.6 Serialization & rate limiting

Triggers run **one at a time** (a process‑wide lock) with a **minimum spacing**
between runs (`run.min_interval_s`, default 0.75s) so a "Run all" — or a fast
clicker — can't flood the inline stack or the customer's SIEM. "Run all" fires
every enabled trigger in catalog order and can be stopped after the current one.

### 1.7 The live‑suspect gate

Four triggers reach **real** suspect infrastructure or live Tor nodes and are
**disabled by default** so the console is safe to run on a customer‑adjacent
network: `ns-badcert`, `ns-tor`, `web-cat-p2p`, `ip-rep-tor`. They are visibly
flagged **LIVE** in the UI and enabled together via one setting
(`enable_live_suspect_hosts: true`) — only in a lab you control.

### 1.8 Security posture & the software's own tests

Because the console executes local commands, it is built defensively: **no
network surface** (no server, no listening socket), **no shell** (`curl.exe`
exec'd directly with an argv list; DNS/TCP are stdlib probes), **no
download‑and‑execute**, per‑trigger timeouts, and per‑trigger param
allowlist/pattern validation. The self‑update channel is **pinned,
non‑overridable, RSA‑2048/SHA‑256 signed, and fails closed** (pure‑stdlib
verification; atomic swap with `.bak`; on‑disk re‑verify to close a TOCTOU
window; Windows SChannel fallback for TLS‑inspecting proxies). Full detail lives
in [`UPDATE_SECURITY.md`](UPDATE_SECURITY.md).

Distinct from the *demo* test cases, the **software has 138 automated unit
tests** (`tests/`, green on CI) covering the runner, the three‑state classifier
and its `expected_on_*` refinement, catalog/YAML loading and validation, the
IP‑reputation probe, the signed updater (round‑tripped against `openssl`), the
signal manifest, headless mode, and a headless Tkinter build smoke test. They
stub the network deliberately (curl via a Python stub, TEST‑NET‑1 for guaranteed
DNS timeouts, `file://` release URLs, a fake Tor list), so the one thing they
*cannot* assert is signal **fidelity to a real IDS SID** — that is only
verifiable on the inline stack, by design.

### 1.9 What's deferred

**East–west tier 1 has shipped** — three segmentation triggers fill the formerly
empty `ew` class (§3.3). What remains deferred is **tier 2**: payload‑signature
testing east–west. IDS content rules carry `flow:established,to_server`, so payload
is only evaluated after a completed three‑way handshake — which needs a **second
deployable** reflector/listener with its own update surface. That breaks the
single‑file guardrail, so it stays out until the update path is hardened for two
artifacts. See `CONFIRMED.md` §7.

Also unverified rather than deferred: **no build has been launched on real
Windows**. `tkinter` cannot be installed in CI, so the window is covered by a
fake‑widget smoke test that catches the Tcl option errors which broke 0.1.1 — but
presenter mode and the report dialog have never opened an actual window.

---

## 2. User Guide

### 2.1 Install & run

**Windows (one‑click):** double‑click **`install.bat`**. A per‑user setup window
(no admin) finds a Windows Python with Tkinter (installing one from python.org if
needed), confirms `curl.exe` is present, copies the app, and creates Start
Menu / Desktop shortcuts and a Settings → Apps entry. See
[`INSTALL.md`](INSTALL.md) for silent install and options.

**Run manually:**

```bash
py secvitals.py          # Windows (from the install folder)
python3 secvitals.py     # Linux (development)
```

Useful flags: `--verbose`, `--config-dir DIR`, `--check-update`, `--update`,
`--version`. No dependencies beyond Python 3.8+ (stdlib only); HTTP triggers need
`curl.exe`.

### 2.1a Know the number before you fire — the signal manifest

Three ways to get the exact, live‑computed signal count, **none of which send
anything**:

```bash
py secvitals.py --list                 # the catalog + the count
py secvitals.py --dry-run              # every command that WOULD be sent
py secvitals.py --list --format json   # the same, machine-readable
```

…or click **☰ Signal manifest** in the window. The window's header also shows the
running total (`66 signals · 41 triggers`), and each trigger card carries its own
signal chip — so `ip-rep-tor` reads *6 signals*, not *1 command*.

Use this to open the demo with a concrete promise: *"I'm about to generate 66
attributable signals across 41 triggers — here's the list."*

The manifest separates three reasons a trigger will not run, because they mean
different things and only one of them is fixable with a toggle:

- **DISABLED — reaches live suspect infrastructure** — the gate (§2.7).
- **NOT CONFIGURED HERE** — east–west triggers with no `east_west.targets`
  defined for this site. No gate can supply a target.
- neither — it runs.

The "if the gate were enabled" figure counts only what the **gate** can unlock, so
it never promises signals that configuration alone would deliver.

### 2.1b Pre‑brief with headless mode

```bash
py secvitals.py --run all                    # everything (gated triggers skipped)
py secvitals.py --run ns-dlp                 # one whole class
py secvitals.py --run ns-uid,web-cat-genai   # named triggers
py secvitals.py --run all --format json      # one JSON document for scripting
```

Run this **from the customer's network before the meeting**. It uses the same
`App.run` and classifier the window does, so what you see is what the demo will
do. Exit codes are policy‑neutral:

| Exit | Meaning |
|---:|---|
| **0** | Every trigger produced a policy result — **including `blocked`**, which is the product working. |
| **1** | At least one `error`/`invalid` — a broken environment or a gated trigger you named explicitly. |
| **2** | Usage or config problem (unknown trigger id/class, bad config). |

A red build here means *fix your environment*, never *the customer's stack failed*.

### 2.1c Demo profiles — run a story, not an inventory

"Run all" is catalog order, which is an inventory. A **profile** is a curated,
ordered subset with a committed signal count:

```bash
py secvitals.py --profiles                     # what's available + each count
py secvitals.py --profile exec-5min --list     # the plan for that profile
py secvitals.py --profile exec-5min --run all  # fire it, in profile order
```

Five ship in `settings.yaml`: `exec-5min` (6 signals), `ids-story` (21),
`swg-story` (9), `data-protection` (5), `modern-cve` (6). A profile only ever
**selects** existing catalog ids — it never defines a command — and every id is
validated at startup, so a typo fails at launch rather than on stage.

In the window, **🎤 Presenter mode** walks one trigger at a time in large type:
expected SID, talking point, where to look on the customer's console, then the
observed state and a running scoreboard by state and class. The scoreboard counts
what **this host observed**; it is never a claim about the customer's stack.

### 2.1d Leave something behind — the evidence report

```bash
py secvitals.py --run all --export demo.html   # HTML leave-behind (.json / .csv too)
py secvitals.py --last-session                 # re-read the last run, fire nothing
```

…or click **⬇ Save report**. Every run is recorded in a **hash‑chained ledger**
stamped with SHA‑256 digests of the code and catalog that produced it, so a report
can be shown not to have been quietly edited after the fact.

The report keeps three kinds of evidence in three columns that are never merged:

| Column | Source | Authority |
|---|---|---|
| **Expected to fire** | the fixed catalog | what *should* happen if the control enforces |
| **Observed locally** | this host's classifier | honest, but only about what *this host* saw |
| **Confirmed on console** | the presenter ticking a box | a human attestation, not a measurement |

That third column is the per‑card **Console:** toggle (*not marked → confirmed ✓ →
not seen*). It is stored beside the machine's observation, never on top of it, and
deliberately sits **outside** the hash chain — a human annotation added after the
run would otherwise look identical to tampering.

**Local disk only.** Nothing is uploaded, and no browser is launched on your behalf.

### 2.1e Pre‑flight — is this host ready?

```bash
py secvitals.py --preflight        # exit 0 ready, 1 not ready
py secvitals.py --strict-catalog   # refuse to start unless the catalog is signed
```

`--preflight` checks curl, egress control, and the catalog signature. It answers
exactly one question — *can this console run its triggers from here?* — and says so
in its own output. It is **not** a prediction of what policy will allow or block;
that is what firing the triggers is for.

### 2.1f East–west: probing internal segmentation

`ew-server-zone`, `ew-user-zone` and `ew-dmz` probe whether one internal zone can
reach another. Tier 1 is a bare TCP connect — no payload, no listener needed.

Targets are **your** addresses, so nothing ships pre‑filled. Until you define
`east_west.targets`, these report *"not configured"*. Reading a result:

| Outcome | What happened | Reported as |
|---|---|---|
| SYN‑ACK | reachable, listening | reachable |
| **RST** | the SYN **arrived** and the host answered — path open, port closed | **reachable** |
| timeout | no answer at all | **blocked** |
| unreachable | `ENETUNREACH` / ICMP unreachable — *this* host has no route | **error** |

A **RST is not a block** — it proves the packet got there, and reporting it as
blocked would credit the firewall with work the host did. A control port on the
same target is probed first; if the host itself does not answer, the result is
`error`, never a false `blocked`.

### 2.2 The window

Triggers are grouped by class into cards. Click a card to expand its context
(class/threat/severity chips, the expected‑fire SID, the talking point, and the
**Fire** button). After a run, the card shows a status line (*last run HH:MM:SS ·
N runs*), the local read, and two on‑demand detail panes: **command/payload
details** (per‑request rc/http/outcome) and **5‑tuple details** (the flow table).
The toolbar has **▶ Run all enabled**, **■ Stop**, and **⟳ Check for updates**.

### 2.3 Reading a result

Map each state to what you *say* in the room:

- **allowed** → "The traffic went through — this control is in detect‑only mode
  (or the category isn't set to Deny). Watch it light up on your console."
- **blocked** → "Your stack dropped it inline. That's the enforcement working."
  *(the money shot)*
- **error** → "That's my environment, not your product — let me fix egress/DNS
  and re‑fire." Never present an `error` as a block.
- **invalid** → a gated trigger is off, or IP‑rep egress control failed.
- **ratio** (IP‑rep) → "N of 6 Tor nodes were blocked by reputation; your
  reputation stats are the source of truth."

### 2.4 The classic before/after (IDS → IPS)

This is the demo's centerpiece:

1. With the customer's policy in **detect‑only (IDS)** mode, fire a trigger
   (e.g. `ns-uid`). Locally: **allowed**. On their console: an **alert**.
2. Flip the same policy to **inline/IPS** (or set the SWG category to **Deny**).
3. Fire the **same** trigger. Locally: **blocked**. Same traffic, now dropped.

Same signal, two outcomes — the strongest story the tool tells.

### 2.5 Nuances worth pre‑loading

- **SWG denies are silent.** There is **no block page** — a deny is a
  timeout/reset. Crucially, an **`allowed` SWG result usually means the category
  isn't set to Deny**, not that enforcement failed. Confirm the policy first.
- **EICAR over HTTPS is reputation, not file scanning.** Without SSL inspection,
  a block on `web-rep-eicar` is URL/category reputation — label it that way.
- **IP reputation is a ratio.** The control probe runs first; if egress is down
  the whole test is `invalid`, not blocked.

### 2.6 Correlating with the customer console

Because Security Vitals polls no API, this correlation *is* the verification
step. Three things make it fast:

1. **The console hint.** Each expanded card names *where to look* on the inline
   stack (alert log, URL‑filtering log, reputation hits, DLP log). Catalog
   entries can override the per‑class default with their own `console_hint`.
2. **The verification key.** After a run, click **Copy verification key** — you
   get one greppable line to paste straight into the console's filter box:

   ```
   2026-07-25T09:14:07Z | ns-uid | expect SID 2100498 — GPL ATTACK_RESPONSE id check returned root | 10.13.1.100:51844 -> 3.33.130.190:80 (testmynids.org) | local:allowed
   ```

   An endpoint the run never learned prints `—` rather than a plausible‑looking
   guess. The same key appears in the card's **verification key** pane and in
   headless output (`verify_key`).
3. **The 5‑tuple pane**, for the full per‑request breakdown when one line isn't
   enough.

### 2.7 Enabling the live‑suspect triggers

Only in a lab you control, set in `config/settings.yaml`:

```yaml
enable_live_suspect_hosts: true
```

This turns on `ns-badcert`, `ns-tor`, `web-cat-p2p`, `web-cat-hacking`,
`web-cat-adult`, `ip-rep-tor`, `ip-rep-botnet`, `ip-rep-scanner` and
`ip-rep-spammer` — the difference between a 66‑signal and a 100‑signal run.

The three reputation feeds beyond Tor reach **real** botnet‑C2, scanner and
mail‑abuse addresses, and `ip-rep-scanner`/`ip-rep-spammer` probe **:22 and :25**,
which some corporate egress policies deny outright. That is a legitimate `blocked`,
but know it so it is not misread as IP‑reputation enforcement specifically.

### 2.8 Configuration knobs (`settings.yaml`)

Logic and config are separate. You edit `settings.yaml`; the **catalog is fixed**
(edit it only as an audited change). The knobs that matter on the day:

| Setting | Default | What it controls |
|---|---|---|
| `enable_live_suspect_hosts` | `false` | The nine LIVE triggers (§2.7). |
| `run.default_timeout_s` | `30` | Per‑trigger timeout ceiling. |
| `run.control_host` / `control_port` | `1.1.1.1` / `443` | The egress control probe (blocked‑vs‑error disambiguation). Set host to `""` to disable. |
| `run.min_interval_s` | `0.75` | Minimum spacing between runs. |
| `run.control_endpoints` | 3 endpoints | Ordered, transport‑matched control list; egress counts as up if **any** answers, so one filtered host cannot mask real blocks. Falls back to `control_host`/`control_port`. |
| `run.ipv6_control_url` | Cloudflare v6 literal | Tells "this host has no IPv6" apart from "policy dropped it". Empty ⇒ IPv6 triggers report `error` rather than guess. |
| `run.correlation_header` | `false` | Stamp `X-SecVitals-Run` on curl triggers. **Off by design** — it marks the traffic synthetic. |
| `run.origin_failover` | `{}` | ERROR‑only failover to an alternate origin. **Empty by design** — see the Wave 2 caveats (§3). |
| `run.strict_catalog` | `false` | Refuse to start unless `catalog.yaml.sig` verifies. |
| `webcc.ip_rep_sample` | `6` | How many addresses each IP‑rep feed probes. |
| `webcc.tor_list_url` / `tor_list_ttl_s` | SecOps‑Institute list / `3600` | Source and cache TTL for the Tor relay list. |
| `webcc.reputation_feeds` | 3 feeds | Named https IP‑reputation feeds (`botnet-c2`, `scanner`, `spammer`). A trigger names a feed by **fixed token**, never a URL. |
| `east_west.targets` | `{}` | Your internal zones (host, control port, denied ports). Empty ⇒ `ew` triggers report *not configured*. |
| `east_west.probe_timeout_s` | `3` | Per‑port east–west probe timeout. |
| `evidence.log` / `evidence.dir` | `true` / per‑user | Local JSONL evidence log and where artifacts land. Local disk only. |
| `profiles` | 5 profiles | Curated, ordered run‑sets. Ids are validated against the catalog at startup. |
| `update.check_on_start` | `false` | Whether to check for updates at launch. |

### 2.9 Updating

Use **⟳ Check for updates** in the window, or `py secvitals.py --update` from the
install folder. Either path runs the hardened, signed self‑update (pinned source,
RSA‑verified, fail closed; the previous file is kept as `.bak`). Restart to run
the new version.

### 2.10 Pre‑demo checklist

1. Run `py secvitals.py --run all` **from the customer's network** — the
   pre‑brief. Exit 0 means every trigger produced a policy result; exit 1 tells
   you which origin or control probe to fix *before* you're on stage.
2. Decide the profile: **default (66 signals)** on a customer‑adjacent network,
   or **lab (100 signals)** with the gate on. Confirm with `--list`, or pick a
   demo profile with `--profile <name> --list` (§2.1c).
3. Fire one cheap trigger (`ns-uid`) and confirm you see it on the customer
   console — this proves the correlation path before the real run. Use **Copy
   verification key** to jump straight to the right filter.
4. Agree with the customer which policy you'll flip for the before/after.
5. Open with the **Signal manifest** so the room knows the number up front.

---

## 3. Roadmap of Features

The roadmap below was generated by fanning out feature ideas across five lenses
(known‑quantity signal accounting, coverage breadth, SE usability, closing the
verification loop, and trust/robustness) and then **adversarially vetting each
idea** against the product's non‑negotiables. Thirty‑two ideas survived; one was
deliberately rejected (§3.6).

> ### ✅ Wave 1 — shipped
>
> The recommended first wave (§3.7) is **delivered**. Items marked ✅ below are in
> the product today:
>
> - **True on‑wire counts** — `on_wire_count()` / `wire_request_count`; the IP‑rep
>   6× under‑report is fixed, and the count is surfaced in the header, on every
>   card, and in headless output.
> - **Dry‑run signal manifest** — `--list` / `--dry-run` / `--format json` and the
>   window's **☰ Signal manifest**; computes from the live catalog and sends
>   nothing (enforced by a test that fails if any I/O is attempted).
> - **Headless pre‑brief mode** — `--run all|<ids>|<classes>` with policy‑neutral
>   exit codes (a `blocked` trigger still exits 0).
> - **Catalog packs** — modern‑exploit (Log4Shell / Shellshock / Spring4Shell /
>   scanner UAs), SWG categories (Generative AI, webmail, dating, job search,
>   weapons, drugs, + gated hacking and adult), and DLP (PAN / SSN / secrets).
>   Signals went from **39 → 55** by default and **53 → 71** in a lab.
> - **Verification key + console hints** — a pasteable correlation line, a
>   per‑class "where to look" hint with an optional per‑trigger `console_hint`,
>   and a **Copy verification key** button.
> - **`expected_on_*` refinement** — the validated‑but‑unused predicates now
>   refine classification for completed requests only, so a block page served at
>   200 is caught without ever promoting an error to `blocked`.
>
> The suite grew from **89 to 138 tests** alongside these changes.

> ### ✅ Wave 2 — shipped (the rest of the roadmap)
>
> Everything else in §3.2–§3.5 is **delivered**, across five independently
> reviewed milestones. Versions are numeric‑only by design: the updater's version
> parser strips non‑digits, so `0.2.0-alpha.1` and `0.2.0` would both parse as
> `(0,2,0)` and an alpha user would never see the final release as newer. The
> alpha marker lives in the release tag instead.
>
> | Milestone | Version | What it delivered |
> |---|---|---|
> | **M1 · Evidence & Reporting** | 0.2.0 | Hash‑chained run ledger, provenance stamp, expected/observed/confirmed scorecard, coverage matrix, JSON/CSV/HTML export, local JSONL evidence log, optional correlation header |
> | **M2 · Presenter Experience** | 0.3.0 | Demo profiles (curated, ordered, validated at startup), presenter mode with a live scoreboard, deterministic pre‑run plan |
> | **M3 · Coverage Breadth** | 0.4.0 | DNS‑security pack (DGA / tunnelling / DoH), DNS query types, three new reputation feeds, IPv6 & HTTP‑3 parity twins with a transport‑capability gate |
> | **M4 · East‑West Tier 1** | 0.5.0 | Internal segmentation probing; fills the `ew` class |
> | **M5 · Trust & Robustness** | 0.6.0 | Multi‑endpoint control probe, catalog signing + `--strict-catalog`, `--preflight`, graceful curl‑absent, ERROR‑only origin failover |
>
> Catalog: **41 → 53 triggers**, **71 → 100** lab signals. Suite: **138 → 306
> tests** across 14 files.
>
> #### Three things Wave 2 deliberately did *not* do
>
> - **The correlation header ships OFF.** It marks the traffic as synthetic and
>   adds a header to requests whose whole job is to reproduce a signature
>   faithfully. That trade belongs to the operator.
> - **Origin failover ships EMPTY.** An alternate origin that does not serve the
>   same content can turn a real signal into a benign request — `ns-uid` matches
>   on the *response body*, so a 404 from an alternate would read as `allowed`
>   while proving nothing. Enable it only with an origin you control.
> - **Catalog signing fails VISIBLE, not closed.** Existing installs have no
>   signature and must keep working, so an unsigned catalog is reported rather
>   than refused. `--strict-catalog` opts into refusal, and gates every path
>   including `--list` — an untrusted catalog should not even be enumerated.
>
> #### What integration cost, and what it caught
>
> The five milestones were built as independent branches off `main`, which meant
> nine merges as each landed. That found **four defects no single‑branch CI could
> have caught**, because each only existed once milestones were combined:
>
> 1. A **dropped `@property`** — both branches added a `Settings` property under a
>    shared `@property` line, and concatenating left the second undecorated. A
>    bound method is always truthy, so evidence logging ran even when an operator
>    had configured it **off**.
> 2. A **dropped `return out`** — `load_ew_targets` and `load_profiles` both end
>    with that exact line; git matched it as shared context and emitted it once.
>    `load_ew_targets` returned `None`, which would have made every east‑west
>    trigger raise instead of reporting "not configured".
> 3. An **availability check split in two** — several call sites still asked only
>    `gated_disabled`, so the header promised signals that could not fire and the
>    coverage matrix counted unconfigured triggers as exercisable.
> 4. A **trigger count that overstated the gate** — "N signals if the gate is
>    enabled (M triggers)" counted triggers no gate can unlock.
>
> Neither of the first two changed a visible line of logic, and both were
> invisible in the conflict diff. All four now have permanent regression guards.

### 3.1 The guardrails every feature must respect

The value of this tool is that its signal set is **fixed, honest, and safe**. Any
new feature must preserve all of:

1. **Fixed catalog** — no command is ever built from free text.
2. **No network surface** — no server, no listening socket.
3. **No shell, no download‑and‑execute** — argv‑only, native probes.
4. **Honest classifier** — `blocked` and `error` never collapse; never a false
   blocked.
5. **Single‑file, stdlib‑only, zero third‑party deps.**
6. **Signed, fail‑closed update** from a pinned source.
7. **Live‑suspect gate** — awkward traffic is off by default.

A good feature *extends the mission* — more, better‑attributed, higher‑quality
signals, or better proof of them — **without touching any of the seven**.

### 3.2 Theme A — Known quantity & attribution *(the north star)*

Make the signal count exact, reproducible, and provable to the customer.

| Feature | What it adds | Value | Effort | Horizon |
|---|---|:--:|:--:|:--:|
| ✅ **True on‑wire count** (`wire_request_count`) | Fix the console under‑reporting IP‑rep 6× (`to_public` reports `len(commands)=1`); show a per‑profile "N signals across M triggers" tally. | ★★★ | S | Near |
| ✅ **Dry‑run "Signal Manifest"** | A zero‑egress preview (GUI toggle + `--dry-run`) listing every enabled trigger's redacted argv, destination, expected SID, and **true** on‑wire count — the pre‑brief artifact and the 6× fix in one. | ★★★★ | S | Near |
| ✅ **Per‑run Signal Ledger + export** | Accumulate every fired request (5‑tuple, 3‑state verdict, rc/http, control_ok) and export **JSON / CSV / printable HTML** as a leave‑behind. Local disk only. | ★★★★ | M | Mid |
| ✅ **Expected‑vs‑Observed scorecard** | Pair each trigger's `expected_fire` with its local result, with an SE‑tickable "confirmed on console" column — the demo's reconciliation sheet. | ★★★★ | M | Mid |
| ✅ **Policy‑coverage matrix** | From catalog metadata + run states, show which dimensions (class, threat, severity) were exercised — and name the empty cells (IP‑rep = Tor‑only, E/W = 0) honestly. | ★★★ | S | Near |
| ✅ **Per‑run correlation ID on the wire** | A code‑pinned `X-SecVitals-Run:<uuid>` header so the customer console can be filtered to exactly this run's flows. | ★★ | M | Mid |

### 3.3 Theme B — Coverage breadth *(more, and more modern, signals)*

New catalog test cases that exercise more of the customer's policy surface. All
are **catalog‑only** additions reusing the existing runners and classifier.

| Feature | What it adds | Value | Effort | Horizon |
|---|---|:--:|:--:|:--:|
| ✅ **SWG category pack** | ~8–10 new `ns-webcc` category triggers (Generative‑AI / Shadow‑AI, Weapons, Hacking, Adult, Dating, Drugs, Job‑search), awkward hosts gated. Category breadth is how a modern SWG is graded. | ★★★★ | S | Near |
| ✅ **Modern‑exploit IDS pack** | `ns-ids` triggers carrying **inert** Log4Shell/Spring4Shell/ShellShock/exploit‑kit‑UA strings as fixed argv literals to the benign origin — the marquee‑CVE SIDs every IPS markets, never actually exploiting anything. | ★★★★ | S | Near |
| ✅ **DLP / data‑exfil pack** | POST obviously‑synthetic test PII (the reserved 4111‑test PAN, a reserved SSN, a fake `AKIA…`/`BEGIN RSA PRIVATE KEY` marker) over HTTP and HTTPS to a benign sink to exercise inline content inspection. | ★★★★ | S | Near |
| ✅ **DNS‑security pack** | Fixed‑string DGA + long‑name tunneling triggers, plus DoH via curl and an optional stdlib TXT query type. | ★★★ | S | Near |
| ✅ **IP‑reputation expansion** | Curated botnet‑C2 / spammer / scanner reputation feeds as gated `ns-iprep` triggers — today IP‑rep is Tor‑only. | ★★★ | M | Mid |
| ✅ **East‑West tier‑1 port probe** | An outbound‑only TCP probe filling the empty `ew` class: SYN‑ACK/RST = reachable, timeout + same‑zone control reachable = blocked, control unreachable = error. First lateral‑movement / segmentation signals. | ★★★★ | L | Mid |
| ✅ **IPv6 / HTTP‑3 (QUIC) twins** | Address‑family and UDP‑443 variants of key triggers to expose policy blind spots (needs a curl control probe so absent v6/QUIC reads as error, not false‑blocked). | ★★★ | L | Mid |

### 3.4 Theme C — SE workflow, evidence & the verification loop

Make a live demo smoother and give the customer something to keep.

| Feature | What it adds | Value | Effort | Horizon |
|---|---|:--:|:--:|:--:|
| ✅ **Headless batch / pre‑brief mode** (`--run`, `--list`, `--format json`) | Validate egress + which signals fire **from the customer network before the meeting**, and prove the known‑quantity set in CI — reusing `App.run`/`classify()` verbatim. A block exits 0 (a win, not a failure); only error/invalid/config problems exit non‑zero. | ★★★★ | M | Near |
| ✅ **Demo profiles / playlists** | Named, ordered run‑sets (e.g. "5‑minute exec demo", "SWG deep‑dive") so a presenter runs a tight, repeatable, *countable* subset instead of all 41. | ★★★★ | M | Mid |
| ✅ **Presenter mode** | A paced talk‑track over Run‑all surfacing each trigger's talking point / expected SID in large type, plus a persistent big‑font scoreboard by class. | ★★★★ | M | Mid |
| ✅ **Self‑contained HTML demo report** | One `html.escape`'d file combining expected SID + honest local state + 5‑tuple + provenance, opened in the browser — the shareable evidence artifact. | ★★★★ | M | Mid |
| ✅ **`console_hint` + live correlation key** | An optional, load‑validated per‑trigger "where to look" hint plus a composed correlation key (live 5‑tuple + UTC window + expected SID) — turns the 5‑tuple table into a pointer at the right console filter. | ★★★★ | S | Near |
| ✅ **Copy‑verification‑key button** | One click copies a greppable `UTC \| trigger \| expect SID \| src→dst \| local:state` line straight into the customer console's filter box — no alt‑tab retyping at the money moment. | ★★★★ | S | Near |
| ✅ **Session recap / evidence log** | A local "Save recap" proof‑of‑fire file, and an append‑only JSONL log with "reload last session" (re‑render cards without re‑firing). No upload, no listener. | ★★★ | M | Near–Mid |
| ✅ **Graceful curl‑absent / offline state** | Detect curl‑missing and full‑offline at startup and mark curl triggers **INVALID** with a one‑line remediation banner instead of a wall of ambiguous ERRORs. | ★★★ | S | Near |

### 3.5 Theme D — Trust & robustness of the signal generator

Keep the tool honest and demo‑proof — several of these close real gaps found in
the current code.

| Feature | What it adds | Value | Effort | Horizon |
|---|---|:--:|:--:|:--:|
| ✅ **Activate `expected_on_*` predicates** | The `expected_on_allow`/`expected_on_block` fields are validated at load but **never consulted** by `classify()`. Wiring them in (reachable‑only) lets an SWG block page served at HTTP 200 or via redirect stop reading as `allowed` — without ever turning an error into a block. | ★★★★ | M | Mid |
| ✅ **Sign & verify the catalog** | Today only `secvitals.py` is authenticated; the catalog is not. Sign `catalog.yaml` and show a verified/modified provenance badge, so the fired traffic provably matches the reviewed catalog. | ★★★ | M | Mid |
| ✅ **Multi‑endpoint control probe** | The blocked‑vs‑error decision hinges on **one** host (`1.1.1.1:443`); if the customer filters it, real blocks degrade to errors. Make it an ordered, transport‑matched list (blocked only if all fail). | ★★★ | M | Mid |
| ✅ **ERROR‑only failover origin** | Auto‑failover to a fixed alternate origin **only when a request honestly ERRORs** (never past blocked/allowed), so a down `testmynids.org` doesn't silently shrink the IDS signal count. | ★★★ | M | Mid |
| ✅ **Pre‑flight environment check** | Verify curl present, control egress up, and the origin answers — explicitly a *readiness* gate, **not** a per‑trigger block predictor. | ★★★ | M | Mid |
| ✅ **Hash‑chained run‑evidence + provenance stamp** | Disk‑only, telemetry‑free run evidence stamped with code + catalog SHA‑256 for after‑the‑fact correlation. | ★★★ | M | Mid |

### 3.6 Deliberately out of scope (and why)

One idea recurred and was **rejected**: an **opt‑in passive syslog/CEF receiver**
that would ingest the customer's alert feed to auto‑confirm which triggers fired.
It is cut because it breaks the load‑bearing guardrail and regresses the mission:

- It requires a **listening socket on a routable interface** — the exact "no
  network surface" property the product won across two design pivots, on a host
  that both runs commands and self‑updates.
- The "companion process" mitigation turns a single‑file app into a **second
  signed‑update deployable** (breaks guardrail #5).
- It makes Security Vitals the **correlation authority** — the role it explicitly
  refuses. Worse, correlation here is inherently fuzzy (WSL/host NAT rewrites
  source ports; SIDs are free‑text), so a missed syslog packet is
  indistinguishable from "not alerted" and could read on stage as *"your IPS did
  not catch this"* — a **false negative about the customer's own product**, which
  is worse than the false‑blocked the classifier was built to prevent.

The customer's SIEM already *is* the reconciliation view; the existing 5‑tuple
report plus the roadmap's evidence exports (§3.4) cover manual correlation
without any of that risk.

### 3.7 Recommended first wave

If you want the highest demo leverage for the least effort — and the tightest fit
to the "known quantity of high‑quality signals" north star — start here:

1. **True on‑wire count + Dry‑run Signal Manifest** (Theme A) — makes the signal
   count honest and lets you *tell the room the number before you fire it*.
2. **Headless pre‑brief mode** (Theme C) — kills on‑stage surprises by validating
   egress and the signal set from the customer network in advance.
3. **SWG category + Modern‑exploit + DLP packs** (Theme B) — three small,
   catalog‑only additions that roughly double the breadth a customer watches
   light up.
4. **Copy‑verification‑key + `console_hint`** (Theme C) — makes the
   click‑to‑console correlation instant at the money moment.
5. **Activate `expected_on_*` predicates** (Theme D) — closes the biggest
   honesty gap in the current classifier.

Everything in the first wave is Near‑term (S/M effort), respects all seven
guardrails, and moves the needle directly on *known quantity* and *high quality*.
The larger bets — **East‑West tier‑1**, **demo profiles/presenter mode**, and
**catalog signing** — are the natural second wave.

> **Both waves are now delivered.** The first wave shipped in 0.1.x; the second
> shipped as milestones M1–M5 (0.2.0 → 0.6.0), covering every remaining item in
> §3.2–§3.5. The rejected idea in §3.6 remains rejected, and tier‑2 east–west
> remains deferred for the reason given in §1.9 — it needs a second deployable.

### 3.8 What is left

With §3.2–§3.5 delivered, the honest backlog is short and mostly *verification*
rather than construction:

| Item | Why it is still open |
|---|---|
| **Real‑Windows validation** | `tkinter` cannot be installed in CI, so no build has opened an actual window. Presenter mode and the report dialog are the least‑exercised code in the product. This is the single highest‑value next step. |
| **Independent review of wave‑1 code** | The wave‑1 changes were merged and are green, but the adversarial review pass over them never completed (a tooling failure, twice). They have had less scrutiny than the wave‑2 designs. |
| **East–west tier 2** | Payload signatures east–west need a second deployable listener; out until the update path is hardened for two artifacts (§1.9). |
| **Signing the shipped catalog** | The machinery and `tools/sign_catalog.sh` exist and are tested, but the published `catalog.yaml` is not yet signed, so installs report `unsigned`. |
| **Feed durability** | Three of the four reputation feeds are third‑party lists (abuse.ch, blocklist.de). A dead feed reports `error`, never a false block — but their availability is outside our control. |
