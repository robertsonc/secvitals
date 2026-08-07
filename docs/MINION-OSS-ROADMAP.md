# From `secvitals` to a MINION: an open-source roadmap for measuring security-control effectiveness

*A plan to evolve `secvitals` from an honest single-host signal generator into an
open-source, ground-truth **effectiveness** measurement platform that mimics
[MINION by NSS Labs](https://www.futuriom.com/articles/news/whats-in-an-minion-by-nss-labs-measuring-security-control-effectiveness/2026/08)
— built entirely from open-source concepts and standard-library code, and with a working
proof of concept already in [`poc/`](../poc/).*

---

## 1. What MINION is, and why it matters here

**MINION by NSS Labs** (announced August 2025 by the relaunched "NSS Labs 2.0"; the
companion data platform debuted at DEF CON 33) is a *managed, third-party* platform that
independently measures how effective a deployed security control actually is. It is **not**
a firewall/IPS/endpoint product — it **evaluates** those products, measuring whether a
control "effectively **detects, blocks, allows, or mishandles** defined threats and
traffic."

The architectural heart is a **pair of devices connected by software**: one **sends**
crafted malicious *and* benign traffic through the control under test, and the paired
device **receives** on the far side and confirms what actually arrived. Because NSS owns
**both ends**, it has **ground truth** for every item — it can see silent drops, silent
alterations, and threats that passed *undetected*, none of which a single-host generator
can observe. On top of that ground truth MINION reports:

- **True-positive block rate** on exploit and malware corpora (reference firewall round:
  3,326 exploit + 11,311 malware samples);
- **Evasion resistance** — the same threat wrapped many ways (5,752 variations across 53
  categories); the drop in block rate is the evasion gap;
- **False-positive accuracy** — legitimate traffic wrongly blocked, now MINION's primary
  measure of operational overhead (it explicitly *replaced* the old price-per-Mbps metric);
- **Encrypted-traffic handling** (TLS/SSL weighted ~95% of the mix) and **performance /
  stability under load** (throughput, latency, 55 stress tests);
- a composite **Security Effectiveness** score (top products score >99%), delivered
  through a self-service, executive-ready **data platform** with comparison and
  decision-support views, positioned as **continuous** ("from attestation to continuous,
  measurable proof") and **audit-ready**.

It descends directly from NSS Labs' historic **Security Value Map** — *Security
Effectiveness* (a composite of exploit/malware block rate and evasion resistance) plotted
against a cost/value axis, with **Recommended / Neutral / Caution** bands.

The lineage matters because `secvitals` already lives in the same problem space (it
reproduces tmNIDS-style triggers to light up an inline stack during a demo), but from a
deliberately humbler posture. This roadmap closes the distance.

## 2. The thesis: the reflector is the keystone

Everything MINION does that `secvitals` cannot — a true **block/allow/mishandle** verdict,
a **false-positive rate**, an **evasion delta**, a defensible **effectiveness score**, real
**east-west lateral detection** — is *downstream of one capability `secvitals` lacks: a
paired **receiver/reflector** on the far side of the control under test.*

`secvitals` today is sender-only. It *infers* "blocked" from a curl exit code plus a
control-egress probe, and its README is careful to say it "refuses to be the correlation
authority." The reflector **is** that authority. It converts heuristic classification into
ground truth: the harness stops guessing and starts **knowing** what traversed the control.

Crucially, this is not a new idea bolted on — it is the exact **"second deployable
reflector/listener with its own update surface"** that the project's own decision record
scoped and deferred for east-west tier-2 (`CONFIRMED.md §7`). Build the reflector, and you
simultaneously (a) deliver the deferred east-west tier-2, (b) unlock a false-positive
denominator, and (c) unlock any defensible effectiveness score. One artifact, three
deferred capabilities. That is why it ranks first — and why the POC builds *only* it.

## 3. Where `secvitals` stands today

**What already maps to MINION (a strong base):**

- A **fixed, countable, inert** signal corpus (66 signals / 41 triggers; 100 / 50 gated)
  fired repeatably — the sender-side test library.
- Breadth in one tool: N/S IDS/IPS, SWG (category + reputation), DLP, IP-reputation, DNS,
  E/W tier-1, and IPv6/HTTP-3 parity twins.
- A disciplined result taxonomy (`allowed / blocked / error / invalid / ratio`) where
  **`blocked` and `error` never collapse** — a partial analogue of MINION's verdict set,
  from the *sender side only*.
- A **hash-chained evidence ledger** stamped with code + catalog digests, an
  expected/observed/confirmed scorecard, and a coverage matrix that **names the empty
  cells** — audit-grade honesty at demo scale.
- Headless pre-brief mode, profiles, presenter mode, HTML/JSON/CSV export, signed
  fail-closed self-update, and catalog signing — the integrity properties an independent
  instrument needs to be trusted.

**What it lacks (the distance to MINION):**

| Gap | Why it matters | MINION parallel |
|---|---|---|
| **A paired receiver → real ground truth** | It classifies only the *local* result and infers block-vs-error. A genuine inline drop and a dead origin can look identical; it can never confirm "the control stopped this," only "my side saw a reset." The honest-classifier apparatus is a *mitigation for not having a receiver*. | The receiver device that observes actual delivery. |
| **False-positive measurement** | It fires only malicious signals, so it can report a block rate but never the false-positive rate that gives it meaning. A control that blocks everything scores 100% and is useless. | False-positive accuracy, netted into the score. |
| **A composite effectiveness score** | It produces per-trigger states, not one defensible grade buyers can compare. | The Security Effectiveness score / SVM. |
| **Evasion / mutation testing** | It sends fixed literal payloads; a signature that trips on the naked string but not a fragmented/encoded one is weak, and it never probes that. | The hostile sender's evasion library. |
| **Performance / stability under load** | It is deliberately rate-limited so it *cannot* flood the path; "catches it at one request" ≠ "effective at line rate." | Performance-under-load dimension. |
| **East-west tier-2 (a real far-segment reflector)** | Tier-1 proves a segment is reachable, not that lateral malicious payload is detected. | The paired receiver on the far segment. |
| **Continuous, independent, longitudinal operation** | A point-in-time, vendor-run demo is not independent evidence. | Continuous managed service + data platform. |

## 4. Capability → open-source mapping

Every MINION capability has a standard-library-first open-source realization. Effort:
**S** ≈ days · **M** ≈ 1–2 weeks · **L** ≈ multi-week / architectural.

| MINION capability | Open-source approach (stdlib-first) | Concrete projects / standards | Effort | Guardrail note |
|---|---|---|:--:|---|
| **Ground-truth receiver** (the keystone) | Second deployable: a tiny `http.server` receiver on infra you own behind the control; sender embeds a per-probe nonce; join sent↔received | `http.server`, `socketserver`, `secrets`/`os.urandom`, `hmac`; ref: interactsh, Canarytokens | **L** | Listener lives *only* on the reflector box, never the console |
| **4-state verdict** detect/**block/allow/mishandle** | Derive from the two-ended join, not a curl rc; **mishandle = arrived-but-bytes-differ** via digest/byte-diff | `hashlib`, `hmac`, `difflib`; OCSF/STIX verdict vocab | **M** | Strengthens the honest classifier — "blocked" becomes *confirmed non-arrival* |
| **False-positive testing** | New benign `fp-*` catalog class fired through identical machinery; any block of a benign flow = FP | Tranco / Majestic top sites, SaaS/update URLs, SpamAssassin ham, AMTSO FP page | **M** | Fixed catalog; benign kept in separate ledger columns |
| **Exploit/malware block-rate corpus** | Grow the fixed-argv catalog from public rule metadata; tag each trigger with **rule SID + ATT&CK T-id** | tmNIDS (already reproduced), Emerging Threats Open, Suricata/Snort community, Atomic Red Team, MITRE ATT&CK/Caldera | **M** | Inert-by-construction; real suspect infra stays gated |
| **Safe malware artifacts** | Inert industry test artifacts only | EICAR (+ nested), GTUBE, AMTSO; MTA.net PCAPs lab-only | **S** | Live PCAPs only behind the live-suspect gate |
| **Evasion resistance** | Re-send each payload through an evasion matrix; measure block-rate drop; extend the v6/h3 twins | fragroute, HTTP Evader, pytbull; stdlib case/URL-encoding, chunked TE, header splitting | **L** | Variants **pre-generated offline** as fixed catalog entries — no runtime synthesis; only credible *with* the reflector |
| **Encrypted-traffic / TLS inspection** | Fire over TLS to a reflector you own that terminates the connection; compare inspected vs uninspected block rate | stdlib `ssl` + `http.client`, self-signed origin cert; ref testssl.sh | **M** | Answerable only because you own the TLS-terminating origin |
| **Performance under load** | Stdlib concurrent load generator → reflector-as-sink; throughput, p50/p95/p99, conn-rate, fail-open; sent==received also proves zero-drop-under-load | `socket` + `concurrent.futures`, `time.perf_counter`, `statistics`; ref iperf3/wrk/tcpreplay | **M** | **Gated** lab mode; default stays one-at-a-time, rate-limited |
| **Security Effectiveness score + SVM** | One auditable number from the 2×2 confusion matrix; evasion-adjusted variant; inline-SVG Security Value Map | pure-Python arithmetic; block/FP rate, Youden's J, F-β, MCC; inline SVG | **M** | Computed *only* from ground-truth verdicts + FP; errors excluded |
| **Continuous / scheduled runs** | Drive headless `--run all --format json` on a schedule; append to the ledger for trend/drift | cron / systemd timers / schtasks / GitHub Actions; JSONL ledger | **S** | No daemon, no new listener — scheduling is external |
| **Managed platform → self-hosted analog** | Each sender **POSTs its signed ledger outbound** to an aggregator; fleet → one aggregator | stdlib `urllib` outbound POST; reuse RSA signing; OCSF/ECS + syslog for SIEM | **L** | Outbound push only — senders keep zero inbound sockets |
| **Self-service data platform** | Emit self-contained static HTML + JSON from the ledger: block-rate/FP trends, SVM scatter, per-class & per-ATT&CK scoreboards | extend `render_html_report`; inline SVG; JSONL as local data lake; ref Datasette | **M** | Offline-only; add the reflector's ground-truth column as authoritative |
| **DLP / exfiltration** | Send synthetic canary secrets to the reflector; it confirms egress (miss) vs stripped (catch); `mishandle` = partial redaction | Luhn-valid test PANs, synthetic PII, GTUBE/EICAR-in-body; Canarytokens pattern | **M** | Only truthfully testable with a receiver |
| **Audit-ready reporting / provenance** | Keep the hash-chained ledger; add machine-readable findings export in a standard schema; sign catalog + reports | existing ledger + `tools/sign_catalog.sh`; SARIF/OCSF/STIX; ref in-toto/SLSA, RFC 3161 | **M** | Already strong; standard export makes results ingestible by audit tools |

## 5. The proof of concept (built)

Phase 0 — the keystone — is **already implemented** in [`poc/`](../poc/) as a
dependency-free, standard-library POC. It stands up the full paired loop and produces a
real Security Effectiveness score from ground truth.

**Components** (see [`poc/README.md`](../poc/README.md) for the topology diagram):

- `minion_reflector.py` — **device B**, the receiver: an `http.server` that records
  `token → sha256(body)` for each arrival and returns an **HMAC-signed** ledger. It only
  ever *hashes* payloads (never executes/resolves/stores them) and caps body size. It is
  the *only* component that listens, and it runs on infra you own behind the control.
- `minion_harness.py` — **device A**, the sender: mints a per-probe nonce, sends each
  probe toward the far side, reads and **verifies** the signed ledger, and **reconciles**
  sent-vs-received into the four ground-truth outcomes below. Scores, reports (text / JSON
  / static HTML), and ships a one-command `--demo`.
- `effectiveness.py` — the pure, network-free **scoring core** (fully unit-tested).
- `minion_control.py` — a **demo/test-only** mock inline control so the whole loop runs on
  loopback; there is no mock in a real engagement.
- `probes.json` — the fixed, inert paired catalog (benign + malicious).

**The four ground-truth outcomes** (what a single-host tool cannot produce):

| Outcome | Reflector saw | Verdict |
|---|---|---|
| `arrived` | token present, digest matches | **allowed** (passed clean) |
| `mangled` | token present, digest differs | **mishandled** (altered in transit) |
| `blocked` | token absent, **path proven up** | **blocked** (dropped inline) |
| `error` | token absent, **nothing arrived** | environment failure — *never a block* |

**The score:** `effectiveness = block_rate × (1 − false_positive_rate)`, where
`block_rate` = threats stopped (blocked ∪ mangled) / malicious tested, and
`false_positive_rate` = benign wrongly stopped / benign tested. Errored/untested probes are
excluded from the denominators and reported by name — the honesty rule inherited straight
from the three-state classifier.

**One command, end to end** (`python3 poc/minion_harness.py --demo`):

```
==================================================================
  SECURITY EFFECTIVENESS   100.0%   grade A
==================================================================
  block rate (threats stopped)      100.0%
  false-positive rate (legit lost)  0.0%

  malicious: 7 tested · 6 blocked · 1 mishandled · 0 LEAKED
  benign:    3 tested · 3 passed · 0 false-blocked · 0 mishandled
  not scored: 0 error(s), canary=arrived
  performance: p50 2.3ms · p95 4.0ms · 245.8/s over 4 completed
```

The demo exercises all four outcomes: 6 threats **blocked**, 1 **mishandled** (a
Spring4Shell payload the control *sanitizes* rather than drops — a state the current
single-host design is blind to), benign traffic **allowed**, the canary confirming the
path is up. Point the control at a dead upstream and every probe honestly scores `error`,
never a false block; feed the harness the wrong HMAC secret and the untrusted ledger scores
`error`-for-all. Both are covered by `tests/test_minion_poc.py` (23 tests).

## 6. Phased roadmap

**Phase 0 — Ground-truth POC (the keystone). ✅ built.** The reflector loop, the paired
inert catalog, the four-state reconciliation, the effectiveness score, a static report, and
tests — all in `poc/`. Proves: ground truth, guardrail-safe two-deployable design,
false-positive measurement, mishandle detection, an error-excluding score, and an auditable
paired run.

**Phase 1 — East-west tier-2 for real.** Point the same reflector at a peer segment behind
the control. This *deletes the deferral* in `CONFIRMED.md §7`: tier-1 proved reachability;
tier-2 now proves **lateral malicious-payload detection** with a peer on the far zone, and
resolves the long-standing "RST vs firewall-drop" ambiguity because a real listener proves
arrival.

**Phase 2 — Breadth: FP corpus + evasion matrix + ATT&CK tagging.** Add the fixed benign
`fp-*` class (Tranco-derived), pre-generate offline evasion variants of existing malicious
payloads (encoding / fragmentation / chunking), and stamp every trigger with a rule SID and
ATT&CK technique id. Block rate finally has a denominator; the evasion delta becomes
measurable (the SVM's green dot vs blue dot); rollups report per tactic.

**Phase 3 — Scoring & data platform.** Promote the POC score to the product: confusion-matrix
metrics, an evasion-adjusted variant, an inline-SVG **Security Value Map**, per-class and
per-ATT&CK scoreboards, and longitudinal trend lines — extending `render_html_report`.
Continuous runs (cron / systemd / Actions) append to the ledger for drift detection: a
control that silently stops blocking shows up as a trend break.

**Phase 4 — Encrypted-traffic + performance-under-load (gated lab).** Reflector terminates
TLS (self-signed origin) → inspected-vs-uninspected block rate. A stdlib concurrent load
generator with the reflector as sink → throughput, p50/p95/p99, connection rate, fail-open
behavior, and zero-drop-under-load (sent == received). Both strictly behind the lab gate.

**Phase 5 — Fleet aggregation + audit interop.** Senders POST signed ledgers **outbound**
to a self-hosted aggregator (the managed-service analog, with no inbound surface on the
senders); add OCSF/SARIF findings export and report signing for GRC/audit ingestion.

**Explicit non-goal (all phases): real exploit compromise of a live victim.** Payloads stay
inert on the wire; the reflector produces `mishandled` by byte-diffing arrived-vs-sent,
never by executing attacker code. True-compromise testing is out of scope and the
delivery-proxy limitation is stated plainly wherever a result is reported.

## 7. Reconciling MINION with the seven guardrails

The value of `secvitals` is that its signal set is fixed, honest, and safe. A MINION-style
evolution must not trade any of that away. Each guardrail that a MINION capability stresses
has a concrete resolution — and in the load-bearing case the receiver *strengthens* the
guarantee rather than eroding it.

| Guardrail (what it protects) | Stressed by | Reconciliation |
|---|---|---|
| **No network surface** (nothing off-box reaches the console) | Needing a receiver + return path | **Scope it to the console.** The reflector is a *separate, lab-gated deployable on a segment you own* behind the control; its only socket is the test target (receiving the attack *is* the test). The **console keeps zero inbound sockets** — verdicts return by the harness reading `/ledger` or the reflector pushing outbound. "No network surface" holds exactly where it was load-bearing. |
| **Single-file, stdlib-only** | A pair is ≥2 programs | Relax to **"single file *per deployable*."** The reflector is a second zero-dependency stdlib file — the scoped widening the decision record already anticipated, not an abandonment of self-containment. |
| **Signed fail-closed update from a pinned source** | A second RCE/update surface | **Extend the identical channel** to the reflector (own embedded key, pinned source, verify-before-apply, atomic swap + `.bak`, on-disk re-verify, fail closed). The **shared test manifest is signed too**, so the reflector can't be pointed at attacker-chosen expectations. |
| **Honest classifier** (`blocked` ≠ `error`) | A single score can launder the distinction | Score derived **only** from ground-truth verdicts + FP; **`error`/inconclusive excluded from the denominator** (never a block, never a miss); coverage matrix + named empty cells always published beside the number. The receiver **strengthens** this — "blocked" becomes *confirmed non-arrival*. |
| **Fixed catalog** (no command from free text) | Evasion breadth + FP corpus + expectations | Everything stays **enumerated**. Evasion variants are **pre-generated offline** as fixed audited entries (exactly like the v6/h3 twins); the benign corpus is fixed catalog; reflector expectations are **signed catalog data** keyed by trigger id. Breadth grows as *more catalog*, never a generator. |
| **No shell / no download-and-execute (inert)** | MINION's strongest evidence is real compromise | **Do not execute live exploits.** Payloads stay inert on the wire (the control inspects the bytes — that's what's graded); the reflector derives `mishandled` by **byte-diffing**, running no attacker code anywhere. Full detect/block/allow/mishandle set *without* compromise. |
| **Live-suspect gate** (dangerous traffic off by default) | Load testing = deliberately flooding; standing up a receiver is lab-only | Put the **reflector, load mode, and real-suspect payloads behind the SAME gate** — a LAB profile the operator explicitly enables on a segment they own. The default customer-adjacent profile stays single-host, receiver-less, rate-limited, unchanged. |

## 8. Sources

- Futuriom — *What's in a Minion by NSS Labs? Measuring Security Control Effectiveness*
  (2026-08).
- PR Newswire / NSS Labs — *NSS Labs Introduces Minion, a Managed Security Testing Service*
  (2025-08-05).
- Futuriom — *NSS Labs Launches Managed Cybersecurity Test Platform* (2025-08).
- NSS Labs / CyberRatings — *When Firewalls Fail Gracefully*.
- NSS Labs — NGFW/NGIPS **Security Value Map** comparative reports (methodology lineage:
  Security Effectiveness, evasion resistance, TCO per protected Mbps).
- Existing project docs: [`docs/SOLUTION-AND-ROADMAP.md`](SOLUTION-AND-ROADMAP.md),
  [`CONFIRMED.md`](../CONFIRMED.md) §7 (deferred east-west tier-2), and the POC in
  [`poc/`](../poc/).
