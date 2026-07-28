# M3 — Coverage Breadth

*Roadmap milestone 3 of 5. Version `0.4.0`. Branch `claude/m3-coverage-breadth`.*

Three gaps in what the catalog could exercise:

- **DNS security** had one policy trigger (`ns-dns`) and nothing for the shapes that
  actually carry C2 and exfiltration — DGA names, tunnelling, and DoH resolver bypass.
- **IP reputation** was Tor-only: a single feed, so the whole reputation category rested
  on one story.
- **Protocol parity** was untested. Everything ran over IPv4/TCP, so a control that
  inspects IPv4 and quietly ignores IPv6 or QUIC would look perfect.

The catalog grows from **41 triggers / 71 lab signals** to **50 triggers / 100 lab
signals** (66 with the live-suspect gate off).

---

## What shipped

| Roadmap item | What it is |
|---|---|
| **DNS-security pack** | `ns-dns-dga` (3 high-entropy names), `ns-dns-tunnel` (long labels, TXT and NULL queries), `ns-doh` (Cloudflare + Google DoH endpoints). |
| **DNS query types** | The built-in probe now sends A / TXT / NULL / AAAA / MX / NS / CNAME / SRV / ANY, chosen by a `type=` token matched against a fixed allowlist. |
| **IP-reputation expansion** | Named feeds: `tor` (unchanged), `botnet-c2` (Feodo Tracker), `scanner` (blocklist.de SSH, probed on :22), `spammer` (blocklist.de mail, probed on :25). |
| **IPv6 / HTTP-3 parity twins** | `ns-uid-v6`, `web-cat-social-v6`, `web-cat-social-h3` — the same payloads over a different transport. |
| **Transport capability gate** | `requires: [ipv6]` / `[http3]`, checked *before* a trigger runs. |

## The honesty problem the parity twins created

This is the part worth reviewing closely.

`curl -6` on a host with **no IPv6 route** exits **7**. The classifier maps exit 7 to
**`blocked`**. Left alone, an IPv6 twin on a v4-only laptop would have reported that the
customer's stack dropped traffic it never even saw — a false positive in favour of the
product, which is precisely the failure mode this app was built to avoid. `--http3` on a
curl built without HTTP/3 has the same shape.

So a trigger declares what it needs, and the requirement is checked **before anything is
sent**:

```yaml
- id: ns-uid-v6
  requires: [ipv6]
```

- `ipv6` → probe a **literal** IPv6 address (`https://[2606:4700:4700::1111]/`, so the
  answer doesn't depend on DNS returning AAAA) with `-k`, since only reachability
  matters. No route ⇒ **`error`**, with the reason *"this host has no working IPv6
  egress, so an IPv6 trigger proves nothing about policy (not a policy result)"*.
- `http3` → read the `Features:` line from `curl --version`. No HTTP/3 ⇒ **`error`**.
- If `run.ipv6_control_url` is blank, IPv6 triggers report `error` rather than guessing —
  an untestable condition is never silently resolved in the product's favour.

An unmet requirement short-circuits `run_trigger` entirely: `result.subs` is empty,
nothing goes on the wire, and the state is `error`. **Never `blocked`.**

## Reputation feeds

A catalog trigger names a feed with a **fixed token** — `["iprep", "botnet-c2"]` — never
a URL. A trigger can therefore only ever reach a destination an operator explicitly put
in `settings.yaml`:

```yaml
webcc:
  reputation_feeds:
    botnet-c2:
      label: "Botnet C2 (Feodo Tracker)"
      url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
      port: 443
```

- Feed URLs **must be https**; a non-https feed is a config error at startup.
- An unknown feed name in the catalog **fails at load**, not at click time.
- Parsing is deliberately strict: a line must be *exactly* an IPv4 address. Comment
  headers, CIDR ranges and timestamps are skipped rather than guessed at — guessing
  would send traffic somewhere the operator never authorised.
- Each feed is cached per URL with a TTL, so a click never refetches.
- **Every feed-backed trigger is gated** (`hits_live_suspect_hosts`). These are real
  suspect addresses; they never fire by default.

Results are still a **ratio, never a verdict** — a lone reach may be a live host, and a
lone block may simply be an offline one.

## DNS pack notes

- An **NXDOMAIN counts as a successful send**. The question crossing the wire is what a
  DNS signature inspects; whether the name resolves is beside the point.
- Labels are validated against the 63-byte protocol limit before the packet is built, so
  a too-long tunnelling label is an error rather than a silently malformed query.
- The tunnelling triggers use TXT and NULL because that is what real tunnelling uses; an
  A-record probe would not reproduce the shape the signature looks for.

## Configuration

```yaml
run:
  ipv6_control_url: "https://[2606:4700:4700::1111]/"   # "" disables IPv6 triggers
webcc:
  reputation_feeds: { ... }                              # named https feeds
```

## Guardrails

All seven hold. Two are load-bearing here:

- **Honest classifier (G4)** — the capability gate exists specifically so an untestable
  transport reports `error`, never `blocked`. That is the single most important
  assertion in this milestone's tests.
- **Fixed catalog (G1)** — feeds are named by token and resolved against operator config;
  DNS query types are matched against a fixed allowlist. Neither can become free text.

## Tests

32 new tests (`tests/test_coverage_breadth.py`); suite now **170 total**. The ones that
matter:

- a host with no IPv6 produces `error` and sends **nothing** — asserted directly against
  `run_trigger`, not just the helper;
- an unconfigured IPv6 control URL is an error, not a guess;
- missing HTTP/3 support is an error naming the reason;
- feed parsing skips CIDR and junk instead of guessing;
- a non-https feed and a bad port are refused at load;
- every `ns-iprep` trigger in the shipped catalog is gated;
- the IPv6 twin's URL is **identical** to its IPv4 original (a parity test is meaningless
  if the payload differs);
- every DNS label in the shipped pack is within the 63-byte limit.
