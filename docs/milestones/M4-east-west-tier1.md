# M4 — East–West Tier 1

*Roadmap milestone 4 of 5. Version `0.5.0`. Branch `claude/m4-east-west-tier1`.*

The `ew` class has existed since Phase 0 as **reserved schema with zero triggers**. Every
signal Security Vitals fired went north–south, to the internet. That left the entire
lateral-movement dimension — the path ransomware actually uses once it is inside —
completely untested.

M4 fills it, at **tier 1** only: a bare TCP connect, no payload, no listener required.
Tier 2 (payload signatures east–west) needs a second deployable and stays deferred, as
recorded in `CONFIRMED.md` §7.

---

## What shipped

| Item | What it is |
|---|---|
| **`ew` runner** | A tier-1 segmentation probe: control port, then each denied port. |
| **Operator-defined targets** | `east_west.targets` in `settings.yaml` — the catalog names a target, the site says what it means. |
| **Three shipped triggers** | `ew-server-zone` (workstation → server zone), `ew-user-zone` (client isolation), `ew-dmz` (DMZ → internal pivot). |
| **"Not configured" as a first-class state** | Distinct from gated, and emphatically distinct from blocked. |

## Why targets live in settings, not the catalog

North–south triggers ship with fixed destinations because the internet is the same
everywhere. **East–west cannot**: the targets are the customer's internal addresses, and
they differ at every site.

So the catalog names a **target** and the operator defines what that name means:

```yaml
east_west:
  probe_timeout_s: 3
  targets:
    server-zone:
      label: "Server zone — file/RDP/database host"
      zone: "servers"
      host: "10.20.30.40"
      control_port: 443          # expected REACHABLE — proves the host is up
      ports: [445, 3389, 22, 1433]   # ports policy should DENY
```

A trigger can only ever probe an address someone deliberately configured. **No target,
no traffic** — same pattern M3 used for reputation feeds, and it keeps the fixed-catalog
guarantee intact.

Nothing ships pre-filled. `settings.yaml` carries an empty `targets: {}` and a commented
example.

## Reading a result — the distinction that matters

Four outcomes per port, and collapsing any two of them would produce a lie:

| Outcome | What actually happened | Reported as |
|---|---|---|
| **SYN-ACK** | Reachable, something is listening | reachable |
| **RST** | The SYN **arrived** and the host answered. The path is open; the port is merely closed. | **reachable** |
| **timeout** | No answer at all — consistent with a drop in transit | **blocked** |
| **unreachable** | `ENETUNREACH` / `EHOSTUNREACH` — this host has no route, or a router sent ICMP unreachable | **error** |

> **A RST is not a block.** It proves the packet got there. Reporting it as `blocked`
> would credit the firewall with work the *host* did — a false positive in the product's
> favour, which is the exact failure mode this app exists to avoid.

> **"No route" is not "dropped".** An unreachable is a fact about *this* host's routing,
> not about the customer's policy. If every port comes back unreachable, the result is
> `error`, not a clean sweep of blocks.

### The control port

A timeout only means something if the host is actually up. So a **control port on the
same target** is probed first:

- control reachable → a timeout on the ports under test is a genuine policy drop;
- control unreachable → **`error`**: the host is down or unroutable from here, and
  nothing can be concluded about segmentation. Never `blocked`.

The control port may **not** also appear in `ports` — it is the reachability reference,
so testing it would make the result circular. That is enforced at load.

## "Not configured" is its own answer

Until a site defines its targets, the `ew` triggers report **`invalid`** with the reason
*"no east-west target named 'server-zone' is configured — add it under
east_west.targets in settings.yaml. Not a policy result."*

This is deliberately a third state, separate from the live-suspect gate:

- The signal manifest lists them under **NOT CONFIGURED HERE**, not under the gate.
- `signals_if_gate_enabled` does **not** count them — flipping the gate cannot supply a
  target, and promising signals that only configuration unlocks would be misleading.
- "Run all" and `--run all` skip them, exactly as they skip gated triggers.
- They contribute **0** to the signal count until configured.

## Guardrails

All seven hold. Notes specific to M4:

- **No listener, no payload.** Tier 1 is a bare TCP connect. Nothing is served, nothing
  is sent, and no second deployable is introduced — which is precisely why tier 2 is
  still deferred.
- **Honest classifier (G4).** Three of this milestone's tests exist solely to keep
  `blocked` from swallowing something it shouldn't: RST, no-route, and dead-host.
- **Fixed catalog (G1).** The catalog carries a target *name*; the address comes from
  operator config. There is no path from a trigger to an arbitrary address.

## Tests

26 new tests (`tests/test_east_west.py`); suite now **164 total**. The important ones:

- `open` and `refused` are distinguished **against real loopback sockets**;
- the exception → outcome mapping is asserted **directly** rather than against an
  unroutable address — some sandboxes *refuse* TEST-NET-1 instead of dropping it, and a
  network-dependent test would have lied about what the code does;
- a dead control port is `error`, never `blocked`;
- all-unreachable is `error`, even with a live control;
- the control port is not counted as a signal;
- `control_port` inside `ports` is refused at load;
- the manifest lists unconfigured triggers separately from gated ones, and the gate-on
  figure does not promise them.
