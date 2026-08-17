# Security Vitals

A local, single-host **security-trigger console** for inline security-stack demos.
The presenter fires a known quantity of signals; the customer's IDS/IPS and Secure
Web Gateway inspect them; this window reports only what *this host* observed.

## Audience

Field engineers and security architects running a live demo on a customer
network — often a 1366×768 laptop, often with the customer's management
console already on the other screen. They have ninety seconds of attention
and cannot afford a UI that looks like a toy, a dashboard, or a guess.

## Job to be done

1. Commit to a number ("66 signals across 41 triggers") before anything leaves the host.
2. Fire one trigger — or a curated profile — and *show* the traffic crossing the inline gate.
3. Report the local result honestly: `allowed`, `blocked`, or `error`. Never collapse those.
4. Leave behind a hash-chained report the customer can keep.

## Voice

Precision instrument, not a consumer app. Short labels. No emoji. No hype.
A block is the money shot — the inline stack doing its job — and the UI
treats it that way. An error is an environment problem and is never dressed
as a block.

## Non-negotiables

- No network surface (no server, no listening socket).
- No browser, no local web UI — one Tkinter process.
- Fixed catalog; commands are never built from free text.
- `blocked` and `error` stay distinct.
- Identity marks that mean something: the lock-and-EKG, HPE green `#01A982`.
