# Update security

Security Vitals self-updates **and** runs local commands. That makes the update
channel a **code-execution channel**: a compromised update is remote code execution
on every SE laptop running the console. This document describes how the channel is
hardened so it **fails closed**.

## What netvitals did (and why we don't copy it)

netvitals' updater (`netquality.py`) fetches the **raw mutable tip of `main`** over
`urllib`, and before overwriting itself it checks only: TLS cert (host auth), an
https→http downgrade guard, `compile()` success, a `"MAGIC"`/`"Network Vitals"`
substring, and `remote_version > local_version`. **None of these authenticate the
code.** Any well-formed file (valid Python + the two strings + a higher version)
passes every gate and executes. The source is also overridable at runtime via
`--update-url`. Ported as-is, that is a fail-open RCE hole.

We reuse netvitals' *mechanism and UX* — the atomic `.new` → `os.replace` swap, the
`.bak` backup, the detached delayed relaunch, and the check-vs-apply split — and add
real authenticity on top.

## The secvitals model

Releases are signed **offline** with an RSA-2048 private key. The app embeds only the
matching **public key** (`UPDATE_PUBKEY`) and verifies every update against it.

A release is three files, published at the pinned `UPDATE_MANIFEST_URL` location:

| file | contents |
|---|---|
| `secvitals.py` | the artifact clients install |
| `manifest.json` | canonical `{"version","artifact","sha256"}` (no trailing newline) |
| `manifest.json.sig` | RSA-2048 / SHA-256 PKCS#1 v1.5 **detached signature over `manifest.json`** |

### Update flow (every step fails closed)

1. Fetch `manifest.json` + `manifest.json.sig` from the **pinned** URL (TLS; https→http
   downgrade refused). The source is a code constant — there is **no `--update-url`
   override** that can bypass verification.
2. **Verify the signature** over the exact manifest bytes with the embedded public key
   (strict PKCS#1 v1.5, full-block compare). Invalid/missing ⇒ **refuse**.
3. Enforce **monotonic version**: the manifest version must be strictly greater than
   the running version (no signed-but-old rollback).
4. Fetch the artifact `secvitals.py` and compute its SHA-256. It must equal
   `manifest.sha256` ⇒ otherwise **refuse**. (The signature covers the hash, so a hash
   match authenticates the artifact.)
5. Install atomically: write `.new`, keep the current file as `.bak`, `os.replace`.
6. **Re-verify the on-disk file's SHA-256** before relaunch — closes the fetch→exec
   TOCTOU window.
7. Relaunch detached after a short delay.

If verification cannot run at all (no public key configured, no signing tool), the
updater **disables itself** rather than applying an unverified update.

### Verifier

Verification is **pure Python standard library** (no `cryptography`/`pynacl`): RSA
verification is modular exponentiation with the public exponent, and PKCS#1 v1.5
signature verification is a strict comparison against the fully reconstructed padded
block. It interoperates with `openssl dgst -sha256 -sign` output (proven by the
round-trip test in `tests/test_update.py`).

## Signing a release

On a trusted, offline machine that holds the private key:

```
tools/sign_release.sh <version> path/to/secvitals.py path/to/private-key.pem release/
```

Then publish `release/secvitals.py`, `release/manifest.json`, and
`release/manifest.json.sig` as the release assets.

## Key management

- **Generate** a release keypair once, offline:
  ```
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out secvitals_release_priv.pem
  openssl rsa -in secvitals_release_priv.pem -pubout -out secvitals_release_pub.pem
  ```
- **Embed** the public key: paste `secvitals_release_pub.pem` into `UPDATE_PUBKEY` in
  `secvitals.py`. The public key is safe to commit; **the private key must never be
  committed or placed on an SE laptop.**
- The value shipped in this repo is a **placeholder/dev key** — replace it with your
  own before relying on the update channel. Until you do, updates fail closed (nobody
  holds a private key that matches a key you didn't install), which is the safe state.
- **Rotate** by shipping a new `UPDATE_PUBKEY` in an app version you distribute
  out-of-band, then signing subsequent releases with the new key.

## Residual notes

- The **tmNIDS binary** is a second download-and-execute channel. It is cached (never
  re-downloaded per click), fetched over pinned TLS with the https→http downgrade
  refused, and supports an **optional SHA-256 pin** (`tmnids.sha256` in
  `settings.yaml`); when set, the cached binary is re-verified on every run and a
  mismatch refuses to run. tmNIDS updates upstream over time, so the pin is opt-in.
