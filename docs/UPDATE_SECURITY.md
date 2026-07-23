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
tools/sign_release.sh <version> path/to/secvitals.py ~/.config/secvitals/secvitals_release_priv.pem release/
```

openssl will prompt for the key passphrase. Before it reports success the script
**verifies its own output** and refuses to leave a publishable release otherwise:

1. the fresh signature must verify against the **public key file** — by default the
   sibling `*_pub.pem` next to the private key, overridable with `SECV_RELEASE_PUBKEY`;
2. that public key must match the `UPDATE_PUBKEY` **compiled into the artifact being
   shipped** (compared by SHA-256 of the DER encoding).

If either check fails the signature file is **deleted**. This matters because signing
with the wrong key produces a perfectly well-formed release that every client rejects —
without a local check the first signal would be broken updates in the field.

Note that the verification uses the public key *file*, never one derived from the
signing key with `openssl rsa -pubout`. A derived key verifies any signature the key
produced, including one made with entirely the wrong key; only an independent copy of
the public key answers "did I sign with the key clients actually trust?".

Then publish `release/secvitals.py`, `release/manifest.json`, and
`release/manifest.json.sig` as the release assets.

## Key management

The release private key is the single credential that can push code to every install.
Treat it as such.

- **Generate** a release keypair once, on a trusted machine, **passphrase-protected**:
  ```
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes-256-cbc \
    -out ~/.config/secvitals/secvitals_release_priv.pem
  chmod 700 ~/.config/secvitals
  chmod 600 ~/.config/secvitals/secvitals_release_priv.pem
  openssl rsa -in ~/.config/secvitals/secvitals_release_priv.pem -pubout \
    -out ~/.config/secvitals/secvitals_release_pub.pem
  ```
  The key lives **outside any git working tree**. The `*.pem` entry in `.gitignore` is
  a backstop, not the protection.

- **Verify the key is actually encrypted.** If the passphrase prompt is answered with
  an empty string, openssl silently writes an *unencrypted* key and still exits 0:
  ```
  head -1 ~/.config/secvitals/secvitals_release_priv.pem   # must say BEGIN ENCRYPTED PRIVATE KEY
  openssl pkey -in ~/.config/secvitals/secvitals_release_priv.pem -noout -passin pass:   # must FAIL
  ```
  A plain `-----BEGIN PRIVATE KEY-----` header means unencrypted. **Regenerate** — do
  not encrypt in place, so that any plaintext copy left in free space belongs to a key
  nothing was ever configured to trust.

- **Back up** the passphrase in a password manager and the key file itself to encrypted
  offline storage. Losing either means losing the ability to ship *any* update that
  existing installs will accept; the only recovery is reinstalling every client
  out-of-band.

- **Embed** the public key: paste `secvitals_release_pub.pem` into `UPDATE_PUBKEY` in
  `secvitals.py`. The public key is safe to commit; **the private key must never be
  committed or placed on an SE laptop.**

### Rotation

Two properties of this design (both verified against the code) make rotation
order-dependent and leakage unrecoverable:

**Clients trust only the key compiled into the build they are running.** `UPDATE_PUBKEY`
is a module constant; `check_update`/`download_and_install` default to it and `main`
passes no override — there is no `--pubkey` and no `--update-url` flag. So a new public
key can only reach an installed client *inside an update*, and that update must be
signed with the **old** key or the client refuses it.

Rotate in this order:

1. Generate the new keypair (as above); keep the old key.
2. Embed the new `UPDATE_PUBKEY` in the source and bump `__version__`.
3. Sign that release with the **OLD** private key — this is the release that carries the
   new trust anchor to the field. (`tools/sign_release.sh` will refuse it, because the
   old public key no longer matches the artifact's embedded key; sign this one release
   manually with `openssl dgst -sha256 -sign`, deliberately.)
4. Publish, and confirm clients have taken it up.
5. Only then sign subsequent releases with the new key. Any install that skipped step 3
   is stranded and needs a manual reinstall.

**A leaked private key has no revocation path.** There is no revocation list, key ID, or
kill switch anywhere in the updater — the only checks are signature validity and a
strictly-increasing version. Anyone holding the key can sign a higher-versioned release
that every install will accept and execute. If the key leaks, the update channel cannot
be repaired remotely: distribute a rebuilt app with a new embedded key out-of-band, and
assume the compromised channel is usable by the attacker until each client is replaced.

## Residual notes

- The **tmNIDS binary** is a second download-and-execute channel. It is cached (never
  re-downloaded per click), fetched over pinned TLS with the https→http downgrade
  refused, and supports an **optional SHA-256 pin** (`tmnids.sha256` in
  `settings.yaml`); when set, the cached binary is re-verified on every run and a
  mismatch refuses to run. tmNIDS updates upstream over time, so the pin is opt-in.
