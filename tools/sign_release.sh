#!/usr/bin/env bash
#
# sign_release.sh — produce a SIGNED Security Vitals release.
#
# Run this on a TRUSTED, OFFLINE machine that holds the release private key.
# The private key must NEVER be committed or copied onto an SE laptop. The app
# ships only the matching PUBLIC key (embedded as UPDATE_PUBKEY in secvitals.py),
# and refuses any update whose manifest signature does not verify against it
# (fail closed). See docs/UPDATE_SECURITY.md.
#
# Usage:
#   tools/sign_release.sh <version> <path/to/secvitals.py> <private-key.pem> [outdir]
#
# Produces in <outdir> (default: ./release):
#   secvitals.py         the artifact clients download
#   manifest.json        {version, artifact, sha256}   (canonical, no trailing newline)
#   manifest.json.sig    RSA-2048 / SHA-256 PKCS#1 v1.5 detached signature over manifest.json
#
# Publish all three as release assets at the pinned UPDATE_MANIFEST_URL location.
#
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <version> <path/to/secvitals.py> <private-key.pem> [outdir]" >&2
  exit 2
fi

VERSION="$1"
ARTIFACT="$2"
KEY="$3"
OUT="${4:-release}"

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
[ -f "$ARTIFACT" ] || { echo "artifact not found: $ARTIFACT" >&2; exit 1; }
[ -f "$KEY" ] || { echo "private key not found: $KEY" >&2; exit 1; }

# The PUBLIC key this signature is checked against. Default: the sibling *_pub.pem next
# to the private key; override with SECV_RELEASE_PUBKEY. This must be the public key
# file, NOT one derived from $KEY with `openssl rsa -pubout`: deriving it from the
# signing key makes the check circular (it would pass for ANY key, including the wrong
# one). We are asking "did I sign with the key clients actually trust?", and only an
# independent copy of that public key can answer it.
PUBKEY="${SECV_RELEASE_PUBKEY:-}"
if [ -z "$PUBKEY" ]; then
  case "$KEY" in
    *_priv.pem) PUBKEY="${KEY%_priv.pem}_pub.pem" ;;
    *.pem)      PUBKEY="${KEY%.pem}_pub.pem" ;;
    *)          PUBKEY="${KEY}_pub.pem" ;;
  esac
fi
[ -f "$PUBKEY" ] || {
  echo "public key not found: $PUBKEY" >&2
  echo "refusing to sign: the signature must be verified before publication." >&2
  echo "Set SECV_RELEASE_PUBKEY=/path/to/secvitals_release_pub.pem" >&2
  exit 1
}

# Sanity: the version being signed must match the artifact's __version__.
FILE_VER=$(grep -oE '^__version__[[:space:]]*=[[:space:]]*"[^"]+"' "$ARTIFACT" | head -1 | sed 's/.*"\(.*\)".*/\1/')
if [ "$FILE_VER" != "$VERSION" ]; then
  echo "refusing: --version=$VERSION but the artifact declares __version__=$FILE_VER" >&2
  exit 1
fi

mkdir -p "$OUT"
cp "$ARTIFACT" "$OUT/secvitals.py"

# SHA-256 of the exact artifact bytes.
SHA=$(openssl dgst -sha256 -r "$OUT/secvitals.py" | awk '{print $1}')

# Canonical manifest: fixed key order, no trailing newline, so the signed bytes are stable.
printf '{"version":"%s","artifact":"secvitals.py","sha256":"%s"}' "$VERSION" "$SHA" > "$OUT/manifest.json"

# Detached RSA/SHA-256 signature over the manifest bytes.
openssl dgst -sha256 -sign "$KEY" -out "$OUT/manifest.json.sig" "$OUT/manifest.json"

# --- Post-signing verification (fail closed) -------------------------------------
# Signing with the wrong key produces a perfectly valid file that every client rejects.
# Verify here, where the mistake is cheap, and destroy the signature if it does not
# hold — a release must never leave this machine unverified.
TMPD=$(mktemp -d)
trap 'rm -rf "$TMPD"' EXIT

fail() {
  rm -f "$OUT/manifest.json.sig"
  echo "SIGNING FAILED: $1" >&2
  echo "The signature has been deleted. $OUT/ holds no publishable release." >&2
  exit 1
}

# 1. The signature must verify under the public key clients are expected to hold.
openssl dgst -sha256 -verify "$PUBKEY" \
  -signature "$OUT/manifest.json.sig" "$OUT/manifest.json" >/dev/null 2>&1 \
  || fail "signature does not verify against $PUBKEY (signed with the wrong private key?)"

# 2. That public key must equal the one compiled into the artifact being shipped.
#    Clients verify with THEIR embedded key, so a signature that verifies against a
#    public key the artifact does not carry still bricks the update channel.
awk '/UPDATE_PUBKEY/{f=1}
     f && /-----BEGIN PUBLIC KEY-----/{p=1}
     p{sub(/^.*"""/, ""); print}
     p && /-----END PUBLIC KEY-----/{exit}' "$OUT/secvitals.py" > "$TMPD/embedded_pub.pem"
[ -s "$TMPD/embedded_pub.pem" ] \
  || fail "no UPDATE_PUBKEY found in the artifact — clients would have nothing to verify with"

fingerprint() { openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print $1}'; }
FP_FILE=$(fingerprint "$PUBKEY")
FP_EMBED=$(fingerprint "$TMPD/embedded_pub.pem")
[ -n "$FP_EMBED" ] || fail "the artifact's embedded UPDATE_PUBKEY is not a readable public key"
[ "$FP_FILE" = "$FP_EMBED" ] \
  || fail "$PUBKEY does not match the UPDATE_PUBKEY embedded in $ARTIFACT
    key file : $FP_FILE
    embedded : $FP_EMBED"

echo "Signed release written to $OUT/"
echo "  version : $VERSION"
echo "  sha256  : $SHA"
echo "  files   : secvitals.py  manifest.json  manifest.json.sig"
echo "  verified: signature checks out against $PUBKEY,"
echo "            which matches the UPDATE_PUBKEY embedded in the artifact"
echo "            (key SHA-256: $FP_FILE)"
echo
echo "Publish all three files as release assets at the pinned UPDATE_MANIFEST_URL location."
