#!/usr/bin/env bash
# Sign config/catalog.yaml so an install can prove the traffic it fires matches the
# catalog that was reviewed.
#
# The update channel authenticates secvitals.py but NOT the catalog, and the catalog is
# what decides where traffic goes. This closes that gap using the SAME RSA-2048/SHA-256
# verifier the updater uses, so there is one signature implementation to trust.
#
#   tools/sign_catalog.sh config/catalog.yaml ~/.config/secvitals/secvitals_release_priv.pem
#
# Verification uses the public key FILE (default: the sibling *_pub.pem, override with
# SECV_RELEASE_PUBKEY). Never a key derived from the private key with `openssl rsa
# -pubout`: a derived key verifies any signature that key produced, including one made
# with entirely the wrong key. Only an independent copy answers "did I sign with the key
# clients actually trust?".
set -euo pipefail

CATALOG="${1:?usage: sign_catalog.sh <catalog.yaml> <private-key.pem>}"
PRIVKEY="${2:?usage: sign_catalog.sh <catalog.yaml> <private-key.pem>}"
PUBKEY="${SECV_RELEASE_PUBKEY:-${PRIVKEY%_priv.pem}_pub.pem}"
SIG="${CATALOG}.sig"

[ -f "$CATALOG" ] || { echo "no such catalog: $CATALOG" >&2; exit 1; }
[ -f "$PRIVKEY" ] || { echo "no such private key: $PRIVKEY" >&2; exit 1; }
[ -f "$PUBKEY" ]  || { echo "no such public key: $PUBKEY (set SECV_RELEASE_PUBKEY)" >&2; exit 1; }

openssl dgst -sha256 -sign "$PRIVKEY" -out "$SIG" "$CATALOG"

# Verify our own output before leaving it in place: signing with the wrong key produces
# a perfectly well-formed signature that every client rejects. Without this check the
# first signal would be a broken install in the field.
if ! openssl dgst -sha256 -verify "$PUBKEY" -signature "$SIG" "$CATALOG" >/dev/null 2>&1; then
    rm -f "$SIG"
    echo "signature did NOT verify against $PUBKEY — signature deleted" >&2
    exit 1
fi

echo "signed:   $CATALOG"
echo "wrote:    $SIG"
echo "verified against $PUBKEY"
echo
echo "Ship catalog.yaml.sig next to catalog.yaml. Check it with:"
echo "  py secvitals.py --preflight        # reports the catalog status"
echo "  py secvitals.py --strict-catalog   # refuses to start unless verified"
