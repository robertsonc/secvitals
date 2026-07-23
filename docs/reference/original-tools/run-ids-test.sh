#!/usr/bin/env bash
# run-ids-test.sh -- fires 3CORESec tmNIDS trigger traffic (runs inside WSL).
# Usage:  run-ids-test.sh [testnumber]   (default 99 = run ALL)
# Lives in the "Demo Toolbox" folder; launched by Run-IDS-Test.cmd.
set -u

TEST="${1:-99}"
TMNIDS="/tmp/tmNIDS"
URL="https://raw.githubusercontent.com/3CORESec/testmynids.org/master/tmNIDS"

echo "=== IDS/IPS trigger test (tmNIDS -$TEST) ==="
date
echo

# Cache the tool so repeat demo runs don't re-download.
if [ ! -x "$TMNIDS" ]; then
  echo ">> Downloading tmNIDS ..."
  curl -sSL "$URL" -o "$TMNIDS" && chmod +x "$TMNIDS" || {
    echo ">> Download failed -- check connectivity." >&2; exit 1; }
fi

"$TMNIDS" -"$TEST"
rc=$?

echo
if [ $rc -eq 0 ]; then
  echo ">> Trigger traffic sent. Check Suricata alerts on the router."
else
  echo ">> tmNIDS exited with code $rc." >&2
fi
