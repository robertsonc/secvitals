#!/usr/bin/env bash
# Cloud Agent per-boot start for Security Vitals. Two idempotent, best-effort jobs that
# must never fail the boot:
#
#   1. Restore RFC 5737 "unreachable" semantics for the reserved documentation ranges
#      (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Several probe/classifier tests
#      fire at 192.0.2.1 and rely on it silently timing out — the behaviour on GitHub CI
#      runners, where these blocks are simply unrouted. This sandbox's transparent egress
#      answers them instead, which would flip those tests from blocked/error to allowed.
#      Routing the blocks on-link so ARP for the target never resolves reproduces the real
#      timeout without touching application or test code.
#
#   2. Provide a headless X display on :99 so the Tkinter console can be launched and
#      exercised (export DISPLAY=:99 before running `python3 secvitals.py`).
set -uo pipefail

export PATH="$PATH:/usr/sbin:/sbin"
SUDO=""
if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi

# 1. On-link routes for the reserved documentation ranges.
iface="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
if [ -n "${iface:-}" ]; then
  for p in 192.0.2.0/24 198.51.100.0/24 203.0.113.0/24; do
    if $SUDO ip route replace "$p" dev "$iface" scope link 2>/dev/null; then
      echo "route: $p -> $iface (scope link)"
    else
      echo "route: could not set $p (continuing)"
    fi
  done
else
  echo "route: no default interface found; skipping documentation-range routes"
fi

# 2. Headless X server for the GUI (idempotent — skip if :99 is already up).
if [ -e /tmp/.X99-lock ] || pgrep -x Xvfb >/dev/null 2>&1; then
  echo "xvfb: display already present"
else
  Xvfb :99 -screen 0 1400x1000x24 >/tmp/xvfb.log 2>&1 &
  echo "xvfb: started on :99 (export DISPLAY=:99 to use the GUI)"
fi

echo "secvitals start complete"
