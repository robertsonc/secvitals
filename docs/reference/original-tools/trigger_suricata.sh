#!/usr/bin/env bash
#
# trigger_suricata.sh — generate benign traffic that trips a Suricata v7 signature,
# so you can validate detection/logging (and IPS drop behavior) end-to-end.
#
# Nothing here is an actual exploit — each method sends a harmless canary string
# or a benign URI that a well-known rule matches on.
#
# Usage:
#   sudo ./trigger_suricata.sh testmyids     # trip ET/GPL SID 2100498 (needs ET Open ruleset)
#   sudo ./trigger_suricata.sh local         # add a LOCAL test rule + trip it (ruleset-independent)
#   sudo ./trigger_suricata.sh watch         # just tail alerts from eve.json
#
set -euo pipefail

EVE="${EVE:-/var/log/suricata/eve.json}"
FASTLOG="${FASTLOG:-/var/log/suricata/fast.log}"
IFACE="${IFACE:-}"                 # interface Suricata sniffs; only needed for reload hints
LOCAL_RULES="${LOCAL_RULES:-/etc/suricata/rules/local.rules}"
SID="9000001"                      # SID for our self-contained local test rule

show_alerts() {
  echo ">> Watching for alerts (Ctrl-C to stop) ..."
  if command -v jq >/dev/null 2>&1 && [ -f "$EVE" ]; then
    tail -n0 -F "$EVE" | jq -rc 'select(.event_type=="alert")
      | "\(.timestamp)  sid=\(.alert.signature_id)  \(.alert.action // "alert")  \(.alert.signature)  \(.src_ip):\(.src_port)->\(.dest_ip):\(.dest_port)"'
  else
    tail -n0 -F "$FASTLOG"
  fi
}

case "${1:-}" in
  testmyids)
    # testmyids.org returns exactly "uid=0(root) gid=0(root) groups=0(root)".
    # That string trips SID 2100498 "GPL ATTACK_RESPONSE id check returned root".
    # It is the canonical, purpose-built IDS self-test. Requires the traffic to
    # cross the interface Suricata is monitoring (a real egress iface, not lo).
    echo ">> Requesting testmyids canary (trips SID 2100498) ..."
    curl -s -A "SuricataSelfTest" http://testmynids.org/uid/index.html || \
      curl -s -A "SuricataSelfTest" http://testmyids.com/uid/index.html
    echo
    echo ">> Sent. Check alerts:  sudo $0 watch"
    ;;

  local)
    # Ruleset-independent: install our own alert rule, reload, then trip it.
    # No dependency on ET/GPL being present. Matches a benign URI.
    echo ">> Installing LOCAL test rule (sid:$SID) into $LOCAL_RULES ..."
    RULE='alert http any any -> any any (msg:"LOCAL Suricata self-test trigger"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/suricata-self-test-9000001"; nocase; classtype:not-suspicious; sid:'"$SID"'; rev:1;)'
    grep -qF "sid:$SID" "$LOCAL_RULES" 2>/dev/null || echo "$RULE" | sudo tee -a "$LOCAL_RULES" >/dev/null

    echo ">> Reloading Suricata rules (live, no restart) ..."
    if command -v suricatasc >/dev/null 2>&1; then
      sudo suricatasc -c reload-rules || sudo suricatasc -c ruleset-reload-nonblocking || true
    else
      echo "   suricatasc not found; falling back to: sudo kill -USR2 \$(pidof suricata)"
      sudo kill -USR2 "$(pidof suricata)" 2>/dev/null || echo "   (reload manually, then re-run)"
    fi
    sleep 1

    echo ">> Generating matching request ..."
    # Point at any reachable host that crosses the monitored interface.
    TARGET="${TARGET:-http://example.com/suricata-self-test-9000001}"
    curl -s -o /dev/null "$TARGET" || true
    echo ">> Sent to $TARGET. Check alerts:  sudo $0 watch"
    ;;

  watch)
    show_alerts
    ;;

  *)
    echo "Usage: sudo $0 {testmyids|local|watch}"
    echo "  testmyids  trip ET/GPL SID 2100498 via testmyids.org canary (needs ET Open)"
    echo "  local      install + trip a self-contained LOCAL rule (any ruleset)"
    echo "  watch      tail alerts from $EVE (or $FASTLOG)"
    exit 1
    ;;
esac
