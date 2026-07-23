#!/usr/bin/env bash
# webcc-test.sh -- trigger EdgeConnect Secure Web Services (BrightCloud WebCC)
# filtering: domain/category + web-reputation + IP reputation. Runs in WSL.
#   webcc-test.sh            -> interactive menu
#   webcc-test.sh 4          -> run only test 4
#   webcc-test.sh all        -> run every test
# Each probe reports the ACTUAL result (ALLOWED / BLOCKED), so the demo is
# self-verifying no matter how the policy is set. Traffic egresses the Windows
# host and crosses the EdgeConnect, where Secure Web Services inspects it.
set -u

TOR_LIST="https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-nodes.lst"

# id | label | category-axis | url-or-marker
domain_tests=(
  "1|Gambling|Web Category|https://www.bet365.com/"
  "2|Social Networking|Web Category|https://www.facebook.com/"
  "3|Streaming Media|Web Category|https://www.youtube.com/"
  "4|Proxy Avoidance / Anonymizer|Web Category + reputation|https://www.hidemyass.com/"
  "5|Peer-to-Peer / Torrent|Web Category|https://thepiratebay.org/"
  "6|Cryptocurrency|Web Category|https://www.coinbase.com/"
  "7|Malware file (EICAR)|Web threat / SWG|https://secure.eicar.org/eicar.com.txt"
  "8|Malware page (Google test)|Web threat / SWG|https://testsafebrowsing.appspot.com/s/malware.html"
  "9|Phishing page (Google test)|Web threat / SWG|https://testsafebrowsing.appspot.com/s/phishing.html"
  "10|Unwanted software (Google test)|Web threat / SWG|https://testsafebrowsing.appspot.com/s/unwanted.html"
)

# ---- probe one URL, classify the outcome ----------------------------------
probe_url() {
  local url="$1" body="/tmp/webcc_body" err="/tmp/webcc_err" res rc code size eff
  # EC WebCC blocks by silently dropping the flow -- there is no block page,
  # so a deny shows up as a connect timeout / reset (curl fails). A completed
  # HTTP response means the category/reputation was allowed.
  res=$(curl -sS -A "WebCC-Demo" -o "$body" \
        -w "%{http_code}|%{size_download}|%{url_effective}" \
        --connect-timeout 6 --max-time 9 "$url" 2>"$err")
  rc=$?
  IFS='|' read -r code size eff <<<"${res:-0|0|}"

  if [ "$rc" -ne 0 ]; then
    printf "BLOCKED   (timeout/reset -- curl rc=%s)\n" "$rc"
  elif [ "$code" = "403" ] || [ "$code" = "451" ]; then
    printf "BLOCKED   (HTTP %s)\n" "$code"
  else
    printf "allowed   (HTTP %s, %sB)\n" "$code" "$size"
  fi
}

run_domain() {
  local id="$1" entry label axis url
  for entry in "${domain_tests[@]}"; do
    [ "${entry%%|*}" = "$id" ] || continue
    IFS='|' read -r _ label axis url <<<"$entry"
    printf "  [%-2s] %-32s %-26s " "$id" "$label" "($axis)"
    probe_url "$url"
    return
  done
  echo "  unknown test id: $id"
}

# ---- IP reputation: connect to Tor Proxy IPs (BrightCloud IP-rep category) --
run_ip_rep() {
  echo "  [11] IP Reputation -- Tor Proxy nodes (BrightCloud IP-rep 'Tor Proxy')"
  local tmp="/tmp/webcc_tor.list"
  if ! curl -sSL "$TOR_LIST" -o "$tmp" 2>/dev/null; then
    echo "       could not fetch Tor node list -- check connectivity." >&2; return
  fi
  local n=0 ip
  # first 6 well-formed IPv4 entries
  while read -r ip; do
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
    n=$((n+1)); [ "$n" -gt 6 ] && break
    if timeout 5 bash -c "exec 3<>/dev/tcp/$ip/443" 2>/dev/null; then
      printf "       %-16s :443  reached   (not blocked by IP reputation)\n" "$ip"
      exec 3>&- 2>/dev/null
    else
      printf "       %-16s :443  BLOCKED   (timeout/reset)\n" "$ip"
    fi
  done < "$tmp"
  echo "       (timeouts on many/all = IP reputation deny is working; a lone"
  echo "        failure may just be a down relay -- confirm on the EC stats.)"
}

run_one() {
  case "$1" in
    11) run_ip_rep ;;
    [0-9]|10) run_domain "$1" ;;
    *) echo "  unknown test: $1" ;;
  esac
}

run_all() {
  echo ">> Domain / category / web-reputation triggers:"
  for entry in "${domain_tests[@]}"; do run_domain "${entry%%|*}"; done
  echo
  echo ">> IP reputation trigger:"
  run_ip_rep
}

menu() {
  while true; do
    clear
    echo "=================================================="
    echo "     EdgeConnect Secure Web Services (WebCC)"
    echo "        BrightCloud filtering demo triggers"
    echo "=================================================="
    echo "  DOMAIN / CATEGORY"
    for entry in "${domain_tests[@]}"; do
      IFS='|' read -r id label axis _ <<<"$entry"
      printf "   %-3s %-32s %s\n" "$id" "$label" "$axis"
    done
    echo "  IP REPUTATION"
    printf "   %-3s %-32s %s\n" "11" "Tor Proxy IPs (:443)" "IP reputation"
    echo "--------------------------------------------------"
    printf "   %-3s %s\n" "a" "Run ALL"
    printf "   %-3s %s\n" "q" "Quit"
    echo "--------------------------------------------------"
    read -rp " Select: " c
    case "$c" in
      q|Q) echo "Bye."; return 0 ;;
      a|A) echo; run_all ;;
      "") continue ;;
      *) echo; run_one "$c" ;;
    esac
    echo
    read -rp " Press Enter to return to the menu ..." _
  done
}

echo "=== EdgeConnect Secure Web Services (BrightCloud WebCC) test ==="
date
echo

case "${1:-}" in
  "")        menu ;;
  all|ALL|99) run_all ;;
  *)         run_one "$1" ;;
esac

echo
echo ">> Done. Authoritative view: EdgeConnect Secure Web Services stats"
echo "   (Allowed/Denied by Category + High-Risk URL/IP flows)."
