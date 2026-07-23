#!/usr/bin/env bash
# run-ids-menu.sh -- interactive picker for the tmNIDS demo (runs inside WSL).
# Launched by Run-IDS-Menu.cmd. Lets the presenter fire one clean signature
# at a time, or run everything.
set -u

TMNIDS="/tmp/tmNIDS"
URL="https://raw.githubusercontent.com/3CORESec/testmynids.org/master/tmNIDS"

tests=(
  "1|Linux UID (uid=0 root)"
  "2|HTTP Basic Authentication"
  "3|HTTP Malware User-Agent"
  "4|Bad Certificates & CAs"
  "5|Tor .onion DNS + known IPs"
  "6|EXE or DLL download over HTTP"
  "7|PDF download with Embedded File"
  "8|Simulate SSH Outbound Scan"
  "9|Miscellaneous domains (TLDs, Sinkhole, DDNS)"
  "10|Anonymous filesharing website"
  "11|External IP Address Lookup"
  "12|URL Shortener"
  "13|Policy Violation - Gaming"
  "14|Adware PUP"
  "15|Malware - Command & Control - Beacon"
  "99|CHAOS!  Run ALL tests"
)

while true; do
  clear
  echo "=================================================="
  echo "        IDS/IPS Demo  -  tmNIDS Test Menu"
  echo "=================================================="
  for t in "${tests[@]}"; do
    printf "   %-3s  %s\n" "${t%%|*}" "${t#*|}"
  done
  echo "    q    Quit"
  echo "--------------------------------------------------"
  read -rp " Select a test number: " choice

  [ "$choice" = "q" ] || [ "$choice" = "Q" ] && { echo "Bye."; exit 0; }
  if ! [[ "$choice" =~ ^[0-9]+$ ]]; then
    echo " Not a number -- try again."; sleep 1; continue
  fi

  if [ ! -x "$TMNIDS" ]; then
    echo " >> Downloading tmNIDS ..."
    curl -sSL "$URL" -o "$TMNIDS" && chmod +x "$TMNIDS" || {
      echo " >> Download failed -- check connectivity." >&2; sleep 2; continue; }
  fi

  echo
  echo " >> Running tmNIDS -$choice ..."
  echo "--------------------------------------------------"
  "$TMNIDS" -"$choice"
  echo "--------------------------------------------------"
  echo " >> Done. Check Suricata alerts on the router."
  echo
  read -rp " Press Enter to return to the menu ..." _
done
