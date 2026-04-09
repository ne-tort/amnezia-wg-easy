#!/bin/sh
# PreDown for awg-cascade.conf — remove policy routing and nft marks created by cascade-in-container-postup.sh
set -e
CLIENT_CIDR="${1:-10.8.0.0/24}"

while ip rule show 2>/dev/null | grep -q "fwmark 0x66 .* lookup 166"; do
  p=$(ip rule show | awk '/fwmark 0x66 .* lookup 166/ {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done
ip route flush table 166 2>/dev/null || true

while ip rule show 2>/dev/null | grep -q "to $CLIENT_CIDR lookup main"; do
  p=$(ip rule show | awk -v cidr="$CLIENT_CIDR" '$0 ~ ("to " cidr " lookup main") {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done

nft delete table inet amnezia_cascade_entry 2>/dev/null || true
exit 0
