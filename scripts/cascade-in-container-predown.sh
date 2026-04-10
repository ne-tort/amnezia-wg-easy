#!/bin/sh
# PreDown for awg-cascade.conf — remove policy routing and nft from cascade-in-container-postup.sh
# Args: $1 = client CIDR, optional $2 = exit public IPv4 (same as postup $3) to remove /32 routes
set -e
CLIENT_CIDR="${1:-10.8.0.0/24}"
EXIT_PUB="${2:-}"
UPLINK_IF=awg-cascade

while ip rule show 2>/dev/null | grep -q "fwmark 0x66 .* lookup 166"; do
  p=$(ip rule show | awk '/fwmark 0x66 .* lookup 166/ {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done

while ip rule show 2>/dev/null | grep -q "from ${CLIENT_CIDR} lookup 166"; do
  p=$(ip rule show | awk -v c="$CLIENT_CIDR" '$0 ~ ("from " c " lookup 166") {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done

ip route flush table 166 2>/dev/null || true

while ip rule show 2>/dev/null | grep -q "to $CLIENT_CIDR lookup main"; do
  p=$(ip rule show | awk -v cidr="$CLIENT_CIDR" '$0 ~ ("to " cidr " lookup main") {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done

for t in $(ip -4 rule show 2>/dev/null | sed -n 's/.*lookup \([0-9][0-9]*\).*/\1/p' | sort -u); do
  [ "$t" = "166" ] && continue
  ip route show table "$t" 2>/dev/null | grep -qE "default .*dev ${UPLINK_IF}( |$)" || continue
  ip route del 0.0.0.0/1 table "$t" 2>/dev/null || true
  ip route del 128.0.0.0/1 table "$t" 2>/dev/null || true
done

nft delete table inet amnezia_cascade_entry 2>/dev/null || true

if [ -n "$EXIT_PUB" ] && echo "$EXIT_PUB" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  for t in 166 $(ip -4 rule show 2>/dev/null | sed -n 's/.*lookup \([0-9][0-9]*\).*/\1/p' | sort -u); do
    ip route del "${EXIT_PUB}/32" table "$t" 2>/dev/null || true
  done
fi
exit 0
