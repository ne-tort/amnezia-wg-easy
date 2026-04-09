#!/bin/sh
# PostUp for awg-cascade.conf inside amnezia-wg-easy container (same netns as awg0).
# Args: $1 = tunnel peer IP (exit side, e.g. 172.31.255.2), $2 = client VPN CIDR (e.g. 10.8.0.0/24)
#
# Policy routing: from client subnet -> table 166 (default via awg-cascade).
# Do NOT delete awg-quick pref-0 fwmark/suppress rules: that breaks awg0 handshakes/replies.
# Cascade rules at pref 1–2 apply after pref 0; internet via cascade may need separate work (nft mark).
set -e
CASCADE_GW="${1:?missing tunnel gw}"
CLIENT_CIDR="${2:?missing client cidr}"
UPLINK_IF=awg-cascade
INGRESS_IF=awg0
PRI_TO_MAIN=1
PRI_FROM_CASCADE=2

sysctl -w net.ipv4.ip_forward=1 >/dev/null
for i in "$INGRESS_IF" "$UPLINK_IF" all; do
  sysctl -w "net.ipv4.conf.${i}.rp_filter=0" >/dev/null 2>&1 || true
done

# Drop legacy fwmark rules (older cascade versions)
while ip rule show 2>/dev/null | grep -q "fwmark 0x66 .* lookup 166"; do
  p=$(ip rule show | awk '/fwmark 0x66 .* lookup 166/ {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done

# Remove stale rules for this CIDR (any priority)
while ip rule show 2>/dev/null | grep -q "from ${CLIENT_CIDR} lookup 166"; do
  p=$(ip rule show | awk -v c="$CLIENT_CIDR" '$0 ~ ("from " c " lookup 166") {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done
while ip rule show 2>/dev/null | grep -q "to ${CLIENT_CIDR} lookup main"; do
  p=$(ip rule show | awk -v c="$CLIENT_CIDR" '$0 ~ ("to " c " lookup main") {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done

# VPN-internal (DNS 10.8..1, same-subnet): main table — evaluated before from->166
ip rule add to "$CLIENT_CIDR" lookup main priority "$PRI_TO_MAIN" 2>/dev/null || true
# Internet from clients: cascade
ip rule add from "$CLIENT_CIDR" table 166 priority "$PRI_FROM_CASCADE" 2>/dev/null || true

ip route flush table 166 2>/dev/null || true
ip route replace default via "$CASCADE_GW" dev "$UPLINK_IF" table 166 2>/dev/null || true

nft delete table inet amnezia_cascade_entry 2>/dev/null || true
nft add table inet amnezia_cascade_entry 2>/dev/null || true
nft 'add chain inet amnezia_cascade_entry forward_cascade { type filter hook forward priority 50; policy accept; }' 2>/dev/null || true
nft flush chain inet amnezia_cascade_entry forward_cascade
nft add rule inet amnezia_cascade_entry forward_cascade iifname "$INGRESS_IF" oifname "$UPLINK_IF" accept
nft add rule inet amnezia_cascade_entry forward_cascade iifname "$UPLINK_IF" oifname "$INGRESS_IF" accept

exit 0
