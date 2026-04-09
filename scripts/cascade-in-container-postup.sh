#!/bin/sh
# PostUp for awg-cascade.conf inside amnezia-wg-easy container (same netns as awg0).
# Args: $1 = tunnel peer IP (exit side, e.g. 172.31.255.2), $2 = client VPN CIDR (e.g. 10.8.0.0/24)
set -e
CASCADE_GW="${1:?missing tunnel gw}"
CLIENT_CIDR="${2:?missing client cidr}"
UPLINK_IF=awg-cascade
INGRESS_IF=awg0

sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Policy routing: marked client traffic uses table 166 via cascade uplink
while ip rule show 2>/dev/null | grep -q "fwmark 0x66 .* lookup 166"; do
  p=$(ip rule show | awk '/fwmark 0x66 .* lookup 166/ {gsub(":","",$1); print $1; exit}')
  [ -n "$p" ] && ip rule del pref "$p" 2>/dev/null || break
done
ip rule add fwmark 0x66 table 166 priority 1100 2>/dev/null || true

# Keep VPN-local traffic on main (gateway/DNS on awg0)
ip rule del to "$CLIENT_CIDR" lookup main 2>/dev/null || true
ip rule add to "$CLIENT_CIDR" lookup main priority 1000 2>/dev/null || true

ip route replace default via "$CASCADE_GW" dev "$UPLINK_IF" table 166 2>/dev/null || true

nft add table inet amnezia_cascade_entry 2>/dev/null || true
nft 'add chain inet amnezia_cascade_entry prerouting_mangle { type filter hook prerouting priority mangle; policy accept; }' 2>/dev/null || true
nft flush chain inet amnezia_cascade_entry prerouting_mangle
nft add rule inet amnezia_cascade_entry prerouting_mangle iifname "$INGRESS_IF" ip saddr "$CLIENT_CIDR" meta mark set 0x66

exit 0
