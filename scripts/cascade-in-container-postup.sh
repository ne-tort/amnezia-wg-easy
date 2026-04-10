#!/bin/sh
# PostUp for awg-cascade.conf inside amnezia-wg-easy container (same netns as awg0).
# Args: $1 = tunnel peer IP (exit side, e.g. 172.31.255.2), $2 = client VPN CIDR (e.g. 10.8.0.0/24)
# Optional $3 = exit host PUBLIC IPv4 (same as Endpoint host) — required so UDP to the peer is not routed into awg-cascade (AllowedIPs 0.0.0.0/0 paradox).
#
# Policy routing: from client subnet -> table 166 (default via awg-cascade).
# Do NOT delete awg-quick pref-0 fwmark/suppress rules: that breaks awg0 handshakes/replies.
# Cascade rules at pref 1-2 apply after pref 0; internet via cascade may need separate work (nft mark).
set -e
CASCADE_GW="${1:?missing tunnel gw}"
CLIENT_CIDR="${2:?missing client cidr}"
EXIT_PUB="${3:-}"
UPLINK_IF=awg-cascade
INGRESS_IF=awg0
PRI_TO_MAIN=1
PRI_FROM_CASCADE=2

DOCKER_IF=eth0
# Default to internet may be eth1 (e.g. amnezia-dns-net) not eth0 (docker bridge) — use full default line.
DEFAULT_LINE=$(ip -4 route show default 2>/dev/null | head -1)
DEFAULT_GW=$(echo "$DEFAULT_LINE" | awk '{print $3; exit}')
DEFAULT_DEV=$(echo "$DEFAULT_LINE" | awk '{print $5; exit}')
[ -n "$DEFAULT_GW" ] || DEFAULT_GW=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
[ -n "$DEFAULT_DEV" ] || DEFAULT_DEV="$DOCKER_IF"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
for i in "$INGRESS_IF" "$UPLINK_IF" all; do
  sysctl -w "net.ipv4.conf.${i}.rp_filter=0" >/dev/null 2>&1 || true
done
# Docker bridge (eth0) + amnezia-dns-net (eth1): strict rp_filter breaks forward/DNS paths.
for i in eth0 eth1; do
  [ -e "/sys/class/net/$i" ] && sysctl -w "net.ipv4.conf.${i}.rp_filter=0" >/dev/null 2>&1 || true
done
# Reduce TX drops under load on cascade uplink (observed millions of drops with default qlen).
ip link set dev "$UPLINK_IF" txqueuelen 10000 2>/dev/null || true

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

# Docker bridge (eth0): awg-quick installs "not fwmark … lookup <table>" where <table> has only
# "default dev awg-cascade". Without a more specific route, traffic from container IP to peers
# (e.g. nginx -> Node on 172.18.0.2:51821) matches default and black-holes via the tunnel.
DOCKER_NET=$(ip -4 route show proto kernel scope link dev "$DOCKER_IF" 2>/dev/null | awk '{print $1; exit}')
if [ -n "$DOCKER_NET" ]; then
  ip route replace "$DOCKER_NET" dev "$DOCKER_IF" table 166 2>/dev/null || true
  # Same for wg-quick's routing table(s) (often 51820) — not always 166.
  for t in $(ip -4 rule show 2>/dev/null | sed -n 's/.*lookup \([0-9][0-9]*\).*/\1/p' | sort -u); do
    ip route show table "$t" 2>/dev/null | grep -qE "default .*dev ${UPLINK_IF}( |$)" || continue
    ip route replace "$DOCKER_NET" dev "$DOCKER_IF" table "$t" 2>/dev/null || true
  done
fi
# Amnezia DNS (amnezia-dns-net 172.29.172.0/24 → 172.29.172.254): Docker may attach it to eth0 or eth1.
# Policy "from CLIENT_CIDR table 166" needs a more-specific route than default via awg-cascade.
AMNEZIA_DNS_NET=""
DNS_IF=""
for try in eth0 eth1; do
  AMNEZIA_DNS_NET=$(ip -4 route show proto kernel scope link dev "$try" 2>/dev/null | awk '/^172\.29\.172\// {print $1; exit}')
  if [ -n "$AMNEZIA_DNS_NET" ]; then
    DNS_IF=$try
    break
  fi
done
if [ -n "$AMNEZIA_DNS_NET" ] && [ -n "$DNS_IF" ]; then
  ip route replace "$AMNEZIA_DNS_NET" dev "$DNS_IF" table 166 2>/dev/null || true
  for t in $(ip -4 rule show 2>/dev/null | sed -n 's/.*lookup \([0-9][0-9]*\).*/\1/p' | sort -u); do
    ip route show table "$t" 2>/dev/null | grep -qE "default .*dev ${UPLINK_IF}( |$)" || continue
    ip route replace "$AMNEZIA_DNS_NET" dev "$DNS_IF" table "$t" 2>/dev/null || true
  done
fi
# Peer Endpoint must leave via the same iface as default route (often eth1, not docker bridge eth0).
if [ -n "$EXIT_PUB" ] && [ -n "$DEFAULT_GW" ] && echo "$EXIT_PUB" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
  ip route replace "$EXIT_PUB/32" via "$DEFAULT_GW" dev "$DEFAULT_DEV" table 166 2>/dev/null || true
  for t in $(ip -4 rule show 2>/dev/null | sed -n 's/.*lookup \([0-9][0-9]*\).*/\1/p' | sort -u); do
    ip route show table "$t" 2>/dev/null | grep -qE "default .*dev ${UPLINK_IF}( |$)" || continue
    ip route replace "$EXIT_PUB/32" via "$DEFAULT_GW" dev "$DEFAULT_DEV" table "$t" 2>/dev/null || true
  done
fi
# wg-quick installs "not fwmark … lookup <N>" where table N has only "default dev awg-cascade".
# Unmarked IPv4 (e.g. handshake replies to arbitrary client public IPs) would match that default
# and go into the tunnel. Two /1 routes beat 0.0.0.0/0 and steer almost all IPv4 to the WAN.
# Never touch table 166: there default via cascade is required for traffic from CLIENT_CIDR.
if [ -n "$DEFAULT_GW" ] && [ -n "$DEFAULT_DEV" ]; then
  for t in $(ip -4 rule show 2>/dev/null | sed -n 's/.*lookup \([0-9][0-9]*\).*/\1/p' | sort -u); do
    [ "$t" = "166" ] && continue
    ip route show table "$t" 2>/dev/null | grep -qE "default .*dev ${UPLINK_IF}( |$)" || continue
    ip route replace 0.0.0.0/1 via "$DEFAULT_GW" dev "$DEFAULT_DEV" table "$t" 2>/dev/null || true
    ip route replace 128.0.0.0/1 via "$DEFAULT_GW" dev "$DEFAULT_DEV" table "$t" 2>/dev/null || true
  done
fi

nft delete table inet amnezia_cascade_entry 2>/dev/null || true
nft add table inet amnezia_cascade_entry 2>/dev/null || true
nft 'add chain inet amnezia_cascade_entry forward_cascade { type filter hook forward priority 50; policy accept; }' 2>/dev/null || true
nft flush chain inet amnezia_cascade_entry forward_cascade
nft add rule inet amnezia_cascade_entry forward_cascade iifname "$INGRESS_IF" oifname "$UPLINK_IF" accept
nft add rule inet amnezia_cascade_entry forward_cascade iifname "$UPLINK_IF" oifname "$INGRESS_IF" accept

exit 0
