#!/bin/sh
# Start dnsmasq when WG_DEFAULT_DNS equals the VPN gateway (e.g. 10.8.0.1 or first host from WG_DEFAULT_ADDRESS).
set -e
# Default gateway = first host in subnet (WG_DEFAULT_ADDRESS with x -> 1).
WG_GW="${WG_DEFAULT_ADDRESS:-10.8.0.x}"
WG_GW="${WG_GW%x}1"
if [ -n "$WG_DEFAULT_DNS" ] && [ "$WG_DEFAULT_DNS" = "$WG_GW" ]; then
  dnsmasq -C /etc/dnsmasq-amnezia.conf -k &
fi
exec /usr/bin/dumb-init node server.js
