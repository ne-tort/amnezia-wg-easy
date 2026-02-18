#!/bin/sh
# Start dnsmasq when WG_DEFAULT_DNS=10.8.0.1 (Amnezia DNS via container), then run Node server.
set -e
if [ "$WG_DEFAULT_DNS" = "10.8.0.1" ]; then
  dnsmasq -C /etc/dnsmasq-amnezia.conf -k &
fi
exec /usr/bin/dumb-init node server.js
