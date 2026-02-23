#!/bin/sh
# Amnezia DNS (dnsmasq) is started from Node after WireGuard interface is up (see lib/amneziaDns.js).
set -e
exec /usr/bin/dumb-init node server.js
