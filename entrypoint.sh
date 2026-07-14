#!/bin/sh
# Amnezia DNS (dnsmasq) starts from Node after WireGuard is up (lib/amneziaDns.js).
set -e

SEED=/app/config/signatures.seed.json
DEST=/opt/amnezia/awg/signatures.json
if [ ! -f "$DEST" ] && [ -f "$SEED" ]; then
  mkdir -p /opt/amnezia/awg
  cp "$SEED" "$DEST"
  echo "[entrypoint] seeded signatures.json from config/signatures.seed.json"
fi

exec /usr/bin/dumb-init node server.js
