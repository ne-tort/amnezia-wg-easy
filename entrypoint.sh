#!/bin/sh
# Amnezia DNS (dnsmasq) starts from Node after WireGuard is up (lib/amneziaDns.js).
set -e

SEED=/app/config/signatures.seed.json
DEST=/opt/amnezia/awg/signatures.json
need_seed=0
if [ ! -f "$DEST" ] || [ ! -s "$DEST" ]; then
  need_seed=1
elif ! grep -q '"profiles"' "$DEST" 2>/dev/null; then
  need_seed=1
fi
if [ "$need_seed" -eq 1 ] && [ -f "$SEED" ]; then
  mkdir -p /opt/amnezia/awg
  cp "$SEED" "$DEST"
  echo "[entrypoint] seeded signatures.json from config/signatures.seed.json"
fi

exec /usr/bin/dumb-init node server.js
