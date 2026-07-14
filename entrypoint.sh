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
elif [ -f "$SEED" ]; then
  seed_ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$SEED" | head -n1)
  dest_ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$DEST" | head -n1)
  seed_ver=${seed_ver:-0}
  dest_ver=${dest_ver:-0}
  if [ "$dest_ver" -lt "$seed_ver" ]; then
    need_seed=1
  fi
fi
if [ "$need_seed" -eq 1 ] && [ -f "$SEED" ]; then
  mkdir -p /opt/amnezia/awg
  cp "$SEED" "$DEST"
  echo "[entrypoint] seeded signatures.json from config/signatures.seed.json"
fi

exec /usr/bin/dumb-init node server.js
