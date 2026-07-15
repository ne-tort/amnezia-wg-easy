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

JUNK_SEED=/app/config/junk-ranges.seed.json
JUNK_DEST=/opt/amnezia/awg/junk-ranges.json
junk_need=0
if [ ! -f "$JUNK_DEST" ] || [ ! -s "$JUNK_DEST" ]; then
  junk_need=1
elif [ -f "$JUNK_SEED" ]; then
  junk_seed_ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$JUNK_SEED" | head -n1)
  junk_dest_ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$JUNK_DEST" | head -n1)
  junk_seed_ver=${junk_seed_ver:-0}
  junk_dest_ver=${junk_dest_ver:-0}
  if [ "$junk_dest_ver" -lt "$junk_seed_ver" ]; then
    junk_need=1
  fi
fi
if [ "$junk_need" -eq 1 ] && [ -f "$JUNK_SEED" ]; then
  mkdir -p /opt/amnezia/awg
  cp "$JUNK_SEED" "$JUNK_DEST"
  echo "[entrypoint] seeded junk-ranges.json from config/junk-ranges.seed.json"
fi

MTU_SEED=/app/config/mtu-profiles.seed.json
MTU_DEST=/opt/amnezia/awg/mtu-profiles.json
mtu_need=0
if [ ! -f "$MTU_DEST" ] || [ ! -s "$MTU_DEST" ]; then
  mtu_need=1
elif [ -f "$MTU_SEED" ]; then
  mtu_seed_ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$MTU_SEED" | head -n1)
  mtu_dest_ver=$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$MTU_DEST" | head -n1)
  mtu_seed_ver=${mtu_seed_ver:-0}
  mtu_dest_ver=${mtu_dest_ver:-0}
  if [ "$mtu_dest_ver" -lt "$mtu_seed_ver" ]; then
    mtu_need=1
  fi
fi
if [ "$mtu_need" -eq 1 ] && [ -f "$MTU_SEED" ]; then
  mkdir -p /opt/amnezia/awg
  cp "$MTU_SEED" "$MTU_DEST"
  echo "[entrypoint] seeded mtu-profiles.json from config/mtu-profiles.seed.json"
fi

exec /usr/bin/dumb-init node server.js
