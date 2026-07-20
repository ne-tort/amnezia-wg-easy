#!/bin/sh
# Reference entrypoint (also embedded in Dockerfile for stdin docker build).
set -e
echo "amnezia-naive container startup"
CFG=""
if [ -f /opt/amnezia/awg/naive/Caddyfile ]; then CFG=/opt/amnezia/awg/naive/Caddyfile; fi
if [ -z "$CFG" ] && [ -f /opt/amnezia/naive/Caddyfile ]; then CFG=/opt/amnezia/naive/Caddyfile; fi

if [ -n "$CFG" ]; then
  exec caddy run --config "$CFG" --adapter caddyfile
fi

echo "No Caddyfile yet; waiting"
exec tail -f /dev/null
