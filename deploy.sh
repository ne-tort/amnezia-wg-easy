#!/bin/bash
# Amnezia WG-Easy — custom build (DPI patches, UI: no QR, Copy button)
# Clone + ./deploy.sh or docker compose up -d --build
#
# Env layout:
#   .env.example = template (original, committed). Placeholders only; never modified by deploy.
#   .env         = working copy (generated). Used by docker compose. Delete to start from scratch.

set -e
cd "$(dirname "$0")"

ENV_TEMPLATE=".env.example"
ENV_WORKING=".env"

# Working env: create from template if missing (so deleting .env and re-running deploy = fresh start)
if [ ! -f "$ENV_WORKING" ]; then
    echo "[deploy] No $ENV_WORKING; creating from $ENV_TEMPLATE..."
    cp "$ENV_TEMPLATE" "$ENV_WORKING"
fi

# Substitute placeholders only in the working file (never touch template)
if grep -E "^WG_HOST=" "$ENV_WORKING" 2>/dev/null | grep -qE "YOUR_SERVER_IP|YOUR_SERVER_IP_OR_HOSTNAME|CHANGE_ME"; then
    WG_HOST=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || echo "CHANGE_ME")
    sed -i "s|^WG_HOST=.*|WG_HOST=${WG_HOST}|" "$ENV_WORKING"
    echo "[deploy] Auto-detected WG_HOST=${WG_HOST}"
fi
if grep -E "^PASSWORD=" "$ENV_WORKING" 2>/dev/null | grep -q "YOUR_ADMIN_PASSWORD"; then
    PWD=$(openssl rand -base64 16)
    sed -i "s|^PASSWORD=.*|PASSWORD=${PWD}|" "$ENV_WORKING"
    echo "[deploy] Generated random PASSWORD (saved in $ENV_WORKING)"
fi

# Stop and remove old containers (from this or previous deploy)
docker rm -f amnezia-wg-easy amnezia-dns 2>/dev/null || true

echo "[deploy] Building and starting..."
docker compose up -d --build --force-recreate --remove-orphans

PORT=$(grep -E "^PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "51821")
WG_HOST=$(grep -E "^WG_HOST=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "localhost")
PASSWORD=$(grep -E "^PASSWORD=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || echo "")
echo "[deploy] Done. Web UI: http://${WG_HOST}:${PORT}"
echo "[deploy] Password: ${PASSWORD}"
echo "[deploy] Amnezia DNS: set WG_DEFAULT_DNS=10.8.0.1 in $ENV_WORKING and re-download client configs to use it."
