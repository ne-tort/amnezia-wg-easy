#!/bin/bash
# Amnezia WG-Easy — custom build (DPI patches, UI: no QR, Copy button)
# Clone + ./deploy.sh or docker compose up -d --build

set -e
cd "$(dirname "$0")"

# Ensure .env exists
if [ ! -f .env ]; then
    echo "[deploy] Creating .env from .env.example..."
    cp .env.example .env
fi

# Replace placeholders if still present (works for both new and existing .env)
if grep -E "^WG_HOST=" .env 2>/dev/null | grep -qE "YOUR_SERVER_IP|YOUR_SERVER_IP_OR_HOSTNAME|CHANGE_ME"; then
    WG_HOST=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || echo "CHANGE_ME")
    sed -i "s|WG_HOST=.*|WG_HOST=${WG_HOST}|" .env
    echo "[deploy] Auto-detected WG_HOST=${WG_HOST}"
fi
if grep -E "^PASSWORD=" .env 2>/dev/null | grep -q "YOUR_ADMIN_PASSWORD"; then
    PWD=$(openssl rand -base64 16)
    sed -i "s|PASSWORD=.*|PASSWORD=${PWD}|" .env
    echo "[deploy] Generated random PASSWORD (saved in .env)"
fi

# Stop old container if switching
docker stop amnezia-wg-easy 2>/dev/null || true

echo "[deploy] Building and starting..."
docker compose up -d --build --force-recreate --remove-orphans

PORT=$(grep -E "^PORT=" .env 2>/dev/null | cut -d= -f2 || echo "51821")
WG_HOST=$(grep -E "^WG_HOST=" .env 2>/dev/null | cut -d= -f2 || echo "localhost")
PASSWORD=$(grep -E "^PASSWORD=" .env 2>/dev/null | cut -d= -f2- || echo "")
echo "[deploy] Done. Web UI: http://${WG_HOST}:${PORT}"
echo "[deploy] Password: ${PASSWORD}"
