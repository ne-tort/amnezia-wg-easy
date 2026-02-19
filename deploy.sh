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

# Set WG_HOST only when not set or still a placeholder (never overwrite an explicit IP or domain)
CURRENT_WG_HOST=$(grep -E "^WG_HOST=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
if [ -z "$CURRENT_WG_HOST" ] || echo "$CURRENT_WG_HOST" | grep -qE "^(YOUR_SERVER_IP|YOUR_SERVER_IP_OR_HOSTNAME|CHANGE_ME)$"; then
  WG_HOST_NEW=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || true)
  if [ -n "$WG_HOST_NEW" ]; then
    if grep -qE "^WG_HOST=" "$ENV_WORKING" 2>/dev/null; then
      sed -i "s|^WG_HOST=.*|WG_HOST=${WG_HOST_NEW}|" "$ENV_WORKING"
    else
      echo "WG_HOST=${WG_HOST_NEW}" >> "$ENV_WORKING"
    fi
    echo "[deploy] WG_HOST set to ${WG_HOST_NEW} (was unset or placeholder)"
  else
    echo "[deploy] WARNING: Could not detect public IP; set WG_HOST in $ENV_WORKING (IP or domain)"
  fi
fi

# First-run admin: if ADMIN_USERNAME or ADMIN_PASSWORD unset/placeholder → admin + generated password
ADMIN_USER_VAL=$(grep -E "^ADMIN_USERNAME=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
ADMIN_PWD_VAL=$(grep -E "^ADMIN_PASSWORD=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
NEED_PWD=
if [ -z "$ADMIN_USER_VAL" ] || [ "$ADMIN_USER_VAL" = "your_admin_username" ]; then
  ADMIN_USER_VAL=admin
  if grep -qE "^ADMIN_USERNAME=" "$ENV_WORKING" 2>/dev/null; then
    sed -i "s|^ADMIN_USERNAME=.*|ADMIN_USERNAME=admin|" "$ENV_WORKING"
  else
    echo "ADMIN_USERNAME=admin" >> "$ENV_WORKING"
  fi
  NEED_PWD=1
fi
if [ -z "$ADMIN_PWD_VAL" ] || [ "$ADMIN_PWD_VAL" = "your_admin_password" ]; then
  ADMIN_PWD_VAL=$(openssl rand -base64 16)
  if grep -qE "^ADMIN_PASSWORD=" "$ENV_WORKING" 2>/dev/null; then
    sed -i "s|^ADMIN_PASSWORD=.*|ADMIN_PASSWORD=${ADMIN_PWD_VAL}|" "$ENV_WORKING"
  else
    echo "ADMIN_PASSWORD=${ADMIN_PWD_VAL}" >> "$ENV_WORKING"
  fi
  echo "[deploy] Generated ADMIN_PASSWORD (saved in $ENV_WORKING)"
fi

# Tear down this project's containers and networks (avoids "Pool overlaps" and stale state)
echo "[deploy] Tearing down existing stack..."
docker compose down --remove-orphans 2>/dev/null || true

# Remove legacy or conflicting networks that use the same subnet (e.g. from older/other deploy)
for net in amnezia-dns-net amnezia-wg-easy_amnezia-dns-net amnezia-wg-easy_default; do
  docker network rm "$net" 2>/dev/null || true
done

# Build and start (build runs as part of up; if another build is in progress, Docker queues)
echo "[deploy] Building and starting..."
docker compose up -d --build --force-recreate --remove-orphans

PORT=$(grep -E "^PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "51821")
WG_HOST=$(grep -E "^WG_HOST=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "localhost")
ADMIN_USER=$(grep -E "^ADMIN_USERNAME=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || echo "admin")
ADMIN_PWD=$(grep -E "^ADMIN_PASSWORD=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || echo "")
echo "[deploy] Done. Web UI: http://${WG_HOST}:${PORT}"
echo "[deploy] Admin login: ${ADMIN_USER}"
echo "[deploy] Admin password: ${ADMIN_PWD}"
echo "[deploy] Amnezia DNS: set WG_DEFAULT_DNS=10.8.0.1 in $ENV_WORKING and re-download client configs to use it."
