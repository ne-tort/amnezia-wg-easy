#!/bin/bash
# Deploy Amnezia WG-Easy (Docker Compose).
# Usage: ./deploy.sh
#
#   .env.example — committed template
#   .env         — working copy for compose (created from template if missing)

set -e
cd "$(dirname "$0")"

# Optional submodule (signature bank tooling); panel image does not need it at build time.
if [ -f .gitmodules ] && [ -d .git ]; then
  if [ ! -f capture_udp_sig/README.md ]; then
    echo "[deploy] Initializing git submodules (capture_udp_sig)..."
    git submodule update --init --recursive || true
  fi
fi

ENV_TEMPLATE=".env.example"
ENV_WORKING=".env"
if [ ! -f "$ENV_TEMPLATE" ]; then
  echo "[deploy] ERROR: missing $ENV_TEMPLATE" >&2
  exit 1
fi

# Portable in-place replace (GNU sed / Git Bash / BSD sed).
env_set() {
  local key="$1" val="$2"
  if grep -qE "^${key}=" "$ENV_WORKING" 2>/dev/null; then
    if sed --version >/dev/null 2>&1; then
      sed -i "s|^${key}=.*|${key}=${val}|" "$ENV_WORKING"
    else
      sed -i '' "s|^${key}=.*|${key}=${val}|" "$ENV_WORKING"
    fi
  else
    echo "${key}=${val}" >> "$ENV_WORKING"
  fi
}

# Working env: create from template if missing (so deleting .env and re-running deploy = fresh start)
if [ ! -f "$ENV_WORKING" ]; then
    echo "[deploy] No $ENV_WORKING; creating from $ENV_TEMPLATE..."
    cp "$ENV_TEMPLATE" "$ENV_WORKING"
fi

# Set WG_HOST only when it is unset/placeholder OR when running "domain mode"
# but WG_HOST is still the local default (127.0.0.1/localhost).
is_local_addr() {
  case "$1" in
    127.0.0.1|localhost) return 0 ;;
    *) return 1 ;;
  esac
}

CURRENT_WG_HOST=$(grep -E "^WG_HOST=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
PANEL_DOMAIN_VAL=$(grep -E "^PANEL_DOMAIN=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)

WG_HOST_IS_LOCAL=1
if is_local_addr "$CURRENT_WG_HOST"; then WG_HOST_IS_LOCAL=0; fi

PANEL_IS_LOCAL=1
if is_local_addr "$PANEL_DOMAIN_VAL"; then PANEL_IS_LOCAL=0; fi

NEED_WG_HOST_DETECT=0
if [ -z "$CURRENT_WG_HOST" ] || echo "$CURRENT_WG_HOST" | grep -qE "^(YOUR_SERVER_IP|YOUR_SERVER_IP_OR_HOSTNAME|CHANGE_ME)$"; then
  NEED_WG_HOST_DETECT=1
elif [ "$WG_HOST_IS_LOCAL" -eq 0 ] && [ "$PANEL_IS_LOCAL" -ne 0 ]; then
  # Domain mode: endpoint must not point to localhost.
  NEED_WG_HOST_DETECT=1
fi

if [ "$NEED_WG_HOST_DETECT" -eq 1 ]; then
  WG_HOST_NEW=$(curl -s -4 --max-time 5 ifconfig.me 2>/dev/null || true)
  if [ -n "$WG_HOST_NEW" ]; then
    env_set WG_HOST "$WG_HOST_NEW"
    echo "[deploy] WG_HOST set to ${WG_HOST_NEW}"
  else
    echo "[deploy] WARNING: Could not detect public IP; set WG_HOST in $ENV_WORKING (IP or domain)"
  fi
fi

# First-run admin: if values are unset/placeholder -> admin/admin
ADMIN_USER_VAL=$(grep -E "^ADMIN_USERNAME=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
ADMIN_PWD_VAL=$(grep -E "^ADMIN_PASSWORD=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
if [ -z "$ADMIN_USER_VAL" ] || [ "$ADMIN_USER_VAL" = "your_admin_username" ]; then
  ADMIN_USER_VAL=admin
  env_set ADMIN_USERNAME admin
fi
if [ -z "$ADMIN_PWD_VAL" ] || [ "$ADMIN_PWD_VAL" = "your_admin_password" ]; then
  ADMIN_PWD_VAL=admin
  env_set ADMIN_PASSWORD "$ADMIN_PWD_VAL"
fi

# Session secret: required for stable/auth-safe sessions; generate if missing.
SESSION_SECRET_VAL=$(grep -E "^SESSION_SECRET=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
if [ -z "$SESSION_SECRET_VAL" ] || [ "$SESSION_SECRET_VAL" = "change-me-in-production" ]; then
  if command -v openssl >/dev/null 2>&1; then
    SESSION_SECRET_VAL=$(openssl rand -base64 32)
  else
    SESSION_SECRET_VAL=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
  fi
  env_set SESSION_SECRET "$SESSION_SECRET_VAL"
  echo "[deploy] Generated SESSION_SECRET (saved in $ENV_WORKING)"
fi

# Amnezia DNS: if WG_DEFAULT_DNS is unset, set it to VPN gateway so dnsmasq starts and clients use gateway as DNS.
WG_ADDR=$(grep -E "^WG_DEFAULT_ADDRESS=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
WG_ADDR=${WG_ADDR:-10.8.0.x}
WG_GW="${WG_ADDR%x}1"
CURRENT_DNS=$(grep -E "^WG_DEFAULT_DNS=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
if [ -z "$CURRENT_DNS" ]; then
  env_set WG_DEFAULT_DNS "$WG_GW"
  echo "[deploy] WG_DEFAULT_DNS set to ${WG_GW} (Amnezia DNS enabled)"
fi

# HTTPS: self-signed (no certbot) for empty / 127.0.0.1 / localhost / plain IPv4 (no ACME for IP).
# Let's Encrypt + certbot when PANEL_DOMAIN is a DNS name and CERTBOT_EMAIL is set.
is_panel_local() {
  local p
  p=$(echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  case "$p" in
    ""|127.0.0.1|localhost) return 0 ;;
  esac
  if echo "$p" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    return 0
  fi
  return 1
}

is_valid_certbot_email() {
  local e
  e=$(echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [ -n "$e" ] || return 1
  case "$e" in
    CHANGE_ME|your_email@example.com) return 1 ;;
    *) return 0 ;;
  esac
}

PANEL_FOR_TLS=$(grep -E "^PANEL_DOMAIN=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
CERTBOT_EMAIL_FOR_TLS=$(grep -E "^CERTBOT_EMAIL=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)

if is_panel_local "$PANEL_FOR_TLS"; then
  COMPOSE_TLS_ARGS=()
  echo "[deploy] HTTPS: self-signed (certbot service not started)"
elif ! is_valid_certbot_email "$CERTBOT_EMAIL_FOR_TLS"; then
  echo "[deploy] ERROR: PANEL_DOMAIN is a DNS name (not localhost/IPv4). Set CERTBOT_EMAIL in $ENV_WORKING for Let's Encrypt (a real mailbox you control)."
  exit 1
else
  COMPOSE_TLS_ARGS=(--profile letsencrypt)
  echo "[deploy] HTTPS: Let's Encrypt (certbot profile enabled)"
fi

# Build and start — retry on transient BuildKit/snapshot errors (common on busy hosts).
echo "[deploy] Building and starting..."
compose_ok=0
for i in 1 2 3; do
  if docker compose "${COMPOSE_TLS_ARGS[@]}" up -d --build --remove-orphans; then
    compose_ok=1
    break
  fi
  if [ "$i" -lt 3 ]; then
    echo "[deploy] compose up --build failed (attempt $i/3); pruning builder cache and retrying in 5s..." >&2
    docker builder prune -f 2>/dev/null || true
    sleep 5
  fi
done
if [ "$compose_ok" -ne 1 ]; then
  echo "[deploy] ERROR: docker compose up --build failed after 3 attempts" >&2
  exit 1
fi

PORT=$(grep -E "^PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "51821")
WG_PORT=$(grep -E "^WG_PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "51820")
PANEL_HTTPS_PORT=$(grep -E "^PANEL_HTTPS_PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "443")
PANEL_HTTP_PORT=$(grep -E "^PANEL_HTTP_PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "80")
WG_HOST=$(grep -E "^WG_HOST=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2 || echo "localhost")
PANEL_DOMAIN=$(grep -E "^PANEL_DOMAIN=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || echo "")
ADMIN_USER=$(grep -E "^ADMIN_USERNAME=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || echo "admin")
ADMIN_PWD=$(grep -E "^ADMIN_PASSWORD=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || echo "")
PANEL_DOMAIN_PRINT="${PANEL_DOMAIN:-$WG_HOST}"
HTTPS_SUFFIX=""
if [ "$PANEL_HTTPS_PORT" != "443" ]; then
  HTTPS_SUFFIX=":${PANEL_HTTPS_PORT}"
fi
echo "[deploy] Done. Panel (HTTPS): https://${PANEL_DOMAIN_PRINT}${HTTPS_SUFFIX}"
if [ "$PANEL_HTTP_PORT" != "80" ]; then
  echo "[deploy] Note: HTTP (redirect/ACME) is on host TCP port ${PANEL_HTTP_PORT} — allow it in firewall; Let's Encrypt HTTP-01 uses this mapping to container port 80."
fi
echo "[deploy] Admin login: ${ADMIN_USER}"
echo "[deploy] Admin password: ${ADMIN_PWD}"
echo "[deploy] VPN: ${WG_HOST}:${WG_PORT} (UDP). DNS: WG_DEFAULT_DNS in $ENV_WORKING (gateway = Amnezia DNS)."
