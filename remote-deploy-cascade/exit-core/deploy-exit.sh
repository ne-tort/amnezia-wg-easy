#!/bin/sh
# Bring up exit stack; enable certbot profile when PANEL_DOMAIN is a public DNS name and CERTBOT_EMAIL is set.
set -e
cd "$(dirname "$0")"
ENV="${ENV:-.env}"
if [ ! -f "$ENV" ]; then
  echo "ERROR: $ENV missing (install.py should create it)." >&2
  exit 1
fi

is_panel_local() {
  p=$(echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  case "$p" in
    ""|127.0.0.1|localhost) return 0 ;;
  esac
  echo "$p" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && return 0
  return 1
}

is_valid_certbot_email() {
  e=$(echo "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [ -n "$e" ] || return 1
  case "$e" in
    CHANGE_ME|your_email@example.com) return 1 ;;
    *) return 0 ;;
  esac
}

PANEL_FOR_TLS=$(grep -E "^PANEL_DOMAIN=" "$ENV" 2>/dev/null | cut -d= -f2- || true)
CERTBOT_EMAIL_FOR_TLS=$(grep -E "^CERTBOT_EMAIL=" "$ENV" 2>/dev/null | cut -d= -f2- || true)

if is_panel_local "$PANEL_FOR_TLS"; then
  COMPOSE_TLS_ARGS=""
  echo "[deploy-exit] HTTPS: self-signed (certbot profile off)"
elif ! is_valid_certbot_email "$CERTBOT_EMAIL_FOR_TLS"; then
  echo "[deploy-exit] ERROR: set CERTBOT_EMAIL in $ENV for Let's Encrypt when PANEL_DOMAIN is a DNS name." >&2
  exit 1
else
  COMPOSE_TLS_ARGS="--profile letsencrypt"
  echo "[deploy-exit] HTTPS: Let's Encrypt (certbot profile on)"
fi

compose_ok=0
for i in 1 2 3; do
  ok=0
  if [ -n "$COMPOSE_TLS_ARGS" ]; then
    docker compose -f docker-compose.yml --profile letsencrypt up -d --build --remove-orphans && ok=1
  else
    docker compose -f docker-compose.yml up -d --build --remove-orphans && ok=1
  fi
  if [ "$ok" -eq 1 ]; then
    compose_ok=1
    break
  fi
  if [ "$i" -lt 3 ]; then
    echo "[deploy-exit] compose up failed (attempt $i/3); prune and retry..." >&2
    docker builder prune -f 2>/dev/null || true
    sleep 5
  fi
done
if [ "$compose_ok" -ne 1 ]; then
  echo "[deploy-exit] ERROR: docker compose up failed after 3 attempts" >&2
  exit 1
fi

echo "[deploy-exit] Done."
