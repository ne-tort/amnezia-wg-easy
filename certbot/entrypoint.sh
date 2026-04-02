#!/bin/sh
# Issue cert on first run from PANEL_DOMAIN and CERTBOT_EMAIL; then renew loop with nginx reload.
# * Prefer Let's Encrypt: if a cert exists but is self-signed (created by nginx), replace it.
set -e
PANEL_DOMAIN="${PANEL_DOMAIN:-}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
LIVE_DIR="/etc/letsencrypt/live/${PANEL_DOMAIN}"
ARCHIVE_DIR="/etc/letsencrypt/archive/${PANEL_DOMAIN}"
LIVE_CERT="${LIVE_DIR}/fullchain.pem"
RELOAD_CMD="docker exec nginx nginx -s reload"
MAX_ATTEMPTS=30

# Returns 0 if existing cert is from Let's Encrypt (do not overwrite).
is_letsencrypt_cert() {
  [ -f "$LIVE_CERT" ] || return 1
  iss=$(openssl x509 -in "$LIVE_CERT" -noout -issuer 2>/dev/null) || return 1
  case "$iss" in *"Let's Encrypt"*) return 0 ;; *) return 1 ;; esac
}

issue_first() {
  for i in $(seq 1 "$MAX_ATTEMPTS"); do
    if certbot certonly --webroot -w /var/www/certbot \
      -d "$PANEL_DOMAIN" --email "$CERTBOT_EMAIL" --agree-tos --non-interactive; then
      return 0
    fi
    [ "$i" -lt "$MAX_ATTEMPTS" ] && sleep 10
  done
  return 1
}

if [ -z "$PANEL_DOMAIN" ] || [ -z "$CERTBOT_EMAIL" ]; then
  echo "PANEL_DOMAIN and CERTBOT_EMAIL must be set. Certbot is disabled (nginx self-signed will be used until configuration is provided)."
  # Keep container running to avoid noisy restarts; do not attempt any certbot operations.
  while :; do sleep 12h; done
elif ! is_letsencrypt_cert; then
  # Remove self-signed or stale cert so certbot can create LE structure (archive + symlinks).
  rm -rf "$LIVE_DIR" "$ARCHIVE_DIR"
  if issue_first; then
    $RELOAD_CMD 2>/dev/null || true
  fi
fi

trap exit TERM
while :; do
  certbot renew --deploy-hook "$RELOAD_CMD"
  sleep 12h & wait ${!}
done
