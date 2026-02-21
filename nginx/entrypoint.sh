#!/bin/sh
# Substitute PANEL_DOMAIN and PANEL_PORT, ensure SSL cert exists (self-signed if not), then start nginx.
set -e
CONF_DIR="${CONF_DIR:-/etc/nginx/conf.d}"
TEMPLATE="${TEMPLATE:-/etc/nginx/conf.d/panel.conf.template}"
OUTPUT="${CONF_DIR}/panel.conf"
LE_LIVE="/etc/letsencrypt/live/${PANEL_DOMAIN}"
CERTBOT_CONF="/etc/letsencrypt"

export PANEL_DOMAIN="${PANEL_DOMAIN:-panel.ai-qwerty.ru}"
export PANEL_PORT="${PANEL_PORT:-51821}"

rm -f "${CONF_DIR}/default.conf"
envsubst '${PANEL_DOMAIN} ${PANEL_PORT}' < "$TEMPLATE" > "$OUTPUT"

# If Let's Encrypt cert does not exist, create a self-signed cert so nginx can start. Certbot replaces it later; do not overwrite existing cert.
if [ ! -f "${LE_LIVE}/fullchain.pem" ]; then
    mkdir -p "${CERTBOT_CONF}/live/${PANEL_DOMAIN}"
    openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "${LE_LIVE}/privkey.pem" \
        -out "${LE_LIVE}/fullchain.pem" \
        -subj "/CN=${PANEL_DOMAIN}"
fi

exec nginx -g "daemon off;"
