#!/bin/sh
# Substitute PANEL_DOMAIN and PANEL_PORT, ensure SSL cert exists (self-signed if not), then start nginx.
set -e
CONF_DIR="${CONF_DIR:-/etc/nginx/conf.d}"
TEMPLATE="${TEMPLATE:-/etc/nginx/conf.d/panel.conf.template}"
OUTPUT="${CONF_DIR}/panel.conf"
LE_LIVE="/etc/letsencrypt/live/${PANEL_DOMAIN}"
CERTBOT_CONF="/etc/letsencrypt"

# Prefer explicit PANEL_DOMAIN. If it's not provided, fall back to WG_HOST so
# self-signed cert CN matches the address users are connecting to.
export PANEL_DOMAIN="${PANEL_DOMAIN:-${WG_HOST:-panel.ai-qwerty.ru}}"
export PANEL_PORT="${PANEL_PORT:-51821}"

rm -f "${CONF_DIR}/default.conf"
envsubst '${PANEL_DOMAIN} ${PANEL_PORT}' < "$TEMPLATE" > "$OUTPUT"

# If Let's Encrypt cert does not exist, create a self-signed cert so nginx can start. Certbot replaces it later; do not overwrite existing cert.
if [ ! -f "${LE_LIVE}/fullchain.pem" ]; then
    mkdir -p "${CERTBOT_CONF}/live/${PANEL_DOMAIN}"
    # For local HTTPS (127.0.0.1 / localhost) generate cert with SAN so browsers don't reject it.
    if [ "${PANEL_DOMAIN}" = "127.0.0.1" ] || [ "${PANEL_DOMAIN}" = "localhost" ]; then
        cat > /tmp/openssl-san.cnf <<EOF
[req]
distinguished_name=req_distinguished_name
x509_extensions=v3_req
prompt=no

[req_distinguished_name]
CN=${PANEL_DOMAIN}

[v3_req]
subjectAltName=@alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
EOF
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "${LE_LIVE}/privkey.pem" \
            -out "${LE_LIVE}/fullchain.pem" \
            -config /tmp/openssl-san.cnf -extensions v3_req
    else
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "${LE_LIVE}/privkey.pem" \
            -out "${LE_LIVE}/fullchain.pem" \
            -subj "/CN=${PANEL_DOMAIN}"
    fi
fi

exec nginx -g "daemon off;"
