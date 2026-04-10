#!/bin/sh
# SSL + nginx: profile entry (panel / panel+subpath) or exit (HTTPS reverse proxy only). UDP stays on other services.
set -e
CONF_DIR="${CONF_DIR:-/etc/nginx/conf.d}"
CERTBOT_CONF="/etc/letsencrypt"
OUTPUT="${CONF_DIR}/panel.conf"

export PANEL_DOMAIN="${PANEL_DOMAIN:-${WG_HOST:-localhost}}"
export PANEL_PORT="${PANEL_PORT:-51821}"
export WEBUI_PUBLIC_PREFIX="${WEBUI_PUBLIC_PREFIX:-}"
export NGINX_ROOT_BEHAVIOR="${NGINX_ROOT_BEHAVIOR:-redirect}"
export NGINX_MIRROR_HOST="${NGINX_MIRROR_HOST:-}"
export NGINX_LOCAL_URL="${NGINX_LOCAL_URL:-}"
export NGINX_CONFIG_PROFILE="${NGINX_CONFIG_PROFILE:-entry}"

root_block_exit_placeholder() {
  printf '%s\n' '    location / {'
  printf '%s\n' '        default_type text/plain;'
  printf '%s\n' '        return 503 "Configure NGINX_ROOT_BEHAVIOR and NGINX_MIRROR_HOST or NGINX_LOCAL_URL in .env\\n";'
  printf '%s\n' '    }'
}

root_block_exit_mirror() {
  if [ -z "$NGINX_MIRROR_HOST" ]; then
    root_block_exit_placeholder
    return
  fi
  cat <<EOF
    location / {
        resolver 8.8.8.8 valid=300s ipv6=off;
        set \$mhost "${NGINX_MIRROR_HOST}";
        proxy_pass https://\$mhost;
        proxy_http_version 1.1;
        proxy_ssl_server_name on;
        proxy_ssl_name \$mhost;
        proxy_set_header Host \$mhost;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 15s;
        proxy_read_timeout 60s;
    }
EOF
}

root_block_exit_local() {
  if [ -z "$NGINX_LOCAL_URL" ]; then
    root_block_exit_placeholder
    return
  fi
  cat <<EOF
    location / {
        proxy_pass ${NGINX_LOCAL_URL};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
EOF
}

root_block_entry_redirect() {
  pf="${WEBUI_PUBLIC_PREFIX}"
  cat <<EOF
    location = / {
        return 302 https://\$host${pf}/;
    }
EOF
}

root_block_entry_mirror() {
  if [ -z "$NGINX_MIRROR_HOST" ]; then
    root_block_entry_redirect
    return
  fi
  cat <<EOF
    location / {
        resolver 8.8.8.8 valid=300s ipv6=off;
        set \$mhost "${NGINX_MIRROR_HOST}";
        proxy_pass https://\$mhost;
        proxy_http_version 1.1;
        proxy_ssl_server_name on;
        proxy_ssl_name \$mhost;
        proxy_set_header Host \$mhost;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 15s;
        proxy_read_timeout 60s;
    }
EOF
}

root_block_entry_local() {
  if [ -z "$NGINX_LOCAL_URL" ]; then
    root_block_entry_redirect
    return
  fi
  cat <<EOF
    location / {
        proxy_pass ${NGINX_LOCAL_URL};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
EOF
}

LE_LIVE="/etc/letsencrypt/live/${PANEL_DOMAIN}"
rm -f "${CONF_DIR}/default.conf"

inject_root() {
  _template="$1"
  _rootfile="$2"
  envsubst '${PANEL_DOMAIN} ${PANEL_PORT} ${WEBUI_PUBLIC_PREFIX}' < "$_template" | awk -v rf="$_rootfile" '
    /^[[:space:]]*__ROOT_BLOCK__[[:space:]]*$/ { while ((getline line < rf) > 0) print line; next }
    { print }
  '
}

if [ "$NGINX_CONFIG_PROFILE" = "exit" ]; then
  case "$NGINX_ROOT_BEHAVIOR" in
    mirror) ROOT_BLOCK=$(root_block_exit_mirror) ;;
    local) ROOT_BLOCK=$(root_block_exit_local) ;;
    *) ROOT_BLOCK=$(root_block_exit_placeholder) ;;
  esac
  cat >"$OUTPUT" <<EOF
server {
    listen 80;
    server_name ${PANEL_DOMAIN};
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
server {
    listen 443 ssl;
    server_name ${PANEL_DOMAIN};
    ssl_certificate /etc/letsencrypt/live/${PANEL_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${PANEL_DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
EOF
  printf '%s\n' "$ROOT_BLOCK" >>"$OUTPUT"
  printf '%s\n' "}" >>"$OUTPUT"
elif [ -z "$WEBUI_PUBLIC_PREFIX" ]; then
  TEMPLATE="/etc/nginx/conf.d/panel-legacy.conf.template"
  envsubst '${PANEL_DOMAIN} ${PANEL_PORT}' < "$TEMPLATE" >"$OUTPUT"
else
  TEMPLATE="/etc/nginx/conf.d/panel-subpath.conf.template"
  case "$NGINX_ROOT_BEHAVIOR" in
    mirror) ROOT_BLOCK=$(root_block_entry_mirror) ;;
    local) ROOT_BLOCK=$(root_block_entry_local) ;;
    redirect) ROOT_BLOCK=$(root_block_entry_redirect) ;;
    *) ROOT_BLOCK=$(root_block_entry_redirect) ;;
  esac
  RF=$(mktemp)
  printf '%s\n' "$ROOT_BLOCK" >"$RF"
  inject_root "$TEMPLATE" "$RF" >"$OUTPUT"
  rm -f "$RF"
fi

if [ ! -f "${LE_LIVE}/fullchain.pem" ]; then
    mkdir -p "${CERTBOT_CONF}/live/${PANEL_DOMAIN}"
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
