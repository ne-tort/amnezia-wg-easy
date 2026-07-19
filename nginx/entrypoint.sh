#!/bin/sh
# SSL + nginx: profile entry (panel / panel+subpath) or exit (HTTPS reverse proxy only).
# Host :443 = stream ssl_preread demux (Xray/MTProto); panel TLS listens on :8443.
set -e
CONF_DIR="${CONF_DIR:-/etc/nginx/conf.d}"
STREAM_DIR="${STREAM_DIR:-/etc/nginx/stream.d}"
CERTBOT_CONF="/etc/letsencrypt"
OUTPUT="${CONF_DIR}/panel.conf"
AWG_NGINX="/opt/amnezia/awg/nginx"

export PANEL_DOMAIN="${PANEL_DOMAIN:-${WG_HOST:-localhost}}"
export PANEL_PORT="${PANEL_PORT:-51821}"
export PANEL_HTTPS_PORT="${PANEL_HTTPS_PORT:-10123}"
# Host-facing HTTPS port in redirects (container listens on 8443; publish may be 10123).
if [ "$PANEL_HTTPS_PORT" = "443" ]; then
  export PANEL_HTTPS_REDIRECT_HOST='$host'
else
  export PANEL_HTTPS_REDIRECT_HOST="\$host:${PANEL_HTTPS_PORT}"
fi
export WEBUI_PUBLIC_PREFIX="${WEBUI_PUBLIC_PREFIX:-/panel}"
export SUB_PUBLIC_PREFIX="${SUB_PUBLIC_PREFIX:-/sub}"
export NGINX_ROOT_BEHAVIOR="${NGINX_ROOT_BEHAVIOR:-mirror}"
export NGINX_MIRROR_HOST="${NGINX_MIRROR_HOST:-}"
export NGINX_LOCAL_URL="${NGINX_LOCAL_URL:-}"
export NGINX_CONFIG_PROFILE="${NGINX_CONFIG_PROFILE:-entry}"

# Normalize prefixes to start with /
case "$WEBUI_PUBLIC_PREFIX" in
  /*) ;;
  "") WEBUI_PUBLIC_PREFIX="/panel" ;;
  *) WEBUI_PUBLIC_PREFIX="/${WEBUI_PUBLIC_PREFIX}" ;;
esac
case "$SUB_PUBLIC_PREFIX" in
  /*) ;;
  "") SUB_PUBLIC_PREFIX="/sub" ;;
  *) SUB_PUBLIC_PREFIX="/${SUB_PUBLIC_PREFIX}" ;;
esac
# Strip trailing slash except root
WEBUI_PUBLIC_PREFIX="${WEBUI_PUBLIC_PREFIX%/}"
SUB_PUBLIC_PREFIX="${SUB_PUBLIC_PREFIX%/}"
[ -z "$WEBUI_PUBLIC_PREFIX" ] && WEBUI_PUBLIC_PREFIX="/panel"
[ -z "$SUB_PUBLIC_PREFIX" ] && SUB_PUBLIC_PREFIX="/sub"
export WEBUI_PUBLIC_PREFIX SUB_PUBLIC_PREFIX

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
        return 302 https://${PANEL_HTTPS_REDIRECT_HOST}${pf}/;
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
mkdir -p "${STREAM_DIR}" "${AWG_NGINX}"

# Stream module is dynamic on nginx:alpine; skip load_module when built-in.
if [ -f /usr/lib/nginx/modules/ngx_stream_module.so ]; then
  if ! grep -q 'ngx_stream_module' /etc/nginx/nginx.conf; then
    sed -i '1iload_module /usr/lib/nginx/modules/ngx_stream_module.so;' /etc/nginx/nginx.conf
  fi
fi

# Stream demux configs from volume (portPlan writes demux-*.conf). Fallback empty.
mkdir -p "${AWG_NGINX}/stream"
rm -f "${STREAM_DIR}"/*.conf
if ls "${AWG_NGINX}/stream"/*.conf >/dev/null 2>&1; then
  cp "${AWG_NGINX}/stream"/*.conf "${STREAM_DIR}/"
else
  printf '%s\n' '# no demux yet' > "${STREAM_DIR}/empty.conf"
fi

inject_root() {
  _template="$1"
  _rootfile="$2"
  envsubst '${PANEL_DOMAIN} ${PANEL_PORT} ${WEBUI_PUBLIC_PREFIX} ${SUB_PUBLIC_PREFIX} ${PANEL_HTTPS_PORT} ${PANEL_HTTPS_REDIRECT_HOST}' < "$_template" | awk -v rf="$_rootfile" '
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
        return 301 https://${PANEL_HTTPS_REDIRECT_HOST}\$request_uri;
    }
}
server {
    listen 8443 ssl;
    server_name ${PANEL_DOMAIN};
    ssl_certificate /etc/letsencrypt/live/${PANEL_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${PANEL_DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
EOF
  printf '%s\n' "$ROOT_BLOCK" >>"$OUTPUT"
  printf '%s\n' "}" >>"$OUTPUT"
elif [ "$WEBUI_PUBLIC_PREFIX" = "/" ] || [ -z "$WEBUI_PUBLIC_PREFIX" ]; then
  # Explicit legacy: panel on entire site root
  TEMPLATE="/etc/nginx/conf.d/panel-legacy.conf.template"
  envsubst '${PANEL_DOMAIN} ${PANEL_PORT} ${PANEL_HTTPS_PORT} ${PANEL_HTTPS_REDIRECT_HOST}' < "$TEMPLATE" >"$OUTPUT"
else
  TEMPLATE="/etc/nginx/conf.d/panel-subpath.conf.template"
  case "$NGINX_ROOT_BEHAVIOR" in
    mirror) ROOT_BLOCK=$(root_block_entry_mirror) ;;
    local) ROOT_BLOCK=$(root_block_entry_local) ;;
    redirect) ROOT_BLOCK=$(root_block_entry_redirect) ;;
    *) ROOT_BLOCK=$(root_block_entry_mirror) ;;
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
