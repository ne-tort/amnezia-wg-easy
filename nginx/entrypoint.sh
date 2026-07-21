#!/bin/sh
# SSL + nginx: profile entry (panel / panel+subpath) or exit (HTTPS reverse proxy only).
# Host :443 = stream ssl_preread demux (Xray + shared-port sidecars); panel TLS listens on :8443.
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
export NGINX_MIRROR_HTTPS_PORT="${NGINX_MIRROR_HTTPS_PORT:-}"
export NGINX_LOCAL_URL="${NGINX_LOCAL_URL:-}"
export NGINX_CONFIG_PROFILE="${NGINX_CONFIG_PROFILE:-entry}"
MIRROR_TLS_LISTEN=8444
export MIRROR_TLS_LISTEN

mirror_ports_split() {
  [ -n "$NGINX_MIRROR_HTTPS_PORT" ] \
    && [ "$NGINX_MIRROR_HTTPS_PORT" != "$PANEL_HTTPS_PORT" ]
}

# Host-facing mirror port in redirects when mirror is on a dedicated publish port.
if mirror_ports_split; then
  if [ "$NGINX_MIRROR_HTTPS_PORT" = "443" ]; then
    export MIRROR_HTTPS_REDIRECT_HOST='$host'
  else
    export MIRROR_HTTPS_REDIRECT_HOST="\$host:${NGINX_MIRROR_HTTPS_PORT}"
  fi
else
  export MIRROR_HTTPS_REDIRECT_HOST="$PANEL_HTTPS_REDIRECT_HOST"
fi

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

# Host variants for proxy_redirect / cookie rewrite (www.example.com ↔ example.com).
mirror_host_variants() {
  h="${1:-}"
  [ -z "$h" ] && return 0
  printf '%s\n' "$h"
  case "$h" in
    www.*)
      printf '%s\n' "${h#www.}"
      ;;
    *)
      printf '%s\n' "www.${h}"
      ;;
  esac
}

# Shared reverse-proxy stanzas for root mirror (entry + exit profiles).
mirror_proxy_directives() {
  mhost="${1:-}"
  cat <<EOF
        resolver 8.8.8.8 valid=300s ipv6=off;
        set \$mhost "${mhost}";
        proxy_pass https://\$mhost;
        proxy_http_version 1.1;
        proxy_ssl_server_name on;
        proxy_ssl_name \$mhost;
        proxy_set_header Host \$mhost;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 15s;
        proxy_read_timeout 60s;
        # Keep the browser on our host: upstream often 301 www→apex (e.g. www.czc.cz → czc.cz).
EOF
  # shellcheck disable=SC2039
  while IFS= read -r vh; do
    [ -z "$vh" ] && continue
    cat <<EOF
        proxy_redirect https://${vh}/ /;
        proxy_redirect https://${vh} /;
        proxy_redirect http://${vh}/ /;
        proxy_redirect http://${vh} /;
        proxy_cookie_domain ${vh} \$host;
        proxy_cookie_domain .${vh#www.} \$host;
EOF
  done <<EOF
$(mirror_host_variants "$mhost" | awk 'NF && !seen[$0]++')
EOF
}

root_block_exit_mirror() {
  if [ -z "$NGINX_MIRROR_HOST" ]; then
    root_block_exit_placeholder
    return
  fi
  cat <<EOF
    location / {
$(mirror_proxy_directives "$NGINX_MIRROR_HOST")
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

# Panel path is a secret: never redirect strangers to WEBUI_PUBLIC_PREFIX.
# Unknown paths → close without response (nginx 444).
root_block_entry_stealth() {
  cat <<EOF
    location / {
        return 444;
    }
EOF
}

# Deprecated alias — old "redirect to /panel" leaked the path.
root_block_entry_redirect() {
  root_block_entry_stealth
}

root_block_entry_mirror() {
  if [ -z "$NGINX_MIRROR_HOST" ]; then
    root_block_entry_stealth
    return
  fi
  cat <<EOF
    location / {
$(mirror_proxy_directives "$NGINX_MIRROR_HOST")
    }
EOF
}

root_block_entry_local() {
  if [ -z "$NGINX_LOCAL_URL" ]; then
    root_block_entry_stealth
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

# Dedicated mirror listener (host NGINX_MIRROR_HTTPS_PORT → container :8444).
append_mirror_server_block() {
  [ -n "$NGINX_MIRROR_HOST" ] || return 0
  mirror_ports_split || return 0
  cat >>"$OUTPUT" <<EOF
server {
    listen ${MIRROR_TLS_LISTEN} ssl;
    server_name ${PANEL_DOMAIN};
    ssl_certificate /etc/letsencrypt/live/${PANEL_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${PANEL_DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    port_in_redirect off;
    absolute_redirect off;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
$(mirror_proxy_directives "$NGINX_MIRROR_HOST")
    }
}
EOF
}

pick_entry_root_block() {
  # Split ports: panel listener must not expose/mirror — only exact prefix/sub.
  # Shared port: everything except prefix/sub is the stub (mirror) or stealth.
  if mirror_ports_split; then
    root_block_entry_stealth
    return
  fi
  case "$NGINX_ROOT_BEHAVIOR" in
    mirror) root_block_entry_mirror ;;
    local) root_block_entry_local ;;
    redirect|stealth) root_block_entry_stealth ;;
    *) root_block_entry_mirror ;;
  esac
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
    listen 80 default_server;
    server_name _;
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
  append_mirror_server_block
elif [ "$WEBUI_PUBLIC_PREFIX" = "/" ] || [ -z "$WEBUI_PUBLIC_PREFIX" ]; then
  # Explicit legacy: panel on entire site root
  TEMPLATE="/etc/nginx/conf.d/panel-legacy.conf.template"
  envsubst '${PANEL_DOMAIN} ${PANEL_PORT} ${PANEL_HTTPS_PORT} ${PANEL_HTTPS_REDIRECT_HOST}' < "$TEMPLATE" >"$OUTPUT"
  append_mirror_server_block
else
  TEMPLATE="/etc/nginx/conf.d/panel-subpath.conf.template"
  ROOT_BLOCK=$(pick_entry_root_block)
  RF=$(mktemp)
  printf '%s\n' "$ROOT_BLOCK" >"$RF"
  inject_root "$TEMPLATE" "$RF" >"$OUTPUT"
  rm -f "$RF"
  append_mirror_server_block
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
