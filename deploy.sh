#!/bin/bash
# Deploy Amnezia WG-Easy (Docker Compose).
# Usage: ./deploy.sh
#
#   .env.example — committed template
#   .env         — working copy for compose (created from template if missing)

set -e
cd "$(dirname "$0")"

# Stable compose project name so volumes match install.sh acme inject.
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-amnezia-wg-easy}"

# Target: Linux VPS with Docker Engine + Compose plugin.
# Usage: ./deploy.sh
# Do not set COMPOSE_PROJECT_NAME unless you intentionally isolate a stack.

if ! command -v docker >/dev/null 2>&1; then
  echo "[deploy] ERROR: docker not found" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "[deploy] ERROR: cannot talk to Docker daemon (is it running?)" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "[deploy] ERROR: docker compose plugin not found" >&2
  exit 1
fi

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

# Default client DNS address line (gateway). Amnezia DNS stack itself is toggled from the panel UI.
WG_ADDR=$(grep -E "^WG_DEFAULT_ADDRESS=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
WG_ADDR=${WG_ADDR:-10.8.0.x}
WG_GW="${WG_ADDR%x}1"
CURRENT_DNS=$(grep -E "^WG_DEFAULT_DNS=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
if [ -z "$CURRENT_DNS" ]; then
  env_set WG_DEFAULT_DNS "$WG_GW"
  echo "[deploy] WG_DEFAULT_DNS set to ${WG_GW}"
fi

# Amnezia DNS network + image — same as amnezia-client prepare_host / build_container
# (optional service: docker run from panel UI, not a compose service).
ensure_amnezia_dns_net() {
  if docker network ls --format '{{.Name}}' | grep -qx 'amnezia-dns-net'; then
    return 0
  fi
  # Migrate legacy compose-prefixed nets on 172.29.172.0/24 (cannot rename Docker networks).
  # Drop orphan Unbound so it is recreated on the new net by the panel (same as client reinstall).
  docker rm -f amnezia-dns 2>/dev/null || true
  while IFS= read -r old; do
    [ -n "$old" ] || continue
    [ "$old" = "amnezia-dns-net" ] && continue
    echo "[deploy] Migrating DNS network $old -> amnezia-dns-net"
    for c in $(docker network inspect -f '{{range .Containers}}{{.Name}} {{end}}' "$old" 2>/dev/null); do
      docker network disconnect -f "$old" "$c" 2>/dev/null || true
    done
    docker network rm "$old" 2>/dev/null || true
  done < <(docker network ls --format '{{.Name}}' | grep 'amnezia-dns-net' || true)
  if ! docker network ls --format '{{.Name}}' | grep -qx 'amnezia-dns-net'; then
    docker network create \
      --driver bridge \
      --subnet=172.29.172.0/24 \
      --opt com.docker.network.bridge.name=amn0 \
      amnezia-dns-net
    echo "[deploy] Created network amnezia-dns-net"
  fi
}
ensure_amnezia_dns_net

echo "[deploy] Building amnezia-dns image (client-compatible tag, container not started)..."
if ! docker build -t amnezia-dns ./amnezia-dns; then
  echo "[deploy] ERROR: amnezia-dns image build failed (required for Amnezia DNS from the panel)" >&2
  exit 1
fi
# Drop obsolete local tag from older deploys
docker rmi amnezia-dns:local 2>/dev/null || true

echo "[deploy] Building amnezia-xray image (VLESS Reality; container not started)..."
if ! docker build -t amnezia-xray ./amnezia-xray; then
  echo "[deploy] ERROR: amnezia-xray image build failed (required for Xray toggle from the panel)" >&2
  exit 1
fi

echo "[deploy] Building amnezia-mieru image (mita; container not started)..."
if ! docker build -t amnezia-mieru ./amnezia-mieru; then
  echo "[deploy] ERROR: amnezia-mieru image build failed (required for Mieru toggle from the panel)" >&2
  exit 1
fi

echo "[deploy] Building amnezia-hysteria image (Hysteria2; container not started)..."
if ! docker build -t amnezia-hysteria ./amnezia-hysteria; then
  echo "[deploy] ERROR: amnezia-hysteria image build failed (required for Hysteria toggle from the panel)" >&2
  exit 1
fi

echo "[deploy] Building amnezia-naive image (Caddy forward_proxy; container not started)..."
if ! docker build -t amnezia-naive ./amnezia-naive; then
  echo "[deploy] ERROR: amnezia-naive image build failed (required for Naive toggle from the panel)" >&2
  exit 1
fi

if ! docker network inspect amnezia-dns-net >/dev/null 2>&1; then
  echo "[deploy] ERROR: amnezia-dns-net missing after create" >&2
  exit 1
fi

# HTTPS modes (SSL_MODE in .env, written by install.sh):
#   selfsigned — nginx local cert (empty / 127.0.0.1 / localhost / plain IPv4 without acme)
#   acme       — certs already in volume certbot_conf (acme.sh domain or IP shortlived); no certbot
#   certbot    — docker certbot profile for DNS names + CERTBOT_EMAIL
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
SSL_MODE_VAL=$(grep -E "^SSL_MODE=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
SSL_MODE_VAL=$(echo "${SSL_MODE_VAL:-}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

COMPOSE_TLS_ARGS=()
case "$SSL_MODE_VAL" in
  acme)
    echo "[deploy] HTTPS: SSL_MODE=acme (certs via volume; certbot service not started)"
    ;;
  certbot)
    if ! is_valid_certbot_email "$CERTBOT_EMAIL_FOR_TLS"; then
      echo "[deploy] ERROR: SSL_MODE=certbot requires CERTBOT_EMAIL in $ENV_WORKING"
      exit 1
    fi
    COMPOSE_TLS_ARGS=(--profile letsencrypt)
    echo "[deploy] HTTPS: SSL_MODE=certbot (Let's Encrypt profile enabled)"
    ;;
  selfsigned)
    echo "[deploy] HTTPS: SSL_MODE=selfsigned (certbot service not started)"
    ;;
  *)
    if is_panel_local "$PANEL_FOR_TLS"; then
      echo "[deploy] HTTPS: self-signed (certbot service not started)"
    elif ! is_valid_certbot_email "$CERTBOT_EMAIL_FOR_TLS"; then
      echo "[deploy] ERROR: PANEL_DOMAIN is a DNS name (not localhost/IPv4). Set CERTBOT_EMAIL in $ENV_WORKING for Let's Encrypt, or SSL_MODE=acme after install.sh."
      exit 1
    else
      COMPOSE_TLS_ARGS=(--profile letsencrypt)
      echo "[deploy] HTTPS: Let's Encrypt (certbot profile enabled)"
    fi
    ;;
esac

# Build and start — retry on transient BuildKit/snapshot errors (common on busy hosts).
echo "[deploy] Building and starting..."

# Ensure ports override exists (panel HTTPS; demux ports added by portPlan later).
PORTS_FILE="./docker-compose.ports.yml"
if [ ! -f "$PORTS_FILE" ]; then
  cat >"$PORTS_FILE" <<'EOF'
services:
  nginx:
    ports:
      - "${PANEL_HTTPS_PORT:-10123}:8443"
EOF
fi
COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.ports.yml)

# certbot_* are external (created by install acme inject / here) — silence Compose warn.
ensure_compose_volumes() {
  local v
  for v in \
    "${COMPOSE_PROJECT_NAME}_certbot_conf" \
    "${COMPOSE_PROJECT_NAME}_certbot_www"
  do
    if ! docker volume inspect "$v" >/dev/null 2>&1; then
      echo "[deploy] Creating volume ${v}"
      docker volume create "$v" >/dev/null || true
    fi
  done
}
ensure_compose_volumes

read_env_port() {
  local key="$1" fallback="$2"
  local v
  v=$(grep -E "^${key}=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- | tr -d '\r' || true)
  echo "${v:-$fallback}"
}

data_volume_name() {
  docker volume ls -q 2>/dev/null | grep -E 'amnezia-wg-easy_amnezia-wg-data|amnezia-wg-data' | head -1 || true
}

sync_ports_file_from_volume() {
  local vol vol_file
  vol=$(data_volume_name)
  [[ -n "$vol" ]] || return 0
  vol_file="/var/lib/docker/volumes/${vol}/_data/nginx/docker-compose.ports.yml"
  [[ -f "$vol_file" ]] || return 0
  grep -q 'generated by amnezia-wg-easy portPlan' "$vol_file" 2>/dev/null || return 0
  if ! cmp -s "$vol_file" "$PORTS_FILE" 2>/dev/null; then
    echo "[deploy] Syncing docker-compose.ports.yml from panel volume (portPlan)"
    cp "$vol_file" "$PORTS_FILE"
  fi
}

has_demux_on_volume() {
  local port="$1" vol
  vol=$(data_volume_name)
  [[ -n "$vol" ]] || return 1
  [[ -f "/var/lib/docker/volumes/${vol}/_data/nginx/stream/demux-${port}.conf" ]] && return 0
  [[ -f "/var/lib/docker/volumes/${vol}/_data/nginx/stream-sni-${port}.map" ]] && return 0
  return 1
}

rewrite_compose_ports_minimal() {
  local panel mirror
  panel=$(read_env_port PANEL_HTTPS_PORT 10123)
  mirror=$(read_env_port NGINX_MIRROR_HTTPS_PORT "")
  {
    echo '# generated by deploy.sh — repaired nginx publish set'
    echo 'services:'
    echo '  nginx:'
    echo '    ports:'
    if has_demux_on_volume "$panel"; then
      echo "      - \"${panel}:${panel}\""
    else
      echo '      - "${PANEL_HTTPS_PORT:-10123}:8443"'
    fi
    if [[ -n "$mirror" && "$mirror" != "$panel" ]]; then
      echo "      - \"${mirror}:8444\""
    fi
  } >"$PORTS_FILE"
  echo "[deploy] Rewrote docker-compose.ports.yml (removed duplicate/conflicting host binds)"
}

nginx_compose_host_ports() {
  if command -v python3 >/dev/null 2>&1; then
    docker compose "${COMPOSE_FILES[@]}" config --format json 2>/dev/null \
      | python3 -c "
import json, sys
try:
    c = json.load(sys.stdin)
except Exception:
    sys.exit(0)
ports = (c.get('services') or {}).get('nginx', {}).get('ports') or []
out = set()
for p in ports:
    if isinstance(p, dict):
        pub = p.get('published')
        if pub is not None:
            out.add(str(pub))
    elif isinstance(p, str) and ':' in p:
        out.add(p.split(':', 1)[0])
for h in sorted(out, key=lambda x: int(x) if str(x).isdigit() else str(x)):
    print(h)
" 2>/dev/null || true
    return 0
  fi
  # Fallback: expand common env form and list host ports from the override file.
  local panel line host
  panel=$(read_env_port PANEL_HTTPS_PORT 10123)
  while IFS= read -r line; do
    [[ "$line" =~ \"([^\"]+)\" ]] || continue
    host="${BASH_REMATCH[1]%%:*}"
    host="${host//\$\{PANEL_HTTPS_PORT:-10123\}/$panel}"
    host="${host//\$\{PANEL_HTTPS_PORT\}/$panel}"
    echo "$host"
  done < <(grep -E '^\s+- "' "$PORTS_FILE" 2>/dev/null || true)
}

compose_ports_have_duplicate_hosts() {
  local hosts dups
  hosts=$(nginx_compose_host_ports | sort | uniq -d)
  [[ -n "$hosts" ]]
}

sidecar_publishes_port() {
  local c="$1" port="$2"
  docker inspect -f '{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}' "$c" 2>/dev/null \
    | grep -qE "(^| )${port}/tcp"
}

release_sidecars_blocking_ports() {
  local port c
  for port in "$@"; do
    [[ -n "$port" ]] || continue
    for c in amnezia-xray amnezia-naive amnezia-mieru; do
      if docker inspect "$c" >/dev/null 2>&1 && sidecar_publishes_port "$c" "$port"; then
        echo "[deploy] Stopping ${c} (held host TCP ${port}; panel will reconcile after start)"
        docker rm -f "$c" >/dev/null 2>&1 || true
      fi
    done
  done
}

prepare_nginx_compose_ports() {
  sync_ports_file_from_volume
  if compose_ports_have_duplicate_hosts; then
    echo "[deploy] WARNING: duplicate nginx host port in docker-compose.ports.yml"
    sync_ports_file_from_volume
    if compose_ports_have_duplicate_hosts; then
      rewrite_compose_ports_minimal
    fi
  fi
}

prepare_nginx_host_ports() {
  prepare_nginx_compose_ports
  local port
  while IFS= read -r port; do
    release_sidecars_blocking_ports "$port"
  done < <(nginx_compose_host_ports)
}

prepare_nginx_host_ports

# portPlan may recreate nginx via `docker run --name nginx` (no compose labels).
# That orphan blocks `compose up` with "name already in use".
clear_nginx_name_conflict() {
  if ! docker inspect nginx >/dev/null 2>&1; then
    return 0
  fi
  local labels
  labels=$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' nginx 2>/dev/null || true)
  if [[ -z "$labels" || "$labels" != "$COMPOSE_PROJECT_NAME" ]]; then
    echo "[deploy] Removing orphan nginx container (not owned by compose project ${COMPOSE_PROJECT_NAME})"
    docker rm -f nginx >/dev/null 2>&1 || true
    return 0
  fi
  # Even labeled nginx can block recreate after a failed portPlan docker-run race.
  local state
  state=$(docker inspect -f '{{.State.Status}}' nginx 2>/dev/null || true)
  if [[ "$state" != "running" && "$state" != "restarting" ]]; then
    echo "[deploy] Removing non-running nginx (state=${state:-unknown}) before compose up"
    docker rm -f nginx >/dev/null 2>&1 || true
  fi
}

compose_ok=0
compose_err=""
for i in 1 2 3; do
  clear_nginx_name_conflict
  compose_err=$(docker compose "${COMPOSE_FILES[@]}" "${COMPOSE_TLS_ARGS[@]}" up -d --build --remove-orphans 2>&1) && {
    compose_ok=1
    printf '%s\n' "$compose_err"
    break
  }
  printf '%s\n' "$compose_err" >&2
  if echo "$compose_err" | grep -qiE 'already in use|Conflict|name "/?nginx"'; then
    echo "[deploy] nginx name conflict — force removing and retrying" >&2
    docker rm -f nginx >/dev/null 2>&1 || true
  fi
  if echo "$compose_err" | grep -qiE 'port is already allocated|address already in use'; then
    echo "[deploy] Host port conflict — repairing nginx ports and releasing sidecars" >&2
    prepare_nginx_host_ports
    docker rm -f nginx >/dev/null 2>&1 || true
  fi
  if [ "$i" -lt 3 ]; then
    echo "[deploy] compose up --build failed (attempt $i/3); clearing nginx name + prune, retry in 5s..." >&2
    docker rm -f nginx >/dev/null 2>&1 || true
    docker builder prune -f 2>/dev/null || true
    sleep 5
  fi
done
if [ "$compose_ok" -ne 1 ]; then
  echo "[deploy] ERROR: docker compose up --build failed after 3 attempts" >&2
  exit 1
fi

# DNS prerequisites for panel UI toggle (docker.sock → same daemon as this deploy).
if ! docker image inspect amnezia-dns >/dev/null 2>&1; then
  echo "[deploy] ERROR: amnezia-dns image missing after build" >&2
  exit 1
fi
if ! docker inspect amnezia-awg --format '{{json .NetworkSettings.Networks}}' 2>/dev/null | grep -q 'amnezia-dns-net'; then
  echo "[deploy] WARNING: amnezia-awg is not attached to amnezia-dns-net; Amnezia DNS install may fail" >&2
fi

PORT=$(grep -E "^PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
WG_PORT=$(grep -E "^WG_PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
PANEL_HTTPS_PORT=$(grep -E "^PANEL_HTTPS_PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
PANEL_HTTP_PORT=$(grep -E "^PANEL_HTTP_PORT=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
WG_HOST=$(grep -E "^WG_HOST=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
PANEL_DOMAIN=$(grep -E "^PANEL_DOMAIN=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
ADMIN_USER=$(grep -E "^ADMIN_USERNAME=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
ADMIN_PWD=$(grep -E "^ADMIN_PASSWORD=" "$ENV_WORKING" 2>/dev/null | cut -d= -f2- || true)
PORT=${PORT:-51821}
WG_PORT=${WG_PORT:-51820}
PANEL_HTTPS_PORT=${PANEL_HTTPS_PORT:-10123}
PANEL_HTTP_PORT=${PANEL_HTTP_PORT:-80}
WG_HOST=${WG_HOST:-localhost}
ADMIN_USER=${ADMIN_USER:-admin}
PANEL_DOMAIN_PRINT="${PANEL_DOMAIN:-$WG_HOST}"
HTTPS_SUFFIX=""
if [ "$PANEL_HTTPS_PORT" != "443" ]; then
  HTTPS_SUFFIX=":${PANEL_HTTPS_PORT}"
fi

# Probe localhost host-port (nginx publish), not public PANEL_DOMAIN/WG_HOST — hairpin often fails.
PANEL_PROBE_URL="https://127.0.0.1${HTTPS_SUFFIX}/"
PANEL_URL="https://${PANEL_DOMAIN_PRINT}${HTTPS_SUFFIX}/"
if command -v curl >/dev/null 2>&1; then
  echo "[deploy] Waiting for panel at ${PANEL_PROBE_URL} ..."
  ready=0
  for _ in $(seq 1 40); do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "$PANEL_PROBE_URL" || true)
    case "$code" in
      200|301|302|401) ready=1; break ;;
    esac
    sleep 2
  done
  if [ "$ready" -eq 1 ]; then
    echo "[deploy] Panel is responding (HTTP ${code})"
  else
    echo "[deploy] WARNING: panel not responding yet; check: docker compose logs -f nginx amnezia-wg-easy"
  fi
fi

echo "[deploy] Done. Panel (HTTPS): https://${PANEL_DOMAIN_PRINT}${HTTPS_SUFFIX}"
if [ "$PANEL_HTTP_PORT" != "80" ]; then
  echo "[deploy] Note: HTTP (redirect/ACME) is on host TCP port ${PANEL_HTTP_PORT} — allow it in firewall; Let's Encrypt HTTP-01 uses this mapping to container port 80."
fi
echo "[deploy] Admin login: ${ADMIN_USER}"
echo "[deploy] Admin password: ${ADMIN_PWD}"
echo "[deploy] VPN: ${WG_HOST}:${WG_PORT} (UDP). DNS / Xray: panel header. Host :443 = SNI demux."
