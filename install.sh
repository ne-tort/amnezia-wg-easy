#!/bin/bash
# Amnezia WG-Easy — one-liner installer (3x-ui style).
# Usage:
#   bash <(curl -Ls https://raw.githubusercontent.com/ne-tort/amnezia-wg-easy/master/install.sh)
#
# Env overrides (non-interactive / CI):
#   AWG_NONINTERACTIVE=1
#   AWG_SSL_MODE=ip|domain|none|custom
#   AWG_ADMIN_USER AWG_ADMIN_PASSWORD
#   AWG_DOMAIN AWG_EMAIL AWG_SSL_IPV6
#   AWG_ENABLE_DNS=1|0  AWG_ENABLE_XRAY=1|0
#   AWG_INSTALL_DIR=/opt/amnezia-wg-easy  AWG_GIT_REF=master
#   AWG_REPO_URL=https://github.com/ne-tort/amnezia-wg-easy.git

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

REPO_URL="${AWG_REPO_URL:-https://github.com/ne-tort/amnezia-wg-easy.git}"
GIT_REF="${AWG_GIT_REF:-master}"
INSTALL_DIR="${AWG_INSTALL_DIR:-/opt/amnezia-wg-easy}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-amnezia-wg-easy}"
CONF_DIR="/etc/amnezia-wg-easy"
ACME_HOME="${HOME:-/root}/.acme.sh"
CERT_HOST_DIR="/root/cert/amnezia-wg-easy"

SSL_SCHEME="https"
SSL_HOST=""
SSL_MODE="selfsigned" # selfsigned | acme | certbot
SERVER_IP=""
ADMIN_USER=""
ADMIN_PASS=""
PANEL_DOMAIN_VAL=""
CERTBOT_EMAIL_VAL=""
ENABLE_DNS=1
ENABLE_XRAY=1

[[ "${EUID:-$(id -u)}" -ne 0 ]] && echo -e "${red}Запустите скрипт от root.${plain}" && exit 1

if [[ "${AWG_NONINTERACTIVE:-0}" == "1" ]] || [[ ! -t 0 ]]; then
  NONINTERACTIVE=1
else
  NONINTERACTIVE=0
fi
export NONINTERACTIVE

logi() { echo -e "${green}[install]${plain} $*"; }
logw() { echo -e "${yellow}[install]${plain} $*"; }
loge() { echo -e "${red}[install]${plain} $*" >&2; }

is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}
is_ipv6() {
  [[ "$1" =~ : ]]
}
is_domain() {
  [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+(xn--[a-z0-9]{2,}|[A-Za-z]{2,})$ ]]
}

gen_random_string() {
  local length="${1:-12}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 $((length * 2)) | tr -dc 'A-Za-z0-9' | head -c "$length"
  else
    head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$length"
  fi
}

prompt_or_default() {
  # prompt_or_default VAR "prompt" "default" ENV_OVERRIDE
  local __var="$1" __prompt="$2" __default="${3:-}" __env="${4:-}"
  local __val=""
  if [[ -n "${__env}" && -n "${!__env+x}" && -n "${!__env}" ]]; then
    printf -v "$__var" '%s' "${!__env}"
    return 0
  fi
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    printf -v "$__var" '%s' "$__default"
    return 0
  fi
  read -rp "$__prompt" __val || true
  __val="${__val#"${__val%%[![:space:]]*}"}"
  __val="${__val%"${__val##*[![:space:]]}"}"
  if [[ -z "$__val" ]]; then
    printf -v "$__var" '%s' "$__default"
  else
    printf -v "$__var" '%s' "$__val"
  fi
}

confirm_yn() {
  # confirm_yn "prompt" default_y_or_n ENV → sets CONFIRM_RESULT=0/1
  local prompt="$1" def="${2:-y}" envn="${3:-}"
  local ans=""
  if [[ -n "$envn" && -n "${!envn+x}" ]]; then
    case "${!envn}" in
      1|y|Y|yes|YES|true|TRUE) CONFIRM_RESULT=1; return 0 ;;
      0|n|N|no|NO|false|FALSE) CONFIRM_RESULT=0; return 0 ;;
    esac
  fi
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    [[ "$def" == "y" || "$def" == "Y" ]] && CONFIRM_RESULT=1 || CONFIRM_RESULT=0
    return 0
  fi
  if [[ "$def" == "y" || "$def" == "Y" ]]; then
    read -rp "${prompt} [Y/n]: " ans || true
    ans="${ans:-y}"
  else
    read -rp "${prompt} [y/N]: " ans || true
    ans="${ans:-n}"
  fi
  case "$ans" in
    y|Y|yes|YES) CONFIRM_RESULT=1 ;;
    *) CONFIRM_RESULT=0 ;;
  esac
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    OS_ID="${ID:-unknown}"
  else
    OS_ID="unknown"
  fi
  logi "OS: ${OS_ID}"
}

install_packages() {
  logi "Установка зависимостей..."
  case "$OS_ID" in
    ubuntu|debian)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q curl wget tar ca-certificates openssl cron git socat
      ;;
    centos|rhel|rocky|almalinux|fedora)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y -q curl wget tar ca-certificates openssl cronie git socat
      else
        yum install -y -q curl wget tar ca-certificates openssl cronie git socat
      fi
      ;;
    alpine)
      apk add --no-cache curl wget tar ca-certificates openssl dcron git socat bash
      ;;
    *)
      logw "Неизвестный дистрибутив — установлю пакеты через apt (если есть)"
      if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y -q curl wget tar ca-certificates openssl cron git socat
      fi
      ;;
  esac
}

install_docker() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    logi "Docker и Compose уже установлены"
    return 0
  fi
  logi "Установка Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker 2>/dev/null || true
  systemctl start docker 2>/dev/null || true
  if ! command -v docker >/dev/null 2>&1; then
    loge "Не удалось установить Docker"
    exit 1
  fi
  if ! docker compose version >/dev/null 2>&1; then
    loge "Плагин docker compose не найден"
    exit 1
  fi
  logi "Docker готов"
}

detect_public_ip() {
  SERVER_IP=$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null \
    || curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null \
    || curl -4 -fsS --max-time 8 https://icanhazip.com 2>/dev/null \
    || true)
  SERVER_IP=$(echo "$SERVER_IP" | tr -d '[:space:]')
  if [[ -z "$SERVER_IP" ]] || ! is_ipv4 "$SERVER_IP"; then
    logw "Не удалось определить публичный IPv4"
    SERVER_IP=""
  else
    logi "Публичный IP: ${SERVER_IP}"
  fi
}

clone_or_update_repo() {
  mkdir -p "$(dirname "$INSTALL_DIR")"
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    logi "Обновление репозитория в ${INSTALL_DIR}..."
    git -C "$INSTALL_DIR" fetch --depth 1 origin "$GIT_REF" || git -C "$INSTALL_DIR" fetch origin
    git -C "$INSTALL_DIR" checkout "$GIT_REF" 2>/dev/null || true
    git -C "$INSTALL_DIR" pull --ff-only origin "$GIT_REF" || true
  else
    if [[ -e "$INSTALL_DIR" ]] && [[ ! -d "$INSTALL_DIR/.git" ]]; then
      loge "Каталог ${INSTALL_DIR} занят и это не git-репозиторий"
      exit 1
    fi
    logi "Клонирование ${REPO_URL} → ${INSTALL_DIR}"
    git clone --depth 1 --branch "$GIT_REF" "$REPO_URL" "$INSTALL_DIR" \
      || git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
  fi
}

env_set() {
  local file="$1" key="$2" val="$3"
  if grep -qE "^${key}=" "$file" 2>/dev/null; then
    if sed --version >/dev/null 2>&1; then
      sed -i "s|^${key}=.*|${key}=${val}|" "$file"
    else
      sed -i '' "s|^${key}=.*|${key}=${val}|" "$file"
    fi
  else
    echo "${key}=${val}" >>"$file"
  fi
}

prompt_admin() {
  local custom=""
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    ADMIN_USER="${AWG_ADMIN_USER:-$(gen_random_string 10)}"
    ADMIN_PASS="${AWG_ADMIN_PASSWORD:-$(gen_random_string 16)}"
    return 0
  fi
  confirm_yn "Задать логин/пароль admin вручную? (иначе случайные)" n
  if [[ "$CONFIRM_RESULT" -eq 1 ]]; then
    prompt_or_default ADMIN_USER "Логин admin: " "admin" AWG_ADMIN_USER
    prompt_or_default ADMIN_PASS "Пароль admin: " "" AWG_ADMIN_PASSWORD
    if [[ -z "$ADMIN_PASS" ]]; then
      ADMIN_PASS=$(gen_random_string 16)
      logi "Пароль пустой → сгенерирован: ${ADMIN_PASS}"
    fi
  else
    ADMIN_USER=$(gen_random_string 10)
    ADMIN_PASS=$(gen_random_string 16)
  fi
}

install_acme() {
  if [[ -x "${ACME_HOME}/acme.sh" ]]; then
    return 0
  fi
  logi "Установка acme.sh..."
  curl -fsSL https://get.acme.sh | sh -s email="${CERTBOT_EMAIL_VAL:-admin@localhost}"
  # shellcheck source=/dev/null
  [[ -f "${ACME_HOME}/acme.sh.env" ]] && source "${ACME_HOME}/acme.sh.env" || true
  if [[ ! -x "${ACME_HOME}/acme.sh" ]]; then
    loge "acme.sh не установился"
    return 1
  fi
}

acme_bin() {
  echo "${ACME_HOME}/acme.sh"
}

is_port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :${port}" 2>/dev/null | grep -q LISTEN && return 0
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1 && return 0
  fi
  return 1
}

free_port_80() {
  logi "Освобождаю порт 80 для ACME..."
  docker stop nginx certbot 2>/dev/null || true
  # Best-effort: stop anything on 80 if still busy (don't kill docker daemon)
  if is_port_in_use 80; then
    logw "Порт 80 всё ещё занят — ACME standalone может не сработать"
  fi
}

volume_name_certbot() {
  echo "${COMPOSE_PROJECT_NAME}_certbot_conf"
}

inject_certs_to_volume() {
  local domain="$1"
  local src_dir="$2"
  local vol
  vol=$(volume_name_certbot)
  if [[ ! -f "${src_dir}/fullchain.pem" || ! -f "${src_dir}/privkey.pem" ]]; then
    loge "Нет файлов сертификата в ${src_dir}"
    return 1
  fi
  docker volume create "$vol" >/dev/null
  docker run --rm \
    -v "${vol}:/etc/letsencrypt" \
    -v "${src_dir}:/src:ro" \
    alpine:3.20 sh -c "
      set -e
      mkdir -p '/etc/letsencrypt/live/${domain}'
      cp /src/fullchain.pem '/etc/letsencrypt/live/${domain}/fullchain.pem'
      cp /src/privkey.pem '/etc/letsencrypt/live/${domain}/privkey.pem'
      chmod 644 '/etc/letsencrypt/live/${domain}/fullchain.pem'
      chmod 600 '/etc/letsencrypt/live/${domain}/privkey.pem'
    "
  logi "Сертификат записан в volume ${vol} → live/${domain}"
}

setup_domain_certificate() {
  local domain="$1"
  local email="$2"
  install_acme || return 1
  free_port_80
  mkdir -p "${CERT_HOST_DIR}/${domain}"
  "$(acme_bin)" --set-default-ca --server letsencrypt --force >/dev/null 2>&1 || true
  if [[ -n "$email" ]]; then
    "$(acme_bin)" --register-account -m "$email" >/dev/null 2>&1 || true
  fi
  logi "Выпуск LE-сертификата для домена ${domain}..."
  if ! "$(acme_bin)" --issue -d "$domain" --standalone --httpport 80 --force; then
    loge "Не удалось выпустить сертификат для ${domain} (порт 80 должен быть открыт)"
    return 1
  fi
  local reload_cmd="docker exec nginx nginx -s reload 2>/dev/null || true"
  "$(acme_bin)" --installcert --force -d "$domain" \
    --key-file "${CERT_HOST_DIR}/${domain}/privkey.pem" \
    --fullchain-file "${CERT_HOST_DIR}/${domain}/fullchain.pem" \
    --reloadcmd "$reload_cmd" || true
  inject_certs_to_volume "$domain" "${CERT_HOST_DIR}/${domain}" || return 1
  "$(acme_bin)" --upgrade --auto-upgrade >/dev/null 2>&1 || true
  SSL_MODE="acme"
  SSL_HOST="$domain"
  PANEL_DOMAIN_VAL="$domain"
  return 0
}

setup_ip_certificate() {
  local ipv4="$1"
  local ipv6="${2:-}"
  install_acme || return 1
  free_port_80
  mkdir -p "${CERT_HOST_DIR}/ip"
  local domain_args="-d ${ipv4}"
  if [[ -n "$ipv6" ]] && is_ipv6 "$ipv6"; then
    domain_args="${domain_args} -d ${ipv6}"
  fi
  "$(acme_bin)" --set-default-ca --server letsencrypt --force >/dev/null 2>&1 || true
  if [[ -n "${CERTBOT_EMAIL_VAL}" ]]; then
    "$(acme_bin)" --register-account -m "${CERTBOT_EMAIL_VAL}" >/dev/null 2>&1 || true
  fi
  logi "Выпуск LE IP-сертификата (shortlived ~6 дней) для ${ipv4}..."
  if ! "$(acme_bin)" --issue \
    ${domain_args} \
    --standalone \
    --server letsencrypt \
    --certificate-profile shortlived \
    --days 6 \
    --httpport 80 \
    --force; then
    loge "Не удалось выпустить IP-сертификат (нужен открытый TCP/80 с интернета)"
    return 1
  fi
  local reload_cmd="docker exec nginx nginx -s reload 2>/dev/null || true"
  "$(acme_bin)" --installcert --force -d "$ipv4" \
    --key-file "${CERT_HOST_DIR}/ip/privkey.pem" \
    --fullchain-file "${CERT_HOST_DIR}/ip/fullchain.pem" \
    --reloadcmd "$reload_cmd" || true
  inject_certs_to_volume "$ipv4" "${CERT_HOST_DIR}/ip" || return 1
  "$(acme_bin)" --upgrade --auto-upgrade >/dev/null 2>&1 || true
  SSL_MODE="acme"
  SSL_HOST="$ipv4"
  PANEL_DOMAIN_VAL="$ipv4"
  return 0
}

setup_custom_certificate() {
  local domain="" cert="" key=""
  prompt_or_default domain "Имя для PANEL_DOMAIN (IP или FQDN): " "${SERVER_IP}" AWG_DOMAIN
  prompt_or_default cert "Путь к fullchain.pem: " "" AWG_SSL_CERT
  prompt_or_default key "Путь к privkey.pem: " "" AWG_SSL_KEY
  if [[ ! -f "$cert" || ! -f "$key" ]]; then
    loge "Файлы сертификата не найдены"
    return 1
  fi
  mkdir -p "${CERT_HOST_DIR}/custom"
  cp "$cert" "${CERT_HOST_DIR}/custom/fullchain.pem"
  cp "$key" "${CERT_HOST_DIR}/custom/privkey.pem"
  inject_certs_to_volume "$domain" "${CERT_HOST_DIR}/custom" || return 1
  SSL_MODE="acme"
  SSL_HOST="$domain"
  PANEL_DOMAIN_VAL="$domain"
  return 0
}

prompt_and_setup_ssl() {
  local ssl_choice=""
  SSL_SCHEME="https"
  echo ""
  echo -e "${green}════════ SSL (рекомендуется) ════════${plain}"
  echo -e "${green}1.${plain} Let's Encrypt для домена (90 дней)"
  echo -e "${green}2.${plain} Let's Encrypt для IP (shortlived ~6 дней) — по умолчанию"
  echo -e "${green}3.${plain} Свой сертификат (пути к файлам)"
  echo -e "${green}4.${plain} Пропустить (self-signed)"
  echo -e "${blue}Для 1 и 2 нужен открытый TCP/80.${plain}"

  if [[ "$NONINTERACTIVE" == "1" ]]; then
    case "${AWG_SSL_MODE:-ip}" in
      domain) ssl_choice="1" ;;
      ip) ssl_choice="2" ;;
      custom) ssl_choice="3" ;;
      none|selfsigned|"") ssl_choice="4" ;;
      *) ssl_choice="2" ;;
    esac
  else
    read -rp "Выбор [1-4, Enter=2]: " ssl_choice || true
    ssl_choice="${ssl_choice// /}"
    if [[ "$ssl_choice" != "1" && "$ssl_choice" != "3" && "$ssl_choice" != "4" ]]; then
      ssl_choice="2"
    fi
  fi

  case "$ssl_choice" in
    1)
      local domain="" email=""
      prompt_or_default domain "Домен (A-запись на этот сервер): " "" AWG_DOMAIN
      prompt_or_default email "Email для Let's Encrypt: " "" AWG_EMAIL
      if [[ -z "$domain" ]] || ! is_domain "$domain"; then
        loge "Некорректный домен — self-signed"
        SSL_MODE="selfsigned"
        SSL_HOST="${SERVER_IP:-127.0.0.1}"
        PANEL_DOMAIN_VAL="${SERVER_IP:-127.0.0.1}"
        return 0
      fi
      CERTBOT_EMAIL_VAL="$email"
      if setup_domain_certificate "$domain" "$email"; then
        logi "SSL домена готов"
      else
        logw "SSL домена не удался → self-signed"
        SSL_MODE="selfsigned"
        SSL_HOST="$domain"
        PANEL_DOMAIN_VAL="$domain"
      fi
      ;;
    2)
      local ip="$SERVER_IP"
      if [[ "$NONINTERACTIVE" != "1" ]]; then
        local ip_confirm=""
        read -rp "IP ${ip} верный для входящих подключений? [Y/n]: " ip_confirm || true
        ip_confirm="${ip_confirm:-y}"
        if [[ "$ip_confirm" != "y" && "$ip_confirm" != "Y" ]]; then
          ip=""
          while [[ -z "$ip" ]]; do
            read -rp "Публичный IPv4: " ip || true
            ip="${ip// /}"
            is_ipv4 "$ip" || { loge "Не IPv4"; ip=""; }
          done
        fi
      fi
      if [[ -z "$ip" ]]; then
        loge "IP неизвестен — self-signed"
        SSL_MODE="selfsigned"
        SSL_HOST="127.0.0.1"
        PANEL_DOMAIN_VAL="127.0.0.1"
        return 0
      fi
      local ipv6=""
      prompt_or_default ipv6 "IPv6 (Enter = пропустить): " "" AWG_SSL_IPV6
      prompt_or_default CERTBOT_EMAIL_VAL "Email для LE (необязательно): " "" AWG_EMAIL
      if setup_ip_certificate "$ip" "$ipv6"; then
        logi "SSL IP готов"
        SERVER_IP="$ip"
      else
        logw "SSL IP не удался → self-signed"
        SSL_MODE="selfsigned"
        SSL_HOST="$ip"
        PANEL_DOMAIN_VAL="$ip"
      fi
      ;;
    3)
      if ! setup_custom_certificate; then
        SSL_MODE="selfsigned"
        SSL_HOST="${SERVER_IP:-127.0.0.1}"
        PANEL_DOMAIN_VAL="${SERVER_IP:-127.0.0.1}"
      fi
      ;;
    4|*)
      SSL_MODE="selfsigned"
      SSL_SCHEME="https"
      SSL_HOST="${SERVER_IP:-127.0.0.1}"
      PANEL_DOMAIN_VAL="${SERVER_IP:-127.0.0.1}"
      logi "SSL пропущен — nginx сделает self-signed"
      ;;
  esac
}

write_env() {
  local envf="${INSTALL_DIR}/.env"
  if [[ ! -f "$envf" ]]; then
    cp "${INSTALL_DIR}/.env.example" "$envf"
  fi
  env_set "$envf" ADMIN_USERNAME "$ADMIN_USER"
  env_set "$envf" ADMIN_PASSWORD "$ADMIN_PASS"
  env_set "$envf" WG_HOST "${SERVER_IP:-$PANEL_DOMAIN_VAL}"
  env_set "$envf" PANEL_DOMAIN "$PANEL_DOMAIN_VAL"
  env_set "$envf" SSL_MODE "$SSL_MODE"
  if [[ -n "$CERTBOT_EMAIL_VAL" ]]; then
    env_set "$envf" CERTBOT_EMAIL "$CERTBOT_EMAIL_VAL"
  fi
  if [[ -z "$(grep -E '^SESSION_SECRET=' "$envf" | cut -d= -f2-)" ]] \
    || grep -qE '^SESSION_SECRET=(change-me-in-production)?$' "$envf"; then
    env_set "$envf" SESSION_SECRET "$(gen_random_string 32)"
  fi
  mkdir -p "$CONF_DIR"
  cat >"${CONF_DIR}/install.conf" <<EOF
INSTALL_DIR=${INSTALL_DIR}
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME}
SSL_MODE=${SSL_MODE}
SSL_HOST=${SSL_HOST}
PANEL_DOMAIN=${PANEL_DOMAIN_VAL}
WG_HOST=${SERVER_IP:-$PANEL_DOMAIN_VAL}
ADMIN_USERNAME=${ADMIN_USER}
INSTALLED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
  chmod 600 "${CONF_DIR}/install.conf"
  # Keep a copy of password separately (root-only) for awg-easy show
  umask 077
  cat >"${CONF_DIR}/admin.cred" <<EOF
ADMIN_USERNAME=${ADMIN_USER}
ADMIN_PASSWORD=${ADMIN_PASS}
EOF
  chmod 600 "${CONF_DIR}/admin.cred"
  logi "Записан ${envf} (SSL_MODE=${SSL_MODE})"
}

run_deploy() {
  logi "Запуск deploy.sh..."
  export COMPOSE_PROJECT_NAME
  cd "$INSTALL_DIR"
  chmod +x ./deploy.sh
  ./deploy.sh
}

install_cli() {
  local src="${INSTALL_DIR}/scripts/awg-easy.sh"
  if [[ ! -f "$src" ]]; then
    logw "Нет ${src} — CLI пропущен (обновите репозиторий)"
    return 0
  fi
  chmod +x "$src"
  install -m 755 "$src" /usr/local/bin/awg-easy
  logi "CLI: awg-easy"
}

panel_probe_url() {
  local https_port
  https_port=$(grep -E '^PANEL_HTTPS_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  https_port="${https_port:-443}"
  if [[ "$https_port" == "443" ]]; then
    echo "https://127.0.0.1/"
  else
    echo "https://127.0.0.1:${https_port}/"
  fi
}

wait_panel() {
  local url
  url=$(panel_probe_url)
  logi "Ожидание панели ${url} ..."
  local i code=000
  for i in $(seq 1 60); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "$url" || true)
    case "$code" in
      200|301|302|401) logi "Панель отвечает (HTTP ${code})"; return 0 ;;
    esac
    sleep 2
  done
  logw "Панель пока не ответила (последний код ${code})"
  return 1
}

api_curl() {
  # api_curl METHOD PATH [json_body]
  local method="$1" path="$2" body="${3:-}"
  local url base cookie
  base=$(panel_probe_url)
  base="${base%/}"
  cookie="${CONF_DIR}/session.cj"
  if [[ -n "$body" ]]; then
    curl -sk -c "$cookie" -b "$cookie" -X "$method" "${base}${path}" \
      -H 'Content-Type: application/json' \
      -d "$body" --max-time 120
  else
    curl -sk -c "$cookie" -b "$cookie" -X "$method" "${base}${path}" --max-time 120
  fi
}

api_login() {
  local resp
  resp=$(api_curl POST /api/session "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" || true)
  if echo "$resp" | grep -qi 'success\|username\|true\|{}' || [[ -f "${CONF_DIR}/session.cj" ]]; then
    # Verify with a capability-gated endpoint
    local code
    code=$(curl -sk -b "${CONF_DIR}/session.cj" -o /dev/null -w '%{http_code}' --max-time 10 \
      "$(panel_probe_url | sed 's|/$||')/api/amnezia-xray" || true)
    if [[ "$code" == "200" || "$code" == "403" ]]; then
      return 0
    fi
  fi
  logw "Логин API не подтверждён: ${resp:0:200}"
  return 1
}

enable_dns() {
  logi "Включение Amnezia DNS..."
  local resp
  resp=$(api_curl POST /api/amnezia-dns/enable '{}' || true)
  logi "DNS: ${resp:0:240}"
}

base24_from_ip() {
  local ip="$1"
  local a b c
  IFS=. read -r a b c _ <<<"$ip"
  echo "${a}.${b}.${c}.0/24"
}

enable_xray() {
  logi "Подготовка Xray (SNI Finder + enable)..."
  local sni="" address="${SERVER_IP:-$PANEL_DOMAIN_VAL}"
  local cidr port=8443
  port=$(grep -E '^XRAY_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  port="${port:-8443}"
  cidr=$(base24_from_ip "${SERVER_IP:-0.0.0.0}")

  # Trigger / wait for cache
  api_curl GET "/api/amnezia-xray/sni-cache?ensureBg=1" >/tmp/awg-sni-cache.json || true
  if [[ -n "$SERVER_IP" && "$cidr" != "0.0.0.0/24" ]]; then
    logi "SNI scan ${cidr}..."
    api_curl POST /api/amnezia-xray/sni-scan "{\"cidr\":\"${cidr}\",\"force\":true}" >/dev/null || true
    local i phase
    for i in $(seq 1 120); do
      phase=$(api_curl GET /api/amnezia-xray/sni-scan 2>/dev/null | sed -n 's/.*"phase":"\([^"]*\)".*/\1/p' | head -1)
      [[ "$phase" == "done" || "$phase" == "error" || "$phase" == "idle" ]] && break
      sleep 2
    done
  fi
  api_curl GET /api/amnezia-xray/sni-cache >/tmp/awg-sni-cache.json || true
  sni=$(python3 - <<'PY' 2>/dev/null || true
import json
try:
  d=json.load(open("/tmp/awg-sni-cache.json"))
  print((d.get("defaultSni") or "").strip())
except Exception:
  pass
PY
)
  if [[ -z "$sni" ]]; then
    sni=$(sed -n 's/.*"defaultSni"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /tmp/awg-sni-cache.json 2>/dev/null | head -1)
  fi
  if [[ -z "$sni" ]]; then
    sni="www.gov.uk"
    logw "defaultSni не найден — fallback ${sni}"
  else
    logi "Выбран SNI: ${sni}"
  fi

  local body
  body=$(printf '{"sni":"%s","fingerprint":"chrome","flow":"xtls-rprx-vision","port":%s,"address":"%s"}' \
    "$sni" "$port" "$address")
  local resp
  resp=$(api_curl POST /api/amnezia-xray/enable "$body" || true)
  logi "Xray enable: ${resp:0:300}"
}

post_configure() {
  wait_panel || true
  if ! api_login; then
    logw "Не удалось войти в API — DNS/Xray включите в UI или: awg-easy"
    return 0
  fi
  if [[ "$ENABLE_DNS" -eq 1 ]]; then
    enable_dns || logw "DNS enable не удался"
  fi
  if [[ "$ENABLE_XRAY" -eq 1 ]]; then
    enable_xray || logw "Xray enable не удался"
  fi
}

print_summary() {
  local https_port https_suffix=""
  https_port=$(grep -E '^PANEL_HTTPS_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  https_port="${https_port:-443}"
  [[ "$https_port" != "443" ]] && https_suffix=":${https_port}"
  local wg_port xray_port
  wg_port=$(grep -E '^WG_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  wg_port="${wg_port:-51820}"
  xray_port=$(grep -E '^XRAY_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  xray_port="${xray_port:-8443}"

  echo ""
  echo -e "${green}═══════════════════════════════════════════${plain}"
  echo -e "${green}     Установка завершена                  ${plain}"
  echo -e "${green}═══════════════════════════════════════════${plain}"
  echo -e "${green}URL:      ${SSL_SCHEME}://${SSL_HOST}${https_suffix}/${plain}"
  echo -e "${green}Логин:    ${ADMIN_USER}${plain}"
  echo -e "${green}Пароль:   ${ADMIN_PASS}${plain}"
  echo -e "${green}VPN:      ${SERVER_IP:-$SSL_HOST}:${wg_port}/udp${plain}"
  echo -e "${green}Xray:     ${SERVER_IP:-$SSL_HOST}:${xray_port}/tcp${plain}"
  echo -e "${green}Каталог:  ${INSTALL_DIR}${plain}"
  echo -e "${green}CLI:      awg-easy${plain}"
  echo -e "${green}SSL:      ${SSL_MODE} (${SSL_HOST})${plain}"
  echo -e "${green}═══════════════════════════════════════════${plain}"
  echo -e "${yellow}Сохраните логин и пароль!${plain}"
}

main() {
  echo -e "${green}Amnezia WG-Easy — установщик${plain}"
  detect_os
  install_packages
  install_docker
  detect_public_ip
  clone_or_update_repo
  prompt_admin
  prompt_and_setup_ssl
  write_env
  confirm_yn "Включить Amnezia DNS после установки?" y AWG_ENABLE_DNS
  ENABLE_DNS=$CONFIRM_RESULT
  confirm_yn "Включить Xray (VLESS Reality + SNI Finder) после установки?" y AWG_ENABLE_XRAY
  ENABLE_XRAY=$CONFIRM_RESULT
  run_deploy
  install_cli
  post_configure
  print_summary
}

main "$@"
