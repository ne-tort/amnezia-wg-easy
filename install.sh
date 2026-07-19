#!/bin/bash
# Amnezia WG-Easy — one-liner installer (3x-ui style).
# Usage (prefer IPv4 — broken IPv6 makes raw.githubusercontent.com hang):
#   bash <(curl -4fsSL --connect-timeout 3 --retry 3 https://raw.githubusercontent.com/ne-tort/amnezia-wg-easy/master/install.sh)
#
# Env overrides (non-interactive / CI):
#   AWG_NONINTERACTIVE=1
#   AWG_SSL_MODE=ip|domain|none|custom|reuse
#   AWG_ADMIN_USER AWG_ADMIN_PASSWORD
#   AWG_WG_PORT AWG_PANEL_HTTPS_PORT AWG_XRAY_PORT
#   AWG_DOMAIN AWG_EMAIL AWG_SSL_IPV6
#   AWG_ENABLE_DNS=1|0  AWG_ENABLE_XRAY=1|0  AWG_ENABLE_MTPROTO=1|0
#   AWG_INSTALL_DIR=/opt/amnezia-wg-easy  AWG_GIT_REF=master
#   AWG_REPO_URL=https://github.com/ne-tort/amnezia-wg-easy.git
#   AWG_SSL_FORCE_RENEW=1  — принудительный повторный выпуск LE (по умолчанию reuse)
#   AWG_SSL_REUSE_MIN_DAYS / AWG_SSL_REUSE_MIN_DAYS_IP — мин. остаток дней для reuse

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
ENABLE_MTPROTO=1
WG_PORT_VAL=""
PANEL_HTTPS_PORT_VAL=""
XRAY_PORT_VAL=""
XRAY_PUBLIC_PORT_VAL=""
MTPROTO_PUBLIC_PORT_VAL=""
WEBUI_PUBLIC_PREFIX_VAL="/panel"
SUB_PUBLIC_PREFIX_VAL="/sub"
NGINX_ROOT_BEHAVIOR_VAL="mirror"
NGINX_MIRROR_HOST_VAL=""
MIRROR_USE_SNI_VAL=0

# Random free ports (user/dynamic range) for AWG UDP / Xray+MTProto internal TCP.
PORT_RAND_MIN=20000
PORT_RAND_MAX=50000
# Default panel HTTPS = 443 (SNI demux with Xray/MT). Bare IP stays on shared port via catch-all.
DEFAULT_PANEL_HTTPS_PORT=443
# Preferred internal Xray listen; empty = auto. Clients use public ports / demux.
DEFAULT_XRAY_PORT=""

[[ "${EUID:-$(id -u)}" -ne 0 ]] && echo -e "${red}Запустите скрипт от root.${plain}" && exit 1

# Interactive if we can talk to the controlling TTY (not merely if fd0 is a tty).
# curl|bash leaves fd0 as a pipe; bash <(curl) keeps a tty — handle both.
if [[ "${AWG_NONINTERACTIVE:-0}" == "1" ]]; then
  NONINTERACTIVE=1
elif [[ -c /dev/tty ]]; then
  NONINTERACTIVE=0
  if [[ ! -t 0 ]]; then
    exec </dev/tty
  fi
elif [[ -t 0 ]]; then
  NONINTERACTIVE=0
else
  NONINTERACTIVE=1
fi
export NONINTERACTIVE

logi() { echo -e "${green}[install]${plain} $*"; }
logw() { echo -e "${yellow}[install]${plain} $*"; }
loge() { echo -e "${red}[install]${plain} $*" >&2; }

# Prefer IPv4: many VPS resolve AAAA first but have broken IPv6 → curl SSL hangs.
curl4() {
  curl -4 "$@"
}

is_ipv4() {
  [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}
is_ipv6() {
  [[ "$1" =~ : ]]
}
is_ip_literal() {
  local h="${1:-}"
  h="${h#[}"
  h="${h%]}"
  is_ipv4 "$h" || is_ipv6 "$h"
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
  # Empty Enter always accepts the default (Y/n → yes, y/N → no).
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
  else
    read -rp "${prompt} [y/N]: " ans || true
  fi
  # Trim whitespace; bare Enter → default
  ans="${ans#"${ans%%[![:space:]]*}"}"
  ans="${ans%"${ans##*[![:space:]]}"}"
  if [[ -z "$ans" ]]; then
    [[ "$def" == "y" || "$def" == "Y" ]] && CONFIRM_RESULT=1 || CONFIRM_RESULT=0
    return 0
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
  local need=0
  local bin
  for bin in curl wget tar openssl git socat; do
    if ! command -v "$bin" >/dev/null 2>&1; then
      need=1
      break
    fi
  done
  if [[ "$need" -eq 0 ]]; then
    logi "Зависимости уже установлены — пропускаю apt/yum"
    return 0
  fi
  logi "Установка зависимостей..."
  export DEBIAN_FRONTEND=noninteractive
  case "$OS_ID" in
    ubuntu|debian)
      apt-get update -y
      apt-get install -y -q curl wget tar ca-certificates openssl cron git socat
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
        apt-get install -y -q curl wget tar ca-certificates openssl cron git socat
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
  curl4 -fsSL --connect-timeout 15 --retry 3 https://get.docker.com | sh
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
  if [[ -n "${AWG_SERVER_IP_PRESET:-}" ]] && is_ipv4 "${AWG_SERVER_IP_PRESET}"; then
    SERVER_IP="$AWG_SERVER_IP_PRESET"
    logi "Публичный IP: ${SERVER_IP}"
    return 0
  fi
  SERVER_IP=$(curl4 -fsS --connect-timeout 5 --max-time 8 https://ifconfig.me 2>/dev/null \
    || curl4 -fsS --connect-timeout 5 --max-time 8 https://api.ipify.org 2>/dev/null \
    || curl4 -fsS --connect-timeout 5 --max-time 8 https://icanhazip.com 2>/dev/null \
    || true)
  SERVER_IP=$(echo "$SERVER_IP" | tr -d '[:space:]')
  if [[ -z "$SERVER_IP" ]] || ! is_ipv4 "$SERVER_IP"; then
    logw "Не удалось определить публичный IPv4"
    SERVER_IP=""
  else
    logi "Публичный IP: ${SERVER_IP}"
  fi
}

# bash <(curl …) keeps running the downloaded fd even after git updates INSTALL_DIR.
# Re-exec the repo copy once so prompts/ports logic always match origin/master.
reexec_from_repo_if_needed() {
  local repo_script="${INSTALL_DIR}/install.sh"
  local self target
  [[ -f "$repo_script" ]] || return 0
  [[ "${AWG_REEXECED:-0}" == "1" ]] && return 0
  # BASH_SOURCE[0] is this file (e.g. /dev/fd/N for curl|bash, or INSTALL_DIR/install.sh).
  self=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")
  target=$(readlink -f "$repo_script" 2>/dev/null || echo "$repo_script")
  if [[ "$self" == "$target" ]]; then
    return 0
  fi
  logi "Перезапуск актуального установщика: ${repo_script}"
  export AWG_REEXECED=1
  export AWG_SERVER_IP_PRESET="${SERVER_IP:-}"
  exec bash "$repo_script" "$@"
}

clone_or_update_repo() {
  mkdir -p "$(dirname "$INSTALL_DIR")"
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    logi "Обновление репозитория в ${INSTALL_DIR} → ${GIT_REF} (hard reset)..."
    git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL" 2>/dev/null || true
    # Drop local edits (e.g. installed /usr copy touching scripts/) so checkout cannot abort.
    git -C "$INSTALL_DIR" reset --hard HEAD >/dev/null 2>&1 || true
    git -C "$INSTALL_DIR" clean -fd >/dev/null 2>&1 || true
    # Shallow trees often stick on an old tip; force sync to origin/<ref>.
    if ! git -C "$INSTALL_DIR" fetch --depth 1 origin "$GIT_REF"; then
      git -C "$INSTALL_DIR" fetch origin "$GIT_REF" || git -C "$INSTALL_DIR" fetch origin
    fi
    if git -C "$INSTALL_DIR" rev-parse --verify "origin/${GIT_REF}" >/dev/null 2>&1; then
      git -C "$INSTALL_DIR" checkout -f -B "$GIT_REF" "origin/${GIT_REF}"
      git -C "$INSTALL_DIR" reset --hard "origin/${GIT_REF}"
    else
      git -C "$INSTALL_DIR" checkout -f -B "$GIT_REF" FETCH_HEAD
      git -C "$INSTALL_DIR" reset --hard FETCH_HEAD
    fi
    git -C "$INSTALL_DIR" clean -fd
    logi "Ревизия: $(git -C "$INSTALL_DIR" rev-parse --short HEAD)"
  else
    if [[ -e "$INSTALL_DIR" ]] && [[ ! -d "$INSTALL_DIR/.git" ]]; then
      loge "Каталог ${INSTALL_DIR} занят и это не git-репозиторий"
      exit 1
    fi
    logi "Клонирование ${REPO_URL} → ${INSTALL_DIR}"
    GIT_TERMINAL_PROMPT=0 git clone --depth 1 --branch "$GIT_REF" --progress \
      "$REPO_URL" "$INSTALL_DIR" \
      || GIT_TERMINAL_PROMPT=0 git clone --depth 1 --progress "$REPO_URL" "$INSTALL_DIR"
    logi "Ревизия: $(git -C "$INSTALL_DIR" rev-parse --short HEAD)"
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
  local existing_user="" existing_pass="" custom=""
  if [[ -f "${CONF_DIR}/admin.cred" ]]; then
    existing_user=$(grep -E '^ADMIN_USERNAME=' "${CONF_DIR}/admin.cred" 2>/dev/null | cut -d= -f2- || true)
    existing_pass=$(grep -E '^ADMIN_PASSWORD=' "${CONF_DIR}/admin.cred" 2>/dev/null | cut -d= -f2- || true)
  fi
  if [[ -z "$existing_user" || -z "$existing_pass" ]] && [[ -f "${INSTALL_DIR}/.env" ]]; then
    existing_user=$(grep -E '^ADMIN_USERNAME=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
    existing_pass=$(grep -E '^ADMIN_PASSWORD=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  fi
  existing_user="${existing_user//$'\r'/}"
  existing_pass="${existing_pass//$'\r'/}"

  if [[ "$NONINTERACTIVE" == "1" ]]; then
    if [[ -n "${AWG_ADMIN_USER:-}" || -n "${AWG_ADMIN_PASSWORD:-}" ]]; then
      ADMIN_USER="${AWG_ADMIN_USER:-${existing_user:-$(gen_random_string 10)}}"
      ADMIN_PASS="${AWG_ADMIN_PASSWORD:-${existing_pass:-$(gen_random_string 16)}}"
    elif [[ -n "$existing_user" && -n "$existing_pass" ]]; then
      ADMIN_USER="$existing_user"
      ADMIN_PASS="$existing_pass"
      logi "Оставляю существующие учётные данные (${ADMIN_USER})"
    else
      ADMIN_USER=$(gen_random_string 10)
      ADMIN_PASS=$(gen_random_string 16)
    fi
    return 0
  fi

  if [[ -n "$existing_user" && -n "$existing_pass" ]]; then
    confirm_yn "Новый логин/пароль admin? [редеплой: ${existing_user}]" n
    if [[ "$CONFIRM_RESULT" -eq 0 ]]; then
      ADMIN_USER="$existing_user"
      ADMIN_PASS="$existing_pass"
      logi "admin=${ADMIN_USER}"
      return 0
    fi
    prompt_or_default ADMIN_USER "Логин admin: " "$existing_user" AWG_ADMIN_USER
    prompt_or_default ADMIN_PASS "Пароль admin: " "" AWG_ADMIN_PASSWORD
    if [[ -z "$ADMIN_PASS" ]]; then
      ADMIN_PASS="$existing_pass"
      logi "Пароль пустой → оставлен прежний"
    fi
    return 0
  fi

  confirm_yn "Задать admin вручную?" n
  if [[ "$CONFIRM_RESULT" -eq 1 ]]; then
    prompt_or_default ADMIN_USER "Логин admin [по умолчанию: admin]: " "admin" AWG_ADMIN_USER
    prompt_or_default ADMIN_PASS "Пароль admin [по умолчанию: случайный]: " "" AWG_ADMIN_PASSWORD
    if [[ -z "$ADMIN_PASS" ]]; then
      ADMIN_PASS=$(gen_random_string 16)
      logi "Пароль: ${ADMIN_PASS}"
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
  # LE rejects contacts like admin@localhost ("domain needs at least one dot").
  if is_valid_le_email "${CERTBOT_EMAIL_VAL:-}"; then
    curl4 -fsSL --connect-timeout 15 --retry 3 https://get.acme.sh | sh -s email="${CERTBOT_EMAIL_VAL}"
  else
    curl4 -fsSL --connect-timeout 15 --retry 3 https://get.acme.sh | sh
  fi
  # shellcheck source=/dev/null
  [[ -f "${ACME_HOME}/acme.sh.env" ]] && source "${ACME_HOME}/acme.sh.env" || true
  if [[ ! -x "${ACME_HOME}/acme.sh" ]]; then
    loge "acme.sh не установился"
    return 1
  fi
}

# Let's Encrypt contact: local@domain.tld (domain must contain a dot). Empty = omit contact.
is_valid_le_email() {
  local e="${1:-}"
  [[ -z "$e" ]] && return 1
  [[ "$e" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]
}

# Register/refresh LE account. Prefer a valid email; never send admin@localhost.
ensure_acme_le_account() {
  local email="${1:-}"
  "$(acme_bin)" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  if is_valid_le_email "$email"; then
    if ! "$(acme_bin)" --register-account -m "$email" --server letsencrypt; then
      logw "Регистрация LE-аккаунта с email не удалась — пробую без контакта"
      "$(acme_bin)" --register-account --server letsencrypt >/dev/null 2>&1 || true
    fi
  else
    if [[ -n "$email" ]]; then
      logw "Email «${email}» не подходит для LE (нужен вид user@domain.tld) — регистрирую аккаунт без контакта"
    fi
    "$(acme_bin)" --register-account --server letsencrypt >/dev/null 2>&1 || true
  fi
}

acme_bin() {
  echo "${ACME_HOME}/acme.sh"
}

is_port_in_use() {
  # is_port_in_use PORT [tcp|udp|both]
  # Returns 0 if busy by something other than our stack containers.
  local port="$1" proto="${2:-tcp}"
  local busy=0

  if command -v ss >/dev/null 2>&1; then
    case "$proto" in
      udp)
        ss -lun "sport = :${port}" 2>/dev/null | grep -q UNCONN && busy=1
        ;;
      both)
        ss -ltn "sport = :${port}" 2>/dev/null | grep -q LISTEN && busy=1
        ss -lun "sport = :${port}" 2>/dev/null | grep -q UNCONN && busy=1
        ;;
      *)
        ss -ltn "sport = :${port}" 2>/dev/null | grep -q LISTEN && busy=1
        ;;
    esac
  elif command -v lsof >/dev/null 2>&1; then
    case "$proto" in
      udp) lsof -iUDP:"${port}" -sUDP:Idle >/dev/null 2>&1 && busy=1 ;;
      both)
        lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1 && busy=1
        lsof -iUDP:"${port}" >/dev/null 2>&1 && busy=1
        ;;
      *) lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1 && busy=1 ;;
    esac
  fi

  if [[ "$busy" -eq 0 ]]; then
    return 1
  fi

  # Ports already published by our stack are reusable on redeploy.
  if docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
    | grep -E '^(nginx|amnezia-awg|amnezia-xray) ' \
    | grep -Eq "(:|^)${port}->|:${port}/"; then
    return 1
  fi
  return 0
}

port_excluded() {
  local port="$1" ex
  shift
  for ex in "$@"; do
    [[ -n "$ex" && "$ex" == "$port" ]] && return 0
  done
  return 1
}

random_free_port() {
  # random_free_port PROTO [exclude_port ...]
  local proto="${1:-tcp}"
  shift || true
  local i port
  for i in $(seq 1 100); do
    port=$((PORT_RAND_MIN + RANDOM % (PORT_RAND_MAX - PORT_RAND_MIN + 1)))
    port_excluded "$port" "$@" && continue
    if ! is_port_in_use "$port" "$proto"; then
      echo "$port"
      return 0
    fi
  done
  loge "Не удалось найти свободный порт ${PORT_RAND_MIN}-${PORT_RAND_MAX} (${proto})"
  return 1
}

ensure_free_port() {
  # ensure_free_port PORT PROTO LABEL [exclude...]
  # Echoes PORT if free, else picks random free.
  local want="$1" proto="$2" label="$3"
  shift 3 || true
  if [[ -n "$want" ]] && ! port_excluded "$want" "$@" && ! is_port_in_use "$want" "$proto"; then
    echo "$want"
    return 0
  fi
  if [[ -n "$want" ]] && is_port_in_use "$want" "$proto"; then
    logw "${label}: порт ${want} занят — подбираю случайный ${PORT_RAND_MIN}-${PORT_RAND_MAX}"
  fi
  random_free_port "$proto" "$@"
}

read_existing_env_port() {
  local key="$1"
  grep -E "^${key}=" "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- | tr -d '\r' || true
}

read_install_conf_val() {
  local key="$1"
  grep -E "^${key}=" "${CONF_DIR}/install.conf" 2>/dev/null | cut -d= -f2- | tr -d '\r' || true
}

# True when .env already has a real previous install (redeploy), not a fresh clone of .env.example.
is_redeploy() {
  [[ -f "${INSTALL_DIR}/.env" ]] || return 1
  local u p
  u=$(read_existing_env_port ADMIN_USERNAME)
  p=$(read_existing_env_port WG_PORT)
  [[ -n "$u" && -n "$p" ]]
}

assign_port_or_keep() {
  # assign_port_or_keep OUTVAR PROTO CUR FIRST_DEFAULT LABEL keep_busy_ok [exclude...]
  # Empty interactive answer / missing env override:
  #   redeploy + CUR → keep CUR (even if "busy" by our stack)
  #   first install → FIRST_DEFAULT (empty FIRST_DEFAULT = random)
  local outvar="$1" proto="$2" cur="$3" first_def="$4" label="$5" keep_busy="${6:-1}"
  shift 6 || true
  local chosen="$cur" from_keep=0

  if [[ -n "$chosen" ]]; then
    from_keep=1
  elif [[ -n "$first_def" ]]; then
    chosen="$first_def"
  else
    chosen=$(random_free_port "$proto" "$@") || return 1
  fi

  if [[ "$from_keep" -eq 1 && "$keep_busy" -eq 1 ]]; then
    # Redeploy keep: trust previous assignment (our containers may hold the port).
    printf -v "$outvar" '%s' "$chosen"
    return 0
  fi

  if port_excluded "$chosen" "$@" || is_port_in_use "$chosen" "$proto"; then
    logw "${label}: порт ${chosen} занят — случайный ${PORT_RAND_MIN}-${PORT_RAND_MAX}"
    chosen=$(random_free_port "$proto" "$@") || return 1
  fi
  printf -v "$outvar" '%s' "$chosen"
  return 0
}

prompt_ports() {
  local cur_wg cur_https cur_xray ans="" redeploy=0
  cur_wg=$(read_existing_env_port WG_PORT)
  cur_https=$(read_existing_env_port PANEL_HTTPS_PORT)
  cur_xray=$(read_existing_env_port XRAY_PORT)
  is_redeploy && redeploy=1

  echo ""
  echo -e "${green}════════ Порты ════════${plain}"
  if [[ "$redeploy" -eq 1 ]]; then
    echo -e "${blue}Редеплой: Enter = значения из .env${plain}"
  else
    echo -e "${blue}По умолчанию: Panel/Xray/MT = 443 (SNI demux)${plain}"
  fi

  # --- Panel HTTPS ---
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    if [[ -n "${AWG_PANEL_HTTPS_PORT:-}" ]]; then
      PANEL_HTTPS_PORT_VAL="$AWG_PANEL_HTTPS_PORT"
      if is_port_in_use "$PANEL_HTTPS_PORT_VAL" tcp; then
        logw "HTTPS панели: ${PANEL_HTTPS_PORT_VAL} занят — случайный"
        PANEL_HTTPS_PORT_VAL=$(random_free_port tcp) \
          || { loge "Нет свободного TCP для панели"; exit 1; }
      fi
    else
      assign_port_or_keep PANEL_HTTPS_PORT_VAL tcp "$cur_https" "$DEFAULT_PANEL_HTTPS_PORT" \
        "HTTPS панели" 1 \
        || { loge "Нет свободного TCP для панели"; exit 1; }
    fi
  else
    local hint
    if [[ -n "$cur_https" ]]; then
      hint="редеплой: ${cur_https}"
    else
      hint="по умолчанию: ${DEFAULT_PANEL_HTTPS_PORT}"
    fi
    read -rp "HTTPS панели [${hint}]: " ans || true
    ans="${ans// /}"
    if [[ -z "$ans" ]]; then
      assign_port_or_keep PANEL_HTTPS_PORT_VAL tcp "$cur_https" "$DEFAULT_PANEL_HTTPS_PORT" \
        "HTTPS панели" 1 \
        || { loge "Нет свободного TCP для панели"; exit 1; }
    elif [[ "$ans" =~ ^[0-9]+$ ]] && [[ "$ans" -ge 1 && "$ans" -le 65535 ]]; then
      PANEL_HTTPS_PORT_VAL="$ans"
      if is_port_in_use "$PANEL_HTTPS_PORT_VAL" tcp; then
        logw "HTTPS панели: ${PANEL_HTTPS_PORT_VAL} занят — случайный"
        PANEL_HTTPS_PORT_VAL=$(random_free_port tcp) \
          || { loge "Нет свободного TCP для панели"; exit 1; }
      fi
    else
      logw "Некорректный порт"
      assign_port_or_keep PANEL_HTTPS_PORT_VAL tcp "$cur_https" "$DEFAULT_PANEL_HTTPS_PORT" \
        "HTTPS панели" 1 \
        || { loge "Нет свободного TCP для панели"; exit 1; }
    fi
  fi
  logi "HTTPS панели: ${PANEL_HTTPS_PORT_VAL}/tcp"

  # --- Xray / MTProto public TCP (same port → SNI demux; different → direct publish) ---
  local cur_xray_pub cur_mt_pub
  cur_xray_pub=$(read_existing_env_port XRAY_PUBLIC_PORT)
  cur_mt_pub=$(read_existing_env_port MTPROTO_PUBLIC_PORT)
  [[ -z "$cur_xray_pub" ]] && cur_xray_pub=$(read_existing_env_port XRAY_PORT)

  if [[ "$NONINTERACTIVE" == "1" ]]; then
    XRAY_PUBLIC_PORT_VAL="${AWG_XRAY_PUBLIC_PORT:-${AWG_XRAY_PORT:-${cur_xray_pub:-443}}}"
    MTPROTO_PUBLIC_PORT_VAL="${AWG_MTPROTO_PUBLIC_PORT:-${cur_mt_pub:-$XRAY_PUBLIC_PORT_VAL}}"
  else
    while true; do
      ans=""
      local xhint
      if [[ -n "$cur_xray_pub" ]]; then xhint="редеплой: ${cur_xray_pub}"; else xhint="по умолчанию: 443"; fi
      read -rp "Xray public TCP [${xhint}]: " ans || true
      ans="${ans// /}"
      if [[ -z "$ans" ]]; then
        XRAY_PUBLIC_PORT_VAL="${cur_xray_pub:-443}"
        break
      elif [[ "$ans" =~ ^[0-9]+$ ]] && [[ "$ans" -ge 1 && "$ans" -le 65535 ]]; then
        if [[ "$ans" == "80" ]]; then
          loge "Порт 80 занят ACME/HTTP. Выберите другой."
          continue
        fi
        XRAY_PUBLIC_PORT_VAL="$ans"
        break
      else
        loge "Некорректный порт. Повторите ввод."
      fi
    done
    while true; do
      ans=""
      local mhint
      if [[ -n "$cur_mt_pub" ]]; then mhint="редеплой: ${cur_mt_pub}"; else mhint="по умолчанию: ${XRAY_PUBLIC_PORT_VAL}"; fi
      read -rp "MTProto public TCP [${mhint}]: " ans || true
      ans="${ans// /}"
      if [[ -z "$ans" ]]; then
        MTPROTO_PUBLIC_PORT_VAL="${cur_mt_pub:-$XRAY_PUBLIC_PORT_VAL}"
        break
      elif [[ "$ans" =~ ^[0-9]+$ ]] && [[ "$ans" -ge 1 && "$ans" -le 65535 ]]; then
        if [[ "$ans" == "80" ]]; then
          loge "Порт 80 занят ACME/HTTP. Выберите другой."
          continue
        fi
        MTPROTO_PUBLIC_PORT_VAL="$ans"
        break
      else
        loge "Некорректный порт. Повторите ввод."
      fi
    done
  fi

  if [[ "$XRAY_PUBLIC_PORT_VAL" == "$MTPROTO_PUBLIC_PORT_VAL" ]]; then
    logi "Xray+MTProto public ${XRAY_PUBLIC_PORT_VAL}/tcp — SNI demux через nginx"
    if [[ "$XRAY_PUBLIC_PORT_VAL" == "$PANEL_HTTPS_PORT_VAL" ]]; then
      logi "Панель тоже на ${PANEL_HTTPS_PORT_VAL} — войдёт в demux по SNI (${PANEL_DOMAIN_VAL:-WG_HOST})"
    fi
  else
    logi "Xray public ${XRAY_PUBLIC_PORT_VAL}/tcp (direct), MTProto public ${MTPROTO_PUBLIC_PORT_VAL}/tcp (direct)"
  fi
  # Internal listen ports allocated by panel; keep XRAY_PORT empty/auto in .env
  XRAY_PORT_VAL=""

  # --- WireGuard / AWG UDP ---
  if [[ "$NONINTERACTIVE" == "1" ]]; then
    if [[ -n "${AWG_WG_PORT:-}" ]]; then
      WG_PORT_VAL="$AWG_WG_PORT"
      if is_port_in_use "$WG_PORT_VAL" udp \
        || [[ "$WG_PORT_VAL" == "$PANEL_HTTPS_PORT_VAL" ]] \
        || [[ "$WG_PORT_VAL" == "$XRAY_PORT_VAL" ]]; then
        logw "AWG UDP ${WG_PORT_VAL} недоступен — случайный"
        WG_PORT_VAL=$(random_free_port udp "$PANEL_HTTPS_PORT_VAL" "$XRAY_PORT_VAL") \
          || { loge "Нет свободного UDP для AWG"; exit 1; }
      fi
    else
      # first_def empty → random when no cur
      assign_port_or_keep WG_PORT_VAL udp "$cur_wg" "" \
        "AWG UDP" 1 "$PANEL_HTTPS_PORT_VAL" "$XRAY_PORT_VAL" \
        || { loge "Нет свободного UDP для AWG"; exit 1; }
    fi
  else
    ans=""
    local whint
    if [[ -n "$cur_wg" ]]; then
      whint="редеплой: ${cur_wg}"
    else
      whint="по умолчанию: случайный ${PORT_RAND_MIN}-${PORT_RAND_MAX}"
    fi
    read -rp "AWG UDP [${whint}]: " ans || true
    ans="${ans// /}"
    if [[ -z "$ans" ]]; then
      assign_port_or_keep WG_PORT_VAL udp "$cur_wg" "" \
        "AWG UDP" 1 "$PANEL_HTTPS_PORT_VAL" "$XRAY_PORT_VAL" \
        || { loge "Нет свободного UDP для AWG"; exit 1; }
    elif [[ "$ans" =~ ^[0-9]+$ ]] && [[ "$ans" -ge 1 && "$ans" -le 65535 ]]; then
      WG_PORT_VAL="$ans"
      if is_port_in_use "$WG_PORT_VAL" udp \
        || [[ "$WG_PORT_VAL" == "$PANEL_HTTPS_PORT_VAL" ]] \
        || [[ "$WG_PORT_VAL" == "$XRAY_PORT_VAL" ]]; then
        logw "AWG UDP ${WG_PORT_VAL} занят — случайный"
        WG_PORT_VAL=$(random_free_port udp "$PANEL_HTTPS_PORT_VAL" "$XRAY_PORT_VAL") \
          || { loge "Нет свободного UDP для AWG"; exit 1; }
      fi
    else
      logw "Некорректный порт"
      assign_port_or_keep WG_PORT_VAL udp "$cur_wg" "" \
        "AWG UDP" 1 "$PANEL_HTTPS_PORT_VAL" "$XRAY_PORT_VAL" \
        || { loge "Нет свободного UDP для AWG"; exit 1; }
    fi
  fi
  logi "AWG: ${WG_PORT_VAL}/udp"
}

detect_service_enabled_default() {
  # detect_service_enabled_default dns|xray|mtproto → prints y or n for confirm_yn default
  local kind="$1" conf_key container def="y"
  case "$kind" in
    dns)
      conf_key=ENABLE_DNS
      container=amnezia-dns
      ;;
    xray)
      conf_key=ENABLE_XRAY
      container=amnezia-xray
      ;;
    mtproto)
      conf_key=ENABLE_MTPROTO
      container=amnezia-mtproto
      ;;
    *) echo y; return 0 ;;
  esac
  local prev
  prev=$(read_install_conf_val "$conf_key")
  if [[ "$prev" == "0" || "$prev" == "1" ]]; then
    [[ "$prev" == "1" ]] && echo y || echo n
    return 0
  fi
  if is_redeploy; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$container"; then
      echo y
    else
      echo n
    fi
    return 0
  fi
  echo y
}

free_port_80() {
  logi "Освобождаю порт 80 для ACME..."
  # rm (not only stop): a stopped orphan named nginx still blocks compose up
  docker rm -f nginx certbot 2>/dev/null || true
  if is_port_in_use 80; then
    logw "Порт 80 всё ещё занят — ACME standalone может не сработать"
  fi
}

volume_name_certbot() {
  echo "${COMPOSE_PROJECT_NAME}_certbot_conf"
}

# Min remaining lifetime before we refuse to reuse (days). Domain ≈14, IP shortlived ≈1.
CERT_REUSE_MIN_DAYS_DOMAIN="${AWG_SSL_REUSE_MIN_DAYS:-14}"
CERT_REUSE_MIN_DAYS_IP="${AWG_SSL_REUSE_MIN_DAYS_IP:-1}"

# Filled by discover_reusable_certs() — first good candidate used as menu default.
REUSE_SSL_NAME=""
REUSE_SSL_DIR=""
REUSE_SSL_EXPIRES=""
REUSE_SSL_SOURCE=""

cert_pair_usable() {
  # cert_pair_usable DIR [min_days]
  local dir="$1"
  local min_days="${2:-7}"
  local pem="${dir}/fullchain.pem"
  local key="${dir}/privkey.pem"
  [[ -f "$pem" && -f "$key" && -s "$pem" && -s "$key" ]] || return 1
  command -v openssl >/dev/null 2>&1 || return 1
  openssl x509 -in "$pem" -noout -checkend $((min_days * 86400)) >/dev/null 2>&1
}

cert_not_after() {
  local pem="$1"
  openssl x509 -in "$pem" -noout -enddate 2>/dev/null | cut -d= -f2-
}

cert_cn_or_name() {
  # Prefer leaf CN; fall back to directory basename.
  local pem="$1" fallback="$2"
  local cn
  cn=$(openssl x509 -in "$pem" -noout -subject 2>/dev/null \
    | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,\/]*\).*/\1/p' | head -1 | tr -d ' ')
  if [[ -n "$cn" ]]; then
    echo "$cn"
  else
    echo "$fallback"
  fi
}

apply_reuse_from_dir() {
  # apply_reuse_from_dir NAME SRC_DIR — copy into CERT_HOST_DIR + inject compose volume
  local name="$1"
  local src="$2"
  local dest="${CERT_HOST_DIR}/${name}"
  mkdir -p "$dest"
  if [[ "$(readlink -f "$src" 2>/dev/null || echo "$src")" != "$(readlink -f "$dest" 2>/dev/null || echo "$dest")" ]]; then
    cp -f "${src}/fullchain.pem" "${dest}/fullchain.pem"
    cp -f "${src}/privkey.pem" "${dest}/privkey.pem"
  fi
  chmod 644 "${dest}/fullchain.pem" 2>/dev/null || true
  chmod 600 "${dest}/privkey.pem" 2>/dev/null || true
  inject_certs_to_volume "$name" "$dest" || return 1
  SSL_MODE="acme"
  SSL_HOST="$name"
  PANEL_DOMAIN_VAL="$name"
  logi "SSL: переиспользован ${name} ← ${src}"
  return 0
}

list_certbot_volumes() {
  # Prefer project volume first, then any *certbot_conf leftover (e.g. *-entry_*).
  local primary other
  primary=$(volume_name_certbot)
  echo "$primary"
  while IFS= read -r other; do
    [[ -n "$other" && "$other" != "$primary" ]] && echo "$other"
  done < <(docker volume ls -q 2>/dev/null | grep -E 'certbot_conf$' || true)
}

export_certs_from_volume() {
  # export_certs_from_volume DOMAIN DEST [VOLUME]
  local domain="$1" dest="$2" vol="${3:-}"
  local v
  mkdir -p "$dest"
  if [[ -n "$vol" ]]; then
    docker volume inspect "$vol" >/dev/null 2>&1 || return 1
    docker run --rm \
      -v "${vol}:/etc/letsencrypt:ro" \
      -v "${dest}:/out" \
      alpine:3.20 sh -c "
        set -e
        src='/etc/letsencrypt/live/${domain}'
        if [ ! -f \"\$src/fullchain.pem\" ] || [ ! -f \"\$src/privkey.pem\" ]; then
          exit 1
        fi
        cp \"\$src/fullchain.pem\" /out/fullchain.pem
        cp \"\$src/privkey.pem\" /out/privkey.pem
      " >/dev/null 2>&1
    return $?
  fi
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    if export_certs_from_volume "$domain" "$dest" "$v"; then
      return 0
    fi
  done < <(list_certbot_volumes)
  return 1
}

installcert_from_acme() {
  # Copy already-issued acme.sh cert into host dir (no LE request).
  local name="$1" dest_dir="$2"
  local reload_cmd="docker exec nginx nginx -s reload 2>/dev/null || true"
  mkdir -p "$dest_dir"
  "$(acme_bin)" --install-cert -d "$name" \
    --key-file "${dest_dir}/privkey.pem" \
    --fullchain-file "${dest_dir}/fullchain.pem" \
    --reloadcmd "$reload_cmd" >/dev/null 2>&1
}

remember_reuse_candidate() {
  # remember_reuse_candidate NAME DIR SOURCE [min_days]
  local name="$1" dir="$2" source="$3" min_days="${4:-$CERT_REUSE_MIN_DAYS_DOMAIN}"
  [[ -n "$name" && -n "$dir" ]] || return 1
  cert_pair_usable "$dir" "$min_days" || return 1
  # Keep the first (highest priority) candidate.
  if [[ -n "$REUSE_SSL_NAME" ]]; then
    return 0
  fi
  REUSE_SSL_NAME="$name"
  REUSE_SSL_DIR="$dir"
  REUSE_SSL_SOURCE="$source"
  REUSE_SSL_EXPIRES=$(cert_not_after "${dir}/fullchain.pem")
  return 0
}

discover_reusable_certs() {
  REUSE_SSL_NAME=""
  REUSE_SSL_DIR=""
  REUSE_SSL_EXPIRES=""
  REUSE_SSL_SOURCE=""
  local name="" dir="" tmp v live hint min_d

  # 1) Last install / env hints
  for hint in \
    "$(grep -E '^SSL_HOST=' "${CONF_DIR}/install.conf" 2>/dev/null | cut -d= -f2-)" \
    "$(grep -E '^PANEL_DOMAIN=' "${CONF_DIR}/install.conf" 2>/dev/null | cut -d= -f2-)" \
    "$(grep -E '^PANEL_DOMAIN=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2-)" \
    "$(grep -E '^SSL_HOST=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2-)"; do
    hint="${hint//$'\r'/}"
    [[ -z "$hint" || "$hint" == "127.0.0.1" || "$hint" == "localhost" ]] && continue
    if is_ipv4 "$hint"; then
      min_d="$CERT_REUSE_MIN_DAYS_IP"
    else
      min_d="$CERT_REUSE_MIN_DAYS_DOMAIN"
    fi
    for dir in \
      "${CERT_HOST_DIR}/${hint}" \
      "/root/cert/${hint}"; do
      remember_reuse_candidate "$hint" "$dir" "host:${dir}" "$min_d" && return 0
    done
    if is_ipv4 "$hint"; then
      remember_reuse_candidate "$hint" "${CERT_HOST_DIR}/ip" "host:${CERT_HOST_DIR}/ip" "$min_d" && return 0
    fi
    tmp=$(mktemp -d)
    if export_certs_from_volume "$hint" "$tmp" && cert_pair_usable "$tmp" "$min_d"; then
      mkdir -p "${CERT_HOST_DIR}/${hint}"
      cp "${tmp}/fullchain.pem" "${CERT_HOST_DIR}/${hint}/fullchain.pem"
      cp "${tmp}/privkey.pem" "${CERT_HOST_DIR}/${hint}/privkey.pem"
      rm -rf "$tmp"
      remember_reuse_candidate "$hint" "${CERT_HOST_DIR}/${hint}" "volume" "$min_d" && return 0
    fi
    rm -rf "$tmp"
  done

  # 2) Host directories under /root/cert (incl. amnezia-wg-easy/<name>)
  local pem
  while IFS= read -r pem; do
    [[ -f "$pem" ]] || continue
    dir=$(dirname "$pem")
    name=$(basename "$dir")
    [[ "$name" == "custom" || "$name" == "ip" || "$name" == "live" ]] && continue
    if [[ -f "${dir}/fullchain.pem" ]]; then
      name=$(cert_cn_or_name "${dir}/fullchain.pem" "$name")
    fi
    if is_ipv4 "$name"; then
      min_d="$CERT_REUSE_MIN_DAYS_IP"
    else
      min_d="$CERT_REUSE_MIN_DAYS_DOMAIN"
    fi
    [[ -f "${dir}/privkey.pem" ]] || continue
    remember_reuse_candidate "$name" "$dir" "host:${dir}" "$min_d" && return 0
  done < <(find /root/cert -type f -name fullchain.pem 2>/dev/null | head -50)

  # 3) Any docker certbot_conf volumes → live/*
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    live=$(docker run --rm -v "${v}:/etc/letsencrypt:ro" alpine:3.20 \
      sh -c 'ls -1 /etc/letsencrypt/live 2>/dev/null' 2>/dev/null || true)
    for name in $live; do
      [[ "$name" == "README" ]] && continue
      if is_ipv4 "$name"; then
        min_d="$CERT_REUSE_MIN_DAYS_IP"
      else
        min_d="$CERT_REUSE_MIN_DAYS_DOMAIN"
      fi
      tmp=$(mktemp -d)
      if export_certs_from_volume "$name" "$tmp" "$v" && cert_pair_usable "$tmp" "$min_d"; then
        mkdir -p "${CERT_HOST_DIR}/${name}"
        cp "${tmp}/fullchain.pem" "${CERT_HOST_DIR}/${name}/fullchain.pem"
        cp "${tmp}/privkey.pem" "${CERT_HOST_DIR}/${name}/privkey.pem"
        rm -rf "$tmp"
        remember_reuse_candidate "$name" "${CERT_HOST_DIR}/${name}" "volume:${v}" "$min_d" && return 0
      fi
      rm -rf "$tmp"
    done
  done < <(list_certbot_volumes)

  # 4) acme.sh issued domains
  if [[ -d "${ACME_HOME}" ]]; then
    for dir in "${ACME_HOME}"/*_ecc "${ACME_HOME}"/*_rsa; do
      [[ -d "$dir" ]] || continue
      name=$(basename "$dir")
      name="${name%_ecc}"
      name="${name%_rsa}"
      [[ -z "$name" || "$name" == "ca" ]] && continue
      if is_ipv4 "$name"; then
        min_d="$CERT_REUSE_MIN_DAYS_IP"
      else
        min_d="$CERT_REUSE_MIN_DAYS_DOMAIN"
      fi
      tmp=$(mktemp -d)
      install_acme || true
      if installcert_from_acme "$name" "$tmp" && cert_pair_usable "$tmp" "$min_d"; then
        mkdir -p "${CERT_HOST_DIR}/${name}"
        cp "${tmp}/fullchain.pem" "${CERT_HOST_DIR}/${name}/fullchain.pem"
        cp "${tmp}/privkey.pem" "${CERT_HOST_DIR}/${name}/privkey.pem"
        rm -rf "$tmp"
        remember_reuse_candidate "$name" "${CERT_HOST_DIR}/${name}" "acme.sh" "$min_d" && return 0
      fi
      rm -rf "$tmp"
    done
  fi

  return 1
}

try_reuse_certificate() {
  # try_reuse_certificate NAME HOST_DIR MIN_DAYS
  # Looks in: HOST_DIR → /root/cert/NAME → all certbot volumes → acme.sh. On success injects volume.
  local name="$1" host_dir="$2" min_days="${3:-14}"
  local tmp v

  if [[ "${AWG_SSL_FORCE_RENEW:-0}" == "1" ]]; then
    logw "AWG_SSL_FORCE_RENEW=1 — пропуск переиспользования сертификата"
    return 1
  fi

  # Prefer previously discovered candidate for this name
  if [[ -n "$REUSE_SSL_NAME" && "$REUSE_SSL_NAME" == "$name" && -n "$REUSE_SSL_DIR" ]] \
    && cert_pair_usable "$REUSE_SSL_DIR" "$min_days"; then
    apply_reuse_from_dir "$name" "$REUSE_SSL_DIR" || return 1
    return 0
  fi

  local cand
  for cand in \
    "$host_dir" \
    "${CERT_HOST_DIR}/${name}" \
    "/root/cert/${name}" \
    "${CERT_HOST_DIR}/ip"; do
    if cert_pair_usable "$cand" "$min_days"; then
      apply_reuse_from_dir "$name" "$cand" || return 1
      return 0
    fi
  done

  tmp=$(mktemp -d)
  while IFS= read -r v; do
    [[ -z "$v" ]] && continue
    if export_certs_from_volume "$name" "$tmp" "$v" && cert_pair_usable "$tmp" "$min_days"; then
      logi "Переиспользую сертификат из Docker volume ${v}/live/${name}"
      apply_reuse_from_dir "$name" "$tmp" || { rm -rf "$tmp"; return 1; }
      rm -rf "$tmp"
      return 0
    fi
  done < <(list_certbot_volumes)
  rm -rf "$tmp"

  if [[ -x "$(acme_bin)" ]] || [[ -x "${ACME_HOME}/acme.sh" ]]; then
    install_acme || true
    if [[ -d "${ACME_HOME}/${name}_ecc" || -d "${ACME_HOME}/${name}" \
      || -d "${ACME_HOME}/${name}_rsa" ]]; then
      if installcert_from_acme "$name" "$host_dir" && cert_pair_usable "$host_dir" "$min_days"; then
        logi "Найден сертификат acme.sh для ${name} — устанавливаю без повторного выпуска"
        inject_certs_to_volume "$name" "$host_dir" || return 1
        SSL_MODE="acme"
        SSL_HOST="$name"
        PANEL_DOMAIN_VAL="$name"
        return 0
      fi
    fi
  fi

  return 1
}

setup_reuse_detected_certificate() {
  if [[ -z "$REUSE_SSL_NAME" || -z "$REUSE_SSL_DIR" ]]; then
    discover_reusable_certs || return 1
  fi
  [[ -n "$REUSE_SSL_NAME" && -n "$REUSE_SSL_DIR" ]] || return 1
  apply_reuse_from_dir "$REUSE_SSL_NAME" "$REUSE_SSL_DIR"
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
  local host_dir="${CERT_HOST_DIR}/${domain}"
  mkdir -p "$host_dir"

  if try_reuse_certificate "$domain" "$host_dir" "$CERT_REUSE_MIN_DAYS_DOMAIN"; then
    SSL_MODE="acme"
    SSL_HOST="$domain"
    PANEL_DOMAIN_VAL="$domain"
    return 0
  fi

  install_acme || return 1
  free_port_80
  ensure_acme_le_account "$email"
  logi "Выпуск LE-сертификата для домена ${domain} (без --force; повторный выпуск только если нет действующего)..."
  # Do NOT pass --force: acme.sh will reuse its own cert when still valid.
  local issue_ok=0
  if [[ "${AWG_SSL_FORCE_RENEW:-0}" == "1" ]]; then
    logw "Принудительный выпуск (AWG_SSL_FORCE_RENEW=1)"
    "$(acme_bin)" --issue -d "$domain" --standalone --httpport 80 --force && issue_ok=1
  else
    "$(acme_bin)" --issue -d "$domain" --standalone --httpport 80 && issue_ok=1
  fi
  if [[ "$issue_ok" -ne 1 ]]; then
    # Last chance: maybe issue failed due to rate limit but local cert still usable with shorter TTL
    if try_reuse_certificate "$domain" "$host_dir" 1; then
      logw "Выпуск не удался — использую имеющийся сертификат (осталось >=1 дня)"
      SSL_MODE="acme"
      SSL_HOST="$domain"
      PANEL_DOMAIN_VAL="$domain"
      return 0
    fi
    loge "Не удалось выпустить сертификат для ${domain} (порт 80 должен быть открыт)"
    return 1
  fi
  local reload_cmd="docker exec nginx nginx -s reload 2>/dev/null || true"
  "$(acme_bin)" --install-cert -d "$domain" \
    --key-file "${host_dir}/privkey.pem" \
    --fullchain-file "${host_dir}/fullchain.pem" \
    --reloadcmd "$reload_cmd" || true
  inject_certs_to_volume "$domain" "$host_dir" || return 1
  "$(acme_bin)" --upgrade --auto-upgrade >/dev/null 2>&1 || true
  SSL_MODE="acme"
  SSL_HOST="$domain"
  PANEL_DOMAIN_VAL="$domain"
  return 0
}

setup_ip_certificate() {
  local ipv4="$1"
  local ipv6="${2:-}"
  local host_dir="${CERT_HOST_DIR}/ip"
  mkdir -p "$host_dir"

  if try_reuse_certificate "$ipv4" "$host_dir" "$CERT_REUSE_MIN_DAYS_IP"; then
    SSL_MODE="acme"
    SSL_HOST="$ipv4"
    PANEL_DOMAIN_VAL="$ipv4"
    return 0
  fi

  install_acme || return 1
  free_port_80
  local domain_args=(-d "$ipv4")
  if [[ -n "$ipv6" ]] && is_ipv6 "$ipv6"; then
    domain_args+=(-d "$ipv6")
  fi
  ensure_acme_le_account "${CERTBOT_EMAIL_VAL:-}"
  logi "Выпуск LE IP-сертификата (shortlived ~6 дней) для ${ipv4}..."
  local issue_ok=0
  if [[ "${AWG_SSL_FORCE_RENEW:-0}" == "1" ]]; then
    "$(acme_bin)" --issue \
      "${domain_args[@]}" \
      --standalone \
      --server letsencrypt \
      --certificate-profile shortlived \
      --days 6 \
      --httpport 80 \
      --force && issue_ok=1
  else
    "$(acme_bin)" --issue \
      "${domain_args[@]}" \
      --standalone \
      --server letsencrypt \
      --certificate-profile shortlived \
      --days 6 \
      --httpport 80 && issue_ok=1
  fi
  if [[ "$issue_ok" -ne 1 ]]; then
    if try_reuse_certificate "$ipv4" "$host_dir" 0; then
      logw "Выпуск IP-серта не удался — использую имеющийся (ещё не истёк)"
      SSL_MODE="acme"
      SSL_HOST="$ipv4"
      PANEL_DOMAIN_VAL="$ipv4"
      return 0
    fi
    loge "Не удалось выпустить IP-сертификат (нужен открытый TCP/80 с интернета)"
    return 1
  fi
  local reload_cmd="docker exec nginx nginx -s reload 2>/dev/null || true"
  "$(acme_bin)" --install-cert -d "$ipv4" \
    --key-file "${host_dir}/privkey.pem" \
    --fullchain-file "${host_dir}/fullchain.pem" \
    --reloadcmd "$reload_cmd" || true
  inject_certs_to_volume "$ipv4" "$host_dir" || return 1
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
  local ssl_choice="" have_reuse=0 default_choice="2" prompt_hint="1-4, Enter=2"
  SSL_SCHEME="https"

  # Scan disk/volumes/acme BEFORE the menu so Enter can mean "reuse".
  if [[ "${AWG_SSL_FORCE_RENEW:-0}" != "1" ]] && discover_reusable_certs; then
    have_reuse=1
    default_choice="0"
    prompt_hint="0-4, Enter=0 reuse"
    logi "Найден действующий сертификат: ${REUSE_SSL_NAME} (до ${REUSE_SSL_EXPIRES:-?}, источник ${REUSE_SSL_SOURCE})"
  fi

  echo ""
  echo -e "${green}════════ SSL (рекомендуется) ════════${plain}"
  if [[ "$have_reuse" -eq 1 ]]; then
    echo -e "${green}0.${plain} Переиспользовать ${REUSE_SSL_NAME} (до ${REUSE_SSL_EXPIRES:-?}) — по умолчанию, без LE"
  fi
  echo -e "${green}1.${plain} Let's Encrypt для домена (90 дней)"
  echo -e "${green}2.${plain} Let's Encrypt для IP (shortlived ~6 дней)"
  echo -e "${green}3.${plain} Свой сертификат (пути к файлам)"
  echo -e "${green}4.${plain} Пропустить (self-signed)"
  echo -e "${blue}Для 1 и 2 нужен открытый TCP/80 (не требуется при пункте 0).${plain}"

  if [[ "$NONINTERACTIVE" == "1" ]]; then
    case "${AWG_SSL_MODE:-}" in
      reuse|existing)
        ssl_choice="0"
        ;;
      domain) ssl_choice="1" ;;
      ip) ssl_choice="2" ;;
      custom) ssl_choice="3" ;;
      none|selfsigned) ssl_choice="4" ;;
      "")
        if [[ "$have_reuse" -eq 1 ]]; then
          ssl_choice="0"
        else
          ssl_choice="2"
        fi
        ;;
      *)
        if [[ "$have_reuse" -eq 1 ]]; then
          ssl_choice="0"
        else
          ssl_choice="2"
        fi
        ;;
    esac
  else
    read -rp "Выбор [${prompt_hint}]: " ssl_choice || true
    ssl_choice="${ssl_choice// /}"
    if [[ -z "$ssl_choice" ]]; then
      ssl_choice="$default_choice"
    fi
  fi

  case "$ssl_choice" in
    0)
      if [[ "$have_reuse" -ne 1 ]]; then
        loge "Нет найденного сертификата для переиспользования"
        SSL_MODE="selfsigned"
        SSL_HOST="${SERVER_IP:-127.0.0.1}"
        PANEL_DOMAIN_VAL="${SERVER_IP:-127.0.0.1}"
        return 0
      fi
      if setup_reuse_detected_certificate; then
        logi "SSL: переиспользован ${SSL_HOST} (без обращения к Let's Encrypt)"
      else
        logw "Не удалось переиспользовать — выберите 1/2 или повторите"
        SSL_MODE="selfsigned"
        SSL_HOST="${REUSE_SSL_NAME:-$SERVER_IP}"
        PANEL_DOMAIN_VAL="${SSL_HOST}"
      fi
      ;;
    1)
      local domain="" email=""
      # Prefill with discovered / previous domain
      local domain_default="${REUSE_SSL_NAME:-}"
      if [[ -z "$domain_default" ]] || is_ipv4 "$domain_default"; then
        domain_default=$(grep -E '^PANEL_DOMAIN=' "${CONF_DIR}/install.conf" 2>/dev/null | cut -d= -f2- || true)
      fi
      if [[ -z "$domain_default" ]] || is_ipv4 "$domain_default"; then
        domain_default=""
      fi
      prompt_or_default domain "Домен (A-запись на этот сервер): " "$domain_default" AWG_DOMAIN
      prompt_or_default email "Email для Let's Encrypt (user@domain.tld, Enter = без контакта): " "" AWG_EMAIL
      if [[ -z "$domain" ]] || ! is_domain "$domain"; then
        loge "Некорректный домен — self-signed"
        SSL_MODE="selfsigned"
        SSL_HOST="${SERVER_IP:-127.0.0.1}"
        PANEL_DOMAIN_VAL="${SERVER_IP:-127.0.0.1}"
        return 0
      fi
      if [[ -n "$email" ]] && ! is_valid_le_email "$email"; then
        logw "Email «${email}» отклонён LE (нужен domain с точкой) — выпускаю без контакта"
        email=""
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
      prompt_or_default CERTBOT_EMAIL_VAL "Email для LE (user@domain.tld, Enter = без контакта): " "" AWG_EMAIL
      if [[ -n "${CERTBOT_EMAIL_VAL}" ]] && ! is_valid_le_email "${CERTBOT_EMAIL_VAL}"; then
        logw "Email «${CERTBOT_EMAIL_VAL}» отклонён LE — выпускаю без контакта"
        CERTBOT_EMAIL_VAL=""
      fi
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

# After SSL we know PANEL_DOMAIN: explain demux model (no soft-force off 443 for bare IP).
reconcile_panel_port_for_domain() {
  local shared=0
  if [[ "$PANEL_HTTPS_PORT_VAL" == "$XRAY_PUBLIC_PORT_VAL" ]] \
    || [[ "$PANEL_HTTPS_PORT_VAL" == "$MTPROTO_PUBLIC_PORT_VAL" ]]; then
    shared=1
  fi
  if [[ "$shared" -ne 1 ]]; then
    return 0
  fi
  if is_ip_literal "${PANEL_DOMAIN_VAL}"; then
    logi "Панель IP + общий порт ${PANEL_HTTPS_PORT_VAL}: Xray/MT по SNI; без SNI/чужой SNI → заглушка+/panel"
  else
    logi "Панель FQDN + общий порт ${PANEL_HTTPS_PORT_VAL}: Xray/MT/панель по своим SNI; заглушка+/panel только на SNI панели"
  fi
}

normalize_path_prefix() {
  local raw="${1:-}" fallback="${2:-/panel}"
  raw="${raw//' '/}"
  [[ -z "$raw" ]] && raw="$fallback"
  [[ "$raw" != /* ]] && raw="/${raw}"
  raw="${raw%/}"
  [[ -z "$raw" ]] && raw="$fallback"
  printf '%s' "$raw"
}

# Strip https://, paths, ports, backslashes → bare hostname (lowercase).
normalize_sni_host() {
  local raw="${1:-}"
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "
import re, sys
s = (sys.argv[1] or '').strip().replace(chr(92), '/')
m = re.match(r'^(https?):/+(.+)$', s, flags=re.I)
if m:
  s = m.group(2)
s = s.split('/')[0].split('?')[0].split('#')[0]
if '@' in s:
  s = s.rsplit('@', 1)[-1]
if s.startswith('[') and ']' in s:
  s = s[1:s.index(']')]
elif s.count(':') == 1:
  host, port = s.rsplit(':', 1)
  if port.isdigit():
    s = host
s = s.strip('.').strip().lower()
print(s)
" "$raw" 2>/dev/null || true
    return 0
  fi
  raw="${raw//'\'/}"
  raw=$(printf '%s' "$raw" | sed -E 's#^[Hh][Tt][Tt][Pp][Ss]?:/+##')
  raw="${raw%%/*}"; raw="${raw%%\?*}"; raw="${raw%%#*}"
  raw="${raw##*@}"
  if [[ "$raw" == *:* && "$raw" != \[* ]]; then
    local maybe_port="${raw##*:}"
    if [[ "$maybe_port" =~ ^[0-9]+$ ]]; then
      raw="${raw%:*}"
    fi
  fi
  raw="${raw%.}"
  printf '%s' "$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')"
}

# Auto bank/finder must skip .ru / .su / .рф (xn--p1ai). Manual user entry may use them.
sni_is_blocked_tld() {
  local h
  h=$(normalize_sni_host "$1")
  [[ -z "$h" ]] && return 1
  if [[ "$h" =~ \.(ru|su|xn--p1ai)$ ]]; then
    return 0
  fi
  case "$h" in
    *.рф) return 0 ;;
  esac
  return 1
}

# Reality dest: TLS with ALPN h2 (same bar as SNI Finder / bank probe).
sni_reality_ok() {
  local host
  host=$(normalize_sni_host "$1")
  [[ -z "$host" ]] && return 1
  if ! command -v python3 >/dev/null 2>&1; then
    local code
    code=$(curl -4 -skI -o /dev/null -w '%{http_code}' --http2 --connect-timeout 3 --max-time 8 \
      "https://${host}/" 2>/dev/null || echo 000)
    case "$code" in
      2*|3*) return 0 ;;
    esac
    return 1
  fi
  python3 -c "
import socket, ssl, sys
host = sys.argv[1]
try:
  ctx = ssl.create_default_context()
  ctx.set_alpn_protocols(['h2', 'http/1.1'])
  ctx.check_hostname = False
  ctx.verify_mode = ssl.CERT_NONE
  with socket.create_connection((host, 443), timeout=8) as sock:
    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
      alpn = ssock.selected_alpn_protocol()
      if alpn == 'h2':
        sys.exit(0)
except Exception:
  pass
sys.exit(1)
" "$host" 2>/dev/null
}

# Random checked host from bank (skips blocked TLDs). Prefer mirror-bank, else sni-bank.
pick_checked_bank_host() {
  local prefer="${1:-mirror}" bank="" host=""
  if [[ "$prefer" == "sni" ]]; then
    bank="${INSTALL_DIR}/config/sni-bank.seed.json"
    [[ -f "$bank" ]] || bank="${INSTALL_DIR}/config/mirror-bank.seed.json"
  else
    bank="${INSTALL_DIR}/config/mirror-bank.seed.json"
    [[ -f "$bank" ]] || bank="${INSTALL_DIR}/config/sni-bank.seed.json"
  fi
  if [[ -f "$bank" ]] && command -v python3 >/dev/null 2>&1; then
    host=$(python3 -c "
import json, random, socket, ssl, sys, re
path = sys.argv[1]
blocked = re.compile(r'\\.(ru|su|xn--p1ai)$', re.I)
try:
  raw = json.load(open(path))
  domains = raw if isinstance(raw, list) else list(raw.get('domains') or [])
except Exception:
  domains = []
domains = [str(d).strip().lower().rstrip('.') for d in domains if str(d).strip()]
domains = [d for d in domains if d and not blocked.search(d) and not d.endswith('.рф')]
random.shuffle(domains)

def reality_ok(host):
  try:
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(['h2', 'http/1.1'])
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, 443), timeout=8) as sock:
      with ctx.wrap_socket(sock, server_hostname=host) as ssock:
        return ssock.selected_alpn_protocol() == 'h2'
  except Exception:
    return False

for d in domains:
  if reality_ok(d):
    print(d)
    sys.exit(0)
" "$bank" 2>/dev/null || true)
  fi
  if [[ -z "$host" && -f "$bank" ]]; then
    while IFS= read -r cand; do
      cand=$(normalize_sni_host "$cand")
      [[ -z "$cand" ]] && continue
      sni_is_blocked_tld "$cand" && continue
      if sni_reality_ok "$cand"; then
        host="$cand"
        break
      fi
    done < <(grep -oE '"[^"]+\.[^"]+"' "$bank" | tr -d '"' || true)
  fi
  printf '%s' "${host:-www.sbb.ch}"
}

pick_default_mirror_host() {
  pick_checked_bank_host mirror
}

# Interactive mirror menu (style = SSL): 1=SNI Finder, 2=bank, else hostname.
prompt_mirror_host() {
  local choice="" host="" ok=0
  MIRROR_USE_SNI_VAL=0

  if [[ "$NONINTERACTIVE" == "1" ]]; then
    if [[ "${AWG_MIRROR_USE_SNI:-0}" == "1" ]]; then
      MIRROR_USE_SNI_VAL=1
      NGINX_MIRROR_HOST_VAL=$(normalize_sni_host "${AWG_NGINX_MIRROR_HOST:-}")
      [[ -z "$NGINX_MIRROR_HOST_VAL" ]] && NGINX_MIRROR_HOST_VAL=$(pick_checked_bank_host mirror)
    elif [[ -n "${AWG_NGINX_MIRROR_HOST:-}" ]]; then
      NGINX_MIRROR_HOST_VAL=$(normalize_sni_host "$AWG_NGINX_MIRROR_HOST")
    else
      NGINX_MIRROR_HOST_VAL=$(pick_checked_bank_host mirror)
    fi
    return 0
  fi

  while true; do
    echo ""
    echo -e "${green}════════ Зеркало корня / ════════${plain}"
    echo -e "${green}1.${plain} SNI Finder → зеркало после enable (по умолчанию; fallback банк)"
    echo -e "${green}2.${plain} Случайный из банка (с проверкой Reality TLS+h2)"
    echo -e "${blue}Enter=1; любой другой ввод (не цифра меню) = hostname вручную${plain}"
    read -rp "Выбор [1-2, Enter=1]: " choice || true
    choice="${choice#"${choice%%[![:space:]]*}"}"
    choice="${choice%"${choice##*[![:space:]]}"}"

    case "$choice" in
      ""|1)
        MIRROR_USE_SNI_VAL=1
        NGINX_MIRROR_HOST_VAL=$(pick_checked_bank_host mirror)
        logi "Зеркало временно ${NGINX_MIRROR_HOST_VAL}; после Xray/MT → SNI Finder"
        return 0
        ;;
      2)
        MIRROR_USE_SNI_VAL=0
        host=$(pick_checked_bank_host mirror)
        if [[ -z "$host" ]]; then
          logw "Банк не дал пригодный Reality-host — повторите выбор"
          continue
        fi
        NGINX_MIRROR_HOST_VAL="$host"
        logi "Зеркало из банка: ${NGINX_MIRROR_HOST_VAL}"
        return 0
        ;;
      *)
        if [[ "$choice" =~ ^[0-9]+$ ]]; then
          logw "Неизвестный пункт ${choice}"
          continue
        fi
        host=$(normalize_sni_host "$choice")
        if [[ -z "$host" || "$host" != *.* ]]; then
          logw "Некорректный hostname: «${choice}»"
          continue
        fi
        if sni_is_blocked_tld "$host"; then
          logi "Ручной SNI ${host} (.ru/.su/.рф) — допускаю только по вашему вводу"
        fi
        if ! sni_reality_ok "$host"; then
          logw "${host} не подходит для Reality (нужен TLS + ALPN h2) — снова меню (1/2) или другой host"
          continue
        fi
        MIRROR_USE_SNI_VAL=0
        NGINX_MIRROR_HOST_VAL="$host"
        logi "Зеркало вручную: ${NGINX_MIRROR_HOST_VAL}"
        return 0
        ;;
    esac
  done
}

prompt_webui_paths_and_mirror() {
  local ans="" cur_panel cur_sub redeploy=0
  cur_panel=$(panel_env_get WEBUI_PUBLIC_PREFIX)
  cur_sub=$(panel_env_get SUB_PUBLIC_PREFIX)
  is_redeploy && redeploy=1
  MIRROR_USE_SNI_VAL=0

  echo ""
  echo -e "${green}════════ Пути / зеркало ════════${plain}"

  if [[ "$NONINTERACTIVE" == "1" ]]; then
    WEBUI_PUBLIC_PREFIX_VAL=$(normalize_path_prefix "${AWG_WEBUI_PUBLIC_PREFIX:-${cur_panel:-/panel}}" /panel)
    SUB_PUBLIC_PREFIX_VAL=$(normalize_path_prefix "${AWG_SUB_PUBLIC_PREFIX:-${cur_sub:-/sub}}" /sub)
    NGINX_ROOT_BEHAVIOR_VAL="${AWG_NGINX_ROOT_BEHAVIOR:-mirror}"
    prompt_mirror_host
  else
    if [[ "$redeploy" -eq 1 && -n "$cur_panel" ]]; then
      read -rp "Путь панели [редеплой: ${cur_panel}]: " ans || true
    else
      read -rp "Путь панели [по умолчанию: /panel]: " ans || true
    fi
    ans="${ans//' '/}"
    if [[ -z "$ans" ]]; then
      WEBUI_PUBLIC_PREFIX_VAL=$(normalize_path_prefix "${cur_panel:-/panel}" /panel)
    else
      WEBUI_PUBLIC_PREFIX_VAL=$(normalize_path_prefix "$ans" /panel)
    fi

    ans=""
    if [[ "$redeploy" -eq 1 && -n "$cur_sub" ]]; then
      read -rp "Путь подписок [редеплой: ${cur_sub}]: " ans || true
    else
      read -rp "Путь подписок [по умолчанию: /sub]: " ans || true
    fi
    ans="${ans//' '/}"
    if [[ -z "$ans" ]]; then
      SUB_PUBLIC_PREFIX_VAL=$(normalize_path_prefix "${cur_sub:-/sub}" /sub)
    else
      SUB_PUBLIC_PREFIX_VAL=$(normalize_path_prefix "$ans" /sub)
    fi

    NGINX_ROOT_BEHAVIOR_VAL="mirror"
    prompt_mirror_host
  fi

  NGINX_MIRROR_HOST_VAL=$(normalize_sni_host "$NGINX_MIRROR_HOST_VAL")
  if [[ -z "$NGINX_MIRROR_HOST_VAL" ]]; then
    NGINX_MIRROR_HOST_VAL=$(pick_checked_bank_host mirror)
  fi
  if [[ "${MIRROR_USE_SNI_VAL:-0}" -eq 1 ]]; then
    logi "UI=${WEBUI_PUBLIC_PREFIX_VAL}/ sub=${SUB_PUBLIC_PREFIX_VAL}/ mirror=${NGINX_MIRROR_HOST_VAL} (→ SNI Finder после enable)"
  else
    logi "UI=${WEBUI_PUBLIC_PREFIX_VAL}/ sub=${SUB_PUBLIC_PREFIX_VAL}/ mirror=${NGINX_MIRROR_HOST_VAL}"
  fi
}

apply_mirror_from_sni_if_requested() {
  [[ "${MIRROR_USE_SNI_VAL:-0}" -eq 1 ]] || return 0
  local sni=""
  sni=$(api_curl GET /api/amnezia-xray 2>/dev/null \
    | sed -n 's/.*"sniStored"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  [[ -z "$sni" ]] && sni=$(api_curl GET /api/amnezia-xray 2>/dev/null \
    | sed -n 's/.*"sni"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  if [[ -z "$sni" ]]; then
    sni=$(api_curl GET /api/amnezia-mtproto 2>/dev/null \
      | sed -n 's/.*"sniStored"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  fi
  sni=$(normalize_sni_host "$sni")
  [[ -z "$sni" ]] && return 0
  if sni_is_blocked_tld "$sni"; then
    logw "SNI ${sni} (.ru/.su/.рф) — зеркало не беру из авто-SNI; банк"
    sni=$(pick_checked_bank_host mirror)
  fi
  if ! sni_reality_ok "$sni"; then
    logw "SNI ${sni} не Reality-ok — зеркало из банка"
    sni=$(pick_checked_bank_host mirror)
  fi
  [[ -z "$sni" ]] && return 0
  NGINX_MIRROR_HOST_VAL="$sni"
  env_set "${INSTALL_DIR}/.env" NGINX_MIRROR_HOST "$sni"
  logi "Зеркало → ${sni}"
  recreate_nginx_for_mirror() {
    local out="" attempt=1
    cd "$INSTALL_DIR" || return 0
    # shellcheck disable=SC1091
    set -a; source .env; set +a
    for attempt in 1 2 3; do
      if out=$(docker compose -f docker-compose.yml -f docker-compose.ports.yml up -d --force-recreate nginx 2>&1); then
        return 0
      fi
      if echo "$out" | grep -qiE 'already in use|Conflict|name "/?nginx"'; then
        logw "nginx name conflict при обновлении зеркала — docker rm -f nginx (попытка ${attempt})"
        docker rm -f nginx >/dev/null 2>&1 || true
        sleep 1
        continue
      fi
      logw "nginx recreate (mirror): ${out:0:200}"
      return 0
    done
  }
  recreate_nginx_for_mirror || true
}

write_env() {
  local envf="${INSTALL_DIR}/.env"
  if [[ ! -f "$envf" ]]; then
    cp "${INSTALL_DIR}/.env.example" "$envf"
  fi
  env_set "$envf" ADMIN_USERNAME "$ADMIN_USER"
  env_set "$envf" ADMIN_PASSWORD "$ADMIN_PASS"
  env_set "$envf" AWG_INSTALL_DIR "${INSTALL_DIR}"
  env_set "$envf" WG_HOST "${SERVER_IP:-$PANEL_DOMAIN_VAL}"
  env_set "$envf" PANEL_DOMAIN "$PANEL_DOMAIN_VAL"
  env_set "$envf" SSL_MODE "$SSL_MODE"
  env_set "$envf" WG_PORT "${WG_PORT_VAL}"
  env_set "$envf" PANEL_HTTPS_PORT "${PANEL_HTTPS_PORT_VAL}"
  env_set "$envf" XRAY_PUBLIC_PORT "${XRAY_PUBLIC_PORT_VAL}"
  env_set "$envf" MTPROTO_PUBLIC_PORT "${MTPROTO_PUBLIC_PORT_VAL}"
  env_set "$envf" WEBUI_PUBLIC_PREFIX "${WEBUI_PUBLIC_PREFIX_VAL}"
  env_set "$envf" SUB_PUBLIC_PREFIX "${SUB_PUBLIC_PREFIX_VAL}"
  env_set "$envf" NGINX_ROOT_BEHAVIOR "${NGINX_ROOT_BEHAVIOR_VAL:-mirror}"
  env_set "$envf" NGINX_MIRROR_HOST "${NGINX_MIRROR_HOST_VAL}"
  if [[ -n "${XRAY_PORT_VAL}" ]]; then
    env_set "$envf" XRAY_PORT "${XRAY_PORT_VAL}"
  fi
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
WG_PORT=${WG_PORT_VAL}
PANEL_HTTPS_PORT=${PANEL_HTTPS_PORT_VAL}
XRAY_PUBLIC_PORT=${XRAY_PUBLIC_PORT_VAL}
MTPROTO_PUBLIC_PORT=${MTPROTO_PUBLIC_PORT_VAL}
WEBUI_PUBLIC_PREFIX=${WEBUI_PUBLIC_PREFIX_VAL}
SUB_PUBLIC_PREFIX=${SUB_PUBLIC_PREFIX_VAL}
NGINX_MIRROR_HOST=${NGINX_MIRROR_HOST_VAL}
ENABLE_DNS=${ENABLE_DNS}
ENABLE_XRAY=${ENABLE_XRAY}
ENABLE_MTPROTO=${ENABLE_MTPROTO}
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
  logi "Записан ${envf} (HTTPS=${PANEL_HTTPS_PORT_VAL}, Xray pub=${XRAY_PUBLIC_PORT_VAL}, MT pub=${MTPROTO_PUBLIC_PORT_VAL}, WG=${WG_PORT_VAL}/udp, UI=${WEBUI_PUBLIC_PREFIX_VAL})"
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

panel_env_get() {
  local key="$1"
  grep -E "^${key}=" "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- | tr -d '\r' || true
}

panel_probe_host() {
  local domain
  domain=$(panel_env_get PANEL_DOMAIN)
  [[ -z "$domain" ]] && domain="${PANEL_DOMAIN_VAL}"
  [[ -z "$domain" ]] && domain="127.0.0.1"
  printf '%s' "$domain"
}

panel_probe_url() {
  local https_port host
  https_port=$(panel_env_get PANEL_HTTPS_PORT)
  https_port="${https_port:-${PANEL_HTTPS_PORT_VAL:-443}}"
  host=$(panel_probe_host)
  if is_ip_literal "$host"; then
    if [[ "$https_port" == "443" ]]; then
      echo "https://127.0.0.1"
    else
      echo "https://127.0.0.1:${https_port}"
    fi
  else
    if [[ "$https_port" == "443" ]]; then
      echo "https://${host}"
    else
      echo "https://${host}:${https_port}"
    fi
  fi
}

# Extra curl args so FQDN@443 demux gets correct SNI (default stream is :9 without it).
panel_curl_resolve_args() {
  local https_port host
  https_port=$(panel_env_get PANEL_HTTPS_PORT)
  https_port="${https_port:-${PANEL_HTTPS_PORT_VAL:-443}}"
  host=$(panel_probe_host)
  if ! is_ip_literal "$host"; then
    printf '%s\n' --resolve "${host}:${https_port}:127.0.0.1"
  fi
}

panel_api_prefix() {
  local p
  p=$(panel_env_get WEBUI_PUBLIC_PREFIX)
  p=$(normalize_path_prefix "${p:-${WEBUI_PUBLIC_PREFIX_VAL:-/panel}}" /panel)
  echo "${p}/api"
}

wait_panel() {
  local url
  local -a resolve=()
  mapfile -t resolve < <(panel_curl_resolve_args)
  url="$(panel_probe_url)$(normalize_path_prefix "${WEBUI_PUBLIC_PREFIX_VAL:-/panel}" /panel)/"
  logi "Ожидание панели ${url} ..."
  local i code=000
  for i in $(seq 1 60); do
    code=$(curl -sk "${resolve[@]}" -o /dev/null -w '%{http_code}' --max-time 3 "$url" || true)
    case "$code" in
      200|301|302|401) logi "Панель отвечает (HTTP ${code})"; return 0 ;;
    esac
    sleep 2
  done
  logw "Панель пока не ответила (последний код ${code})"
  return 1
}

api_curl() {
  local method="$1" path="$2" body="${3:-}"
  local url base cookie apiprefix
  local -a resolve=()
  mapfile -t resolve < <(panel_curl_resolve_args)
  base=$(panel_probe_url)
  apiprefix=$(panel_api_prefix)
  if [[ "$path" == /api/* ]]; then
    path="${apiprefix}${path#/api}"
  fi
  cookie="${CONF_DIR}/session.cj"
  local maxtime=120
  [[ "$path" == *"/amnezia-dns/enable"* ]] && maxtime=180
  if [[ -n "$body" ]]; then
    curl -sk "${resolve[@]}" -c "$cookie" -b "$cookie" -X "$method" "${base}${path}" \
      -H 'Content-Type: application/json' \
      -d "$body" --max-time "$maxtime"
  else
    curl -sk "${resolve[@]}" -c "$cookie" -b "$cookie" -X "$method" "${base}${path}" --max-time "$maxtime"
  fi
}

api_login() {
  local resp code
  local -a resolve=()
  mapfile -t resolve < <(panel_curl_resolve_args)
  resp=$(api_curl POST /api/session "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" || true)
  if echo "$resp" | grep -qi 'success\|username\|true\|{}' || [[ -f "${CONF_DIR}/session.cj" ]]; then
    code=$(curl -sk "${resolve[@]}" -b "${CONF_DIR}/session.cj" -o /dev/null -w '%{http_code}' --max-time 10 \
      "$(panel_probe_url)$(panel_api_prefix)/amnezia-xray" || true)
    if [[ "$code" == "200" || "$code" == "403" ]]; then
      return 0
    fi
  fi
  logw "Логин API не подтверждён: ${resp:0:200}"
  return 1
}

enable_dns() {
  logi "Включение Amnezia DNS..."
  local status profile_id="" resp
  status=$(api_curl GET /api/amnezia-dns || true)
  profile_id=$(printf '%s' "$status" | sed -n 's/.*"profileId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  if [[ -n "$profile_id" ]]; then
    logi "DNS: оставляю profileId=${profile_id}"
  else
    logi "DNS: profileId не задан — API возьмёт bank default"
  fi
  # Empty body → stored profile, else bank default (do not force catalog default on redeploy).
  # Enable can take minutes (Unbound pull/smoke); give curl enough time.
  resp=$(api_curl POST /api/amnezia-dns/enable '{}' || true)
  logi "DNS: ${resp:0:240}"
  if echo "$resp" | grep -Eq '"success"[[:space:]]*:[[:space:]]*true|"phase"[[:space:]]*:[[:space:]]*"running"'; then
    return 0
  fi
  logw "DNS enable не подтверждён — повтор через 5с..."
  sleep 5
  resp=$(api_curl POST /api/amnezia-dns/enable '{}' || true)
  logi "DNS retry: ${resp:0:240}"
  if echo "$resp" | grep -Eq '"success"[[:space:]]*:[[:space:]]*true|"phase"[[:space:]]*:[[:space:]]*"running"'; then
    return 0
  fi
  return 1
}

base24_from_ip() {
  local ip="$1"
  local a b c
  IFS=. read -r a b c _ <<<"$ip"
  echo "${a}.${b}.${c}.0/24"
}

enable_xray() {
  logi "Подготовка Xray..."
  local sni="" address="${SERVER_IP:-$PANEL_DOMAIN_VAL}"
  local cidr pub status sni_stored body resp
  pub=$(grep -E '^XRAY_PUBLIC_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  pub="${pub:-443}"

  status=$(api_curl GET /api/amnezia-xray || true)
  sni_stored=$(printf '%s' "$status" | sed -n 's/.*"sniStored"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  sni_stored=$(normalize_sni_host "$sni_stored")
  if [[ -n "$sni_stored" ]]; then
    if sni_is_blocked_tld "$sni_stored"; then
      logw "Xray: SNI ${sni_stored} пропущен (.ru/.su/.рф) — авто не использует; новый выбор"
    elif sni_reality_ok "$sni_stored"; then
      logi "Xray: оставляю SNI ${sni_stored} (без скана)"
      body=$(printf '{"publicPort":%s}' "$pub")
      resp=$(api_curl POST /api/amnezia-xray/enable "$body" || true)
      logi "Xray enable: ${resp:0:300}"
      return 0
    else
      logw "Xray: SNI ${sni_stored} не Reality-ok — новый выбор"
    fi
  fi

  logi "Xray: SNI Finder + enable"
  cidr=$(base24_from_ip "${SERVER_IP:-0.0.0.0}")
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
import json, re
blocked = re.compile(r'\.(ru|su|xn--p1ai)$', re.I)
def ok(d):
  d = (d or '').strip().lower().rstrip('.')
  if not d or blocked.search(d) or d.endswith('.рф'):
    return False
  return True
try:
  d = json.load(open('/tmp/awg-sni-cache.json'))
  cand = (d.get('defaultSni') or '').strip()
  if ok(cand):
    print(cand)
    raise SystemExit
  for e in (d.get('entries') or []):
    if e.get('alive') is False:
      continue
    dom = (e.get('domain') or '').strip()
    if ok(dom):
      print(dom)
      raise SystemExit
except SystemExit:
  raise
except Exception:
  pass
PY
)
  sni=$(normalize_sni_host "$sni")
  if [[ -n "$sni" ]] && ( sni_is_blocked_tld "$sni" || ! sni_reality_ok "$sni" ); then
    logw "Xray: кандидат ${sni} отклонён — банк"
    sni=""
  fi
  if [[ -z "$sni" ]]; then
    sni=$(pick_checked_bank_host sni)
    logw "Xray: SNI из банка ${sni}"
  else
    logi "Выбран SNI: ${sni}"
  fi

  body=$(printf '{"sni":"%s","fingerprint":"chrome","flow":"xtls-rprx-vision","publicPort":%s,"address":"%s"}' \
    "$sni" "$pub" "$address")
  resp=$(api_curl POST /api/amnezia-xray/enable "$body" || true)
  logi "Xray enable: ${resp:0:300}"
}

enable_mtproto() {
  logi "Подготовка MTProto..."
  local sni="" address="${SERVER_IP:-$PANEL_DOMAIN_VAL}"
  local xray_sni status sni_stored body resp pub
  pub=$(grep -E '^MTPROTO_PUBLIC_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  pub="${pub:-443}"

  status=$(api_curl GET /api/amnezia-mtproto || true)
  sni_stored=$(printf '%s' "$status" | sed -n 's/.*"sniStored"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  sni_stored=$(normalize_sni_host "$sni_stored")
  if [[ -n "$sni_stored" ]]; then
    if sni_is_blocked_tld "$sni_stored"; then
      logw "MTProto: SNI ${sni_stored} пропущен (.ru/.su/.рф) — новый выбор"
    elif sni_reality_ok "$sni_stored"; then
      logi "MTProto: оставляю SNI ${sni_stored}"
      body=$(printf '{"address":"%s","publicPort":%s}' "$address" "$pub")
      resp=$(api_curl POST /api/amnezia-mtproto/enable "$body" || true)
      logi "MTProto enable: ${resp:0:300}"
      return 0
    else
      logw "MTProto: SNI ${sni_stored} не Reality-ok — новый выбор"
    fi
  fi

  xray_sni=$(api_curl GET /api/amnezia-xray 2>/dev/null \
    | sed -n 's/.*"sniStored"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  if [[ -z "$xray_sni" ]]; then
    xray_sni=$(api_curl GET /api/amnezia-xray 2>/dev/null \
      | sed -n 's/.*"sni"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  fi
  xray_sni=$(normalize_sni_host "$xray_sni")

  api_curl GET /api/amnezia-xray/sni-cache >/tmp/awg-sni-cache.json || true
  sni=$(python3 - <<PY 2>/dev/null || true
import json, re
exclude = "${xray_sni}".strip().lower()
blocked = re.compile(r'\.(ru|su|xn--p1ai)$', re.I)
def ok(d):
  d = (d or '').strip().lower().rstrip('.')
  if not d or d == exclude:
    return False
  if blocked.search(d) or d.endswith('.рф'):
    return False
  return True
try:
  d = json.load(open("/tmp/awg-sni-cache.json"))
  for e in (d.get("entries") or []):
    if e.get("alive") is False:
      continue
    if ok(e.get("domain") or ""):
      print((e.get("domain") or "").strip())
      raise SystemExit
  if ok(d.get("defaultSni") or ""):
    print((d.get("defaultSni") or "").strip())
    raise SystemExit
except SystemExit:
  raise
except Exception:
  pass
for path in (
  "${INSTALL_DIR}/config/sni-bank.seed.json",
  "/app/config/sni-bank.seed.json",
):
  try:
    raw = json.load(open(path))
    domains = raw if isinstance(raw, list) else list((raw or {}).get("domains") or [])
    for dom in domains:
      if ok(dom):
        print(str(dom).strip())
        raise SystemExit
  except SystemExit:
    raise
  except Exception:
    continue
PY
)
  sni=$(normalize_sni_host "$sni")
  if [[ -n "$sni" ]] && ( sni_is_blocked_tld "$sni" || ! sni_reality_ok "$sni" || [[ "$sni" == "$xray_sni" ]] ); then
    sni=""
  fi
  if [[ -z "$sni" ]]; then
    sni=$(pick_checked_bank_host sni)
    local sni_l xray_l
    sni_l=$(printf '%s' "$sni" | tr '[:upper:]' '[:lower:]')
    xray_l=$(printf '%s' "$xray_sni" | tr '[:upper:]' '[:lower:]')
    if [[ -n "$xray_l" && "$sni_l" == "$xray_l" ]]; then
      # try another bank pick by excluding via second call — soft fallback
      sni="www.ns.nl"
      if [[ "$(printf '%s' "$sni" | tr '[:upper:]' '[:lower:]')" == "$xray_l" ]]; then
        sni="www.czc.cz"
      fi
      if ! sni_reality_ok "$sni"; then
        sni=$(pick_checked_bank_host sni)
      fi
    fi
    logw "MTProto SNI fallback (bank): ${sni}"
  else
    logi "MTProto SNI: ${sni} (≠ Xray ${xray_sni:-none})"
  fi

  body=$(printf '{"sni":"%s","address":"%s","publicPort":%s}' "$sni" "$address" "$pub")
  resp=$(api_curl POST /api/amnezia-mtproto/enable "$body" || true)
  logi "MTProto enable: ${resp:0:300}"
}

post_configure() {
  wait_panel || true
  if ! api_login; then
    logw "Не удалось войти в API — DNS/Xray/MTProto включите в UI или: awg-easy"
    return 0
  fi
  if [[ "$ENABLE_DNS" -eq 1 ]]; then
    enable_dns || logw "DNS enable не удался"
  fi
  if [[ "$ENABLE_XRAY" -eq 1 ]]; then
    enable_xray || logw "Xray enable не удался"
  fi
  if [[ "$ENABLE_MTPROTO" -eq 1 ]]; then
    enable_mtproto || logw "MTProto enable не удался"
  fi
  apply_mirror_from_sni_if_requested || true
}

print_summary() {
  local https_port https_suffix="" ui_prefix sub_prefix mirror
  https_port=$(grep -E '^PANEL_HTTPS_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  https_port="${https_port:-10123}"
  [[ "$https_port" != "443" ]] && https_suffix=":${https_port}"
  ui_prefix=$(grep -E '^WEBUI_PUBLIC_PREFIX=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  ui_prefix=$(normalize_path_prefix "${ui_prefix:-/panel}" /panel)
  sub_prefix=$(grep -E '^SUB_PUBLIC_PREFIX=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  sub_prefix=$(normalize_path_prefix "${sub_prefix:-/sub}" /sub)
  mirror=$(grep -E '^NGINX_MIRROR_HOST=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  local wg_port xray_port
  wg_port=$(grep -E '^WG_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  wg_port="${wg_port:-?}"
  xray_port=$(grep -E '^XRAY_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  xray_port="${xray_port:-auto}"

  echo ""
  echo -e "${green}═══════════════════════════════════════════${plain}"
  echo -e "${green}     Установка завершена                  ${plain}"
  echo -e "${green}═══════════════════════════════════════════${plain}"
  echo -e "${green}URL:      ${SSL_SCHEME}://${SSL_HOST}${https_suffix}${ui_prefix}/${plain}"
  echo -e "${green}Sub:      ${SSL_SCHEME}://${SSL_HOST}${https_suffix}${sub_prefix}/{name}${plain}"
  echo -e "${green}Root:     mirror → ${mirror:-?}${plain}"
  echo -e "${green}Логин:    ${ADMIN_USER}${plain}"
  echo -e "${green}Пароль:   ${ADMIN_PASS}${plain}"
  echo -e "${green}VPN:      ${SERVER_IP:-$SSL_HOST}:${wg_port}/udp${plain}"
  echo -e "${green}Demux:    ${SERVER_IP:-$SSL_HOST}:443/tcp (SNI)${plain}"
  echo -e "${green}Xray int: ${xray_port} (внутри Docker)${plain}"
  echo -e "${green}Каталог:  ${INSTALL_DIR}${plain}"
  echo -e "${green}CLI:      awg-easy${plain}"
  echo -e "${green}SSL:      ${SSL_MODE} (${SSL_HOST})${plain}"
  echo -e "${green}═══════════════════════════════════════════${plain}"
  echo -e "${yellow}Сохраните логин и пароль!${plain}"
}

main() {
  echo -e "${green}Amnezia WG-Easy — установщик${plain}"
  detect_os
  if [[ "${AWG_REEXECED:-0}" == "1" ]]; then
    # Already ran packages/docker/clone in the curl-bootstrap process; skip the slow redo.
    logi "Продолжаю после reexec (зависимости/репозиторий уже готовы)"
    detect_public_ip
  else
    install_packages
    install_docker
    detect_public_ip
    clone_or_update_repo
    reexec_from_repo_if_needed "$@"
  fi
  prompt_admin
  prompt_ports
  prompt_and_setup_ssl
  reconcile_panel_port_for_domain
  prompt_webui_paths_and_mirror
  if is_redeploy; then
    # Skip DNS/Xray/MTProto prompts on redeploy — keep first-install choices from install.conf / containers.
    local dns_def xray_def mt_def
    dns_def=$(detect_service_enabled_default dns)
    xray_def=$(detect_service_enabled_default xray)
    mt_def=$(detect_service_enabled_default mtproto)
    [[ "$dns_def" == "y" || "$dns_def" == "Y" ]] && ENABLE_DNS=1 || ENABLE_DNS=0
    [[ "$xray_def" == "y" || "$xray_def" == "Y" ]] && ENABLE_XRAY=1 || ENABLE_XRAY=0
    [[ "$mt_def" == "y" || "$mt_def" == "Y" ]] && ENABLE_MTPROTO=1 || ENABLE_MTPROTO=0
    logi "Редеплой: DNS=${ENABLE_DNS} Xray=${ENABLE_XRAY} MTProto=${ENABLE_MTPROTO} (из install.conf / контейнеров)"
  else
    confirm_yn "Amnezia DNS?" y AWG_ENABLE_DNS
    ENABLE_DNS=$CONFIRM_RESULT
    confirm_yn "Xray (VLESS Reality)?" y AWG_ENABLE_XRAY
    ENABLE_XRAY=$CONFIRM_RESULT
    confirm_yn "MTProto (Telemt)?" y AWG_ENABLE_MTPROTO
    ENABLE_MTPROTO=$CONFIRM_RESULT
  fi
  write_env
  run_deploy
  install_cli
  post_configure
  print_summary
}

main "$@"
