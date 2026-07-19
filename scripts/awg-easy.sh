#!/bin/bash
# Amnezia WG-Easy management menu (install: /usr/local/bin/awg-easy).
# Usage: awg-easy [start|stop|restart|update|status|show|ssl|dns|xray|uninstall|menu]

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

CONF_DIR="${AWG_CONF_DIR:-/etc/amnezia-wg-easy}"
INSTALL_DIR="${AWG_INSTALL_DIR:-}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-amnezia-wg-easy}"

load_conf() {
  if [[ -f "${CONF_DIR}/install.conf" ]]; then
    # shellcheck disable=SC1091
    source "${CONF_DIR}/install.conf"
  fi
  INSTALL_DIR="${INSTALL_DIR:-/opt/amnezia-wg-easy}"
  COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-amnezia-wg-easy}"
  export COMPOSE_PROJECT_NAME
}

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo -e "${red}Нужен root${plain}"; exit 1; }
}

compose() {
  load_conf
  (cd "$INSTALL_DIR" && docker compose "$@")
}

panel_base() {
  local https_port
  https_port=$(grep -E '^PANEL_HTTPS_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  https_port="${https_port:-10123}"
  if [[ "$https_port" == "443" ]]; then
    echo "https://127.0.0.1"
  else
    echo "https://127.0.0.1:${https_port}"
  fi
}

admin_user() {
  if [[ -f "${CONF_DIR}/admin.cred" ]]; then
    grep -E '^ADMIN_USERNAME=' "${CONF_DIR}/admin.cred" | cut -d= -f2-
  else
    grep -E '^ADMIN_USERNAME=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2-
  fi
}

admin_pass() {
  if [[ -f "${CONF_DIR}/admin.cred" ]]; then
    grep -E '^ADMIN_PASSWORD=' "${CONF_DIR}/admin.cred" | cut -d= -f2-
  else
    grep -E '^ADMIN_PASSWORD=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2-
  fi
}

api() {
  local method="$1" path="$2" body="${3:-}"
  local base cookie user pass
  load_conf
  base=$(panel_base)
  cookie="${CONF_DIR}/session.cj"
  user=$(admin_user)
  pass=$(admin_pass)
  mkdir -p "$CONF_DIR"
  curl -sk -c "$cookie" -b "$cookie" -X POST "${base}/api/session" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${user}\",\"password\":\"${pass}\"}" >/dev/null || true
  if [[ -n "$body" ]]; then
    curl -sk -c "$cookie" -b "$cookie" -X "$method" "${base}${path}" \
      -H 'Content-Type: application/json' -d "$body" --max-time 180
  else
    curl -sk -c "$cookie" -b "$cookie" -X "$method" "${base}${path}" --max-time 180
  fi
  echo
}

cmd_start() { need_root; compose up -d; echo -e "${green}Started${plain}"; }
cmd_stop() { need_root; compose stop; echo -e "${green}Stopped${plain}"; }
cmd_restart() { need_root; compose restart; echo -e "${green}Restarted${plain}"; }

cmd_status() {
  load_conf
  echo "INSTALL_DIR=${INSTALL_DIR}"
  compose ps || true
  docker ps --filter name=amnezia- --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
}

cmd_show() {
  load_conf
  local domain host https_port suffix="" wg_port xray_port
  domain=$(grep -E '^PANEL_DOMAIN=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  host=$(grep -E '^WG_HOST=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  https_port=$(grep -E '^PANEL_HTTPS_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  https_port="${https_port:-10123}"
  [[ "$https_port" != "443" ]] && suffix=":${https_port}"
  wg_port=$(grep -E '^WG_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  xray_port=$(grep -E '^XRAY_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  echo -e "${green}URL:${plain}    https://${domain:-$host}${suffix}/"
  echo -e "${green}User:${plain}   $(admin_user)"
  echo -e "${green}Pass:${plain}   $(admin_pass)"
  echo -e "${green}VPN:${plain}    ${host}:${wg_port:-?}/udp"
  local xpub mtpub
  xpub=$(grep -E '^XRAY_PUBLIC_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  mtpub=$(grep -E '^MTPROTO_PUBLIC_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  echo -e "${green}Xray:${plain}   public ${xpub:-443}/tcp"
  echo -e "${green}MTProto:${plain} public ${mtpub:-${xpub:-443}}/tcp"
  echo -e "${green}Dir:${plain}    ${INSTALL_DIR}"
  if [[ -f "${CONF_DIR}/install.conf" ]]; then
    grep -E '^(SSL_MODE|SSL_HOST)=' "${CONF_DIR}/install.conf" || true
  fi
}

cmd_update() {
  need_root
  load_conf
  echo -e "${yellow}git pull + deploy.sh${plain}"
  git -C "$INSTALL_DIR" pull --ff-only || true
  chmod +x "${INSTALL_DIR}/deploy.sh" "${INSTALL_DIR}/scripts/awg-easy.sh" 2>/dev/null || true
  install -m 755 "${INSTALL_DIR}/scripts/awg-easy.sh" /usr/local/bin/awg-easy
  (cd "$INSTALL_DIR" && ./deploy.sh)
}

cmd_ssl() {
  need_root
  load_conf
  echo -e "${yellow}Повторный SSL: перезапустите установщик${plain}"
  echo "  bash ${INSTALL_DIR}/install.sh"
  echo "или:"
  echo "  bash <(curl -4fsSL --connect-timeout 3 --retry 3 https://raw.githubusercontent.com/ne-tort/amnezia-wg-easy/master/install.sh)"
}

cmd_dns_on() {
  need_root
  # Empty body → keep stored profileId, else bank default
  api POST /api/amnezia-dns/enable '{}'
}
cmd_dns_off() { need_root; api POST /api/amnezia-dns/disable '{}'; }

cmd_xray_on() {
  need_root
  load_conf
  local host port sni status sni_stored
  host=$(grep -E '^WG_HOST=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  port=$(grep -E '^XRAY_PORT=' "${INSTALL_DIR}/.env" 2>/dev/null | cut -d= -f2- || true)
  port="${port:-443}"
  status=$(api GET /api/amnezia-xray 2>/dev/null || true)
  sni_stored=$(printf '%s' "$status" | sed -n 's/.*"sniStored"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
  if [[ -n "$sni_stored" ]]; then
    api POST /api/amnezia-xray/enable "{\"port\":${port}}"
    return 0
  fi
  api GET '/api/amnezia-xray/sni-cache?ensureBg=1' >/tmp/awg-sni-cache.json || true
  sni=$(sed -n 's/.*"defaultSni"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /tmp/awg-sni-cache.json 2>/dev/null | head -1)
  sni="${sni:-www.gov.uk}"
  api POST /api/amnezia-xray/enable \
    "{\"sni\":\"${sni}\",\"fingerprint\":\"chrome\",\"flow\":\"xtls-rprx-vision\",\"port\":${port},\"address\":\"${host}\"}"
}
cmd_xray_off() { need_root; api POST /api/amnezia-xray/disable '{}'; }

cmd_uninstall() {
  need_root
  load_conf
  echo -e "${red}Остановка стека в ${INSTALL_DIR}${plain}"
  read -rp "Удалить volumes (данные клиентов/БД)? [y/N]: " wipe || true
  compose down || true
  docker rm -f amnezia-dns amnezia-xray 2>/dev/null || true
  if [[ "${wipe}" == "y" || "${wipe}" == "Y" ]]; then
    compose down -v || true
    echo "Volumes removed"
  fi
  rm -f /usr/local/bin/awg-easy
  echo -e "${green}Готово. Каталог ${INSTALL_DIR} не удалён (удалите вручную при необходимости).${plain}"
}

show_menu() {
  echo -e "${green}Amnezia WG-Easy — меню${plain}"
  echo "  0) Exit"
  echo "  1) Start"
  echo "  2) Stop"
  echo "  3) Restart"
  echo "  4) Status"
  echo "  5) Show credentials / URL"
  echo "  6) Update (git pull + deploy)"
  echo "  7) SSL redo (hint)"
  echo "  8) Enable DNS"
  echo "  9) Disable DNS"
  echo " 10) Enable Xray"
  echo " 11) Disable Xray"
  echo " 12) Uninstall"
  read -rp "Выбор: " n || true
  case "$n" in
    1) cmd_start ;;
    2) cmd_stop ;;
    3) cmd_restart ;;
    4) cmd_status ;;
    5) cmd_show ;;
    6) cmd_update ;;
    7) cmd_ssl ;;
    8) cmd_dns_on ;;
    9) cmd_dns_off ;;
    10) cmd_xray_on ;;
    11) cmd_xray_off ;;
    12) cmd_uninstall ;;
    *) exit 0 ;;
  esac
}

main() {
  load_conf
  case "${1:-menu}" in
    start) cmd_start ;;
    stop) cmd_stop ;;
    restart) cmd_restart ;;
    status) cmd_status ;;
    show) cmd_show ;;
    update) cmd_update ;;
    ssl) cmd_ssl ;;
    dns-on|dns) cmd_dns_on ;;
    dns-off) cmd_dns_off ;;
    xray-on|xray) cmd_xray_on ;;
    xray-off) cmd_xray_off ;;
    uninstall) cmd_uninstall ;;
    menu|"") show_menu ;;
    *)
      echo "Usage: awg-easy {start|stop|restart|status|show|update|ssl|dns-on|dns-off|xray-on|xray-off|uninstall|menu}"
      exit 1
      ;;
  esac
}

main "$@"
