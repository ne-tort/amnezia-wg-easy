#!/bin/bash
# Open firewall ports for Amnezia WG-Easy (run on host, with sudo if needed).
# Reads .env in project root. Defaults: WG_PORT=51820, PANEL_HTTP_PORT=80, PANEL_HTTPS_PORT=443.
# PORT (internal Node) is not exposed on the host when using nginx.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"
WG_PORT=51820
PANEL_HTTP_PORT=80
PANEL_HTTPS_PORT=443

if [ -f "$ENV_FILE" ]; then
  . "$ENV_FILE" 2>/dev/null || true
fi
WG_PORT="${WG_PORT:-51820}"
PANEL_HTTP_PORT="${PANEL_HTTP_PORT:-80}"
PANEL_HTTPS_PORT="${PANEL_HTTPS_PORT:-443}"

echo "Opening UDP ${WG_PORT} (VPN), TCP ${PANEL_HTTP_PORT} (HTTP redirect/ACME), TCP ${PANEL_HTTPS_PORT} (HTTPS panel)..."

if command -v ufw >/dev/null 2>&1; then
  sudo ufw allow "${WG_PORT}/udp" comment 'AmneziaWG VPN'
  sudo ufw allow "${PANEL_HTTP_PORT}/tcp" comment 'Amnezia WG-Easy HTTP'
  sudo ufw allow "${PANEL_HTTPS_PORT}/tcp" comment 'Amnezia WG-Easy HTTPS'
  sudo ufw status | grep -E "${WG_PORT}|${PANEL_HTTP_PORT}|${PANEL_HTTPS_PORT}" || true
  echo "Done (ufw). Reload with: sudo ufw reload"
elif command -v firewall-cmd >/dev/null 2>&1; then
  sudo firewall-cmd --permanent --add-port="${WG_PORT}/udp"
  sudo firewall-cmd --permanent --add-port="${PANEL_HTTP_PORT}/tcp"
  sudo firewall-cmd --permanent --add-port="${PANEL_HTTPS_PORT}/tcp"
  sudo firewall-cmd --reload
  echo "Done (firewalld)."
else
  sudo iptables -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT
  sudo iptables -C INPUT -p tcp --dport "${PANEL_HTTP_PORT}" -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport "${PANEL_HTTP_PORT}" -j ACCEPT
  sudo iptables -C INPUT -p tcp --dport "${PANEL_HTTPS_PORT}" -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport "${PANEL_HTTPS_PORT}" -j ACCEPT
  echo "Done (iptables). To persist: install iptables-persistent or netfilter-persistent and run save."
fi
