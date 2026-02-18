#!/bin/bash
# Open firewall ports for Amnezia WG-Easy (run on host, with sudo if needed).
# Ports are read from .env in project root; defaults: WG_PORT=41194, PORT=51821.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"
WG_PORT=41194
PORT=51821

if [ -f "$ENV_FILE" ]; then
  . "$ENV_FILE" 2>/dev/null || true
fi
WG_PORT="${WG_PORT:-41194}"
PORT="${PORT:-51821}"

echo "Opening UDP ${WG_PORT} (VPN) and TCP ${PORT} (Web UI)..."

if command -v ufw >/dev/null 2>&1; then
  sudo ufw allow "${WG_PORT}/udp" comment 'AmneziaWG VPN'
  sudo ufw allow "${PORT}/tcp" comment 'Amnezia WG-Easy UI'
  sudo ufw status | grep -E "${WG_PORT}|${PORT}" || true
  echo "Done (ufw). Reload with: sudo ufw reload"
elif command -v firewall-cmd >/dev/null 2>&1; then
  sudo firewall-cmd --permanent --add-port="${WG_PORT}/udp"
  sudo firewall-cmd --permanent --add-port="${PORT}/tcp"
  sudo firewall-cmd --reload
  echo "Done (firewalld)."
else
  sudo iptables -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT
  sudo iptables -C INPUT -p tcp --dport "${PORT}" -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport "${PORT}" -j ACCEPT
  echo "Done (iptables). To persist: install iptables-persistent or netfilter-persistent and run save."
fi
