#!/bin/bash
# Open firewall ports for Amnezia WG-Easy (run on host, with sudo if needed).
# Reads .env: WG_PORT, PANEL_HTTP/HTTPS, XRAY_PUBLIC_PORT, MTPROTO_PUBLIC_PORT.
# DNS (53/853) is VPN-internal only — not opened on the host.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"
WG_PORT=51820
PANEL_HTTP_PORT=80
PANEL_HTTPS_PORT=10123
XRAY_PUBLIC_PORT=443
MTPROTO_PUBLIC_PORT=443

if [ -f "$ENV_FILE" ]; then
  . "$ENV_FILE" 2>/dev/null || true
fi
WG_PORT="${WG_PORT:-51820}"
PANEL_HTTP_PORT="${PANEL_HTTP_PORT:-80}"
PANEL_HTTPS_PORT="${PANEL_HTTPS_PORT:-10123}"
XRAY_PUBLIC_PORT="${XRAY_PUBLIC_PORT:-443}"
MTPROTO_PUBLIC_PORT="${MTPROTO_PUBLIC_PORT:-$XRAY_PUBLIC_PORT}"

PORTS_TCP=("${PANEL_HTTP_PORT}" "${PANEL_HTTPS_PORT}" "${XRAY_PUBLIC_PORT}" "${MTPROTO_PUBLIC_PORT}")
# unique
uniq_tcp=()
for p in "${PORTS_TCP[@]}"; do
  skip=0
  for u in "${uniq_tcp[@]:-}"; do
    [[ "$u" == "$p" ]] && skip=1 && break
  done
  [[ "$skip" -eq 0 && -n "$p" ]] && uniq_tcp+=("$p")
done

echo "Opening UDP ${WG_PORT} (VPN) and TCP: ${uniq_tcp[*]} (panel/HTTP + Xray/MT public)..."
echo "Note: Amnezia DNS stays on VPN only (no host :53/:853)."

open_tcp() {
  local p="$1"
  if command -v ufw >/dev/null 2>&1; then
    sudo ufw allow "${p}/tcp" comment "Amnezia WG-Easy TCP ${p}"
  elif command -v firewall-cmd >/dev/null 2>&1; then
    sudo firewall-cmd --permanent --add-port="${p}/tcp"
  else
    sudo iptables -C INPUT -p tcp --dport "${p}" -j ACCEPT 2>/dev/null \
      || sudo iptables -I INPUT -p tcp --dport "${p}" -j ACCEPT
  fi
}

if command -v ufw >/dev/null 2>&1; then
  sudo ufw allow "${WG_PORT}/udp" comment 'AmneziaWG VPN'
  for p in "${uniq_tcp[@]}"; do open_tcp "$p"; done
  sudo ufw status | head -40 || true
  echo "Done (ufw). Reload with: sudo ufw reload"
elif command -v firewall-cmd >/dev/null 2>&1; then
  sudo firewall-cmd --permanent --add-port="${WG_PORT}/udp"
  for p in "${uniq_tcp[@]}"; do open_tcp "$p"; done
  sudo firewall-cmd --reload
  echo "Done (firewalld)."
else
  sudo iptables -C INPUT -p udp --dport "${WG_PORT}" -j ACCEPT 2>/dev/null \
    || sudo iptables -I INPUT -p udp --dport "${WG_PORT}" -j ACCEPT
  for p in "${uniq_tcp[@]}"; do open_tcp "$p"; done
  echo "Done (iptables)."
fi
