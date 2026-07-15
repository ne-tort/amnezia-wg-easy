#!/bin/bash
# Reference entrypoint (also embedded in Dockerfile for stdin docker build).
set -e
echo "amnezia-xray container startup"
PORT="${XRAY_SERVER_PORT:-8443}"
CFG=""
if [ -f /opt/amnezia/awg/xray/server.json ]; then CFG=/opt/amnezia/awg/xray/server.json; fi
if [ -z "$CFG" ] && [ -f /opt/amnezia/xray/server.json ]; then CFG=/opt/amnezia/xray/server.json; fi

iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p icmp -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p tcp --dport "${PORT}" -j ACCEPT 2>/dev/null || true
iptables -P INPUT DROP 2>/dev/null || true

killall -KILL xray 2>/dev/null || true

if [ -n "$CFG" ]; then
  xray -test -config "$CFG"
  exec xray -config "$CFG"
fi

echo "No server.json yet; waiting"
exec tail -f /dev/null
