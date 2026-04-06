#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq tcpdump curl >/dev/null
IP=$(getent ahostsv4 cloudflare.com | awk 'NR==1 {print $1; exit}')
echo "IP=$IP"
tcpdump -i eth0 -w /tmp/c.pcap -U -n "udp and host ${IP} and port 443" &
TPID=$!
sleep 0.5
curl --http3 -m 8 -s -o /dev/null "https://cloudflare.com/" || true
sleep 1
kill "${TPID}" 2>/dev/null || true
wait "${TPID}" 2>/dev/null || true
ls -la /tmp/c.pcap
tcpdump -r /tmp/c.pcap -c 3 -n
