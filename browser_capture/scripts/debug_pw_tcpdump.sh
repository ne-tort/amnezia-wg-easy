#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq tcpdump dnsutils xvfb >/dev/null
pip install --break-system-packages -q "playwright==1.49.1"

IP=$(getent ahostsv4 cloudflare.com | awk 'NR==1 {print $1; exit}')
echo "resolved IPv4=$IP"
RULE="MAP cloudflare.com $IP"
tcpdump -i eth0 -w /tmp/x.pcap -U -n "udp and host ${IP} and port 443" &
TPID=$!
sleep 0.6
xvfb-run -a python3 << PY
from playwright.sync_api import sync_playwright
rule = "${RULE}"
origin_quic = "https://cloudflare.com:443"
with sync_playwright() as p:
    b = p.chromium.launch(
        headless=False,
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--enable-quic",
            f"--origin-to-force-quic-on={origin_quic}",
            f"--host-resolver-rules={rule}",
        ],
    )
    pg = b.new_page()
    pg.goto("https://cloudflare.com/", timeout=90000)
    b.close()
PY
sleep 1
kill "${TPID}" 2>/dev/null || true
wait "${TPID}" 2>/dev/null || true
ls -la /tmp/x.pcap
tcpdump -r /tmp/x.pcap -c 3 -n 2>/dev/null || echo "tcpdump read failed"
