#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq tcpdump dnsutils xvfb >/dev/null
pip install --break-system-packages -q "playwright==1.49.1"

IP=$(getent ahostsv4 cloudflare.com | awk 'NR==1 {print $1; exit}')
echo "resolved IPv4=$IP"
RULE="MAP cloudflare.com $IP"
# Broad: any traffic to Cloudflare IP (see TCP vs UDP).
tcpdump -i eth0 -w /tmp/y.pcap -U -n "host ${IP}" &
TPID=$!
sleep 0.6
xvfb-run -a python3 << PY
from playwright.sync_api import sync_playwright
rule = "${RULE}"
with sync_playwright() as p:
    b = p.chromium.launch(
        headless=False,
        args=[
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--enable-quic",
            "--origin-to-force-quic-on=https://cloudflare.com:443",
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
echo "--- summary ---"
tcpdump -r /tmp/y.pcap -n 2>/dev/null | head -40 || true
