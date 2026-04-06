#!/usr/bin/env bash
# Real QUIC UDP capture comparison: (A) curl+tcpdump like python_signatures/quic_collector
# (B) Playwright Chromium + tcpdump like browser_capture (needs playwright install).
# Run: docker run --rm --cap-add=NET_RAW -v "$(pwd)/..:/work" -w /work/browser_capture debian:testing-slim bash scripts/docker_compare_quic_capture.sh

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  tcpdump curl ca-certificates python3 python3-pip \
  >/dev/null

pip3 install --break-system-packages -q scapy

URL="${1:-https://cloudflare.com/}"
export CAPTURE_URL="$URL"
python3 <<'PY'
import os, socket, subprocess, sys
from pathlib import Path
from urllib.parse import urlparse

url = os.environ["CAPTURE_URL"]
p = urlparse(url)
host = p.hostname or "localhost"
port = p.port or 443

infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
host_ip = next((x[4][0] for x in infos if x[0] == socket.AF_INET), None)
if not host_ip:
    raise SystemExit("no IPv4 for " + host)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((host_ip, port))
local_ip = s.getsockname()[0]
s.close()

bpf = f"udp and host {host_ip} and port {port}"
tmpdir = Path(os.environ.get("TMPDIR", "/tmp")) / "qcap"
tmpdir.mkdir(parents=True, exist_ok=True)
pcap = tmpdir / "cap.pcap"

cmd = ["tcpdump", "-w", str(pcap), "-U", "-n", "-i", "eth0", bpf]
proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    import time
    time.sleep(0.5)
    subprocess.run(
        ["curl", "--http3", "-m", "8", "-s", "-o", "/dev/null", url],
        check=False,
        timeout=15,
    )
    time.sleep(0.4)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

from scapy.all import PcapReader  # noqa: E402
from scapy.layers.inet import IP, UDP  # noqa: E402

outgoing = []
if pcap.exists() and pcap.stat().st_size > 24:
    with PcapReader(str(pcap)) as r:
        for pkt in r:
            if UDP not in pkt or IP not in pkt:
                continue
            udp = pkt[UDP]
            payload = bytes(udp.payload)
            if not payload:
                continue
            src = str(pkt[IP].src)
            if src == local_ip and len(payload) >= 4:
                outgoing.append(payload)

def trunc(b: bytes, n: int = 96) -> str:
    if len(b) <= n:
        return b.hex()
    return b[:n].hex() + f"... (+{len(b)-n} bytes)"

def qh(b: bytes) -> dict:
    if len(b) < 6:
        return {"len": len(b)}
    ver = int.from_bytes(b[1:5], "big")
    return {
        "len": len(b),
        "first_byte": f"0x{b[0]:02x}",
        "long_header": bool(b[0] & 0x80),
        "version_hex": f"0x{ver:08x}",
        "trunc_hex": trunc(b),
    }

print("=== A) curl --http3 + tcpdump (как QuicSignatureCollector) ===")
print(f"url={url}")
print(f"server_ip={host_ip} local_ip={local_ip} bpf={bpf}")
if not outgoing:
    print("NO_OUTGOING_UDP (capture empty or filter mismatch)")
else:
    for i, pl in enumerate(outgoing[:5]):
        print(f"outgoing[{i}]: {qh(pl)}")
    print()
    print("collector-style I1 would be first outgoing payload:")
    print("  hex prefix:", trunc(outgoing[0], 64))
PY

echo ""
echo "=== B) Playwright Chromium — пропуск (установите playwright + chromium в образе) ==="
echo "Для полного B добавьте в Dockerfile: pip install playwright && playwright install chromium"
echo "и вызовите python -m browser_capture с тем же URL."
