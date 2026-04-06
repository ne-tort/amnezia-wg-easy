#!/usr/bin/env python3
"""Run CaptureOrchestrator with Docker-friendly Chromium flags; print JSON summary."""
from __future__ import annotations

import json
import socket
import sys
from urllib.parse import urlparse

from browser_capture.core.orchestrator import CaptureOrchestrator


def trunc_hex(b: bytes, n: int = 64) -> str:
    if len(b) <= n:
        return b.hex()
    return b[:n].hex() + f"... (+{len(b) - n} bytes)"


def _ipv4_for_url(url: str) -> tuple[str, str]:
    """Return (hostname, ipv4) so Chromium can be pinned to the same address as tcpdump BPF."""
    p = urlparse(url)
    host = p.hostname or ""
    if not host:
        raise ValueError("URL needs a host")
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    for info in infos:
        if info[0] == socket.AF_INET:
            return host, str(info[4][0])
    raise RuntimeError(f"No IPv4 for {host}")


def main() -> int:
    # Google often negotiates QUIC in headless Docker; many CDNs fall back to TCP-only → empty UDP capture.
    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.google.com/"
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 40
    host, host_ip = _ipv4_for_url(url)
    # Without this, Chromium may prefer IPv6 while BPF is IPv4-only → empty pcap in Docker.
    resolver_map = f"MAP {host} {host_ip}"
    extra = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        f"--host-resolver-rules={resolver_map}",
    ]
    o = CaptureOrchestrator()
    r = o.capture_quic_http3(
        url,
        iface="eth0",
        timeout=timeout,
        headless=True,
        extra_chromium_args=extra,
    )
    out = {
        "chromium_host_resolver_rules": resolver_map,
        "meta": r.meta,
        "bpf": r.bpf_filter,
        "outgoing_count": len(r.outgoing),
        "quic_initial_candidates": len(r.quic_initial_candidates),
        "initial_lens": [len(p) for p in r.quic_initial_candidates[:8]],
        "initial_hex_prefix": [trunc_hex(p, 64) for p in r.quic_initial_candidates[:5]],
    }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
