"""
QUIC / HTTP3 signature collector.

- With `--dry-run`: emits placeholder signatures from target URLs (no real traffic).
- Without `--dry-run`: runs tcpdump and triggers HTTP/3 via curl, then uses the
  first outgoing UDP packet (QUIC Initial) as the l1 signature. Requires tcpdump
  and curl with HTTP/3 support (e.g. curl 7.66+ with libcurl built for HTTP/3).
"""

from __future__ import annotations

import socket
import subprocess
from typing import Any, Dict, List
from urllib.parse import urlparse

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args
from python_signatures.profile_cps import QUIC_CPS_I1_HABR, QUIC_CPS_I2_HABR

try:
    from python_signatures.capture import (
        CaptureError,
        capture_udp_payloads_with_trigger,
    )
except ImportError:
    CaptureError = RuntimeError  # type: ignore[misc, assignment]
    capture_udp_payloads_with_trigger = None  # type: ignore[misc, assignment]


def _resolve_host(host: str, port: int) -> str:
    """Resolve host to a single IPv4 or IPv6 address."""
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    for info in infos:
        af, _, _, _, sockaddr = info
        if af == socket.AF_INET:
            return sockaddr[0]
    if infos:
        return infos[0][4][0]
    raise RuntimeError(f"Cannot resolve host: {host}")


def _get_local_ip_for_target(host: str, port: int) -> str:
    """Get local IP used when sending to (host, port) via a UDP probe."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, port))
        return sock.getsockname()[0]
    finally:
        sock.close()


def _capture_quic_packets(
    url: str, iface: str | None, timeout: int
) -> tuple[bytes, bytes | None]:
    """Return first and optional second outgoing QUIC UDP payload (same flow)."""
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or 443
    if not parsed.scheme:
        raise ValueError(f"Invalid URL (no scheme): {url}")

    host_ip = _resolve_host(host, port)
    local_ip = _get_local_ip_for_target(host_ip, port)
    bpf = f"udp and host {host_ip} and port {port}"

    def trigger() -> None:
        subprocess.run(
            ["curl", "--http3", "-m", str(min(5, max(1, timeout))), "-s", "-o", "/dev/null", url],
            check=False,
            capture_output=True,
            timeout=timeout + 2,
        )

    packets = capture_udp_payloads_with_trigger(bpf, trigger, iface=iface, timeout=timeout)
    outgoing: List[bytes] = []
    for payload, src_ip, _sport, _dst_ip, _dport in packets:
        if src_ip == local_ip and len(payload) >= 4:
            outgoing.append(payload)
    if not outgoing:
        raise CaptureError("No outgoing QUIC packet found in capture (is curl built with HTTP/3?).")
    second = outgoing[1] if len(outgoing) > 1 else None
    return outgoing[0], second


class QuicSignatureCollector(SignatureCollector):
    """Collects QUIC Initial packet signatures via curl + tcpdump, or placeholders in dry-run."""

    def __init__(self, options):
        super().__init__("quic", options)

    def _ensure_config(self) -> Dict[str, Any]:
        if not self._config:
            self.load_config()
        return self._config

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self._ensure_config()
        urls = cfg.get("urls") or []

        if not isinstance(urls, list) or not all(isinstance(u, str) for u in urls):
            raise RuntimeError('Config must contain "urls": ["https://example.com/", ...].')

        limit = self.options.count or len(urls)
        timeout = self.options.timeout or 5
        iface = self.options.iface
        signatures: List[Dict[str, Any]] = []

        if self.options.dry_run:
            # CPS from Habr / AmneziaWG 2.0 (QUIC-like), not URL bytes — those are not QUIC Initial.
            for url in urls:
                if len(signatures) >= limit:
                    break
                entry: Dict[str, Any] = {
                    "protocol": self.protocol_name,
                    "target": url,
                    "direction": "client",
                    "hex": QUIC_CPS_I1_HABR,
                    "i2": QUIC_CPS_I2_HABR,
                }
                signatures.append(entry)
            return signatures

        if capture_udp_payloads_with_trigger is None:
            raise RuntimeError("Capture module not available; run with --dry-run for placeholders.")

        for url in urls:
            if len(signatures) >= limit:
                break
            try:
                first, second = _capture_quic_packets(url, iface, timeout)
                entry = {
                    "protocol": self.protocol_name,
                    "target": url,
                    "direction": "client",
                    "hex": self.format_signature(first),
                }
                if second:
                    entry["i2"] = self.format_signature(second)
                signatures.append(entry)
            except (CaptureError, ValueError, OSError) as e:
                raise RuntimeError(f"QUIC capture failed for {url}: {e}") from e

        return signatures


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser("QUIC/HTTP3 signature collector (use --dry-run for placeholders)")
    args = parser.parse_args(argv)
    opts = options_from_args(args)

    collector = QuicSignatureCollector(opts)
    signatures = collector.collect()
    collector.save(signatures)

    print(
        f"Collected {len(signatures)} QUIC signatures from {opts.config_path} "
        f"(dry_run={opts.dry_run})."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

