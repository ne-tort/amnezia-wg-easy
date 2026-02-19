"""
SIP signature collector.

- With `--dry-run`: emits a minimal synthetic SIP OPTIONS request as l1.
- Without `--dry-run`: sends a real SIP OPTIONS to each server and captures
  the first outgoing UDP packet as l1. Config may set \"use_response\": true
  to use the first incoming (server) packet instead.
"""

from __future__ import annotations

import os
import socket
from typing import Any, Dict, List

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args

try:
    from python_signatures.capture import (
        CaptureError,
        capture_udp_payloads_with_trigger,
    )
except ImportError:
    CaptureError = RuntimeError  # type: ignore[misc, assignment]
    capture_udp_payloads_with_trigger = None  # type: ignore[misc, assignment]


def _minimal_sip_options(host: str, port: int) -> bytes:
    """Build minimal SIP OPTIONS request for wire capture placeholder."""
    branch = "z9hG4bK" + os.urandom(8).hex()
    return (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch}\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:collector@localhost>;tag=1\r\n"
        "To: <sip:user@{host}>\r\n"
        "Call-ID: " + os.urandom(8).hex() + "\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Contact: <sip:collector@127.0.0.1:5060>\r\n"
        "Content-Length: 0\r\n\r\n"
    ).format(host=host).encode("utf-8")


def _parse_server(server: str) -> tuple[str, int]:
    if ":" in server:
        host, port_s = server.rsplit(":", 1)
        return host.strip(), int(port_s.strip())
    return server.strip(), 5060


def _resolve_host(host: str, port: int) -> str:
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    for info in infos:
        if info[0] == socket.AF_INET:
            return info[4][0]
    if infos:
        return infos[0][4][0]
    raise RuntimeError(f"Cannot resolve: {host}")


def _get_local_ip_for_target(host: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, port))
        return sock.getsockname()[0]
    finally:
        sock.close()


def _send_sip_options(host: str, port: int) -> None:
    msg = _minimal_sip_options(host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(3)
        sock.sendto(msg, (host, port))
        sock.recv(4096)
    finally:
        sock.close()


def _capture_sip_packet(
    server: str,
    use_response: bool,
    iface: str | None,
    timeout: int,
) -> bytes:
    host, port = _parse_server(server)
    host_ip = _resolve_host(host, port)
    local_ip = _get_local_ip_for_target(host_ip, port)
    bpf = f"udp and host {host_ip} and port {port}"

    def trigger() -> None:
        _send_sip_options(host_ip, port)

    packets = capture_udp_payloads_with_trigger(bpf, trigger, iface=iface, timeout=timeout)
    for payload, src_ip, _sport, _dst_ip, _dport in packets:
        if use_response:
            if src_ip != local_ip and len(payload) >= 4:
                return payload
        else:
            if src_ip == local_ip and len(payload) >= 4:
                return payload
    raise CaptureError(
        "No SIP packet found in capture (expected "
        + ("response" if use_response else "request")
        + ")."
    )


class SipSignatureCollector(SignatureCollector):
    """Produces SIP request or response signatures; uses capture when not dry-run."""

    def __init__(self, options):
        super().__init__("sip", options)

    def _ensure_config(self) -> Dict[str, Any]:
        if not self._config:
            self.load_config()
        return self._config

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self._ensure_config()
        servers = cfg.get("servers") or []

        if not isinstance(servers, list) or not all(isinstance(s, str) for s in servers):
            raise RuntimeError(
                'Config must contain "servers": ["sip.example.com:5060", ...].'
            )

        use_response = cfg.get("use_response") is True
        direction = "server" if use_response else "client"
        limit = self.options.count or len(servers)
        timeout = self.options.timeout or 5
        iface = self.options.iface
        signatures: List[Dict[str, Any]] = []

        if self.options.dry_run or capture_udp_payloads_with_trigger is None:
            for server in servers:
                if len(signatures) >= limit:
                    break
                host, port = _parse_server(server)
                payload = _minimal_sip_options(host, port)
                signatures.append(
                    {
                        "protocol": self.protocol_name,
                        "target": server,
                        "direction": "client",
                        "hex": self.format_signature(payload),
                    }
                )
            return signatures

        for server in servers:
            if len(signatures) >= limit:
                break
            try:
                payload = _capture_sip_packet(server, use_response, iface, timeout)
                signatures.append(
                    {
                        "protocol": self.protocol_name,
                        "target": server,
                        "direction": direction,
                        "hex": self.format_signature(payload),
                    }
                )
            except (CaptureError, OSError) as e:
                raise RuntimeError(f"SIP capture failed for {server}: {e}") from e

        return signatures


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser(
        "SIP signature collector (use --dry-run for synthetic OPTIONS payloads)"
    )
    args = parser.parse_args(argv)
    opts = options_from_args(args)

    collector = SipSignatureCollector(opts)
    signatures = collector.collect()
    collector.save(signatures)

    print(
        f"Collected {len(signatures)} SIP signatures from {opts.config_path} "
        f"(dry_run={opts.dry_run})."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
