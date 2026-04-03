"""
STUN signature collector.

- With `--dry-run` or when capture is unavailable: emits minimal STUN Binding
  Request payloads (synthetic) as used in Node obfuscation profiles.
- Without `--dry-run`: sends a real STUN Binding Request and captures traffic;
  uses either the first outgoing (client) or first incoming (server) packet as
  l1, according to config \"use_response\": true|false (default: client request).
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

# * Minimal STUN Binding Request (type 0x0001, length 0, magic 0x2112A442 + 12-byte tid).
STUN_BINDING_REQUEST = bytes.fromhex("000100002112a442") + os.urandom(12)


def _parse_server(server: str) -> tuple[str, int]:
    """Return (host, port) for 'host:port' or 'host' (default port 19302)."""
    if ":" in server:
        host, port_s = server.rsplit(":", 1)
        return host.strip(), int(port_s.strip())
    return server.strip(), 19302


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


def _send_stun_binding_request(host: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(3)
        sock.sendto(STUN_BINDING_REQUEST, (host, port))
        sock.recv(1024)
    finally:
        sock.close()


def _capture_stun_packet(
    server: str,
    use_response: bool,
    iface: str | None,
    timeout: int,
) -> bytes:
    """Single packet: client request (default) or server response (use_response)."""
    if not use_response:
        req, _resp = _capture_stun_request_response(server, iface, timeout)
        return req
    host, port = _parse_server(server)
    host_ip = _resolve_host(host, port)
    local_ip = _get_local_ip_for_target(host_ip, port)
    bpf = f"udp and host {host_ip} and port {port}"

    def trigger() -> None:
        _send_stun_binding_request(host_ip, port)

    packets = capture_udp_payloads_with_trigger(bpf, trigger, iface=iface, timeout=timeout)
    for payload, src_ip, _sport, _dst_ip, _dport in packets:
        if src_ip != local_ip and len(payload) >= 4:
            return payload
    raise CaptureError("No STUN response packet found in capture.")


def _capture_stun_request_response(
    server: str,
    iface: str | None,
    timeout: int,
) -> tuple[bytes, bytes | None]:
    """First outgoing Binding Request and optional first incoming packet (for I2)."""
    host, port = _parse_server(server)
    host_ip = _resolve_host(host, port)
    local_ip = _get_local_ip_for_target(host_ip, port)
    bpf = f"udp and host {host_ip} and port {port}"

    def trigger() -> None:
        _send_stun_binding_request(host_ip, port)

    packets = capture_udp_payloads_with_trigger(bpf, trigger, iface=iface, timeout=timeout)
    req: bytes | None = None
    resp: bytes | None = None
    for payload, src_ip, _sport, _dst_ip, _dport in packets:
        if src_ip == local_ip and len(payload) >= 4:
            if req is None:
                req = payload
        elif src_ip != local_ip and len(payload) >= 4:
            if resp is None:
                resp = payload
    if req is None:
        raise CaptureError("No outgoing STUN packet found in capture.")
    return req, resp


class StunSignatureCollector(SignatureCollector):
    """Produces STUN request or response signatures; uses capture when not dry-run."""

    def __init__(self, options):
        super().__init__("stun", options)

    def _ensure_config(self) -> Dict[str, Any]:
        if not self._config:
            self.load_config()
        return self._config

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self._ensure_config()
        servers = cfg.get("servers") or []

        if not isinstance(servers, list) or not all(isinstance(s, str) for s in servers):
            raise RuntimeError(
                'Config must contain "servers": ["stun.example.com:19302", ...].'
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
                tid = os.urandom(12)
                req = bytes.fromhex("000100002112a442") + tid
                resp_hdr = bytes.fromhex("010100002112a442") + tid
                entry: Dict[str, Any] = {
                    "protocol": self.protocol_name,
                    "target": server,
                    "direction": "client",
                    "hex": self.format_signature(req),
                    "i2": self.format_signature(resp_hdr + os.urandom(8)),
                }
                signatures.append(entry)
            return signatures

        for server in servers:
            if len(signatures) >= limit:
                break
            try:
                if use_response:
                    payload = _capture_stun_packet(server, True, iface, timeout)
                    signatures.append(
                        {
                            "protocol": self.protocol_name,
                            "target": server,
                            "direction": direction,
                            "hex": self.format_signature(payload),
                        }
                    )
                else:
                    req_b, resp_b = _capture_stun_request_response(server, iface, timeout)
                    entry = {
                        "protocol": self.protocol_name,
                        "target": server,
                        "direction": direction,
                        "hex": self.format_signature(req_b),
                    }
                    if resp_b:
                        entry["i2"] = self.format_signature(resp_b)
                    signatures.append(entry)
            except (CaptureError, OSError) as e:
                raise RuntimeError(f"STUN capture failed for {server}: {e}") from e

        return signatures


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser(
        "STUN signature collector (use --dry-run for synthetic request payloads)"
    )
    args = parser.parse_args(argv)
    opts = options_from_args(args)

    collector = StunSignatureCollector(opts)
    signatures = collector.collect()
    collector.save(signatures)

    print(
        f"Collected {len(signatures)} STUN signatures from {opts.config_path} "
        f"(dry_run={opts.dry_run})."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

