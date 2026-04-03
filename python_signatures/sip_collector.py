"""
SIP signature collector.

- With `--dry-run`: loads tests/fixtures/signatures/sip.json (CI only).
- Without `--dry-run`: sends UDP SIP, captures first outgoing (I1) and first incoming (I2).

Config:
  - method: OPTIONS (default), REGISTER, or INVITE (RFC 3261-shaped text).
  - use_response: legacy; only sets \"direction\" label — I1 is always request, I2 is response.
"""

from __future__ import annotations

import os
import socket
from typing import Any, Dict, List

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args
from python_signatures.dry_run_fixtures import build_dry_run_signatures

try:
    from python_signatures.capture import (
        CaptureError,
        capture_udp_payloads_with_trigger,
    )
except ImportError:
    CaptureError = RuntimeError  # type: ignore[misc, assignment]
    capture_udp_payloads_with_trigger = None  # type: ignore[misc, assignment]


def _minimal_sip_options(host: str, port: int) -> bytes:
    """Minimal SIP OPTIONS request."""
    branch = "z9hG4bK" + os.urandom(8).hex()
    return (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch}\r\n"
        "Max-Forwards: 70\r\n"
        "From: <sip:collector@localhost>;tag=1\r\n"
        f"To: <sip:user@{host}>\r\n"
        "Call-ID: " + os.urandom(8).hex() + "\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Contact: <sip:collector@127.0.0.1:5060>\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("utf-8")


def _minimal_sip_register(host: str, port: int) -> bytes:
    """Minimal REGISTER (VoIP client registration)."""
    branch = "z9hG4bK" + os.urandom(8).hex()
    return (
        f"REGISTER sip:{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch}\r\n"
        "Max-Forwards: 70\r\n"
        f"From: <sip:u@{host}>;tag=reg\r\n"
        f"To: <sip:u@{host}>\r\n"
        "Call-ID: " + os.urandom(8).hex() + "\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Contact: <sip:collector@127.0.0.1:5060>\r\n"
        "Expires: 3600\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("utf-8")


def _minimal_sip_invite(host: str, port: int) -> bytes:
    """INVITE with minimal SDP (typical VoIP offer)."""
    branch = "z9hG4bK" + os.urandom(8).hex()
    sdp = (
        "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\n"
        "t=0 0\r\nm=audio 9 RTP/AVP 0\r\n"
    )
    body = sdp.encode("utf-8")
    head = (
        f"INVITE sip:peer@{host} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5060;branch={branch}\r\n"
        "Max-Forwards: 70\r\n"
        f"From: <sip:u@{host}>;tag=1\r\n"
        f"To: <sip:peer@{host}>\r\n"
        "Call-ID: " + os.urandom(8).hex() + "\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:collector@127.0.0.1:5060>\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("utf-8")
    return head + body


def _build_sip_message(host: str, port: int, method: str) -> bytes:
    m = method.upper()
    if m == "REGISTER":
        return _minimal_sip_register(host, port)
    if m == "INVITE":
        return _minimal_sip_invite(host, port)
    return _minimal_sip_options(host, port)


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


def _send_sip_payload(host: str, port: int, payload: bytes) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(3)
        sock.sendto(payload, (host, port))
        sock.recv(4096)
    finally:
        sock.close()


def _capture_sip_request_response(
    server: str,
    iface: str | None,
    timeout: int,
    method: str = "OPTIONS",
) -> tuple[bytes, bytes | None]:
    """First outgoing SIP request and optional first incoming datagram (I2)."""
    host, port = _parse_server(server)
    host_ip = _resolve_host(host, port)
    local_ip = _get_local_ip_for_target(host_ip, port)
    bpf = f"udp and host {host_ip} and port {port}"

    def trigger() -> None:
        msg = _build_sip_message(host_ip, port, method)
        _send_sip_payload(host_ip, port, msg)

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
        raise CaptureError("No outgoing SIP packet found in capture.")
    return req, resp


class SipSignatureCollector(SignatureCollector):
    """Produces SIP request/response signatures; uses capture when not dry-run."""

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
        method = (cfg.get("method") or "OPTIONS").upper()
        if method not in {"OPTIONS", "REGISTER", "INVITE"}:
            raise RuntimeError('Config "method" must be OPTIONS, REGISTER, or INVITE.')

        limit = self.options.count or len(servers)
        timeout = self.options.timeout or 5
        iface = self.options.iface
        signatures: List[Dict[str, Any]] = []

        if self.options.dry_run:
            return build_dry_run_signatures(
                "sip",
                self.protocol_name,
                servers,
                limit=limit,
                direction=direction,
            )

        if capture_udp_payloads_with_trigger is None:
            raise RuntimeError(
                "Capture module not available. Use --dry-run (fixture CPS) or install capture support."
            )

        for server in servers:
            if len(signatures) >= limit:
                break
            try:
                req_b, resp_b = _capture_sip_request_response(
                    server, iface, timeout, method
                )
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
                raise RuntimeError(f"SIP capture failed for {server}: {e}") from e

        return signatures


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser(
        "SIP signature collector (--dry-run loads tests/fixtures/signatures/sip.json)"
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
