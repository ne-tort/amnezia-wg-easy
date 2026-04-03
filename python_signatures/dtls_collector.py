"""
DTLS signature collector.

- With `--dry-run`: emits a minimal synthetic DTLS ClientHello-like placeholder.
- Without `--dry-run`: runs openssl s_client with DTLS to each target and
  captures the first outgoing UDP packet (ClientHello) as l1. Requires
  openssl with DTLS support.
"""

from __future__ import annotations

import os
import socket
import subprocess
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

# * Minimal placeholder: not a full ClientHello, just a recognizable prefix for dry-run.
DTLS_PLACEHOLDER = bytes.fromhex("16feff000000000000000000")


def _parse_target(target: str) -> tuple[str, int]:
    if ":" in target:
        host, port_s = target.rsplit(":", 1)
        return host.strip(), int(port_s.strip())
    return target.strip(), 443


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


def _run_dtls_client(host: str, port: int, timeout: int) -> None:
    subprocess.run(
        [
            "openssl", "s_client", "-connect", f"{host}:{port}",
            "-dtls1_2", "-brief",
        ],
        capture_output=True,
        timeout=timeout + 2,
        check=False,
    )


def _capture_dtls_client_packets(
    target: str,
    iface: str | None,
    timeout: int,
) -> tuple[bytes, bytes | None]:
    """First and optional second outgoing DTLS UDP payload (ClientHello flight)."""
    host, port = _parse_target(target)
    host_ip = _resolve_host(host, port)
    local_ip = _get_local_ip_for_target(host_ip, port)
    bpf = f"udp and host {host_ip} and port {port}"

    def trigger() -> None:
        _run_dtls_client(host_ip, port, timeout)

    packets = capture_udp_payloads_with_trigger(bpf, trigger, iface=iface, timeout=timeout)
    outgoing: List[bytes] = []
    for payload, src_ip, _sport, _dst_ip, _dport in packets:
        if src_ip == local_ip and len(payload) >= 4:
            outgoing.append(payload)
    if not outgoing:
        raise CaptureError(
            "No outgoing DTLS packet found (openssl s_client -dtls1_2 may be unsupported)."
        )
    second = outgoing[1] if len(outgoing) > 1 else None
    return outgoing[0], second


class DtlsSignatureCollector(SignatureCollector):
    """Produces DTLS ClientHello signatures; uses capture when not dry-run."""

    def __init__(self, options):
        super().__init__("dtls", options)

    def _ensure_config(self) -> Dict[str, Any]:
        if not self._config:
            self.load_config()
        return self._config

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self._ensure_config()
        targets = cfg.get("targets") or []

        if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
            raise RuntimeError(
                'Config must contain "targets": ["host:443", "host:5684", ...].'
            )

        limit = self.options.count or len(targets)
        timeout = self.options.timeout or 5
        iface = self.options.iface
        signatures: List[Dict[str, Any]] = []

        if self.options.dry_run or capture_udp_payloads_with_trigger is None:
            for target in targets:
                if len(signatures) >= limit:
                    break
                tail = DTLS_PLACEHOLDER + os.urandom(24)
                entry: Dict[str, Any] = {
                    "protocol": self.protocol_name,
                    "target": target,
                    "direction": "client",
                    "hex": self.format_signature(DTLS_PLACEHOLDER),
                    "i2": self.format_signature(tail),
                }
                signatures.append(entry)
            return signatures

        for target in targets:
            if len(signatures) >= limit:
                break
            try:
                first, second = _capture_dtls_client_packets(target, iface, timeout)
                entry = {
                    "protocol": self.protocol_name,
                    "target": target,
                    "direction": "client",
                    "hex": self.format_signature(first),
                }
                if second:
                    entry["i2"] = self.format_signature(second)
                signatures.append(entry)
            except (CaptureError, OSError) as e:
                raise RuntimeError(f"DTLS capture failed for {target}: {e}") from e

        return signatures


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser(
        "DTLS ClientHello signature collector (use --dry-run for placeholders)"
    )
    args = parser.parse_args(argv)
    opts = options_from_args(args)

    collector = DtlsSignatureCollector(opts)
    signatures = collector.collect()
    collector.save(signatures)

    print(
        f"Collected {len(signatures)} DTLS signatures from {opts.config_path} "
        f"(dry_run={opts.dry_run})."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
