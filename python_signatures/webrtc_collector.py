"""
WebRTC (ICE/STUN) signature collector.

Uses the same approach as the STUN collector: ICE typically starts with STUN
Binding requests. With `--dry-run` emits minimal STUN request; without,
sends real STUN and captures first client or server packet per config
\"use_response\": true|false.
"""

from __future__ import annotations

from typing import Any, Dict, List

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args
from python_signatures.stun_collector import _capture_stun_packet, STUN_BINDING_REQUEST

try:
    from python_signatures.capture import CaptureError
except ImportError:
    CaptureError = RuntimeError  # type: ignore[misc, assignment]


class WebrtcSignatureCollector(SignatureCollector):
    """WebRTC l1 signatures from ICE/STUN; delegates to STUN capture logic."""

    def __init__(self, options):
        super().__init__("webrtc", options)

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

        try:
            from python_signatures.capture import capture_udp_payloads_with_trigger
        except ImportError:
            capture_udp_payloads_with_trigger = None

        if self.options.dry_run or capture_udp_payloads_with_trigger is None:
            for server in servers:
                if len(signatures) >= limit:
                    break
                signatures.append(
                    {
                        "protocol": self.protocol_name,
                        "target": server,
                        "direction": "client",
                        "hex": self.format_signature(STUN_BINDING_REQUEST),
                    }
                )
            return signatures

        for server in servers:
            if len(signatures) >= limit:
                break
            try:
                payload = _capture_stun_packet(server, use_response, iface, timeout)
                signatures.append(
                    {
                        "protocol": self.protocol_name,
                        "target": server,
                        "direction": direction,
                        "hex": self.format_signature(payload),
                    }
                )
            except (CaptureError, OSError) as e:
                raise RuntimeError(f"WebRTC (STUN) capture failed for {server}: {e}") from e

        return signatures


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser(
        "WebRTC (ICE/STUN) signature collector (use --dry-run for synthetic payloads)"
    )
    args = parser.parse_args(argv)
    opts = options_from_args(args)

    collector = WebrtcSignatureCollector(opts)
    signatures = collector.collect()
    collector.save(signatures)

    print(
        f"Collected {len(signatures)} WebRTC signatures from {opts.config_path} "
        f"(dry_run={opts.dry_run})."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
