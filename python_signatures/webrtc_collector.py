"""
WebRTC (ICE/STUN) signature collector.

Same capture path as STUN. `--dry-run` loads tests/fixtures/signatures/webrtc.json.
"""

from __future__ import annotations

from typing import Any, Dict, List

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args
from python_signatures.dry_run_fixtures import build_dry_run_signatures
from python_signatures.stun_collector import _capture_stun_request_response

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

        if self.options.dry_run:
            return build_dry_run_signatures(
                "webrtc",
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
                req_b, resp_b = _capture_stun_request_response(server, iface, timeout)
                entry = {
                    "protocol": self.protocol_name,
                    "target": server,
                    "direction": "server" if use_response else "client",
                    "hex": self.format_signature(req_b),
                }
                if resp_b:
                    entry["i2"] = self.format_signature(resp_b)
                signatures.append(entry)
            except (CaptureError, OSError) as e:
                raise RuntimeError(f"WebRTC (STUN) capture failed for {server}: {e}") from e

        return signatures


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser(
        "WebRTC (ICE/STUN) signature collector (--dry-run loads webrtc.json fixture)"
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
