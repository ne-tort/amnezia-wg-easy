"""
STUN Binding via WebRTC in Chromium + tcpdump.
"""

from __future__ import annotations

from typing import Any, Dict, List

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args
from python_signatures.dry_run_fixtures import build_dry_run_signatures

try:
    from browser_capture.core.orchestrator import CaptureOrchestrator
except ImportError:
    CaptureOrchestrator = None  # type: ignore[misc, assignment]


def _resolve_stun_url(cfg: Dict[str, Any]) -> str:
    u = cfg.get("stun_url")
    if isinstance(u, str) and u.strip():
        return u.strip()
    servers = cfg.get("servers")
    if isinstance(servers, list) and servers:
        first = str(servers[0]).strip()
        if first.startswith("stun:"):
            return first
        if ":" in first:
            return f"stun:{first}"
        return f"stun:{first}:3478"
    return "stun:stun.l.google.com:19302"


class BrowserStunSignatureCollector(SignatureCollector):
    """ICE + STUN from real pcap; ``dry_run`` uses ``<profile_id>.json`` fixture (tests only)."""

    def __init__(self, options: Any) -> None:
        rid = getattr(options, "registry_profile_id", None)
        if not isinstance(rid, str) or not rid.strip():
            rid = "stun_browser"
        super().__init__(rid.strip(), options)

    def _ensure_config(self) -> Dict[str, Any]:
        if not self._config:
            self.load_config()
        return self._config

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self._ensure_config()
        stun_url = cfg.get("stun_url") or "stun:stun.l.google.com:19302"
        if not isinstance(stun_url, str):
            raise RuntimeError('Config "stun_url" must be a string.')

        timeout = self.options.timeout or 45
        iface = self.options.iface

        if self.options.dry_run:
            return build_dry_run_signatures(
                self.protocol_name,
                self.protocol_name,
                [stun_url],
                limit=1,
                direction="client",
            )

        if CaptureOrchestrator is None:
            raise RuntimeError(
                "browser_capture is not installed. From repo root: pip install -e browser_capture && playwright install chromium"
            )

        orch = CaptureOrchestrator()
        try:
            r = orch.capture_stun_webrtc(stun_url=stun_url, iface=iface, timeout=timeout)
        except Exception as e:
            raise RuntimeError(f"Browser STUN capture failed: {e}") from e

        if not r.outgoing_stun:
            raise RuntimeError("No outgoing STUN packet in capture")

        entry: Dict[str, Any] = {
            "protocol": self.protocol_name,
            "target": stun_url,
            "direction": "client",
            "hex": self.format_signature(r.outgoing_stun),
        }
        if r.incoming_stun:
            entry["i2"] = self.format_signature(r.incoming_stun)
        return [entry]


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser("Browser STUN collector (WebRTC ICE + tcpdump)")
    args = parser.parse_args(argv)
    opts = options_from_args(args)
    col = BrowserStunSignatureCollector(opts)
    sigs = col.collect()
    col.save(sigs)
    print(f"Collected {len(sigs)} browser STUN signatures (dry_run={opts.dry_run}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
