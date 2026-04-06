"""
CLI: ``browser-capture https://example.com/`` — run QUIC-oriented browser capture (needs tcpdump + Playwright).
"""

from __future__ import annotations

import argparse
import json
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Capture UDP (QUIC) while Chromium loads an HTTPS URL (tcpdump + Playwright)."
    )
    parser.add_argument("url", help="HTTPS URL, e.g. https://cloudflare.com/")
    parser.add_argument(
        "--iface",
        "-i",
        default=None,
        help="Network interface for tcpdump (default: any)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Seconds to wait for packets after navigation",
    )
    parser.add_argument(
        "--headed",
        action="store_true",
        help="Run Chromium with a window (better fingerprint than headless on some sites)",
    )
    parser.add_argument(
        "--no-quic",
        action="store_true",
        help="Pass --disable-quic to Chromium (for comparison only)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print summary as JSON (payloads as hex)",
    )
    args = parser.parse_args(argv)

    from browser_capture.core.orchestrator import CaptureOrchestrator

    orch = CaptureOrchestrator()
    try:
        result = orch.capture_quic_http3(
            args.url,
            iface=args.iface,
            timeout=args.timeout,
            headless=not args.headed,
            enable_quic=not args.no_quic,
        )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.json:
        out = {
            "meta": result.meta,
            "bpf": result.bpf_filter,
            "quic_initial_hex": [p.hex() for p in result.quic_initial_candidates],
            "outgoing_count": len(result.outgoing),
            "udp_total": len(result.all_udp),
        }
        print(json.dumps(out, indent=2))
        return 0

    print("meta:", result.meta)
    print("bpf:", result.bpf_filter)
    print("udp packets:", len(result.all_udp), "outgoing:", len(result.outgoing))
    print("QUIC Initial candidates:", len(result.quic_initial_candidates))
    for i, p in enumerate(result.quic_initial_candidates[:5]):
        print(f"  [{i}] len={len(p)} hex_prefix={p[:24].hex()}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
