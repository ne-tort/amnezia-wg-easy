"""
QUIC/HTTP3 capture via Chromium (Playwright) + tcpdump — see ``browser_capture`` package.
"""

from __future__ import annotations

from typing import Any, Dict, List

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args
from python_signatures.dry_run_fixtures import build_dry_run_signatures

try:
    from browser_capture.core.models import QuicTlsCaptureResult
    from browser_capture.core.orchestrator import CaptureOrchestrator
except ImportError:  # pragma: no cover - optional path install
    CaptureOrchestrator = None  # type: ignore[misc, assignment]
    QuicTlsCaptureResult = None  # type: ignore[misc, assignment]


class BrowserQuicSignatureCollector(SignatureCollector):
    """Chromium + tcpdump → real QUIC bytes; ``dry_run`` swaps in fixture JSON (tests only)."""

    def __init__(self, options: Any) -> None:
        rid = getattr(options, "registry_profile_id", None)
        if not isinstance(rid, str) or not rid.strip():
            rid = "quic_browser"
        super().__init__(rid.strip(), options)

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
        timeout = self.options.timeout or 45
        iface = self.options.iface
        split_coalesced = bool(cfg.get("split_coalesced", False))
        https_quic_tcp = bool(cfg.get("https_quic_tcp", False))
        tls_clienthello_as_i1 = bool(cfg.get("tls_clienthello_as_i1", False))

        if self.options.dry_run:
            return build_dry_run_signatures(
                self.protocol_name,
                self.protocol_name,
                urls,
                limit=limit,
                direction="client",
            )

        if CaptureOrchestrator is None:
            raise RuntimeError(
                "browser_capture is not installed. From repo root: pip install -e browser_capture && playwright install chromium"
            )

        orch = CaptureOrchestrator()
        signatures: List[Dict[str, Any]] = []

        for url in urls:
            if len(signatures) >= limit:
                break
            try:
                if https_quic_tcp:
                    r = orch.capture_https_quic_and_tcp(
                        url,
                        iface=iface,
                        timeout=timeout,
                        split_coalesced=split_coalesced,
                    )
                else:
                    r = orch.capture_quic_http3(
                        url,
                        iface=iface,
                        timeout=timeout,
                        split_coalesced=split_coalesced,
                    )
                chain = list(r.quic_packet_chain) if r.quic_packet_chain else list(r.quic_initial_candidates)
                if not chain and not (
                    tls_clienthello_as_i1
                    and https_quic_tcp
                    and QuicTlsCaptureResult is not None
                    and isinstance(r, QuicTlsCaptureResult)
                    and r.first_outgoing_tcp_payload
                ):
                    raise RuntimeError("No QUIC/TLS payload chain in capture")

                entry: Dict[str, Any] = {
                    "protocol": self.protocol_name,
                    "target": url,
                    "direction": "client",
                }
                use_tls_i1 = (
                    tls_clienthello_as_i1
                    and https_quic_tcp
                    and QuicTlsCaptureResult is not None
                    and isinstance(r, QuicTlsCaptureResult)
                    and r.first_outgoing_tcp_payload is not None
                )
                if use_tls_i1:
                    entry["hex"] = self.format_signature(r.first_outgoing_tcp_payload)
                    slot_keys = ("i2", "i3", "i4", "i5")
                    for sk, idx in zip(slot_keys, range(len(chain))):
                        entry[sk] = self.format_signature(chain[idx])
                else:
                    entry["hex"] = self.format_signature(chain[0])
                    slot_keys = ("i2", "i3", "i4", "i5")
                    for sk, j in zip(slot_keys, range(1, len(chain))):
                        entry[sk] = self.format_signature(chain[j])
                signatures.append(entry)
            except Exception as e:
                raise RuntimeError(f"Browser QUIC capture failed for {url}: {e}") from e

        return signatures


def main(argv: List[str] | None = None) -> int:
    parser = build_arg_parser(
        "Browser QUIC collector (Chromium + tcpdump). Dry-run: tests/fixtures/signatures/quic_browser.json"
    )
    args = parser.parse_args(argv)
    opts = options_from_args(args)
    col = BrowserQuicSignatureCollector(opts)
    sigs = col.collect()
    col.save(sigs)
    print(f"Collected {len(sigs)} browser QUIC signatures (dry_run={opts.dry_run}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
