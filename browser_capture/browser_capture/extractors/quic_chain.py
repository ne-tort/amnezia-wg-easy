"""
Build an ordered list of up to N distinct outgoing QUIC payloads for i1–i5 mapping.

Order: Initial candidates first, then other long-header packets, then remaining UDP payloads.
"""

from __future__ import annotations

from browser_capture.extractors.quic_udp import is_likely_quic_long_header


def build_quic_packet_chain(
    initial_candidates: list[bytes],
    filtered_payloads: list[bytes],
    raw_outgoing_payloads: list[bytes],
    *,
    max_packets: int = 5,
) -> list[bytes]:
    """
    ``initial_candidates``: Initial-like (or filtered) QUIC packets in capture order.
    ``filtered_payloads``: same set used for filtering (post-split / nib filter).
    ``raw_outgoing_payloads``: per-datagram outgoing UDP payloads (chronological).
    """
    chain: list[bytes] = []

    def _add_from(seq: list[bytes]) -> None:
        for b in seq:
            if len(chain) >= max_packets:
                return
            if b not in chain:
                chain.append(b)

    _add_from(initial_candidates)
    if len(chain) < max_packets:
        for b in filtered_payloads:
            if len(chain) >= max_packets:
                break
            if b in chain:
                continue
            if is_likely_quic_long_header(b):
                chain.append(b)
    if len(chain) < max_packets:
        _add_from(raw_outgoing_payloads)
    return chain[:max_packets]
