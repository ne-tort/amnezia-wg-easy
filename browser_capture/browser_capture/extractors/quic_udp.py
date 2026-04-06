"""
Heuristics to pick QUIC Long Header / Initial-like UDP payloads from raw bytes.

Not a full QUIC parser — enough to select candidates for CPS ``<b 0x...>`` extraction.
RFC 9000: Long Header (first bit 1), Version at bytes 1–4.
"""

from __future__ import annotations

# QUIC version 1
_QUIC_V1 = 0x00000001
# Common legacy / interop
_EXTRA_VERSIONS = frozenset(
    {
        0x6B3343CF,  # draft-29
        0xFF00001D,  # draft-29 alt
    }
)


def is_likely_quic_long_header(payload: bytes) -> bool:
    if len(payload) < 6:
        return False
    if (payload[0] & 0x80) == 0:
        return False
    ver = int.from_bytes(payload[1:5], "big")
    if ver == 0:
        return False
    return True


def is_likely_quic_initial(payload: bytes) -> bool:
    """
    Initial packet (RFC 9000) uses long header with type Initial (first byte 0xC0–0xCF range common).
    0-RTT uses 0xD0–0xDF; include optionally for broader capture.
    """
    if len(payload) < 20:
        return False
    if not is_likely_quic_long_header(payload):
        return False
    ver = int.from_bytes(payload[1:5], "big")
    if ver != _QUIC_V1 and ver not in _EXTRA_VERSIONS:
        # Unknown version but still long header — allow if looks like first flight
        if ver > 0xFF000000:
            return False
    # Long header packet types: high nibble often 0xC (Initial) or 0xD (0-RTT)
    hb = payload[0] & 0xF0
    return hb in (0xC0, 0xD0)


def filter_quic_initial_candidates(payloads: list[bytes]) -> list[bytes]:
    """Return payloads that look like QUIC Initial / long-header first flights."""
    return [p for p in payloads if is_likely_quic_initial(p)]
