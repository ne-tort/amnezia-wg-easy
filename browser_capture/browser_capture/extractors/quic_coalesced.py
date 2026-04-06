"""
Split coalesced QUIC packets inside one UDP datagram (RFC 9000).

Uses long-header length field for Initial/0-RTT/Handshake/Retry where applicable.
Falls back to scanning for the next plausible long-header start if parsing fails.
"""

from __future__ import annotations

# RFC 9000 variable-length integer
def read_varint(buf: bytes, off: int) -> tuple[int, int]:
    if off >= len(buf):
        raise ValueError("varint past eof")
    b0 = buf[off]
    t = b0 >> 6
    if t == 0:
        return b0 & 0x3F, off + 1
    if t == 1:
        if off + 2 > len(buf):
            raise ValueError("varint past eof")
        return ((b0 & 0x3F) << 8) | buf[off + 1], off + 2
    if t == 2:
        if off + 4 > len(buf):
            raise ValueError("varint past eof")
        return (
            ((b0 & 0x3F) << 24)
            | (buf[off + 1] << 16)
            | (buf[off + 2] << 8)
            | buf[off + 3]
        ), off + 4
    if off + 8 > len(buf):
        raise ValueError("varint past eof")
    v = (
        (b0 & 0x3F) << 56
        | buf[off + 1] << 48
        | buf[off + 2] << 40
        | buf[off + 3] << 32
        | buf[off + 4] << 24
        | buf[off + 5] << 16
        | buf[off + 6] << 8
        | buf[off + 7]
    )
    return v, off + 8


def _long_header_total_len(data: bytes, start: int) -> int | None:
    """
    Return total byte length of one long-header QUIC packet starting at ``start``,
    or None if not parseable.
    """
    if start + 6 > len(data):
        return None
    if (data[start] & 0x80) == 0:
        return None
    ver = int.from_bytes(data[start + 1 : start + 5], "big")
    if ver == 0:
        return None
    # RFC 9000: bits 5-4 of first byte = Long Packet Type (Initial, 0-RTT, Handshake, Retry)
    ptype = (data[start] >> 4) & 0x03
    off = start + 5
    try:
        dcil = data[off]
        off += 1 + dcil
        if off > len(data):
            return None
        scil = data[off]
        off += 1 + scil
        if off > len(data):
            return None
        if ptype == 3:  # Retry — ODCID + Retry Token + tag; approximate rest of datagram
            return len(data) - start
        if ptype == 0:  # Initial: Token Length + Token + Length
            tok_len, off = read_varint(data, off)
            off += tok_len
            if off > len(data):
                return None
        # 0-RTT, Handshake: Length immediately after SCID; Initial after token
        plen, off = read_varint(data, off)
        total = off - start + plen
        if total > len(data) - start:
            return len(data) - start
        return total
    except (ValueError, IndexError):
        return None


def split_coalesced_long_header_packets(udp_payload: bytes) -> list[bytes]:
    """
    Split ``udp_payload`` into individual long-header QUIC packets when coalesced.
    If a single packet or parse fails, returns ``[udp_payload]`` or best effort.
    """
    if len(udp_payload) < 20:
        return [udp_payload]
    out: list[bytes] = []
    pos = 0
    while pos < len(udp_payload):
        if (udp_payload[pos] & 0x80) == 0:
            # Short header: rest is one logical packet (do not split further without keys)
            out.append(udp_payload[pos:])
            break
        tlen = _long_header_total_len(udp_payload, pos)
        if tlen is None or tlen < 20:
            out.append(udp_payload[pos:])
            break
        end = pos + min(tlen, len(udp_payload) - pos)
        out.append(udp_payload[pos:end])
        pos = end
        if pos < len(udp_payload) and end == pos:
            break
    return out if out else [udp_payload]


def filter_long_header_type_nibble(
    payloads: list[bytes], allowed_high_nibbles: frozenset[int] | None
) -> list[bytes]:
    """If ``allowed_high_nibbles`` is set, keep packets whose first byte high nibble is in set (e.g. 0xE for some stacks)."""
    if not allowed_high_nibbles:
        return payloads
    res: list[bytes] = []
    for p in payloads:
        if len(p) < 1:
            continue
        hn = (p[0] >> 4) & 0x0F
        if hn in allowed_high_nibbles:
            res.append(p)
    return res
