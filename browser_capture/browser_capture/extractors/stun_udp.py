"""
STUN message detection (RFC 5389) on UDP payload.
"""

from __future__ import annotations

_STUN_MAGIC = bytes.fromhex("2112a442")


def is_stun_message(payload: bytes) -> bool:
    if len(payload) < 20:
        return False
    return payload[4:8] == _STUN_MAGIC


def filter_stun_binding_messages(payloads: list[bytes]) -> list[bytes]:
    """Keep payloads that look like STUN (magic cookie at bytes 4–7)."""
    return [p for p in payloads if is_stun_message(p)]


def first_stun_outgoing_incoming(
    packets: list[tuple[bytes, str, str]],
    local_ip: str,
) -> tuple[bytes | None, bytes | None]:
    """
    ``packets`` is list of (payload, src_ip, dst_ip).
    Returns (first outgoing STUN, first incoming STUN) if any.
    """
    out: bytes | None = None
    inc: bytes | None = None
    for payload, src, _dst in packets:
        if not is_stun_message(payload):
            continue
        if src == local_ip and out is None:
            out = payload
        elif src != local_ip and inc is None:
            inc = payload
        if out is not None and inc is not None:
            break
    return out, inc
