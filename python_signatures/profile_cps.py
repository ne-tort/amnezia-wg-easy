"""
Per-profile CPS defaults for I2–I5 when collectors do not supply packets.

Priority:
  1. Values returned by the collector (from real capture): ``hex`` (I1), optional ``i2``…``i5``.
  2. If a key is missing (e.g. no second UDP packet captured), ``merge_collector_output``
     fills from PROFILE_DEFAULTS below (curated CPS / wire-shaped fallbacks, not live traffic).

Uses only tags supported by amneziawg-go CPS: <b>, <t>, <r>, <rc>, <rd>.
Do not use <c> (packet counter): not implemented in userspace go core — see amneziawg-go #120.
"""

from __future__ import annotations

import os
from typing import Any, Dict

# * Second QUIC fragment when capture did not yield a second outgoing packet (Habr-style example).
QUIC_CPS_I2_HABR = "<b 0xf6ab3267fa><t><rc 20><r 80>"

# * Second DNS wire when collector did not run: A query for example.com with EDNS0 (40 B), realistic client.
_DNS_FALLBACK_I2_WIRE = (
    "ad3801000001000000000001076578616d706c6503636f6d000001000100002904d0000000000000"
)

# * Profile-specific fallbacks (I1 comes from collector "hex").
PROFILE_DEFAULTS: Dict[str, Dict[str, str]] = {
    "dns": {
        "i2": f"<b 0x{_DNS_FALLBACK_I2_WIRE}>",
        "i3": "<t>",
    },
    "quic": {
        "i2": QUIC_CPS_I2_HABR,
        "i3": "<t>",
    },
    "stun": {
        "i2": "<b 0x010100002112a442><rc 12><r 64>",
        "i3": "<t>",
    },
    "sip": {
        "i2": "<rc 40><r 80>",
        "i3": "<t>",
    },
    "webrtc": {
        "i2": "<b 0x010100002112a442><rc 12><r 64>",
        "i3": "<t>",
    },
    "dtls": {
        # Handshake record (0x16), DTLS 1.2 (0xfefd), not ChangeCipherSpec (0x14).
        "i2": "<b 0x16fefd0000000000000000000000><r 96>",
        "i3": "<t>",
    },
}


def obfs_r_bytes() -> int:
    return int(os.environ.get("OBFS_R_BYTES", "48"), 10)


def merge_collector_output(profile_id: str, sig: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build signatures.json entry with i1–i5.

    Collector sets ``hex`` (I1) from capture; optional ``i2``…``i5`` when present.
    Any missing slot uses PROFILE_DEFAULTS for that profile (fallback when capture
    did not provide a second packet, etc.).
    """
    hex_val = sig.get("hex")
    if not isinstance(hex_val, str) or not hex_val.strip().startswith("<b 0x"):
        raise ValueError("signature must have hex (I1) starting with <b 0x")

    out: Dict[str, Any] = {"i1": hex_val.strip()}
    prof = PROFILE_DEFAULTS.get(profile_id, PROFILE_DEFAULTS["dns"])
    r_n = obfs_r_bytes()

    def pick(key: str, fallback: str) -> str:
        v = sig.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        return fallback

    out["i2"] = pick("i2", prof.get("i2", "<rc 24><r 80>"))
    out["i3"] = pick("i3", prof.get("i3", "<t>"))
    out["i4"] = pick("i4", f"<r {r_n}>")
    out["i5"] = pick("i5", f"<r {r_n}>")

    return out
