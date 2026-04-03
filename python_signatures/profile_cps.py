"""
Per-profile CPS defaults for I2–I5 when collectors do not supply packets.

Uses only tags supported by amneziawg-go CPS: <b>, <t>, <r>, <rc>, <rd>.
Do not use <c> (packet counter): not implemented in userspace go core — see amneziawg-go #120.
"""

from __future__ import annotations

import os
from typing import Any, Dict

# * Habr / AmneziaWG 2.0 examples: second QUIC-like fragment after Initial (magic + t + rc + r).
_QUIC_I2_TEMPLATE = "<b 0xf6ab3267fa><t><rc 20><r 80>"

# * Profile-specific fallbacks (I1 comes from collector "hex").
PROFILE_DEFAULTS: Dict[str, Dict[str, str]] = {
    "dns": {
        "i2": "<rc 32><r 72>",
        "i3": "<t>",
    },
    "quic": {
        "i2": _QUIC_I2_TEMPLATE,
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
        "i2": "<b 0x14feff0000000000000000000000><r 96>",
        "i3": "<t>",
    },
}


def obfs_r_bytes() -> int:
    return int(os.environ.get("OBFS_R_BYTES", "48"), 10)


def merge_collector_output(profile_id: str, sig: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build signatures.json entry with i1–i5. Collector sets "hex" (I1); optional i2–i5
    override per-profile defaults (PROFILE_DEFAULTS + <r N> for I4/I5).
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
