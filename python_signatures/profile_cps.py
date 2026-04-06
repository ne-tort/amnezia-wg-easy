"""
Per-profile CPS merge for I1–I5.

Priority:
  1. Collector ``hex`` (I1) and any non-empty ``i2``…``i5`` from live capture.
  2. Every missing slot is filled from ``ARCHITECT_DEFAULTS[profile_id]`` in
     ``architect_fallbacks.py`` (versioned bundle — single objective fallback).

There is no separate PROFILE layer: Architect holds the full I2–I5 chain for
each ``profile_id`` so merge always emits a complete five-slot CPS map.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from python_signatures.architect_fallbacks import ARCHITECT_DEFAULTS


def obfs_r_bytes() -> int:
    """Legacy helper for tooling that still reads ``OBFS_R_BYTES`` from the environment."""
    return int(os.environ.get("OBFS_R_BYTES", "48"), 10)


def merge_collector_output(profile_id: str, sig: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build ``{ i1, i2, i3, i4, i5 }`` CPS strings.

    I1 is always ``sig``'s ``hex``. I2–I5: capture values win; otherwise Architect
    constants for this ``profile_id`` (every profile must define all four keys).
    """
    hex_val = sig.get("hex")
    if not isinstance(hex_val, str) or not hex_val.strip().startswith("<b 0x"):
        raise ValueError("signature must have hex (I1) starting with <b 0x")

    arch = ARCHITECT_DEFAULTS.get(profile_id)
    if arch is None:
        raise ValueError(
            f"merge_collector_output: unknown profile_id={profile_id!r}; "
            f"add full i2–i5 to ARCHITECT_DEFAULTS in architect_fallbacks.py"
        )
    for key in ("i2", "i3", "i4", "i5"):
        if key not in arch:
            raise ValueError(
                f"ARCHITECT_DEFAULTS[{profile_id!r}] must define {key!r} (full I2–I5 bundle)"
            )

    out: Dict[str, Any] = {"i1": hex_val.strip()}

    def pick(key: str) -> str:
        v = sig.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
        return arch[key]

    out["i2"] = pick("i2")
    out["i3"] = pick("i3")
    out["i4"] = pick("i4")
    out["i5"] = pick("i5")

    return out
