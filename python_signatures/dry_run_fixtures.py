"""
Pre-recorded CPS snapshots for `run_all --dry-run` and unit tests only.

They are **not** the objective output of the library: they are static JSON
committed under ``tests/fixtures/signatures/`` so CI can run without tcpdump,
curl targets, or browser_capture.

Objective I1–I5: run ``python -m python_signatures.run_all --out …`` **without**
``--dry-run`` so each collector executes real capture, then merge runs as usual.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

_FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "signatures"


def load_dry_run_fixture(profile_id: str) -> Dict[str, Any]:
    """Load tests/fixtures/signatures/{profile_id}.json (hex, optional i2)."""
    path = _FIXTURES_DIR / f"{profile_id}.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"Dry-run fixture missing: {path}. "
            "Add a JSON file with 'hex' (and optional 'i2') CPS strings."
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Fixture {path} must be a JSON object.")
    hex_val = data.get("hex")
    if not isinstance(hex_val, str) or not hex_val.strip().startswith("<b 0x"):
        raise ValueError(f"Fixture {path} must contain string 'hex' starting with <b 0x")
    return data


def build_dry_run_signatures(
    profile_id: str,
    protocol_name: str,
    targets: List[str],
    *,
    limit: int | None = None,
    direction: str = "client",
) -> List[Dict[str, Any]]:
    """Build signature dicts for each target using the same fixture CPS."""
    fx = load_dry_run_fixture(profile_id)
    hex_v = fx["hex"].strip()
    i2_v = fx.get("i2")
    if isinstance(i2_v, str):
        i2_v = i2_v.strip()
    else:
        i2_v = None

    out: List[Dict[str, Any]] = []
    lim = limit if limit is not None else len(targets)
    for t in targets:
        if len(out) >= lim:
            break
        entry: Dict[str, Any] = {
            "protocol": protocol_name,
            "target": t,
            "direction": direction,
            "hex": hex_v,
        }
        if i2_v:
            entry["i2"] = i2_v
        out.append(entry)
    return out
