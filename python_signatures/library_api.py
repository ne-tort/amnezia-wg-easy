"""
Library API for web-panel integration.

This module provides a stable programmatic contract to:
- read one full I1-I5 profile from signatures JSON,
- read all profiles,
- trigger regeneration via collectors (real capture by default).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from python_signatures.architect_fallbacks import ARCHITECT_BUNDLE_DATE, ARCHITECT_BUNDLE_VERSION
from python_signatures.run_all import PROTOCOL_REGISTRY, run_all

ProfileMap = Dict[str, str]
ProfilesMap = Dict[str, ProfileMap]


def known_profile_ids() -> list[str]:
    """Return all profile ids supported by current collectors registry."""
    return [profile_id for profile_id, _, _ in PROTOCOL_REGISTRY]


def _normalize_profile_entry(raw: Any) -> ProfileMap:
    """Normalize one JSON entry to strict i1..i5 map."""
    if isinstance(raw, str):
        s = raw.strip()
        if s.startswith("{"):
            try:
                raw = json.loads(s)
            except json.JSONDecodeError:
                raw = {"i1": s}
        elif s:
            raw = {"i1": s}
        else:
            raw = {}

    if not isinstance(raw, dict):
        return {}

    out: ProfileMap = {}
    for key in ("i1", "i2", "i3", "i4", "i5"):
        v = raw.get(key)
        if isinstance(v, str) and v.strip():
            out[key] = v.strip()
    return out


def _validate_full_profile(profile_id: str, profile: ProfileMap) -> None:
    missing = [k for k in ("i1", "i2", "i3", "i4", "i5") if not profile.get(k)]
    if missing:
        raise ValueError(f"profile {profile_id!r} is incomplete, missing: {', '.join(missing)}")


def _read_profiles(signatures_path: Path) -> ProfilesMap:
    raw = json.loads(signatures_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"signatures file must be a JSON object: {signatures_path}")

    out: ProfilesMap = {}
    for profile_id, payload in raw.items():
        if not isinstance(profile_id, str):
            continue
        out[profile_id] = _normalize_profile_entry(payload)
    return out


def get_profile(
    profile_id: str,
    *,
    signatures_path: str | Path,
) -> Dict[str, Any]:
    """
    Return one profile in a web-panel friendly shape.

    Output schema:
      {
        "profile_id": "...",
        "i1": "...", "i2": "...", "i3": "...", "i4": "...", "i5": "...",
        "source_meta": {
          "architect_bundle_version": "...",
          "architect_bundle_date": "...",
          "source": "signatures_json",
          "signatures_path": "..."
        }
      }
    """
    pid = str(profile_id).strip()
    if pid not in known_profile_ids():
        raise ValueError(f"unknown profile_id={pid!r}; expected one of: {', '.join(known_profile_ids())}")

    path = Path(signatures_path).resolve()
    profiles = _read_profiles(path)
    profile = profiles.get(pid)
    if not profile:
        raise ValueError(f"profile {pid!r} not found in signatures file: {path}")
    _validate_full_profile(pid, profile)

    return {
        "profile_id": pid,
        "i1": profile["i1"],
        "i2": profile["i2"],
        "i3": profile["i3"],
        "i4": profile["i4"],
        "i5": profile["i5"],
        "source_meta": {
            "architect_bundle_version": ARCHITECT_BUNDLE_VERSION,
            "architect_bundle_date": ARCHITECT_BUNDLE_DATE,
            "source": "signatures_json",
            "signatures_path": str(path),
        },
    }


def get_all_profiles(*, signatures_path: str | Path) -> Dict[str, Dict[str, Any]]:
    """Return all known profiles in get_profile() schema."""
    path = Path(signatures_path).resolve()
    result: Dict[str, Dict[str, Any]] = {}
    for pid in known_profile_ids():
        result[pid] = get_profile(pid, signatures_path=path)
    return result


def regenerate_signatures(
    *,
    out_path: str | Path,
    config_dir: str | Path,
    timeout: int = 30,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Regenerate signatures JSON by running collectors, then return metadata.
    """
    out_p = Path(out_path).resolve()
    cfg_p = Path(config_dir).resolve()
    data = run_all(cfg_p, out_p, timeout=timeout, dry_run=dry_run)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return {
        "success": True,
        "profiles_count": len(data),
        "out_path": str(out_p),
        "dry_run": bool(dry_run),
        "architect_bundle_version": ARCHITECT_BUNDLE_VERSION,
        "architect_bundle_date": ARCHITECT_BUNDLE_DATE,
    }
