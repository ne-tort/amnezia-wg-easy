"""Contract tests for python_signatures.library_api."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from python_signatures.library_api import get_all_profiles, get_profile, known_profile_ids


def _write_signatures(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "quic": {
                    "i1": "<b 0x01>",
                    "i2": "<b 0x02>",
                    "i3": "<b 0x03>",
                    "i4": "<b 0x04>",
                    "i5": "<b 0x05>",
                },
                "dns": {
                    "i1": "<b 0x11>",
                    "i2": "<b 0x12>",
                    "i3": "<b 0x13>",
                    "i4": "<b 0x14>",
                    "i5": "<b 0x15>",
                },
            }
        ),
        encoding="utf-8",
    )


def test_get_profile_returns_full_payload(tmp_path: Path) -> None:
    sig_path = tmp_path / "signatures.json"
    _write_signatures(sig_path)

    out = get_profile("quic", signatures_path=sig_path)
    assert out["profile_id"] == "quic"
    assert out["i1"] == "<b 0x01>"
    assert out["i5"] == "<b 0x05>"
    assert out["source_meta"]["architect_bundle_version"]


def test_get_profile_unknown_profile_raises(tmp_path: Path) -> None:
    sig_path = tmp_path / "signatures.json"
    _write_signatures(sig_path)

    with pytest.raises(ValueError, match="unknown profile_id"):
        get_profile("nonexistent", signatures_path=sig_path)


def test_get_profile_incomplete_profile_raises(tmp_path: Path) -> None:
    sig_path = tmp_path / "signatures.json"
    sig_path.write_text(json.dumps({"quic": {"i1": "<b 0x01>"}}), encoding="utf-8")

    with pytest.raises(ValueError, match="incomplete"):
        get_profile("quic", signatures_path=sig_path)


def test_get_all_profiles_returns_known_registry_only(tmp_path: Path) -> None:
    sig_path = tmp_path / "signatures.json"
    payload = {
        pid: {
            "i1": f"<b 0x{idx:02x}01>",
            "i2": f"<b 0x{idx:02x}02>",
            "i3": f"<b 0x{idx:02x}03>",
            "i4": f"<b 0x{idx:02x}04>",
            "i5": f"<b 0x{idx:02x}05>",
        }
        for idx, pid in enumerate(known_profile_ids(), start=1)
    }
    sig_path.write_text(json.dumps(payload), encoding="utf-8")

    all_profiles = get_all_profiles(signatures_path=sig_path)
    assert sorted(all_profiles.keys()) == sorted(known_profile_ids())
    assert all_profiles["quic"]["i3"].startswith("<b 0x")
