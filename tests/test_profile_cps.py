"""profile_cps.merge_collector_output builds full i1–i5 CPS maps."""

import pytest

from python_signatures.base import split_r_tags
from python_signatures.profile_cps import merge_collector_output


def test_merge_fills_chain() -> None:
    out = merge_collector_output(
        "dns",
        {"hex": "<b 0x010203>"},
    )
    assert out["i1"] == "<b 0x010203>"
    assert "e166010000010000000000000a323430433a3a3636363600001c0001" in out["i2"]
    assert "cd6f0100000100000000000002373702393102363801380000010001" in out["i3"]
    assert "8037010000010000000000000236340136023634013600001c0001" in out["i4"]
    assert "1a41010000010000000000000331393403323432013201330000010001" in out["i5"]


def test_merge_unknown_profile_raises() -> None:
    with pytest.raises(ValueError, match="unknown profile_id"):
        merge_collector_output("nonexistent_profile_xyz", {"hex": "<b 0x01>"})


def test_merge_respects_overrides() -> None:
    out = merge_collector_output(
        "quic",
        {
            "hex": "<b 0xab>",
            "i2": "<rc 10><r 20>",
            "i4": "<r 99>",
        },
    )
    assert out["i2"] == "<rc 10><r 20>"
    assert out["i4"] == "<r 99>"


def test_split_r_tags_chunks() -> None:
    assert split_r_tags(0) == ""
    assert split_r_tags(100) == "<r 100>"
    assert split_r_tags(1500, max_chunk=1000) == "<r 1000><r 500>"
