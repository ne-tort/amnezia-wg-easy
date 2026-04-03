"""profile_cps.merge_collector_output builds full i1–i5 CPS maps."""

from python_signatures.base import split_r_tags
from python_signatures.profile_cps import merge_collector_output


def test_merge_fills_chain() -> None:
    out = merge_collector_output(
        "dns",
        {"hex": "<b 0x010203>"},
    )
    assert out["i1"] == "<b 0x010203>"
    assert "i2" in out and "i3" in out
    assert out["i3"] == "<t>"
    assert out["i4"].startswith("<r ")
    assert out["i5"].startswith("<r ")


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
