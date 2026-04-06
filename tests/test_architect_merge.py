"""Merge prefers capture; missing I2–I5 come from ARCHITECT_DEFAULTS only."""

from python_signatures.profile_cps import merge_collector_output


def test_merge_quic_rfc_uses_architect_i2_i5() -> None:
    out = merge_collector_output(
        "quic_rfc",
        {"hex": "<b 0xc10000000101>"},
    )
    assert out["i1"] == "<b 0xc10000000101>"
    assert "<rc 12>" in out["i2"]
    assert "c200000001" in out["i3"]
    assert out["i4"].startswith("<b 0xc100000001")


def test_merge_http3_architect() -> None:
    out = merge_collector_output("http3", {"hex": "<b 0xe10000000111>"})
    assert "e200000001" in out["i2"]


def test_merge_quic_browser_falls_back_without_architect() -> None:
    out = merge_collector_output(
        "quic_browser",
        {"hex": "<b 0xaa>"},
    )
    assert out["i1"] == "<b 0xaa>"
    assert "c0000000011421fb303f533722bcba00d68aad60d8b10e451b3d04ed7d1ca0008832068f" in out["i2"]


def test_merge_quic_browser_full_capture_preserves_all_slots() -> None:
    """Collector supplied i2–i5: merge must not replace with Architect/PROFILE."""
    sig = {
        "hex": "<b 0x01>",
        "i2": "<b 0x02>",
        "i3": "<b 0x03>",
        "i4": "<b 0x04>",
        "i5": "<b 0x05>",
    }
    out = merge_collector_output("quic_browser", sig)
    assert out["i1"] == "<b 0x01>"
    assert out["i2"] == "<b 0x02>"
    assert out["i3"] == "<b 0x03>"
    assert out["i4"] == "<b 0x04>"
    assert out["i5"] == "<b 0x05>"


def test_merge_quic_browser_partial_capture_architect_fills_tail() -> None:
    """Only hex from capture: i2–i5 from ARCHITECT_DEFAULTS quic_browser."""
    out = merge_collector_output(
        "quic_browser",
        {"hex": "<b 0xc1000000010800>"},
    )
    assert out["i1"] == "<b 0xc1000000010800>"
    assert "1421fb303f533722bcba00d68aad60d8b10e451b3d04ed7d1ca0008832068f" in out["i2"]
    assert "0913060d199eea2632f30551754f67b113945c58b996268507f24577b192117a8f1fb5ad276c5c38" in out["i3"]
    assert "08a5effc604907c5f803ec563f0cc32b0d0417fe107c145254ce1c8f90e9" in out["i4"]
    assert "125a1c4d8a3b17165e82954739914a4d8971e5101896d624e91096bdfdddf999d415646a00df30a199" in out["i5"]
