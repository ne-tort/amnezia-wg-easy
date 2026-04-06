"""Unit tests for QUIC heuristics (no browser, no tcpdump)."""

from browser_capture.extractors.quic_chain import build_quic_packet_chain
from browser_capture.extractors.quic_udp import (
    filter_quic_initial_candidates,
    is_likely_quic_initial,
)


def test_rejects_short_payload() -> None:
    assert not is_likely_quic_initial(b"\x00")


def test_rejects_short_header() -> None:
    assert not is_likely_quic_initial(b"\x80" + b"\x00" * 4)


def test_accepts_typical_quic_v1_initial_prefix() -> None:
    # Long header, version 1, plausible Initial first byte (0xC0 | ...)
    payload = bytes.fromhex("c700000001") + b"\x00" * 200
    assert is_likely_quic_initial(payload)


def test_filter_list() -> None:
    good = bytes.fromhex("c700000001") + b"\x00" * 100
    bad = b"notquic" * 20
    assert filter_quic_initial_candidates([bad, good]) == [good]


def test_build_quic_packet_chain_order_and_dedup() -> None:
    a = bytes.fromhex("c100000001") + b"\x00" * 20
    b = bytes.fromhex("e100000001") + b"\x00" * 20
    c = b"noise-udp-payload" * 4
    chain = build_quic_packet_chain([a], [a, b], [c, a, b], max_packets=5)
    assert chain[0] == a
    assert b in chain
    assert chain.count(a) == 1
