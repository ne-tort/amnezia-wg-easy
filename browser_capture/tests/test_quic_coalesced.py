"""QUIC coalescing helpers (no network)."""

import pytest

from browser_capture.extractors.quic_coalesced import (
    read_varint,
    split_coalesced_long_header_packets,
)


def test_read_varint_one_byte() -> None:
    v, n = read_varint(bytes([0x25]), 0)
    assert v == 37
    assert n == 1


def test_split_short_payload_unchanged() -> None:
    pl = b"\x00" * 10
    assert split_coalesced_long_header_packets(pl) == [pl]


@pytest.mark.integration
def test_integration_placeholder() -> None:
    """Real tcpdump+Chrome tests run in Docker scripts, not CI by default."""
    pass
