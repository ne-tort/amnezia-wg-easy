from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class UdpPacket:
    """One UDP datagram as seen on the wire (payload only, no IP/UDP headers)."""

    payload: bytes
    src_ip: str
    sport: int
    dst_ip: str
    dport: int


@dataclass(frozen=True)
class SiteTarget:
    """HTTPS target for QUIC/HTTP3-style capture."""

    url: str
    """Full URL, e.g. https://example.com/"""


@dataclass
class CaptureResult:
    """Outcome of a browser + pcap capture run."""

    target: SiteTarget
    bpf_filter: str
    all_udp: list[UdpPacket] = field(default_factory=list)
    """All UDP payloads matching the BPF filter (chronological)."""
    outgoing: list[UdpPacket] = field(default_factory=list)
    """Packets with src_ip == local endpoint (client -> server)."""
    quic_initial_candidates: list[bytes] = field(default_factory=list)
    """Payloads that pass is_likely_quic_initial."""
    quic_long_header_split: list[bytes] = field(default_factory=list)
    """Per-packet long-header slices after coalescing split (optional)."""
    quic_packet_chain: list[bytes] = field(default_factory=list)
    """Up to 5 distinct outgoing QUIC payloads for i1–i5 (Initial first, then other long-header, then UDP)."""
    meta: dict[str, Any] = field(default_factory=dict)
    """e.g. resolved_host_ip, local_ip, errors."""


@dataclass
class QuicTlsCaptureResult:
    """QUIC UDP plus optional first outgoing TCP payload (TLS handshakes)."""

    target: SiteTarget
    bpf_filter: str
    all_udp: list[UdpPacket] = field(default_factory=list)
    outgoing: list[UdpPacket] = field(default_factory=list)
    quic_initial_candidates: list[bytes] = field(default_factory=list)
    quic_packet_chain: list[bytes] = field(default_factory=list)
    """Same semantics as ``CaptureResult.quic_packet_chain``."""
    first_outgoing_tcp_payload: bytes | None = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class StunBrowserResult:
    """STUN Binding capture from WebRTC-in-Chromium."""

    stun_server: str
    bpf_filter: str
    all_udp: list[UdpPacket] = field(default_factory=list)
    outgoing_stun: bytes | None = None
    incoming_stun: bytes | None = None
    meta: dict[str, Any] = field(default_factory=dict)
