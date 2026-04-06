"""
Tie together: DNS resolve → BPF → tcpdump → Chromium trigger → QUIC-oriented extraction.
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse

from browser_capture.browser.chromium_session import run_with_page
from browser_capture.core.models import (
    CaptureResult,
    QuicTlsCaptureResult,
    SiteTarget,
    StunBrowserResult,
    UdpPacket,
)
from browser_capture.core.pcap_backend import capture_tcp_udp_during, capture_udp_during
from browser_capture.extractors.quic_coalesced import (
    filter_long_header_type_nibble,
    split_coalesced_long_header_packets,
)
from browser_capture.extractors.quic_chain import build_quic_packet_chain
from browser_capture.extractors.quic_udp import filter_quic_initial_candidates, is_likely_quic_initial
from browser_capture.extractors.stun_udp import first_stun_outgoing_incoming
from browser_capture.triggers.quic_http3 import QuicHttp3Trigger
from browser_capture.triggers.webrtc_stun import run_webrtc_stun


def _resolve_ipv4(host: str) -> str:
    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    for info in infos:
        if info[0] == socket.AF_INET:
            return str(info[4][0])
    raise RuntimeError(f"No IPv4 address for host: {host}")


def _parse_stun_url(stun_url: str) -> tuple[str, int]:
    u = stun_url.strip()
    if u.lower().startswith("stuns:"):
        u = u[6:]
    elif u.lower().startswith("stun:"):
        u = u[5:]
    if "@" in u:
        u = u.split("@", 1)[1]
    if "/" in u:
        u = u.split("/", 1)[0]
    if ":" in u:
        host, port_s = u.rsplit(":", 1)
        return host.strip(), int(port_s)
    return u.strip(), 3478


def _local_ip_toward(host: str, port: int) -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((host, port))
        return str(sock.getsockname()[0])
    finally:
        sock.close()


class CaptureOrchestrator:
    """High-level API for browser-assisted UDP capture."""

    def capture_quic_http3(
        self,
        url: str,
        *,
        iface: str | None = None,
        timeout: int = 30,
        headless: bool = True,
        enable_quic: bool = True,
        extra_chromium_args: list[str] | None = None,
        wait_until: str = "domcontentloaded",
        navigation_timeout_ms: int = 60_000,
        split_coalesced: bool = False,
        quic_high_nibble_filter: frozenset[int] | None = None,
    ) -> CaptureResult:
        """
        Open ``url`` in Chromium while tcpdump records UDP to the resolved server:443.

        Requires: tcpdump on PATH, Playwright Chromium installed, network path to host.
        """
        target = SiteTarget(url=url)
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise ValueError("URL must include a host, e.g. https://example.com/")
        port = parsed.port or 443

        host_ip = _resolve_ipv4(host)
        local_ip = _local_ip_toward(host_ip, port)
        bpf = f"udp and host {host_ip} and port {port}"

        trigger_nav = QuicHttp3Trigger(
            url,
            wait_until=wait_until,
            timeout_ms=navigation_timeout_ms,
        )

        def trigger() -> None:
            def work(page):
                trigger_nav.run(page)

            run_with_page(
                work,
                headless=headless,
                enable_quic=enable_quic,
                extra_launch_args=extra_chromium_args,
            )

        raw = capture_udp_during(bpf, trigger, iface=iface, timeout=timeout)
        outgoing = [p for p in raw if p.src_ip == local_ip]
        payloads = [p.payload for p in outgoing]
        split_flat: list[bytes] = []
        if split_coalesced:
            for pl in payloads:
                split_flat.extend(split_coalesced_long_header_packets(pl))
        to_filter = split_flat if split_coalesced and split_flat else payloads
        if quic_high_nibble_filter:
            to_filter = filter_long_header_type_nibble(to_filter, quic_high_nibble_filter)
        candidates = [p for p in to_filter if is_likely_quic_initial(p)]
        if not candidates:
            candidates = filter_quic_initial_candidates(to_filter if to_filter else payloads)

        packet_chain = build_quic_packet_chain(
            candidates,
            to_filter,
            payloads,
            max_packets=5,
        )

        return CaptureResult(
            target=target,
            bpf_filter=bpf,
            all_udp=raw,
            outgoing=outgoing,
            quic_initial_candidates=candidates,
            quic_long_header_split=split_flat,
            quic_packet_chain=packet_chain,
            meta={
                "resolved_host_ip": host_ip,
                "local_ip": local_ip,
                "hostname": host,
                "port": port,
                "split_coalesced": split_coalesced,
                "quic_chain_len": len(packet_chain),
            },
        )

    def capture_stun_webrtc(
        self,
        *,
        stun_url: str = "stun:stun.l.google.com:19302",
        iface: str | None = None,
        timeout: int = 45,
        headless: bool = True,
        extra_chromium_args: list[str] | None = None,
    ) -> StunBrowserResult:
        """
        Start ICE with ``stun_url`` in Chromium while tcpdump records UDP to the STUN server.
        """
        host, port = _parse_stun_url(stun_url)
        host_ip = _resolve_ipv4(host)
        local_ip = _local_ip_toward(host_ip, port)
        bpf = f"udp and host {host_ip} and port {port}"

        def trigger() -> None:
            def work(page):
                run_webrtc_stun(page, stun_url=stun_url, timeout_ms=min(timeout * 1000, 120_000))

            run_with_page(
                work,
                headless=headless,
                enable_quic=True,
                extra_launch_args=extra_chromium_args,
            )

        raw = capture_udp_during(bpf, trigger, iface=iface, timeout=timeout)
        triples: list[tuple[bytes, str, str]] = [
            (p.payload, p.src_ip, p.dst_ip) for p in raw
        ]
        out_b, in_b = first_stun_outgoing_incoming(triples, local_ip)
        return StunBrowserResult(
            stun_server=f"{host}:{port}",
            bpf_filter=bpf,
            all_udp=raw,
            outgoing_stun=out_b,
            incoming_stun=in_b,
            meta={
                "resolved_stun_ip": host_ip,
                "local_ip": local_ip,
                "stun_url": stun_url,
            },
        )

    def capture_https_quic_and_tcp(
        self,
        url: str,
        *,
        iface: str | None = None,
        timeout: int = 30,
        headless: bool = True,
        enable_quic: bool = True,
        extra_chromium_args: list[str] | None = None,
        wait_until: str = "domcontentloaded",
        navigation_timeout_ms: int = 60_000,
        split_coalesced: bool = False,
        quic_high_nibble_filter: frozenset[int] | None = None,
    ) -> QuicTlsCaptureResult:
        """
        Same as QUIC capture but BPF includes TCP and UDP to port — first outgoing TCP
        segment (often TLS ClientHello) is stored for ``alt-svc``-style profiles.
        """
        target = SiteTarget(url=url)
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            raise ValueError("URL must include a host")
        port = parsed.port or 443
        host_ip = _resolve_ipv4(host)
        local_ip = _local_ip_toward(host_ip, port)
        bpf = f"(tcp or udp) and host {host_ip} and port {port}"

        trigger_nav = QuicHttp3Trigger(
            url,
            wait_until=wait_until,
            timeout_ms=navigation_timeout_ms,
        )

        def trigger() -> None:
            def work(page):
                trigger_nav.run(page)

            run_with_page(
                work,
                headless=headless,
                enable_quic=enable_quic,
                extra_launch_args=extra_chromium_args,
            )

        raw_u, raw_t = capture_tcp_udp_during(bpf, trigger, iface=iface, timeout=timeout)
        outgoing_u = [p for p in raw_u if p.src_ip == local_ip]
        payloads = [p.payload for p in outgoing_u]
        split_flat: list[bytes] = []
        if split_coalesced:
            for pl in payloads:
                split_flat.extend(split_coalesced_long_header_packets(pl))
        to_filter = split_flat if split_coalesced and split_flat else payloads
        if quic_high_nibble_filter:
            to_filter = filter_long_header_type_nibble(to_filter, quic_high_nibble_filter)
        candidates = [p for p in to_filter if is_likely_quic_initial(p)]
        if not candidates:
            candidates = filter_quic_initial_candidates(to_filter if to_filter else payloads)
        outgoing_tcp = [p for p in raw_t if p.src_ip == local_ip]
        first_tcp = outgoing_tcp[0].payload if outgoing_tcp else None
        packet_chain = build_quic_packet_chain(
            candidates,
            to_filter,
            payloads,
            max_packets=5,
        )
        return QuicTlsCaptureResult(
            target=target,
            bpf_filter=bpf,
            all_udp=raw_u,
            outgoing=outgoing_u,
            quic_initial_candidates=candidates,
            quic_packet_chain=packet_chain,
            first_outgoing_tcp_payload=first_tcp,
            meta={
                "resolved_host_ip": host_ip,
                "local_ip": local_ip,
                "hostname": host,
                "port": port,
                "quic_chain_len": len(packet_chain),
            },
        )
