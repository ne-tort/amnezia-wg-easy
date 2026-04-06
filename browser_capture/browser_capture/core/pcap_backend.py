"""
tcpdump -> pcap -> Scapy UDP payload extraction (standalone copy of the idea from wg-easy capture.py).
"""

from __future__ import annotations

from dataclasses import dataclass
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, List, Optional

from scapy.all import PcapReader  # type: ignore[import]
from scapy.layers.inet import IP, TCP, UDP  # type: ignore[import]
from scapy.layers.inet6 import IPv6  # type: ignore[import]

from browser_capture.core.models import UdpPacket


@dataclass(frozen=True)
class TcpPayload:
    """First-seen TCP payload segment (may be partial TLS record)."""

    payload: bytes
    src_ip: str
    sport: int
    dst_ip: str
    dport: int


class PcapError(RuntimeError):
    """Capture or tcpdump failure."""


def read_udp_from_pcap(pcap_path: Path) -> List[UdpPacket]:
    out: List[UdpPacket] = []
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if UDP not in pkt or not (IP in pkt or IPv6 in pkt):
                continue
            udp = pkt[UDP]
            payload = bytes(udp.payload)
            if not payload:
                continue
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            out.append(
                UdpPacket(
                    payload=payload,
                    src_ip=src_ip,
                    sport=int(udp.sport),
                    dst_ip=dst_ip,
                    dport=int(udp.dport),
                )
            )
    return out


def read_tcp_udp_from_pcap(pcap_path: Path) -> tuple[List[UdpPacket], List["TcpPayload"]]:
    """UDP and TCP payloads from one pcap (chronological per layer type)."""
    return read_udp_from_pcap(pcap_path), read_tcp_payloads_from_pcap(pcap_path)


def read_tcp_payloads_from_pcap(pcap_path: Path) -> List["TcpPayload"]:
    """All TCP segments with non-empty payload (chronological)."""
    out: List[TcpPayload] = []
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if TCP not in pkt or not (IP in pkt or IPv6 in pkt):
                continue
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)
            if not payload:
                continue
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            out.append(
                TcpPayload(
                    payload=payload,
                    src_ip=str(ip_layer.src),
                    sport=int(tcp.sport),
                    dst_ip=str(ip_layer.dst),
                    dport=int(tcp.dport),
                )
            )
    return out


def capture_tcp_during(
    bpf_filter: str,
    trigger: Callable[[], None],
    *,
    iface: Optional[str] = None,
    timeout: int = 30,
    tcpdump_sleep: float = 0.5,
) -> List[TcpPayload]:
    """Like ``capture_udp_during`` but returns TCP payloads (e.g. TLS ClientHello)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = Path(tmpdir) / "capture.pcap"
        cmd = ["tcpdump", "-w", str(pcap_path), "-U", "-n"]
        if iface:
            cmd.extend(["-i", iface])
        cmd.append(bpf_filter)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            raise PcapError("tcpdump not found on PATH; install tcpdump.") from exc

        try:
            time.sleep(tcpdump_sleep)
            trigger()
            start = time.time()
            while time.time() - start < timeout:
                if pcap_path.exists() and pcap_path.stat().st_size > 24:
                    time.sleep(0.35)
                    break
                time.sleep(0.15)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not pcap_path.exists() or pcap_path.stat().st_size <= 24:
            raise PcapError("No packets captured; check BPF, iface, or firewall.")

        return read_tcp_payloads_from_pcap(pcap_path)


def capture_tcp_udp_during(
    bpf_filter: str,
    trigger: Callable[[], None],
    *,
    iface: Optional[str] = None,
    timeout: int = 30,
    tcpdump_sleep: float = 0.5,
) -> tuple[List[UdpPacket], List[TcpPayload]]:
    """Single tcpdump session; return both UDP and TCP payloads (e.g. QUIC + TLS)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = Path(tmpdir) / "capture.pcap"
        cmd = ["tcpdump", "-w", str(pcap_path), "-U", "-n"]
        if iface:
            cmd.extend(["-i", iface])
        cmd.append(bpf_filter)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            raise PcapError("tcpdump not found on PATH; install tcpdump.") from exc

        try:
            time.sleep(tcpdump_sleep)
            trigger()
            start = time.time()
            while time.time() - start < timeout:
                if pcap_path.exists() and pcap_path.stat().st_size > 24:
                    time.sleep(0.35)
                    break
                time.sleep(0.15)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not pcap_path.exists() or pcap_path.stat().st_size <= 24:
            raise PcapError("No packets captured; check BPF, iface, or firewall.")

        return read_tcp_udp_from_pcap(pcap_path)


def capture_udp_during(
    bpf_filter: str,
    trigger: Callable[[], None],
    *,
    iface: Optional[str] = None,
    timeout: int = 30,
    tcpdump_sleep: float = 0.5,
) -> List[UdpPacket]:
    """
    Start tcpdump, wait, run ``trigger()`` (sync), stop tcpdump, return all UDP packets.

    ``trigger`` should generate the traffic (e.g. open a page in Chromium).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        pcap_path = Path(tmpdir) / "capture.pcap"
        cmd = ["tcpdump", "-w", str(pcap_path), "-U", "-n"]
        if iface:
            cmd.extend(["-i", iface])
        cmd.append(bpf_filter)

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError as exc:
            raise PcapError("tcpdump not found on PATH; install tcpdump.") from exc

        try:
            time.sleep(tcpdump_sleep)
            trigger()
            start = time.time()
            while time.time() - start < timeout:
                if pcap_path.exists() and pcap_path.stat().st_size > 24:
                    time.sleep(0.35)
                    break
                time.sleep(0.15)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

        if not pcap_path.exists() or pcap_path.stat().st_size <= 24:
            raise PcapError("No packets captured; check BPF, iface, or firewall.")

        return read_udp_from_pcap(pcap_path)
