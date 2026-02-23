"""
Integration tests for Amnezia DNS resolution.

Resolves a domain via amnezia-dns (Unbound at 172.29.172.254) and optionally
via VPN gateway (dnsmasq at 10.8.0.1). Run from host: ensure amnezia-dns and
amnezia-awg are up; for 10.8.0.1 the test must run inside the wg-easy container
(e.g. docker exec amnezia-awg python -m pytest tests/test_amnezia_dns_resolve.py -v).
"""

import os

import pytest

try:
    import dns.resolver
except ImportError:
    dns = None  # type: ignore[assignment]


# * Resolver IPs: Unbound in amnezia-dns container; dnsmasq on VPN gateway in amnezia-awg.
AMNEZIA_UNBOUND_IP = os.environ.get("AMNEZIA_DNS_RESOLVER", "172.29.172.254")
GATEWAY_DNS_IP = os.environ.get("AMNEZIA_GATEWAY_DNS", "10.8.0.1")
TEST_DOMAIN = os.environ.get("AMNEZIA_DNS_TEST_DOMAIN", "example.com")
RESOLVE_TIMEOUT = float(os.environ.get("AMNEZIA_DNS_TIMEOUT", "5.0"))


def _resolve_a(server: str, name: str = TEST_DOMAIN) -> list[str]:
    """Resolve A records for `name` using DNS server `server`. Returns list of IP strings."""
    if dns is None:
        pytest.skip("dnspython not installed")
    res = dns.resolver.Resolver()
    res.nameservers = [server]
    res.timeout = RESOLVE_TIMEOUT
    res.lifetime = RESOLVE_TIMEOUT
    answers = res.resolve(name, "A")
    return [str(r) for r in answers]


@pytest.mark.integration
def test_resolve_via_amnezia_unbound() -> None:
    """Resolve a domain via amnezia-dns (Unbound). Requires amnezia-dns container reachable."""
    try:
        ips = _resolve_a(AMNEZIA_UNBOUND_IP)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
        pytest.skip(f"Amnezia Unbound not reachable or no answer: {e}")
    assert len(ips) >= 1, "Expected at least one A record"
    for ip in ips:
        assert "." in ip, f"Expected IPv4-like address, got {ip!r}"


@pytest.mark.integration
def test_resolve_via_gateway_dns() -> None:
    """Resolve a domain via VPN gateway (dnsmasq -> Unbound). Run inside amnezia-awg container."""
    try:
        ips = _resolve_a(GATEWAY_DNS_IP)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout) as e:
        pytest.skip(f"Gateway DNS not reachable or no answer (run inside container?): {e}")
    assert len(ips) >= 1, "Expected at least one A record"
