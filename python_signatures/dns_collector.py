"""
DNS signature collector.

Builds real DNS queries in wire format (RFC 1035) for configured domains and
emits them as AmneziaWG-compatible `<b 0x...>` signatures (I1 payloads).

Config:
  - mode: "query" (client query wire, default) or "response" (full resolver reply).
  - use_edns: if true (default), add EDNS0 (RFC 6891) — typical for resolvers/clients.

Requires:
    pip install dnspython
"""

from __future__ import annotations

from typing import Any, Dict, List

import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype

from python_signatures.base import SignatureCollector, build_arg_parser, options_from_args


class DnsSignatureCollector(SignatureCollector):
  """Generates DNS wire-format queries for a list of domains."""

  def __init__(self, options):
    super().__init__("dns", options)

  def _ensure_config(self) -> Dict[str, Any]:
    if not self._config:
      self.load_config()
    return self._config

  def collect(self) -> List[Dict[str, Any]]:
    cfg = self._ensure_config()
    domains = cfg.get("domains") or []

    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
      raise RuntimeError("Config must contain \"domains\": [\"example.com\", ...].")

    mode = (cfg.get("mode") or "query").lower()
    if mode not in {"response", "query"}:
      raise RuntimeError("Config field \"mode\" must be \"response\" or \"query\" if set.")

    use_edns = cfg.get("use_edns", True)
    if not isinstance(use_edns, bool):
      use_edns = str(use_edns).lower() in ("1", "true", "yes")

    rtype_str = (cfg.get("record_type") or "A").upper()
    try:
      rtype = getattr(dns.rdatatype, rtype_str)
    except AttributeError as exc:
      raise RuntimeError(f"Unsupported DNS record_type: {rtype_str}") from exc

    limit = self.options.count or len(domains)

    resolver = str(cfg.get("resolver") or "8.8.8.8")
    port = int(cfg.get("port") or 53)

    signatures: List[Dict[str, Any]] = []
    for domain in domains:
      if len(signatures) >= limit:
        break

      # Build a standard DNS query message (optional EDNS0 for realistic size/shape).
      msg = dns.message.make_query(
        qname=domain.rstrip("."),
        rdtype=rtype,
        rdclass=dns.rdataclass.IN,
        use_edns=use_edns,
      )
      if mode == "query":
        wire = msg.to_wire()
      else:
        # Real DNS response from resolver; full header + Question + Answer/Authority/Additional.
        try:
          response = dns.query.udp(msg, resolver, port=port, timeout=self.options.timeout or 3.0)
        except Exception as exc:  # noqa: BLE001
          raise RuntimeError(f"DNS query to {resolver}:{port} for {domain} failed: {exc}") from exc
        wire = response.to_wire()

      sig = self.format_signature(wire)
      entry: Dict[str, Any] = {
          "protocol": self.protocol_name,
          "target": domain,
          "direction": "client",  # I1 usually mimics client -> server.
          "hex": sig,
      }
      # Second wire (another QNAME) for I2 signature packet (AmneziaWG 2.0 chain).
      alt_name = "google.com"
      if domain.rstrip(".").lower() == alt_name:
        alt_name = "cloudflare.com"
      msg2 = dns.message.make_query(
        alt_name,
        rdtype=rtype,
        rdclass=dns.rdataclass.IN,
        use_edns=use_edns,
      )
      if mode == "query":
        wire2 = msg2.to_wire()
      else:
        try:
          response2 = dns.query.udp(msg2, resolver, port=port, timeout=self.options.timeout or 3.0)
        except Exception as exc:  # noqa: BLE001
          raise RuntimeError(f"DNS second query to {resolver}:{port} for {alt_name} failed: {exc}") from exc
        wire2 = response2.to_wire()
      entry["i2"] = self.format_signature(wire2)
      signatures.append(entry)

    return signatures


def main(argv: List[str] | None = None) -> int:
  parser = build_arg_parser("DNS wire-format signature collector")
  args = parser.parse_args(argv)
  opts = options_from_args(args)

  collector = DnsSignatureCollector(opts)
  signatures = collector.collect()
  collector.save(signatures)

  print(
    f"Collected {len(signatures)} DNS signatures "
    f"from {opts.config_path}."
  )
  return 0


if __name__ == "__main__":  # pragma: no cover
  raise SystemExit(main())

