"""
DNS signature collector.

Builds real DNS queries in wire format (RFC 1035) for configured domains and
emits them as AmneziaWG-compatible `<b 0x...>` signatures (I1 payloads).

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

    mode = (cfg.get("mode") or "response").lower()
    if mode not in {"response", "query"}:
      raise RuntimeError("Config field \"mode\" must be \"response\" or \"query\" if set.")

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

      # Build a standard DNS query message.
      msg = dns.message.make_query(
        qname=domain.rstrip("."),
        rdtype=rtype,
        rdclass=dns.rdataclass.IN,
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
      signatures.append(
        {
          "protocol": self.protocol_name,
          "target": domain,
          "direction": "client",  # I1 usually mimics client -> server.
          "hex": sig,
        }
      )

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

