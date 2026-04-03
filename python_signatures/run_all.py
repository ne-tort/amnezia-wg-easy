"""
Run all protocol signature collectors and write a single JSON keyed by profile id.

Used by the Node backend to refresh I1 signatures. Exit code 0 only when every
collector succeeds; on any failure nothing is written (fallback preserved).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from python_signatures.base import CollectorOptions
from python_signatures.dns_collector import DnsSignatureCollector
from python_signatures.profile_cps import merge_collector_output
from python_signatures.quic_collector import QuicSignatureCollector
from python_signatures.stun_collector import StunSignatureCollector
from python_signatures.sip_collector import SipSignatureCollector
from python_signatures.webrtc_collector import WebrtcSignatureCollector
from python_signatures.dtls_collector import DtlsSignatureCollector

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# * Registry: profile_id -> (CollectorClass, config filename under config_dir).
PROTOCOL_REGISTRY = [
    ("dns", DnsSignatureCollector, "dns_targets.json"),
    ("quic", QuicSignatureCollector, "quic_targets.json"),
    ("stun", StunSignatureCollector, "stun_targets.json"),
    ("sip", SipSignatureCollector, "sip_targets.json"),
    ("webrtc", WebrtcSignatureCollector, "webrtc_targets.json"),
    ("dtls", DtlsSignatureCollector, "dtls_targets.json"),
]


def run_all(config_dir: Path, out_path: Path, timeout: int, dry_run: bool) -> dict:
    """
    Run each collector and build profile_id -> { i1, i2, i3, i4, i5 } (CPS strings).
    Raises on first collector failure; does not write to disk.
    """
    result: dict[str, dict] = {}
    for profile_id, collector_cls, config_name in PROTOCOL_REGISTRY:
        config_path = config_dir / config_name
        if not config_path.exists():
            raise FileNotFoundError(f"Config not found: {config_path}")
        opts = CollectorOptions(
            config_path=config_path,
            out_path=None,
            count=1,
            timeout=timeout,
            dry_run=dry_run,
        )
        collector = collector_cls(opts)
        try:
            signatures = collector.collect()
        except Exception as e:
            logger.exception("Collector %s failed: %s", profile_id, e)
            raise
        if not signatures or not isinstance(signatures[0].get("hex"), str):
            raise ValueError(f"Collector {profile_id} returned no valid hex")
        result[profile_id] = merge_collector_output(profile_id, signatures[0])
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run all signature collectors and write JSON (profile_id -> { i1..i5 } CPS)."
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Output JSON path (only written on full success).",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Directory containing protocol config JSONs (default: package config/).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-collector timeout in seconds.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load committed CPS from tests/fixtures/signatures/*.json (CI; no live capture).",
    )
    args = parser.parse_args(argv)
    out_path = Path(args.out).resolve()
    config_dir = args.config_dir
    if config_dir is None:
        config_dir = Path(__file__).resolve().parent / "config"
    config_dir = config_dir.resolve()
    try:
        data = run_all(config_dir, out_path, timeout=args.timeout, dry_run=args.dry_run)
    except Exception:
        return 1
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("Wrote %d profiles to %s", len(data), out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
