"""
Base abstractions and helpers for protocol signature collectors.

Design goals:
- Each collector is a small class with a clear `collect()` method.
- Collectors can be used as a library (import and call) or as standalone
  scripts (via a tiny CLI in each module).
"""

from __future__ import annotations

import abc
import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class CollectorOptions:
    """Options shared across collectors."""

    config_path: Path
    out_path: Optional[Path] = None
    count: Optional[int] = None
    iface: Optional[str] = None
    timeout: Optional[int] = None
    dry_run: bool = False


class SignatureCollector(abc.ABC):
    """Base class for all protocol signature collectors."""

    protocol_name: str
    options: CollectorOptions
    _config: Dict[str, Any] = field(default_factory=dict)  # type: ignore[assignment]

    def __init__(self, protocol_name: str, options: CollectorOptions) -> None:
        self.protocol_name = protocol_name
        self.options = options
        self._config = {}

    def load_config(self) -> Dict[str, Any]:
        """Load JSON config from options.config_path."""
        path = self.options.config_path
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise RuntimeError(f"Config file not found: {path}") from exc
        except OSError as exc:
            raise RuntimeError(f"Failed to read config file: {path}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON in config {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise RuntimeError(f"Config {path} must be a JSON object at top level.")

        self._config = data
        return data

    @abc.abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """Collect signatures and return a list of signature dicts."""

    @staticmethod
    def format_signature(payload: bytes) -> str:
        """Format bytes payload to `<b 0x...>` string accepted by AmneziaWG."""
        hex_str = payload.hex()
        return f"<b 0x{hex_str}>"

    def save(self, signatures: List[Dict[str, Any]]) -> None:
        """Save signatures to JSON if out_path is set; print to stdout otherwise."""
        if self.options.out_path is None:
            json.dump(signatures, sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return

        out_path = self.options.out_path
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(signatures, ensure_ascii=False, indent=2), encoding="utf-8")


def build_arg_parser(description: str) -> argparse.ArgumentParser:
    """Create a standard argument parser for collectors."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "--config",
        required=True,
        help="Path to JSON config file with targets.",
    )
    parser.add_argument(
        "--out",
        help="Path to output JSON file with collected signatures. Defaults to stdout.",
    )
    parser.add_argument(
        "--count",
        type=int,
        help="Maximum number of signatures to collect (per protocol run).",
    )
    parser.add_argument(
        "--iface",
        help="Network interface to capture on (for collectors that support capture).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Overall timeout in seconds for collection (per run).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not send or capture real traffic where applicable; just build payloads.",
    )
    return parser


def options_from_args(args: argparse.Namespace) -> CollectorOptions:
    """Convert argparse args to CollectorOptions."""
    config_path = Path(args.config).expanduser()
    out_path = Path(args.out).expanduser() if args.out else None
    return CollectorOptions(
        config_path=config_path,
        out_path=out_path,
        count=args.count,
        iface=args.iface,
        timeout=args.timeout,
        dry_run=bool(args.dry_run),
    )

