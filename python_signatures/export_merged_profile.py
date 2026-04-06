"""
Print merged i1–i5 CPS JSON for a dry-run fixture ``profile_id``.

Usage: ``python -m python_signatures.export_merged_profile quic_rfc``
"""

from __future__ import annotations

import json
import sys

from python_signatures.architect_fallbacks import ARCHITECT_BUNDLE_DATE, ARCHITECT_BUNDLE_VERSION
from python_signatures.dry_run_fixtures import load_dry_run_fixture
from python_signatures.profile_cps import merge_collector_output


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("Usage: export_merged_profile <profile_id>", file=sys.stderr)
        return 2
    pid = args[0]
    fx = load_dry_run_fixture(pid)
    sig: dict = {"hex": fx["hex"].strip()}
    for k in ("i2", "i3", "i4", "i5"):
        v = fx.get(k)
        if isinstance(v, str) and v.strip():
            sig[k] = v.strip()
    out = merge_collector_output(pid, sig)
    print(
        f"# ARCHITECT_BUNDLE_VERSION={ARCHITECT_BUNDLE_VERSION} "
        f"ARCHITECT_BUNDLE_DATE={ARCHITECT_BUNDLE_DATE}",
        file=sys.stderr,
    )
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
