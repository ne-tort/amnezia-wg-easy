import json
from pathlib import Path

from python_signatures.base import CollectorOptions
from python_signatures.dns_collector import DnsSignatureCollector


def test_dns_collector_basic(tmp_path: Path) -> None:
    """Smoke test: collector produces at least one valid signature."""
    cfg_path = tmp_path / "dns_targets.json"
    cfg_path.write_text(
        json.dumps(
            {
                "resolver": "8.8.8.8",
                "port": 53,
                "record_type": "A",
                "domains": ["example.com"],
            }
        ),
        encoding="utf-8",
    )

    opts = CollectorOptions(config_path=cfg_path, out_path=None, count=1)
    collector = DnsSignatureCollector(opts)
    sigs = collector.collect()

    assert len(sigs) == 1
    sig = sigs[0]["hex"]
    assert isinstance(sig, str)
    assert sig.startswith("<b 0x")
    assert sig.endswith(">")
    # payload must not be empty
    assert len(sig) > len("<b 0x>")
