"""Library template profile for ``dns`` (no live resolver)."""

from pathlib import Path

from python_signatures.base import CollectorOptions
from python_signatures.library_template_collector import LibraryTemplateProfileCollector


def test_dns_template_collector_basic() -> None:
    repo = Path(__file__).resolve().parent.parent
    cfg_path = repo / "python_signatures" / "config" / "profile_templates" / "dns.json"
    opts = CollectorOptions(config_path=cfg_path, registry_profile_id="dns", dry_run=False)
    collector = LibraryTemplateProfileCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    sig = sigs[0]["hex"]
    assert isinstance(sig, str)
    assert sig.startswith("<b 0x")
    assert sig.endswith(">")
    assert len(sig) > len("<b 0x>")
