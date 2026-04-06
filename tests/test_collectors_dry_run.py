"""
Dry-run tests: browser collectors load committed CPS from tests/fixtures/signatures/*.json.

No live capture; asserts output format matches AmneziaWG (<b 0x...>).
"""

import json
from pathlib import Path

import pytest

from python_signatures.base import CollectorOptions
from python_signatures.browser_quic_collector import BrowserQuicSignatureCollector
from python_signatures.browser_stun_collector import BrowserStunSignatureCollector
from python_signatures.library_template_collector import LibraryTemplateProfileCollector


def _assert_signature_format(sig: dict) -> None:
    hex_val = sig.get("hex")
    assert isinstance(hex_val, str), "hex must be string"
    assert hex_val.startswith("<b 0x"), "hex must be <b 0x...>"
    assert hex_val.endswith(">"), "hex must end with >"
    assert len(hex_val) > len("<b 0x>"), "payload must not be empty"


@pytest.fixture
def quic_config(tmp_path: Path) -> Path:
    p = tmp_path / "quic.json"
    p.write_text(json.dumps({"urls": ["https://example.com/"], "port": 443}), encoding="utf-8")
    return p


@pytest.fixture
def stun_config(tmp_path: Path) -> Path:
    p = tmp_path / "stun.json"
    p.write_text(json.dumps({"servers": ["stun.example.com:19302"]}), encoding="utf-8")
    return p


@pytest.fixture
def webrtc_config(tmp_path: Path) -> Path:
    p = tmp_path / "webrtc.json"
    p.write_text(json.dumps({"servers": ["stun.example.com:19302"]}), encoding="utf-8")
    return p


def test_quic_collector_dry_run(quic_config: Path) -> None:
    opts = CollectorOptions(
        config_path=quic_config,
        out_path=None,
        count=1,
        dry_run=True,
        registry_profile_id="quic",
    )
    collector = BrowserQuicSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "quic" and sigs[0]["direction"] == "client"
    _assert_signature_format(sigs[0])


def test_stun_collector_dry_run(stun_config: Path) -> None:
    opts = CollectorOptions(
        config_path=stun_config,
        out_path=None,
        count=1,
        dry_run=True,
        registry_profile_id="stun",
    )
    collector = BrowserStunSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "stun" and sigs[0]["direction"] == "client"
    _assert_signature_format(sigs[0])


def test_webrtc_collector_dry_run(webrtc_config: Path) -> None:
    opts = CollectorOptions(
        config_path=webrtc_config,
        out_path=None,
        count=1,
        dry_run=True,
        registry_profile_id="webrtc",
    )
    collector = BrowserStunSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "webrtc" and sigs[0]["direction"] == "client"
    _assert_signature_format(sigs[0])


@pytest.fixture
def quic_browser_config(tmp_path: Path) -> Path:
    p = tmp_path / "qb.json"
    p.write_text(json.dumps({"urls": ["https://example.com/"]}), encoding="utf-8")
    return p


@pytest.fixture
def stun_browser_config(tmp_path: Path) -> Path:
    p = tmp_path / "sb.json"
    p.write_text(json.dumps({"stun_url": "stun:stun.example.com:19302"}), encoding="utf-8")
    return p


def test_browser_quic_collector_dry_run(quic_browser_config: Path) -> None:
    opts = CollectorOptions(
        config_path=quic_browser_config,
        out_path=None,
        count=1,
        dry_run=True,
        registry_profile_id="quic_browser",
    )
    collector = BrowserQuicSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "quic_browser"
    _assert_signature_format(sigs[0])


def test_browser_stun_collector_dry_run(stun_browser_config: Path) -> None:
    opts = CollectorOptions(
        config_path=stun_browser_config,
        out_path=None,
        count=1,
        dry_run=True,
        registry_profile_id="stun_browser",
    )
    collector = BrowserStunSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "stun_browser"
    _assert_signature_format(sigs[0])


def test_library_template_collectors_use_repo_templates() -> None:
    repo = Path(__file__).resolve().parent.parent
    cfg_dir = repo / "python_signatures" / "config" / "profile_templates"
    for pid, fname in (("dns", "dns.json"), ("sip", "sip.json"), ("dtls", "dtls.json")):
        p = cfg_dir / fname
        opts = CollectorOptions(config_path=p, registry_profile_id=pid, dry_run=False)
        col = LibraryTemplateProfileCollector(opts)
        sigs = col.collect()
        assert len(sigs) == 1
        assert sigs[0]["protocol"] == pid
        _assert_signature_format(sigs[0])
