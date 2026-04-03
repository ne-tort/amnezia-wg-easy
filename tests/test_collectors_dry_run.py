"""
Dry-run tests: collectors load committed CPS from tests/fixtures/signatures/*.json.

No live capture; asserts output format matches AmneziaWG (<b 0x...>).
"""

import json
from pathlib import Path

import pytest

from python_signatures.base import CollectorOptions
from python_signatures.quic_collector import QuicSignatureCollector
from python_signatures.stun_collector import StunSignatureCollector
from python_signatures.sip_collector import SipSignatureCollector
from python_signatures.webrtc_collector import WebrtcSignatureCollector
from python_signatures.dtls_collector import DtlsSignatureCollector


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
def sip_config(tmp_path: Path) -> Path:
    p = tmp_path / "sip.json"
    p.write_text(json.dumps({"servers": ["sip.example.com:5060"]}), encoding="utf-8")
    return p


@pytest.fixture
def webrtc_config(tmp_path: Path) -> Path:
    p = tmp_path / "webrtc.json"
    p.write_text(json.dumps({"servers": ["stun.example.com:19302"]}), encoding="utf-8")
    return p


@pytest.fixture
def dtls_config(tmp_path: Path) -> Path:
    p = tmp_path / "dtls.json"
    p.write_text(json.dumps({"targets": ["example.com:443"]}), encoding="utf-8")
    return p


def test_quic_collector_dry_run(quic_config: Path) -> None:
    opts = CollectorOptions(config_path=quic_config, out_path=None, count=1, dry_run=True)
    collector = QuicSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "quic" and sigs[0]["direction"] == "client"
    _assert_signature_format(sigs[0])


def test_stun_collector_dry_run(stun_config: Path) -> None:
    opts = CollectorOptions(config_path=stun_config, out_path=None, count=1, dry_run=True)
    collector = StunSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "stun" and sigs[0]["direction"] == "client"
    _assert_signature_format(sigs[0])


def test_sip_collector_dry_run(sip_config: Path) -> None:
    opts = CollectorOptions(config_path=sip_config, out_path=None, count=1, dry_run=True)
    collector = SipSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "sip" and sigs[0]["direction"] == "client"
    _assert_signature_format(sigs[0])


def test_webrtc_collector_dry_run(webrtc_config: Path) -> None:
    opts = CollectorOptions(config_path=webrtc_config, out_path=None, count=1, dry_run=True)
    collector = WebrtcSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "webrtc" and sigs[0]["direction"] == "client"
    _assert_signature_format(sigs[0])


def test_dtls_collector_dry_run(dtls_config: Path) -> None:
    opts = CollectorOptions(config_path=dtls_config, out_path=None, count=1, dry_run=True)
    collector = DtlsSignatureCollector(opts)
    sigs = collector.collect()
    assert len(sigs) == 1
    assert sigs[0]["protocol"] == "dtls" and sigs[0]["direction"] == "client"
    _assert_signature_format(sigs[0])
