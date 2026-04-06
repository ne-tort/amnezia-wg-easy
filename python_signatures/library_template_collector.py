"""
Library template profiles: CPS seeds from committed JSON (no live capture).

Used for profile_ids without a dedicated browser trigger (dns, sip, dtls).
``hex`` must start with ``<b 0x``; merge fills I2–I5 from ARCHITECT_DEFAULTS.
"""

from __future__ import annotations

from typing import Any, Dict, List

from python_signatures.base import SignatureCollector


class LibraryTemplateProfileCollector(SignatureCollector):
    """Load ``hex`` / optional ``i2``… from ``config/profile_templates/<id>.json``."""

    def __init__(self, options: Any) -> None:
        pid = getattr(options, "registry_profile_id", None)
        if not isinstance(pid, str) or not pid.strip():
            raise ValueError("LibraryTemplateProfileCollector requires options.registry_profile_id")
        super().__init__(pid.strip(), options)

    def collect(self) -> List[Dict[str, Any]]:
        cfg = self.load_config()
        hex_val = cfg.get("hex")
        if not isinstance(hex_val, str) or not hex_val.strip().startswith("<b 0x"):
            raise RuntimeError(
                f"Template {self.options.config_path} must contain string 'hex' starting with <b 0x"
            )
        entry: Dict[str, Any] = {
            "protocol": self.protocol_name,
            "target": str(cfg.get("target", self.protocol_name)),
            "direction": "client",
            "hex": hex_val.strip(),
        }
        for k in ("i2", "i3", "i4", "i5"):
            v = cfg.get(k)
            if isinstance(v, str) and v.strip():
                entry[k] = v.strip()
        return [entry]
