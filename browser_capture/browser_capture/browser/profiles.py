"""
Browser context knobs to approximate a real desktop Chrome (locale, viewport, UA).
"""

from __future__ import annotations

from typing import Any


def default_context_kwargs() -> dict[str, Any]:
    """Arguments for ``browser.new_context``."""
    return {
        "locale": "en-US",
        "timezone_id": "Europe/Moscow",
        "viewport": {"width": 1280, "height": 720},
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
    }


def chromium_launch_args(enable_quic: bool = True) -> list[str]:
    """Extra Chromium flags; QUIC is on by default in Chromium unless disabled."""
    args: list[str] = []
    if not enable_quic:
        args.append("--disable-quic")
    # Docker / CI often need:
    # args.append("--no-sandbox")
    return args
