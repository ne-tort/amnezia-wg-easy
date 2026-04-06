"""
Navigate to an HTTPS URL so Chromium may speak HTTP/3 (QUIC) if offered by the server.
"""

from __future__ import annotations

from playwright.sync_api import Page

from browser_capture.triggers.base import Trigger


class QuicHttp3Trigger(Trigger):
    def __init__(
        self,
        url: str,
        *,
        wait_until: str = "domcontentloaded",
        timeout_ms: int = 60_000,
    ) -> None:
        self.url = url
        self.wait_until = wait_until
        self.timeout_ms = timeout_ms

    def run(self, page: Page) -> None:
        page.goto(self.url, wait_until=self.wait_until, timeout=self.timeout_ms)
