"""
Sync Playwright Chromium lifecycle for triggers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Optional

from playwright.sync_api import Browser, BrowserContext, Page, Playwright, sync_playwright

from browser_capture.browser.profiles import chromium_launch_args, default_context_kwargs


class ChromiumSession:
    """Owns Playwright + Chromium + context + page; use as context manager."""

    def __init__(
        self,
        *,
        headless: bool = True,
        enable_quic: bool = True,
        extra_launch_args: Optional[list[str]] = None,
    ) -> None:
        self.headless = headless
        self.enable_quic = enable_quic
        self._extra_launch_args = extra_launch_args or []
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

    def __enter__(self) -> "ChromiumSession":
        self._playwright = sync_playwright().start()
        args = chromium_launch_args(self.enable_quic) + self._extra_launch_args
        self._browser = self._playwright.chromium.launch(
            headless=self.headless,
            args=args,
        )
        self._context = self._browser.new_context(**default_context_kwargs())
        self._page = self._context.new_page()
        return self

    def __exit__(self, *exc: Any) -> None:
        if self._context:
            self._context.close()
        if self._browser:
            self._browser.close()
        if self._playwright:
            self._playwright.stop()
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None

    @property
    def page(self) -> Page:
        if self._page is None:
            raise RuntimeError("ChromiumSession not started; use 'with ChromiumSession() as s:'")
        return self._page


def run_with_page(
    fn: Callable[[Page], None],
    *,
    headless: bool = True,
    enable_quic: bool = True,
    extra_launch_args: Optional[list[str]] = None,
) -> None:
    """Run ``fn(page)`` inside a launched Chromium session."""
    with ChromiumSession(
        headless=headless,
        enable_quic=enable_quic,
        extra_launch_args=extra_launch_args,
    ) as session:
        fn(session.page)
