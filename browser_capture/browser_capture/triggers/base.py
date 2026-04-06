from __future__ import annotations

import abc

from playwright.sync_api import Page


class Trigger(abc.ABC):
    """Protocol: drive ``page`` to generate target traffic."""

    @abc.abstractmethod
    def run(self, page: Page) -> None:
        raise NotImplementedError
