from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from threading import Lock
from typing import ParamSpec, TypeVar

from playwright.sync_api import BrowserContext, Page

from .browser_contracts import BrowserContractError
from .browser_launcher import ChromiumLauncher

_P = ParamSpec("_P")
_R = TypeVar("_R")


class SerializedBrowserWorker:
    def __init__(self) -> None:
        self._lock = Lock()
        self._executor: ThreadPoolExecutor | None = None

    def start(self) -> None:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=1,
                    thread_name_prefix="faultloom-chromium",
                )

    def call(
        self,
        operation: Callable[_P, _R],
        *args: _P.args,
        **kwargs: _P.kwargs,
    ) -> _R:
        with self._lock:
            executor = self._executor
        if executor is None:
            raise BrowserContractError("browser driver worker is not active")
        return executor.submit(operation, *args, **kwargs).result()

    def shutdown(self) -> None:
        with self._lock:
            executor = self._executor
            self._executor = None
        if executor is not None:
            executor.shutdown(wait=True)


class BrowserSession:
    __slots__ = ("launcher", "context", "page", "parent_action_id", "phase")

    def __init__(
        self,
        launcher: ChromiumLauncher,
        context: BrowserContext,
        page: Page,
    ) -> None:
        self.launcher = launcher
        self.context = context
        self.page = page
        self.parent_action_id = ""
        self.phase = NavigationPhase.IDLE


class NavigationPhase(Enum):
    IDLE = "idle"
    LOADING = "loading"
    WAITING_CHILD = "waiting_child"
    READY = "ready"
