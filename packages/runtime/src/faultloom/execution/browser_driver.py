from __future__ import annotations

from threading import Lock
from typing import assert_never

from playwright.sync_api import (
    BrowserContext,
    Error as PlaywrightError,
    Page,
    Route,
)

from .browser_artifact import browser_route_artifact
from .browser_contracts import BrowserContractError, BrowserIdentityContext
from .browser_launcher import ChromiumLaunchConfig, ChromiumLauncher
from .browser_driver_runtime import BrowserSession, NavigationPhase, SerializedBrowserWorker
from .browser_routes import (
    AbortIntercept,
    BrowserRouteRegistry,
    FulfillIntercept,
    PauseIntercept,
)
from .contracts import (
    BrowserChildCandidate,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
    SemanticHttpObservation,
)

class ChromiumBrowserDriver:
    def __init__(self, config: ChromiumLaunchConfig) -> None:
        self._config = config
        self._routes = BrowserRouteRegistry()
        self._sessions: dict[str, BrowserSession] = {}
        self._session_lock = Lock()
        self._worker = SerializedBrowserWorker()

    def register_context(self, context: BrowserIdentityContext) -> None:
        self._worker.start()
        try:
            self._worker.call(self._register_context, context)
        except BrowserContractError:
            self._shutdown_worker_if_idle()
            raise

    def close_context(self, context_id: str) -> None:
        try:
            self._worker.call(self._close_context, context_id)
        finally:
            self._shutdown_worker_if_idle()

    def navigate(
        self,
        context: BrowserIdentityContext,
        command: GatewayDispatchCommand,
        result: GatewayResult,
    ) -> tuple[BrowserChildCandidate, ...]:
        return self._worker.call(self._navigate, context, command, result)

    def fulfill_child(
        self,
        candidate: BrowserChildCandidate,
        command: GatewayDispatchCommand,
        result: GatewayResult,
    ) -> tuple[BrowserChildCandidate, ...]:
        return self._worker.call(self._fulfill_child, candidate, command, result)

    def abort_child(self, candidate_id: str) -> None:
        self._worker.call(self._abort_child, candidate_id)

    def navigation_ready(self, context_id: str) -> bool:
        return self._worker.call(self._navigation_ready, context_id)

    def interrupt_context(self, context_id: str) -> None:
        self._session(context_id).launcher.interrupt()

    def _register_context(self, context: BrowserIdentityContext) -> None:
        context_id = context.browser_context_id
        with self._session_lock:
            if context_id in self._sessions:
                raise BrowserContractError("browser context is already registered")
        launcher = ChromiumLauncher(self._config)
        browser = launcher.browser()
        browser_context: BrowserContext | None = None
        try:
            created_context = browser.new_context(
                accept_downloads=False,
                service_workers="block",
            )
            browser_context = created_context
            created_context.route(
                "**/*",
                lambda route: self._intercept(context_id, route),
            )
            created_context.route_web_socket(
                "**/*",
                lambda route: route.close(code=1008, reason="Gateway admission required"),
            )
            page = created_context.new_page()
            page.on("domcontentloaded", lambda _: self._mark_ready(context_id))
            page.on("download", lambda download: download.cancel())
        except PlaywrightError as exc:
            if browser_context is not None:
                browser_context.close()
            launcher.close()
            raise BrowserContractError("isolated Chromium context launch failed") from exc
        with self._session_lock:
            self._sessions[context_id] = BrowserSession(launcher, created_context, page)

    def _close_context(self, context_id: str) -> None:
        with self._session_lock:
            session = self._sessions.pop(context_id, None)
        if session is None:
            raise BrowserContractError("browser driver context is not active")
        cleanup_failed = False
        for route in self._routes.close_context(context_id):
            try:
                route.abort("blockedbyclient")
            except PlaywrightError:
                cleanup_failed = True
        try:
            session.page.close()
        except PlaywrightError:
            cleanup_failed = True
        try:
            session.context.close()
        except PlaywrightError:
            cleanup_failed = True
        try:
            session.launcher.close()
        except BrowserContractError:
            cleanup_failed = True
        if cleanup_failed:
            raise BrowserContractError("browser context cleanup was incomplete")

    def _navigate(
        self,
        context: BrowserIdentityContext,
        command: GatewayDispatchCommand,
        result: GatewayResult,
    ) -> tuple[BrowserChildCandidate, ...]:
        context_id = context.browser_context_id
        session = self._session(context_id)
        url = self._routes.arm_navigation(
            context_id,
            command.request,
            _completed_observation(result),
        )
        session.parent_action_id = command.intent.action_id
        session.phase = NavigationPhase.LOADING
        try:
            _ = session.page.goto(url, wait_until="commit", timeout=5_000)
            _ = session.page.content()
        except PlaywrightError as exc:
            raise BrowserContractError("isolated Chromium navigation failed closed") from exc
        return self._finish_pump(context_id, session)

    def _fulfill_child(
        self,
        candidate: BrowserChildCandidate,
        command: GatewayDispatchCommand,
        result: GatewayResult,
    ) -> tuple[BrowserChildCandidate, ...]:
        context_id = candidate.browser_context_id
        session = self._session(context_id)
        try:
            artifact = browser_route_artifact(_completed_observation(result))
        except BrowserContractError:
            self._abort_child(candidate.candidate_id)
            raise
        route = self._routes.take(candidate)
        session.parent_action_id = command.intent.action_id
        try:
            route.fulfill(
                status=artifact.status,
                headers=dict(artifact.headers),
                body=artifact.body,
            )
            _ = session.page.content()
        except PlaywrightError as exc:
            try:
                route.abort("blockedbyclient")
            except PlaywrightError as abort_exc:
                raise BrowserContractError(
                    "isolated Chromium child failure could not be aborted"
                ) from abort_exc
            raise BrowserContractError("isolated Chromium child fulfillment failed") from exc
        return self._finish_pump(context_id, session)

    def _abort_child(self, candidate_id: str) -> None:
        route = self._routes.abort(candidate_id)
        try:
            route.abort("blockedbyclient")
        except PlaywrightError as exc:
            raise BrowserContractError("browser route abort failed") from exc

    def _navigation_ready(self, context_id: str) -> bool:
        return self._session(context_id).phase is NavigationPhase.READY

    def _finish_pump(
        self,
        context_id: str,
        session: BrowserSession,
    ) -> tuple[BrowserChildCandidate, ...]:
        candidates = self._routes.drain_discovered(context_id)
        if candidates and session.phase is not NavigationPhase.READY:
            session.phase = NavigationPhase.WAITING_CHILD
        elif not candidates and session.phase is not NavigationPhase.READY:
            try:
                session.page.wait_for_load_state("domcontentloaded", timeout=5_000)
            except PlaywrightError as exc:
                raise BrowserContractError(
                    "isolated Chromium navigation readiness failed closed"
                ) from exc
            session.phase = NavigationPhase.READY
        return candidates

    def _mark_ready(self, context_id: str) -> None:
        session = self._sessions.get(context_id)
        if session is not None:
            session.phase = NavigationPhase.READY

    def _intercept(self, context_id: str, route: Route) -> None:
        session = self._session(context_id)
        decision = self._routes.intercept(
            context_id,
            session.parent_action_id,
            route,
            route.request,
        )
        match decision:
            case FulfillIntercept(artifact=artifact):
                route.fulfill(
                    status=artifact.status,
                    headers=dict(artifact.headers),
                    body=artifact.body,
                )
            case PauseIntercept():
                return
            case AbortIntercept():
                route.abort("blockedbyclient")
            case unreachable:
                assert_never(unreachable)

    def _session(self, context_id: str) -> BrowserSession:
        with self._session_lock:
            session = self._sessions.get(context_id)
        if session is None:
            raise BrowserContractError("browser driver context is not active")
        return session

    def _shutdown_worker_if_idle(self) -> None:
        with self._session_lock:
            idle = not self._sessions
        if not idle:
            return
        self._worker.shutdown()


def _completed_observation(result: GatewayResult) -> SemanticHttpObservation:
    match result:
        case GatewayDeniedResult():
            raise BrowserContractError("Gateway denied browser fulfillment")
        case GatewayDispatchResult(observation=observation):
            if observation is None:
                raise BrowserContractError("Gateway returned no browser observation")
            return observation
        case unreachable:
            assert_never(unreachable)
