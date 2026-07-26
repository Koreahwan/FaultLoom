from __future__ import annotations

import socket
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from threading import Event, Thread
from time import monotonic

import pytest
from playwright.sync_api import Error as PlaywrightError

import faultloom.execution as execution
from faultloom.execution.browser_launcher import ChromiumLauncher

from .browser_execution_helpers import browser_context
from .execution_helpers import (
    CHANNEL_KEY,
    NOW,
    RecordingGateway,
    command,
    completed_result,
    semantic_request,
)

CHROMIUM = Path("/home/hw/.cache/ms-playwright/chromium-1232/chrome-linux64/chrome")
CHROMIUM_DIGEST = "sha256:888bc05a6af72381dd9e45777a0a65569078a732d8c71f194f2789fdbfc6ad53"


class _BlockingGateway(RecordingGateway):
    def __init__(
        self,
        handler: Callable[[execution.GatewayDispatchCommand], execution.GatewayResult],
    ) -> None:
        super().__init__(handler)
        self.entered = Event()
        self.release = Event()
        self.interrupted = Event()

    def dispatch(
        self,
        frame: execution.GatewayDispatchFrame,
    ) -> execution.GatewayResponseEnvelope:
        if frame.command.intent.action_id == "action.blocked":
            self.entered.set()
            if not self.release.wait(timeout=10):
                raise TimeoutError("test Gateway was not interrupted")
        return super().dispatch(frame)

    def interrupt(self) -> None:
        self.interrupted.set()
        self.release.set()


def test_runtime_exports_a_digest_pinned_chromium_driver() -> None:
    assert callable(getattr(execution, "ChromiumBrowserDriver", None))
    assert callable(getattr(execution, "ChromiumLaunchConfig", None))


def test_driver_rejects_chromium_before_launch_when_digest_differs(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "chromium"
    executable.write_bytes(b"not-the-pinned-browser")
    executable.chmod(0o700)
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=executable,
            executable_digest="sha256:" + "11" * 32,
        )
    )

    with pytest.raises(execution.BrowserContractError, match="digest"):
        driver.register_context(browser_context())


def test_bwrap_chromium_cannot_connect_to_owned_host_loopback() -> None:
    launcher = ChromiumLauncher(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.setblocking(False)
    context = launcher.browser().new_context()
    try:
        page = context.new_page()
        with pytest.raises(PlaywrightError):
            page.goto(
                f"http://127.0.0.1:{listener.getsockname()[1]}/forbidden",
                timeout=5_000,
            )
        with pytest.raises(BlockingIOError):
            listener.accept()
    finally:
        context.close()
        launcher.close()
        listener.close()


def test_real_chromium_renders_only_gateway_bytes_and_pauses_child_route() -> None:
    request = semantic_request(path="/page")
    approved = command(request=request)
    body = b'<main>gateway-only</main><img src="/asset">'
    headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"text/html",
        ),
    )
    gateway = RecordingGateway(
        lambda dispatch: completed_result(dispatch, body=body, headers=headers)
    )
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    browser = execution.BrowserExecutionCoordinator(
        execution.SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        ),
        browser_driver=driver,
    )
    context = browser_context()

    browser.register_context(context)
    try:
        browser.navigate(context.browser_context_id, approved)
        pending = browser.pending_candidate_ids(context.browser_context_id)
        assert len(pending) == 1
        candidate_id = pending[0]
        child = command(
            action_id="action.asset",
            lease_id="lease.asset",
            request=semantic_request(path="/asset"),
            identity=context.identity,
            parent_action_ids=("action.nav",),
        )

        browser.execute_child(context.browser_context_id, candidate_id, child)

        assert browser.pending_candidate_ids(context.browser_context_id) == ()
        with pytest.raises(execution.BrowserContractError, match="already consumed"):
            browser.execute_child(context.browser_context_id, candidate_id, child)
    finally:
        browser.close_context(context.browser_context_id)

    assert [frame.command.intent.action_id for frame in gateway.calls] == [
        "action.nav",
        "action.asset",
    ]
    assert [frame.command.lease.lease_id for frame in gateway.calls] == [
        "lease.nav",
        "lease.asset",
    ]


def test_parser_blocking_child_pauses_before_ready_then_resumes_navigation() -> None:
    html_headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"text/html",
        ),
    )
    script_headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"application/javascript",
        ),
    )

    def respond(dispatch: execution.GatewayDispatchCommand) -> execution.GatewayResult:
        if dispatch.request.endpoint.path == "/page":
            return completed_result(
                dispatch,
                body=b'<script src="/blocking.js"></script><main>ready</main>',
                headers=html_headers,
            )
        return completed_result(
            dispatch,
            body=b"document.body.dataset.gatewayScript = 'complete';",
            headers=script_headers,
        )

    gateway = RecordingGateway(respond)
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    browser = execution.BrowserExecutionCoordinator(
        execution.SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        ),
        browser_driver=driver,
    )
    context = browser_context()
    browser.register_context(context)
    started = monotonic()
    try:
        browser.navigate(
            context.browser_context_id,
            command(request=semantic_request(path="/page")),
        )
        elapsed = monotonic() - started
        candidate_id = browser.pending_candidate_ids(context.browser_context_id)[0]
        assert browser.navigation_ready(context.browser_context_id) is False
        child = command(
            action_id="action.script",
            lease_id="lease.script",
            request=semantic_request(path="/blocking.js"),
            identity=context.identity,
            parent_action_ids=("action.nav",),
        )

        browser.execute_child(context.browser_context_id, candidate_id, child)

        assert browser.navigation_ready(context.browser_context_id) is True
    finally:
        browser.close_context(context.browser_context_id)

    assert elapsed < 3
    assert [frame.command.intent.action_id for frame in gateway.calls] == [
        "action.nav",
        "action.script",
    ]


def test_close_interrupts_blocked_gateway_route_and_browser_process_boundedly() -> None:
    html_headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"text/html",
        ),
    )

    def respond(dispatch: execution.GatewayDispatchCommand) -> execution.GatewayResult:
        if dispatch.request.endpoint.path == "/page":
            return completed_result(
                dispatch,
                body=b'<script src="/blocked.js"></script>',
                headers=html_headers,
            )
        return completed_result(dispatch, body=b"void 0")

    gateway = _BlockingGateway(respond)
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    browser = execution.BrowserExecutionCoordinator(
        execution.SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        ),
        browser_driver=driver,
    )
    context = browser_context()
    browser.register_context(context)
    browser.navigate(
        context.browser_context_id,
        command(request=semantic_request(path="/page")),
    )
    candidate_id = browser.pending_candidate_ids(context.browser_context_id)[0]
    child = command(
        action_id="action.blocked",
        lease_id="lease.blocked",
        request=semantic_request(path="/blocked.js"),
        identity=context.identity,
        parent_action_ids=("action.nav",),
    )
    child_errors: list[Exception] = []
    close_errors: list[Exception] = []
    close_done = Event()

    def execute_blocked_child() -> None:
        try:
            browser.execute_child(context.browser_context_id, candidate_id, child)
        except execution.BrowserContractError as exc:
            child_errors.append(exc)

    def close_browser() -> None:
        try:
            browser.close_context(context.browser_context_id)
        except execution.BrowserContractError as exc:
            close_errors.append(exc)
        finally:
            close_done.set()

    worker = Thread(target=execute_blocked_child)
    closer = Thread(target=close_browser)
    worker.start()
    assert gateway.entered.wait(timeout=2)
    started = monotonic()
    closer.start()
    completed_boundedly = close_done.wait(timeout=2)
    elapsed = monotonic() - started
    gateway.release.set()
    worker.join(timeout=5)
    closer.join(timeout=5)

    assert completed_boundedly
    assert elapsed < 2
    assert gateway.interrupted.is_set()
    assert not worker.is_alive()
    assert not closer.is_alive()
    assert len(child_errors) == 1
    assert isinstance(child_errors[0], execution.BrowserContractError)
    assert close_errors == []


def test_close_interrupts_blocked_chromium_operation_boundedly() -> None:
    html_headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"text/html",
        ),
    )
    gateway_entered = Event()

    def respond(dispatch: execution.GatewayDispatchCommand) -> execution.GatewayResult:
        gateway_entered.set()
        return completed_result(
            dispatch,
            body=b"<script>while (true) {}</script>",
            headers=html_headers,
        )

    gateway = RecordingGateway(respond)
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    browser = execution.BrowserExecutionCoordinator(
        execution.SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        ),
        browser_driver=driver,
    )
    context = browser_context()
    browser.register_context(context)
    operation_errors: list[Exception] = []
    close_errors: list[Exception] = []
    close_done = Event()

    def navigate_forever() -> None:
        try:
            browser.navigate(
                context.browser_context_id,
                command(request=semantic_request(path="/infinite")),
            )
        except execution.BrowserContractError as exc:
            operation_errors.append(exc)

    def close_browser() -> None:
        try:
            browser.close_context(context.browser_context_id)
        except execution.BrowserContractError as exc:
            close_errors.append(exc)
        finally:
            close_done.set()

    worker = Thread(target=navigate_forever)
    closer = Thread(target=close_browser)
    worker.start()
    assert gateway_entered.wait(timeout=2)
    started = monotonic()
    closer.start()
    completed_boundedly = close_done.wait(timeout=2)
    elapsed = monotonic() - started
    if not completed_boundedly:
        driver.interrupt_context(context.browser_context_id)
    worker.join(timeout=5)
    closer.join(timeout=5)

    assert completed_boundedly
    assert elapsed < 2
    assert not worker.is_alive()
    assert not closer.is_alive()
    assert len(operation_errors) == 1
    assert isinstance(operation_errors[0], execution.BrowserContractError)
    assert close_errors == []


def test_real_chromium_aborts_cross_origin_child_before_gateway() -> None:
    approved = command(request=semantic_request(path="/page"))
    body = b'<img src="http://outside.test/asset">'
    headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"text/html",
        ),
    )
    gateway = RecordingGateway(
        lambda dispatch: completed_result(dispatch, body=body, headers=headers)
    )
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    browser = execution.BrowserExecutionCoordinator(
        execution.SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        ),
        browser_driver=driver,
    )
    context = browser_context()

    browser.register_context(context)
    browser.navigate(context.browser_context_id, approved)
    pending = browser.pending_candidate_ids(context.browser_context_id)
    browser.close_context(context.browser_context_id)

    assert pending == ()
    assert len(gateway.calls) == 1


def test_real_chromium_blocks_service_worker_and_websocket_transports() -> None:
    approved = command(request=semantic_request(path="/"))
    body = (
        b"<script>navigator.serviceWorker.register('/worker.js').catch(() => {});"
        b"new WebSocket('ws://loopback.test/socket');</script>"
    )
    headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"text/html",
        ),
    )
    gateway = RecordingGateway(
        lambda dispatch: completed_result(dispatch, body=body, headers=headers)
    )
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    browser = execution.BrowserExecutionCoordinator(
        execution.SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        ),
        browser_driver=driver,
    )
    context = browser_context()

    browser.register_context(context)
    try:
        browser.navigate(context.browser_context_id, approved)
        pending = browser.pending_candidate_ids(context.browser_context_id)
    finally:
        browser.close_context(context.browser_context_id)

    assert pending == ()
    assert len(gateway.calls) == 1


def test_expired_child_lease_aborts_paused_real_chromium_route() -> None:
    clock = [NOW]
    headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"text/html",
        ),
    )
    gateway = RecordingGateway(
        lambda dispatch: completed_result(
            dispatch,
            body=b'<img src="/asset">',
            headers=headers,
        )
    )
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    browser = execution.BrowserExecutionCoordinator(
        execution.SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: clock[0]
        ),
        browser_driver=driver,
    )
    context = browser_context()

    browser.register_context(context)
    try:
        browser.navigate(context.browser_context_id, command(request=semantic_request(path="/")))
        candidate_id = browser.pending_candidate_ids(context.browser_context_id)[0]
        child = command(
            action_id="action.asset",
            lease_id="lease.asset",
            request=semantic_request(path="/asset"),
            identity=context.identity,
            parent_action_ids=("action.nav",),
        )
        clock[0] = NOW + timedelta(minutes=2)

        with pytest.raises(execution.ExecutionContractError, match="not currently valid"):
            browser.execute_child(context.browser_context_id, candidate_id, child)
        with pytest.raises(execution.BrowserContractError, match="unavailable for abort"):
            driver.abort_child(candidate_id)
    finally:
        browser.close_context(context.browser_context_id)

    assert len(gateway.calls) == 1


@pytest.mark.parametrize(
    ("status_code", "child_headers", "error"),
    [
        (
            302,
            ("location", b"/other"),
            "redirects",
        ),
        (
            200,
            ("content-disposition", b"attachment"),
            "unsafe",
        ),
    ],
)
def test_redirect_or_download_response_aborts_paused_real_chromium_route(
    status_code: int,
    child_headers: tuple[str, bytes],
    error: str,
) -> None:
    html_headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name="content-type",
            value=b"text/html",
        ),
    )
    unsafe_headers = (
        execution.SemanticResponseHeader(
            schema_version="0.1.0",
            name=child_headers[0],
            value=child_headers[1],
        ),
    )

    def respond(dispatch: execution.GatewayDispatchCommand) -> execution.GatewayResult:
        if dispatch.request.endpoint.path == "/":
            return completed_result(
                dispatch,
                body=b'<iframe src="/child"></iframe>',
                headers=html_headers,
            )
        return completed_result(
            dispatch,
            body=b"blocked",
            headers=unsafe_headers,
            status_code=status_code,
        )

    gateway = RecordingGateway(respond)
    driver = execution.ChromiumBrowserDriver(
        execution.ChromiumLaunchConfig(
            schema_version="0.1.0",
            executable=CHROMIUM,
            executable_digest=CHROMIUM_DIGEST,
        )
    )
    browser = execution.BrowserExecutionCoordinator(
        execution.SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        ),
        browser_driver=driver,
    )
    context = browser_context()

    browser.register_context(context)
    try:
        browser.navigate(context.browser_context_id, command(request=semantic_request(path="/")))
        candidate_id = browser.pending_candidate_ids(context.browser_context_id)[0]
        child = command(
            action_id="action.child",
            lease_id="lease.child",
            request=semantic_request(path="/child"),
            identity=context.identity,
            parent_action_ids=("action.nav",),
        )

        with pytest.raises(execution.BrowserContractError, match=error):
            browser.execute_child(context.browser_context_id, candidate_id, child)
        with pytest.raises(execution.BrowserContractError, match="unavailable for abort"):
            driver.abort_child(candidate_id)
    finally:
        browser.close_context(context.browser_context_id)

    assert len(gateway.calls) == 2
