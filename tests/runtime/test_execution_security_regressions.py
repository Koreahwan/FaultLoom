from __future__ import annotations

from queue import Queue
from threading import Event, Thread

import pytest

from faultloom.execution import (
    BrowserChildKind,
    BrowserExecutionCoordinator,
    ExecutionContractError,
    GatewayDeniedResult,
    GatewayDispatchFrame,
    GatewayResponseEnvelope,
    GatewayResult,
    SemanticHttpExecutor,
    gateway_dispatch_frame,
    gateway_frame_digest,
)
from faultloom.execution.browser_lifecycle import BrowserOperation
from faultloom_protocol import SCHEMA_VERSION

from .browser_execution_helpers import browser_context, http_candidate
from .execution_helpers import (
    CHANNEL_KEY,
    D2,
    NOW,
    RecordingGateway,
    command,
    completed_result,
)


class PausingCandidateCoordinator(BrowserExecutionCoordinator):
    def __init__(
        self,
        http_executor: SemanticHttpExecutor,
        ready: Event,
        release: Event,
    ) -> None:
        super().__init__(http_executor)
        self._ready = ready
        self._release = release

    def _admit_candidates(
        self,
        operation: BrowserOperation,
        result: GatewayResult,
    ) -> None:
        self._ready.set()
        if not self._release.wait(timeout=5):
            raise RuntimeError("test candidate barrier timed out")
        super()._admit_candidates(operation, result)


class TamperingGateway(RecordingGateway):
    def dispatch(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope:
        envelope = super().dispatch(frame)
        return envelope.model_copy(update={"response_mac": D2})


def test_context_close_waits_for_inflight_and_discards_late_children() -> None:
    candidate = http_candidate(BrowserChildKind.SUBRESOURCE, suffix="script")
    ready = Event()
    release = Event()
    approved = command()
    expected = completed_result(approved, child_candidates=(candidate,))
    browser = PausingCandidateCoordinator(
        SemanticHttpExecutor._for_test(
            RecordingGateway(lambda _: expected),
            channel_key=CHANNEL_KEY,
            now=lambda: NOW,
        ),
        ready,
        release,
    )
    browser.register_context(browser_context())
    navigation: Queue[GatewayResult | Exception] = Queue()

    def navigate() -> None:
        try:
            navigation.put(browser.navigate("browser.owner", approved))
        except Exception as exc:
            navigation.put(exc)

    worker = Thread(target=navigate)
    worker.start()
    assert ready.wait(timeout=5)
    closer = Thread(target=lambda: browser.close_context("browser.owner"))
    closer.start()
    assert closer.is_alive()
    release.set()
    worker.join(timeout=5)
    closer.join(timeout=5)

    assert not worker.is_alive()
    assert not closer.is_alive()
    assert navigation.get_nowait() == expected


def test_gateway_denial_must_bind_the_exact_dispatch_frame() -> None:
    approved = command()
    frame = gateway_dispatch_frame(approved)
    denial = GatewayDeniedResult(
        schema_version=SCHEMA_VERSION,
        action_id=approved.intent.action_id,
        request_digest=D2,
        reason_code="scope.revoked",
    )
    executor = SemanticHttpExecutor._for_test(
        RecordingGateway(lambda _: denial),
        channel_key=CHANNEL_KEY,
        now=lambda: NOW,
    )
    assert denial.request_digest != gateway_frame_digest(frame)

    with pytest.raises(ExecutionContractError, match="request"):
        executor.execute(approved)


def test_gateway_response_authentication_detects_mutation() -> None:
    approved = command()
    executor = SemanticHttpExecutor._for_test(
        TamperingGateway(completed_result),
        channel_key=CHANNEL_KEY,
        now=lambda: NOW,
    )

    with pytest.raises(ExecutionContractError, match="authentication"):
        executor.execute(approved)

    assert executor.unknown_action_ids() == (approved.intent.action_id,)
