from __future__ import annotations

from collections.abc import Callable
from queue import Queue
from threading import Event, Thread
from typing import assert_never

import pytest

from faultloom.execution import (
    BrowserChildKind,
    BrowserExecutionCoordinator,
    CancellationReason,
    ExecutionContractError,
    GatewayCancellationReceipt,
    GatewayCancellationRequest,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchFrame,
    GatewayResponseEnvelope,
    GatewayResult,
    SemanticHttpExecutor,
    gateway_dispatch_frame,
    gateway_frame_digest,
)
from faultloom.execution.browser_lifecycle import BrowserOperation
from faultloom_protocol import SCHEMA_VERSION

from .execution_helpers import (
    CHANNEL_KEY,
    D2,
    NOW,
    RecordingGateway,
    command,
    completed_result,
)
from .browser_execution_helpers import browser_context, http_candidate


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


class SignallingGateway(RecordingGateway):
    def __init__(self, handler: Callable[[GatewayDispatchCommand], GatewayResult]) -> None:
        super().__init__(handler)
        self.cancellation_started = Event()

    def cancel_context(
        self,
        request: GatewayCancellationRequest,
    ) -> GatewayCancellationReceipt:
        receipt = super().cancel_context(request)
        self.cancellation_started.set()
        return receipt


class PausingGateway(SignallingGateway):
    def __init__(
        self,
        handler: Callable[[GatewayDispatchCommand], GatewayResult],
        ready: Event,
        release: Event,
    ) -> None:
        super().__init__(handler)
        self._ready = ready
        self._release = release

    def dispatch(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope:
        self._ready.set()
        if not self._release.wait(timeout=5):
            raise RuntimeError("test dispatch barrier timed out")
        return super().dispatch(frame)


class TamperingGateway(RecordingGateway):
    def dispatch(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope:
        envelope = super().dispatch(frame)
        return envelope.model_copy(update={"response_mac": D2})

    def cancel_context(
        self,
        request: GatewayCancellationRequest,
    ) -> GatewayCancellationReceipt:
        receipt = super().cancel_context(request)
        return receipt.model_copy(update={"response_mac": D2})


@pytest.mark.parametrize("reason", tuple(CancellationReason))
def test_context_cancellation_before_gateway_dispatch_fences_navigation(
    reason: CancellationReason,
) -> None:
    # Given: navigation passed identity admission but has not called the Gateway.
    ready = Event()
    release = Event()
    gateway = PausingGateway(completed_result, ready, release)
    browser = BrowserExecutionCoordinator(
        SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        )
    )
    browser.register_context(browser_context())
    navigation_outcomes: Queue[GatewayResult | Exception] = Queue()
    cancellation_outcomes: Queue[GatewayCancellationReceipt | Exception] = Queue()

    def navigate() -> None:
        try:
            navigation_outcomes.put(browser.navigate("browser.owner", command()))
        except Exception as exc:
            navigation_outcomes.put(exc)

    def cancel() -> None:
        try:
            match reason:
                case CancellationReason.CONTEXT_CLOSED:
                    receipt = browser.close_context("browser.owner")
                case CancellationReason.SCOPE_REVOKED:
                    receipt = browser.revoke_context("browser.owner")
                case unreachable:
                    assert_never(unreachable)
            cancellation_outcomes.put(receipt)
        except Exception as exc:
            cancellation_outcomes.put(exc)

    worker = Thread(target=navigate)
    worker.start()
    assert ready.wait(timeout=5)

    # When: close or revoke reaches the Gateway before paused dispatch resumes.
    closer = Thread(target=cancel)
    closer.start()
    assert gateway.cancellation_started.wait(timeout=5)
    release.set()
    worker.join(timeout=5)
    closer.join(timeout=5)

    # Then: the cancelled generation cannot produce target-bearing Gateway traffic.
    assert not worker.is_alive()
    assert not closer.is_alive()
    assert gateway.calls == []
    assert gateway.cancel_calls[0].reason is reason
    assert isinstance(navigation_outcomes.get_nowait(), GatewayDeniedResult)
    assert isinstance(cancellation_outcomes.get_nowait(), GatewayCancellationReceipt)


def test_completed_navigation_is_preserved_when_close_wins_before_child_admission() -> None:
    # Given: the Gateway completed, while child admission is paused.
    candidate = http_candidate(BrowserChildKind.SUBRESOURCE, suffix="script")
    ready = Event()
    release = Event()
    approved = command()
    expected = completed_result(approved, child_candidates=(candidate,))
    gateway = SignallingGateway(lambda _: expected)
    browser = PausingCandidateCoordinator(
        SemanticHttpExecutor._for_test(
            gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
        ),
        ready,
        release,
    )
    browser.register_context(browser_context())
    navigation_outcomes: Queue[GatewayResult | Exception] = Queue()
    cancellation_outcomes: Queue[GatewayCancellationReceipt | Exception] = Queue()

    def navigate() -> None:
        try:
            navigation_outcomes.put(browser.navigate("browser.owner", approved))
        except Exception as exc:
            navigation_outcomes.put(exc)

    def close() -> None:
        try:
            cancellation_outcomes.put(browser.close_context("browser.owner"))
        except Exception as exc:
            cancellation_outcomes.put(exc)

    worker = Thread(target=navigate)
    worker.start()
    assert ready.wait(timeout=5)

    # When: the context closes before discovered children can be admitted.
    closer = Thread(target=close)
    closer.start()
    assert gateway.cancellation_started.wait(timeout=5)
    release.set()
    worker.join(timeout=5)
    closer.join(timeout=5)

    # Then: the completed result remains truthful instead of becoming a local error.
    assert not worker.is_alive()
    assert not closer.is_alive()
    assert navigation_outcomes.get_nowait() == expected
    assert isinstance(cancellation_outcomes.get_nowait(), GatewayCancellationReceipt)


def test_gateway_denial_must_bind_the_exact_dispatch_frame() -> None:
    # Given: an authenticated denial carrying another valid SHA-256 digest.
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

    # When/Then: the substituted response is rejected as an uncertain dispatch.
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


def test_gateway_cancellation_authentication_detects_mutation() -> None:
    request = GatewayCancellationRequest(
        schema_version=SCHEMA_VERSION,
        context_id="browser.owner",
        context_generation=1,
        reason=CancellationReason.SCOPE_REVOKED,
    )
    executor = SemanticHttpExecutor._for_test(
        TamperingGateway(completed_result),
        channel_key=CHANNEL_KEY,
        now=lambda: NOW,
    )

    with pytest.raises(ExecutionContractError, match="authentication"):
        executor.cancel_context(request)
