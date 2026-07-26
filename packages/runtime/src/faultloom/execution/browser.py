from __future__ import annotations

from typing import Protocol, assert_never

from faultloom_protocol import DispatchOutcome

from .browser_contracts import (
    BrowserContractError,
    BrowserIdentityContext,
    browser_flow_kind,
)
from .browser_lifecycle import BrowserLifecycle, BrowserOperation
from .contracts import (
    BrowserChildCandidate,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
)
from .gateway import ExecutionFlowKind, GatewayDispatchFrame
from .http import SemanticHttpExecutor
from .http_validation import ExecutionContractError


class BrowserDriverPort(Protocol):
    def register_context(self, context: BrowserIdentityContext) -> None: ...

    def close_context(self, context_id: str) -> None: ...

    def interrupt_context(self, context_id: str) -> None: ...

    def navigate(
        self,
        context: BrowserIdentityContext,
        command: GatewayDispatchCommand,
        result: GatewayResult,
    ) -> tuple[BrowserChildCandidate, ...]: ...

    def fulfill_child(
        self,
        candidate: BrowserChildCandidate,
        command: GatewayDispatchCommand,
        result: GatewayResult,
    ) -> tuple[BrowserChildCandidate, ...]: ...

    def abort_child(self, candidate_id: str) -> None: ...

    def navigation_ready(self, context_id: str) -> bool: ...


class BrowserExecutionCoordinator:
    """Keep identity partitions disjoint and mediate all HTTP child requests."""

    def __init__(
        self,
        http_executor: SemanticHttpExecutor,
        *,
        browser_driver: BrowserDriverPort | None = None,
    ) -> None:
        self._http = http_executor
        self._lifecycle = BrowserLifecycle()
        self._driver = browser_driver

    def register_context(self, context: BrowserIdentityContext) -> None:
        self._lifecycle.register(context)
        if self._driver is not None:
            self._driver.register_context(context)

    def close_context(self, context_id: str) -> None:
        cancellation = self._lifecycle.begin_cancellation(context_id)
        if cancellation.action_ids:
            if self._driver is not None:
                self._driver.interrupt_context(context_id)
            self._http.interrupt()
        self._lifecycle.wait_for_cancellation(cancellation)
        if self._driver is not None:
            self._driver.close_context(context_id)

    def navigate(self, context_id: str, command: GatewayDispatchCommand) -> GatewayResult:
        if command.intent.parent_action_ids:
            raise BrowserContractError("top-level navigation cannot impersonate a child action")
        operation = self._lifecycle.begin(context_id, command)
        frame = GatewayDispatchFrame(
            schema_version=command.schema_version,
            command=command,
            context_generation=operation.generation,
            flow_kind=ExecutionFlowKind.NAVIGATION,
        )
        try:
            result = self._http.execute(frame)
            self._admit_candidates(operation, result)
            if self._driver is not None and self._is_completed(result):
                self._lifecycle.admit_discovered(
                    operation,
                    self._driver.navigate(operation.context, command, result),
                )
            return result
        finally:
            self._lifecycle.finish(command.intent.action_id)

    def execute_child(
        self,
        context_id: str,
        candidate_id: str,
        command: GatewayDispatchCommand,
    ) -> GatewayResult:
        operation = self._lifecycle.begin_child(context_id, candidate_id, command)
        frame = GatewayDispatchFrame(
            schema_version=command.schema_version,
            command=command,
            context_generation=operation.generation,
            flow_kind=browser_flow_kind(operation.candidate.kind),
            parent_action_id=operation.candidate.parent_action_id,
        )
        try:
            try:
                result = self._http.execute(frame)
            except ExecutionContractError:
                if self._driver is not None:
                    self._driver.abort_child(candidate_id)
                raise
            self._admit_candidates(
                BrowserOperation(
                    context=operation.context,
                    generation=operation.generation,
                ),
                result,
            )
            if self._driver is not None:
                if self._is_completed(result):
                    self._lifecycle.admit_discovered(
                        BrowserOperation(
                            context=operation.context,
                            generation=operation.generation,
                        ),
                        self._driver.fulfill_child(operation.candidate, command, result),
                    )
                else:
                    self._driver.abort_child(candidate_id)
            return result
        finally:
            self._lifecycle.finish(command.intent.action_id)

    def pending_candidate_ids(self, context_id: str) -> tuple[str, ...]:
        return self._lifecycle.pending_candidate_ids(context_id)

    def navigation_ready(self, context_id: str) -> bool:
        if self._driver is None:
            return True
        return self._driver.navigation_ready(context_id)

    def pending_websocket_candidates(
        self,
        context_id: str,
    ) -> tuple[BrowserChildCandidate, ...]:
        return self._lifecycle.pending_websocket_candidates(context_id)

    def _admit_candidates(
        self,
        operation: BrowserOperation,
        result: GatewayResult,
    ) -> None:
        self._lifecycle.admit_candidates(operation, result)

    @staticmethod
    def _is_completed(result: GatewayResult) -> bool:
        match result:
            case GatewayDeniedResult():
                return False
            case GatewayDispatchResult():
                return result.receipt.outcome is DispatchOutcome.COMPLETED
            case unreachable:
                assert_never(unreachable)
