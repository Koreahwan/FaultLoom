from __future__ import annotations

from .browser_contracts import (
    BrowserContractError,
    BrowserIdentityContext,
    browser_flow_kind,
)
from .browser_lifecycle import BrowserLifecycle, BrowserOperation
from .contracts import (
    BrowserChildCandidate,
    GatewayDispatchCommand,
    GatewayResult,
)
from .gateway import ExecutionFlowKind, GatewayDispatchFrame
from .http import SemanticHttpExecutor


class BrowserExecutionCoordinator:
    """Keep identity partitions disjoint and mediate all HTTP child requests."""

    def __init__(self, http_executor: SemanticHttpExecutor) -> None:
        self._http = http_executor
        self._lifecycle = BrowserLifecycle()

    def register_context(self, context: BrowserIdentityContext) -> None:
        self._lifecycle.register(context)

    def close_context(self, context_id: str) -> None:
        operation = self._lifecycle.begin_cancellation(context_id)
        self._lifecycle.wait_for_cancellation(operation)

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
            result = self._http.execute(frame)
            self._admit_candidates(
                BrowserOperation(
                    context=operation.context,
                    generation=operation.generation,
                ),
                result,
            )
            return result
        finally:
            self._lifecycle.finish(command.intent.action_id)

    def pending_candidate_ids(self, context_id: str) -> tuple[str, ...]:
        return self._lifecycle.pending_candidate_ids(context_id)

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
