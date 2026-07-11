"""Multi-identity browser coordination with per-child Gateway approval.

The coordinator models the network boundary used by a Playwright/Chromium
adapter.  It does not give that adapter a target URL or a target socket.  Every
network-bearing navigation, redirect, frame, subresource, service-worker fetch,
and download re-enters :class:`SemanticHttpExecutor` with a fresh lease.
WebSocket candidates remain pending for the separately admitted semantic
WebSocket engine rather than being disguised as HTTP.
"""

from __future__ import annotations

from threading import Lock
from typing import Literal, Self

from pydantic import model_validator

from faultloom_protocol.base import Identifier

from .contracts import (
    BrowserChildCandidate,
    BrowserChildKind,
    ExecutionIdentity,
    ExecutionModel,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
)
from .http import ExecutionContractError, SemanticHttpExecutor


class BrowserContractError(ExecutionContractError):
    """A browser context or discovered child violated an isolation contract."""


class UnsupportedBrowserTransport(BrowserContractError):
    """The child requires a separately admitted non-HTTP executor."""


class BrowserIdentityContext(ExecutionModel):
    browser_context_id: Identifier
    storage_partition_id: Identifier
    identity: ExecutionIdentity
    automation_driver: Literal["playwright"] = "playwright"
    browser_engine: Literal["chromium"] = "chromium"

    @model_validator(mode="after")
    def _authenticated_and_consistent(self) -> Self:
        if self.identity.context_id != self.browser_context_id:
            raise ValueError("browser and execution context IDs differ")
        if self.identity.identity_id is None or self.identity.session_ref is None:
            raise ValueError("browser contexts require an operator-provisioned session handle")
        return self


class BrowserExecutionCoordinator:
    """Keep identity partitions disjoint and mediate all HTTP child requests."""

    def __init__(self, http_executor: SemanticHttpExecutor) -> None:
        self._http = http_executor
        self._lock = Lock()
        self._contexts: dict[str, BrowserIdentityContext] = {}
        self._closed_contexts: set[str] = set()
        self._session_owners: dict[str, str] = {}
        self._partition_owners: dict[str, str] = {}
        self._pending: dict[str, BrowserChildCandidate] = {}
        self._consumed: set[str] = set()

    def register_context(self, context: BrowserIdentityContext) -> None:
        context_id = context.browser_context_id
        session_uri = context.identity.session_ref.uri
        partition_id = context.storage_partition_id
        with self._lock:
            if context_id in self._contexts or context_id in self._closed_contexts:
                raise BrowserContractError(f"browser context ID is not fresh: {context_id}")
            if session_uri in self._session_owners:
                raise BrowserContractError(
                    "a session handle cannot be shared across browser contexts"
                )
            if partition_id in self._partition_owners:
                raise BrowserContractError("a storage partition cannot be shared across identities")
            self._contexts[context_id] = context
            self._session_owners[session_uri] = context_id
            self._partition_owners[partition_id] = context_id

    def close_context(self, context_id: str) -> None:
        with self._lock:
            context = self._contexts.pop(context_id, None)
            if context is None:
                raise BrowserContractError(f"browser context is not active: {context_id}")
            self._closed_contexts.add(context_id)
            for candidate_id in tuple(self._pending):
                if self._pending[candidate_id].browser_context_id == context_id:
                    del self._pending[candidate_id]
                    self._consumed.add(candidate_id)

    def navigate(self, context_id: str, command: GatewayDispatchCommand) -> GatewayResult:
        context = self._require_command_identity(context_id, command)
        if command.intent.parent_action_ids:
            raise BrowserContractError("top-level navigation cannot impersonate a child action")
        result = self._http.execute(command)
        self._admit_candidates(context, result)
        return result

    def execute_child(
        self,
        context_id: str,
        candidate_id: str,
        command: GatewayDispatchCommand,
    ) -> GatewayResult:
        context = self._require_command_identity(context_id, command)
        with self._lock:
            candidate = self._pending.get(candidate_id)
            if candidate is None:
                if candidate_id in self._consumed:
                    raise BrowserContractError("browser child candidate was already consumed")
                raise BrowserContractError("browser child candidate was not discovered")
            if candidate.browser_context_id != context_id:
                raise BrowserContractError("browser child belongs to another identity context")
            if candidate.kind is BrowserChildKind.WEBSOCKET:
                raise UnsupportedBrowserTransport(
                    "WebSocket candidate requires the separately admitted semantic WebSocket engine"
                )
            if candidate.request is None or command.request != candidate.request:
                raise BrowserContractError("approved request differs from the discovered child")
            if candidate.parent_action_id not in command.intent.parent_action_ids:
                raise BrowserContractError("child intent lacks its discovered parent binding")
            del self._pending[candidate_id]
            self._consumed.add(candidate_id)
        result = self._http.execute(command)
        self._admit_candidates(context, result)
        return result

    def pending_candidate_ids(self, context_id: str) -> tuple[str, ...]:
        with self._lock:
            self._require_active_context_locked(context_id)
            return tuple(
                sorted(
                    candidate_id
                    for candidate_id, candidate in self._pending.items()
                    if candidate.browser_context_id == context_id
                )
            )

    def pending_websocket_candidates(self, context_id: str) -> tuple[BrowserChildCandidate, ...]:
        with self._lock:
            self._require_active_context_locked(context_id)
            return tuple(
                sorted(
                    (
                        candidate
                        for candidate in self._pending.values()
                        if candidate.browser_context_id == context_id
                        and candidate.kind is BrowserChildKind.WEBSOCKET
                    ),
                    key=lambda candidate: candidate.candidate_id,
                )
            )

    def _require_command_identity(
        self,
        context_id: str,
        command: GatewayDispatchCommand,
    ) -> BrowserIdentityContext:
        with self._lock:
            context = self._require_active_context_locked(context_id)
            if command.identity != context.identity:
                raise BrowserContractError(
                    "command session differs from the isolated browser context"
                )
            return context

    def _require_active_context_locked(self, context_id: str) -> BrowserIdentityContext:
        context = self._contexts.get(context_id)
        if context is None:
            raise BrowserContractError(f"browser context is not active: {context_id}")
        return context

    def _admit_candidates(
        self,
        context: BrowserIdentityContext,
        result: GatewayResult,
    ) -> None:
        if not isinstance(result, GatewayDispatchResult) or result.observation is None:
            return
        candidates = result.observation.child_candidates
        with self._lock:
            self._require_active_context_locked(context.browser_context_id)
            candidate_ids = {candidate.candidate_id for candidate in candidates}
            if candidate_ids.intersection(self._pending) or candidate_ids.intersection(
                self._consumed
            ):
                raise BrowserContractError("browser child candidate ID was reused")
            for candidate in candidates:
                if candidate.browser_context_id != context.browser_context_id:
                    raise BrowserContractError("browser child escaped its identity context")
            self._pending.update((candidate.candidate_id, candidate) for candidate in candidates)
