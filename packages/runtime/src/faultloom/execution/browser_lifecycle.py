from __future__ import annotations

from dataclasses import dataclass
from threading import Condition, Lock
from typing import assert_never

from .browser_contracts import (
    BrowserContractError,
    BrowserIdentityContext,
    UnsupportedBrowserTransport,
)
from .contracts import (
    BrowserChildCandidate,
    BrowserChildKind,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
)


@dataclass(frozen=True, slots=True)
class BrowserOperation:
    context: BrowserIdentityContext
    generation: int


@dataclass(frozen=True, slots=True)
class BrowserChildOperation:
    context: BrowserIdentityContext
    candidate: BrowserChildCandidate
    generation: int


class BrowserLifecycle:
    def __init__(self) -> None:
        self._lock = Lock()
        self._condition = Condition(self._lock)
        self._contexts: dict[str, BrowserIdentityContext] = {}
        self._generations: dict[str, int] = {}
        self._closed_contexts: set[str] = set()
        self._session_owners: dict[str, str] = {}
        self._partition_owners: dict[str, str] = {}
        self._pending: dict[str, tuple[BrowserChildCandidate, int]] = {}
        self._consumed: set[str] = set()
        self._in_flight: dict[str, tuple[str, int]] = {}

    def register(self, context: BrowserIdentityContext) -> None:
        context_id = context.browser_context_id
        session_uri = context.session_uri
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
            self._generations[context_id] = 1
            self._session_owners[session_uri] = context_id
            self._partition_owners[partition_id] = context_id

    def begin(
        self,
        context_id: str,
        command: GatewayDispatchCommand,
    ) -> BrowserOperation:
        with self._condition:
            context = self._require_command_identity_locked(context_id, command)
            generation = self._generations[context_id]
            self._reserve_action_locked(command.intent.action_id, context_id, generation)
            return BrowserOperation(context=context, generation=generation)

    def begin_child(
        self,
        context_id: str,
        candidate_id: str,
        command: GatewayDispatchCommand,
    ) -> BrowserChildOperation:
        with self._condition:
            context = self._require_command_identity_locked(context_id, command)
            pending = self._pending.get(candidate_id)
            if pending is None:
                if candidate_id in self._consumed:
                    raise BrowserContractError("browser child candidate was already consumed")
                raise BrowserContractError("browser child candidate was not discovered")
            candidate, generation = pending
            if candidate.browser_context_id != context_id:
                raise BrowserContractError("browser child belongs to another identity context")
            match candidate.kind:
                case BrowserChildKind.WEBSOCKET:
                    raise UnsupportedBrowserTransport(
                        "WebSocket candidate requires the separately admitted "
                        "semantic WebSocket engine"
                    )
                case (
                    BrowserChildKind.REDIRECT
                    | BrowserChildKind.IFRAME
                    | BrowserChildKind.SUBRESOURCE
                    | BrowserChildKind.SERVICE_WORKER
                    | BrowserChildKind.DOWNLOAD
                ):
                    pass
                case unreachable:
                    assert_never(unreachable)
            if candidate.request is None or command.request != candidate.request:
                raise BrowserContractError("approved request differs from the discovered child")
            if candidate.parent_action_id not in command.intent.parent_action_ids:
                raise BrowserContractError("child intent lacks its discovered parent binding")
            self._reserve_action_locked(command.intent.action_id, context_id, generation)
            del self._pending[candidate_id]
            self._consumed.add(candidate_id)
            return BrowserChildOperation(
                context=context,
                candidate=candidate,
                generation=generation,
            )

    def begin_cancellation(self, context_id: str) -> BrowserOperation:
        with self._condition:
            context = self._contexts.pop(context_id, None)
            if context is None:
                raise BrowserContractError(f"browser context is not active: {context_id}")
            generation = self._generations.pop(context_id)
            self._closed_contexts.add(context_id)
            for candidate_id in tuple(self._pending):
                candidate, _ = self._pending[candidate_id]
                if candidate.browser_context_id == context_id:
                    del self._pending[candidate_id]
                    self._consumed.add(candidate_id)
            return BrowserOperation(context=context, generation=generation)

    def wait_for_cancellation(self, operation: BrowserOperation) -> None:
        owner = (operation.context.browser_context_id, operation.generation)
        with self._condition:
            self._condition.wait_for(
                lambda: all(current_owner != owner for current_owner in self._in_flight.values())
            )

    def admit_candidates(
        self,
        operation: BrowserOperation,
        result: GatewayResult,
    ) -> None:
        match result:
            case GatewayDeniedResult():
                return
            case GatewayDispatchResult():
                observation = result.observation
                if observation is None:
                    return
                candidates = observation.child_candidates
            case unreachable:
                assert_never(unreachable)
        with self._condition:
            context_id = operation.context.browser_context_id
            active = self._contexts.get(context_id)
            generation = self._generations.get(context_id)
            if active != operation.context or generation != operation.generation:
                self._consumed.update(candidate.candidate_id for candidate in candidates)
                return
            candidate_ids = {candidate.candidate_id for candidate in candidates}
            if candidate_ids.intersection(self._pending) or candidate_ids.intersection(
                self._consumed
            ):
                for candidate_id in candidate_ids:
                    self._pending.pop(candidate_id, None)
                self._consumed.update(candidate_ids)
                raise BrowserContractError("browser child candidate ID was reused")
            for candidate in candidates:
                if candidate.browser_context_id != context_id:
                    raise BrowserContractError("browser child escaped its identity context")
            self._pending.update(
                (candidate.candidate_id, (candidate, operation.generation))
                for candidate in candidates
            )

    def finish(self, action_id: str) -> None:
        with self._condition:
            self._in_flight.pop(action_id, None)
            self._condition.notify_all()

    def pending_candidate_ids(self, context_id: str) -> tuple[str, ...]:
        with self._lock:
            self._require_active_context_locked(context_id)
            return tuple(
                sorted(
                    candidate_id
                    for candidate_id, (candidate, _) in self._pending.items()
                    if candidate.browser_context_id == context_id
                )
            )

    def pending_websocket_candidates(
        self,
        context_id: str,
    ) -> tuple[BrowserChildCandidate, ...]:
        with self._lock:
            self._require_active_context_locked(context_id)
            return tuple(
                sorted(
                    (
                        candidate
                        for candidate, _ in self._pending.values()
                        if candidate.browser_context_id == context_id
                        and candidate.kind is BrowserChildKind.WEBSOCKET
                    ),
                    key=lambda candidate: candidate.candidate_id,
                )
            )

    def _require_command_identity_locked(
        self,
        context_id: str,
        command: GatewayDispatchCommand,
    ) -> BrowserIdentityContext:
        context = self._require_active_context_locked(context_id)
        if command.identity != context.identity:
            raise BrowserContractError("command session differs from the isolated browser context")
        return context

    def _require_active_context_locked(self, context_id: str) -> BrowserIdentityContext:
        context = self._contexts.get(context_id)
        if context is None:
            raise BrowserContractError(f"browser context is not active: {context_id}")
        return context

    def _reserve_action_locked(
        self,
        action_id: str,
        context_id: str,
        generation: int,
    ) -> None:
        if action_id in self._in_flight:
            raise BrowserContractError(f"browser action is already in flight: {action_id}")
        self._in_flight[action_id] = (context_id, generation)
