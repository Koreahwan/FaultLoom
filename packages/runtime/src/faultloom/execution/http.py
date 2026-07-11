"""Fail-closed semantic HTTP dispatch through an injected Gateway port."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Protocol

from faultloom_protocol import DispatchOutcome

from .contracts import (
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
)


class ExecutionContractError(ValueError):
    """An approval, request, or Gateway response is not exactly bound."""


class DispatchReplayError(ExecutionContractError):
    """An action or single-use lease was already presented to this executor."""


class DispatchUncertainError(ExecutionContractError):
    """The local caller cannot prove whether a Gateway dispatch occurred."""


class GatewayPort(Protocol):
    """The sole target-egress dependency available to the runtime executor."""

    def dispatch(self, command: GatewayDispatchCommand) -> GatewayResult:
        """Ask the separate Gateway process to verify, compile, and dispatch once."""


class LocalDispatchState(str, Enum):
    IN_FLIGHT = "in_flight"
    DENIED = "denied"
    COMPLETED = "completed"
    FAILED = "failed"
    PENDING = "pending"
    UNKNOWN = "unknown"


_TERMINAL_OUTCOMES = frozenset(
    {DispatchOutcome.COMPLETED, DispatchOutcome.FAILED, DispatchOutcome.CANCELLED}
)


class SemanticHttpExecutor:
    """Validate one approved semantic request and hand it only to the Gateway.

    The executor intentionally has no URL opener, DNS resolver, socket, browser,
    or retry loop.  A local exception or invalid receipt is recorded as unknown,
    so the same action/lease cannot be automatically replayed.
    """

    def __init__(
        self,
        gateway: GatewayPort,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._gateway = gateway
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._lock = Lock()
        self._states: dict[str, LocalDispatchState] = {}
        self._leases: dict[str, str] = {}

    def execute(self, command: GatewayDispatchCommand) -> GatewayResult:
        now = self._validated_now()
        self._validate_before_dispatch(command, now)
        action_id = command.intent.action_id
        lease_id = command.lease.lease_id
        with self._lock:
            if action_id in self._states:
                raise DispatchReplayError(f"action has already been presented: {action_id}")
            prior_action = self._leases.get(lease_id)
            if prior_action is not None:
                raise DispatchReplayError(
                    f"single-use lease {lease_id} was already presented for {prior_action}"
                )
            self._states[action_id] = LocalDispatchState.IN_FLIGHT
            self._leases[lease_id] = action_id

        try:
            result = self._gateway.dispatch(command)
        except BaseException as exc:
            self._set_state(action_id, LocalDispatchState.UNKNOWN)
            if isinstance(exc, Exception):
                raise DispatchUncertainError(
                    "Gateway call failed after local dispatch reservation; "
                    "reconciliation is required"
                ) from exc
            raise

        try:
            state = self._validate_gateway_result(command, result)
        except (TypeError, ValueError, ExecutionContractError) as exc:
            self._set_state(action_id, LocalDispatchState.UNKNOWN)
            if isinstance(exc, ExecutionContractError):
                raise
            raise ExecutionContractError("Gateway returned an invalid typed response") from exc
        self._set_state(action_id, state)
        return result

    def state_for(self, action_id: str) -> LocalDispatchState | None:
        with self._lock:
            return self._states.get(action_id)

    def unknown_action_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    action_id
                    for action_id, state in self._states.items()
                    if state is LocalDispatchState.UNKNOWN
                )
            )

    def pending_action_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    action_id
                    for action_id, state in self._states.items()
                    if state in {LocalDispatchState.IN_FLIGHT, LocalDispatchState.PENDING}
                )
            )

    def _set_state(self, action_id: str, state: LocalDispatchState) -> None:
        with self._lock:
            self._states[action_id] = state

    def _validated_now(self) -> datetime:
        now = self._now()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ExecutionContractError("execution clock must return an aware datetime")
        return now

    @staticmethod
    def _validate_before_dispatch(command: GatewayDispatchCommand, now: datetime) -> None:
        lease = command.lease
        if now < lease.issued_at or now >= lease.expires_at:
            raise ExecutionContractError("action lease is not currently valid")
        if command.decision.evaluated_at > now:
            raise ExecutionContractError("policy decision is from the future")
        if lease.reservation.request_bytes == 0 or lease.reservation.response_bytes == 0:
            raise ExecutionContractError("semantic HTTP requires non-zero byte reservations")
        if command.request.body_ref is not None:
            if command.request.body_ref.byte_length > lease.reservation.request_bytes:
                raise ExecutionContractError("request body exceeds its lease reservation")

    @staticmethod
    def _validate_gateway_result(
        command: GatewayDispatchCommand,
        result: object,
    ) -> LocalDispatchState:
        if isinstance(result, GatewayDeniedResult):
            if result.action_id != command.intent.action_id:
                raise ExecutionContractError("Gateway denial belongs to another action")
            return LocalDispatchState.DENIED
        if not isinstance(result, GatewayDispatchResult):
            raise TypeError("Gateway result has an unknown type")

        receipt = result.receipt
        if (
            receipt.lease_id != command.lease.lease_id
            or receipt.intent_digest != command.intent_digest
            or receipt.decision_digest != command.decision_digest
            or receipt.scope_epoch != command.lease.scope_epoch
        ):
            raise ExecutionContractError("Gateway receipt binding mismatch")
        if receipt.bytes_sent > command.lease.reservation.request_bytes:
            raise ExecutionContractError("Gateway exceeded reserved request bytes")
        if receipt.bytes_received > command.lease.reservation.response_bytes:
            raise ExecutionContractError("Gateway exceeded reserved response bytes")
        if receipt.response_status is not None and not 100 <= receipt.response_status <= 599:
            raise ExecutionContractError("Gateway returned an invalid HTTP status")
        if receipt.outcome is DispatchOutcome.COMPLETED and receipt.response_status is None:
            raise ExecutionContractError("completed semantic HTTP receipt requires a status")
        if receipt.outcome in _TERMINAL_OUTCOMES and receipt.completed_at is None:
            raise ExecutionContractError("terminal Gateway receipt requires completed_at")

        observation = result.observation
        if observation is None:
            if receipt.response_digest is not None or receipt.bytes_received:
                raise ExecutionContractError(
                    "Gateway response bytes require an observation reference"
                )
        else:
            response_ref = observation.response_ref
            if receipt.response_digest != response_ref.cas_digest:
                raise ExecutionContractError("response observation digest differs from the receipt")
            if response_ref.run_id != command.intent.run_id:
                raise ExecutionContractError("response observation belongs to another run")
            if response_ref.byte_length != receipt.bytes_received:
                raise ExecutionContractError("response observation length differs from the receipt")
            for child in observation.child_candidates:
                if child.parent_action_id != command.intent.action_id:
                    raise ExecutionContractError("browser child belongs to another parent action")
                if child.browser_context_id != command.identity.context_id:
                    raise ExecutionContractError("browser child escaped its identity context")

        if receipt.outcome is DispatchOutcome.COMPLETED:
            return LocalDispatchState.COMPLETED
        if receipt.outcome in {DispatchOutcome.FAILED, DispatchOutcome.CANCELLED}:
            return LocalDispatchState.FAILED
        if receipt.outcome is DispatchOutcome.DISPATCHED:
            return LocalDispatchState.PENDING
        if receipt.outcome is DispatchOutcome.UNKNOWN_OUTCOME:
            return LocalDispatchState.UNKNOWN
        raise ExecutionContractError("Gateway receipt has an unsupported outcome")
