"""Fail-closed semantic HTTP dispatch through an authenticated Gateway port."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from threading import Lock
from typing import Protocol, Self, assert_never

from faultloom_protocol import sha256_digest

from .contracts import (
    GatewayDispatchCommand,
    GatewayResult,
)
from .gateway import (
    GatewayCancellationReceipt,
    GatewayCancellationRequest,
    GatewayDispatchFrame,
    GatewayResponseEnvelope,
    gateway_cancellation_is_authentic,
    gateway_dispatch_frame,
)
from .gateway_client import AuthenticatedGatewayClient
from .http_validation import (
    DispatchReplayError,
    DispatchUncertainError,
    ExecutionContractError,
    LocalDispatchState,
    ReconciliationStateError,
    validate_gateway_envelope,
)


class GatewayPort(Protocol):
    """The sole target-egress dependency available to the runtime executor."""

    def dispatch(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope: ...

    def cancel_context(
        self,
        request: GatewayCancellationRequest,
    ) -> GatewayCancellationReceipt: ...

    def reconcile(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope | None: ...


class SemanticHttpExecutor:
    """Validate one approved semantic request and hand it only to the Gateway.

    The executor intentionally has no URL opener, DNS resolver, socket, browser,
    or retry loop.  A local exception or invalid receipt is recorded as unknown,
    so the same action/lease cannot be automatically replayed.
    """

    def __init__(
        self,
        gateway: AuthenticatedGatewayClient,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if type(gateway) is not AuthenticatedGatewayClient:
            raise ExecutionContractError(
                "production execution requires the authenticated pipe Gateway client"
            )
        self._initialize(gateway, gateway.channel_key, now)

    @classmethod
    def _for_test(
        cls,
        gateway: GatewayPort,
        *,
        channel_key: bytes,
        now: Callable[[], datetime] | None = None,
    ) -> Self:
        instance = cls.__new__(cls)
        instance._initialize(gateway, channel_key, now)
        return instance

    def _initialize(
        self,
        gateway: GatewayPort,
        channel_key: bytes,
        now: Callable[[], datetime] | None,
    ) -> None:
        if len(channel_key) < 32:
            raise ExecutionContractError("Gateway channel key must contain at least 256 bits")
        self._gateway = gateway
        self._channel_key = bytes(channel_key)
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._lock = Lock()
        self._states: dict[str, LocalDispatchState] = {}
        self._leases: dict[str, str] = {}
        self._frames: dict[str, GatewayDispatchFrame] = {}

    def execute(
        self,
        dispatch: GatewayDispatchCommand | GatewayDispatchFrame,
    ) -> GatewayResult:
        match dispatch:
            case GatewayDispatchCommand():
                frame = gateway_dispatch_frame(dispatch)
            case GatewayDispatchFrame():
                frame = dispatch
            case unreachable:
                assert_never(unreachable)
        command = frame.command
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
            self._frames[action_id] = frame

        envelope: GatewayResponseEnvelope | None = None
        try:
            envelope = self._gateway.dispatch(frame)
        except Exception as exc:
            raise DispatchUncertainError(
                "Gateway call failed after local dispatch reservation; reconciliation is required"
            ) from exc
        finally:
            if envelope is None:
                self._set_state(action_id, LocalDispatchState.UNKNOWN)
        if envelope is None:
            raise DispatchUncertainError("Gateway returned no authenticated response")

        try:
            state = validate_gateway_envelope(frame, envelope, self._channel_key)
        except (TypeError, ValueError, ExecutionContractError) as exc:
            self._set_state(action_id, LocalDispatchState.UNKNOWN)
            match exc:
                case ExecutionContractError():
                    raise
                case TypeError() | ValueError():
                    raise ExecutionContractError(
                        "Gateway returned an invalid typed response"
                    ) from exc
                case unreachable:
                    assert_never(unreachable)
        self._set_state(action_id, state)
        return envelope.result

    def reconcile(self, action_id: str) -> GatewayResult | None:
        with self._lock:
            if self._states.get(action_id) is not LocalDispatchState.UNKNOWN:
                raise ReconciliationStateError(
                    f"action is not awaiting reconciliation: {action_id}"
                )
            frame = self._frames[action_id]
        try:
            envelope = self._gateway.reconcile(frame)
        except Exception as exc:
            raise DispatchUncertainError("Gateway reconciliation channel failed") from exc
        if envelope is None:
            return None
        state = validate_gateway_envelope(frame, envelope, self._channel_key)
        self._set_state(action_id, state)
        return envelope.result

    def cancel_context(
        self,
        request: GatewayCancellationRequest,
    ) -> GatewayCancellationReceipt:
        try:
            receipt = self._gateway.cancel_context(request)
        except Exception as exc:
            raise DispatchUncertainError("Gateway cancellation channel failed") from exc
        if receipt.request_digest != sha256_digest(request):
            raise ExecutionContractError("Gateway cancellation request binding mismatch")
        if not gateway_cancellation_is_authentic(receipt, self._channel_key):
            raise ExecutionContractError("Gateway cancellation authentication failed")
        return receipt

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
