"""Validation for authenticated semantic HTTP Gateway responses."""

from __future__ import annotations

from enum import Enum
from typing import assert_never

from faultloom_protocol import DispatchOutcome

from .contracts import (
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
)
from .gateway import (
    GatewayDispatchFrame,
    GatewayResponseEnvelope,
    gateway_frame_digest,
    gateway_response_is_authentic,
)


class ExecutionContractError(ValueError):
    """An approval, request, or Gateway response is not exactly bound."""


class DispatchReplayError(ExecutionContractError):
    """An action or single-use lease was already presented to this executor."""


class DispatchUncertainError(ExecutionContractError):
    """The local caller cannot prove whether a Gateway dispatch occurred."""


class GatewayChannelError(OSError):
    pass


class ReconciliationStateError(ExecutionContractError):
    pass


class LocalDispatchState(str, Enum):
    IN_FLIGHT = "in_flight"
    DENIED = "denied"
    COMPLETED = "completed"
    FAILED = "failed"
    PENDING = "pending"
    UNKNOWN = "unknown"


def validate_gateway_envelope(
    frame: GatewayDispatchFrame,
    envelope: GatewayResponseEnvelope,
    channel_key: bytes,
) -> LocalDispatchState:
    request_digest = gateway_frame_digest(frame)
    if envelope.request_frame_digest != request_digest:
        raise ExecutionContractError("Gateway response request binding mismatch")
    if not gateway_response_is_authentic(envelope, channel_key):
        raise ExecutionContractError("Gateway response authentication failed")
    return _validate_gateway_result(frame.command, envelope.result, request_digest)


def _validate_gateway_result(
    command: GatewayDispatchCommand,
    result: GatewayResult,
    request_frame_digest: str,
) -> LocalDispatchState:
    match result:
        case GatewayDeniedResult():
            if result.action_id != command.intent.action_id:
                raise ExecutionContractError("Gateway denial belongs to another action")
            if result.request_digest != request_frame_digest:
                raise ExecutionContractError("Gateway denial request binding mismatch")
            return LocalDispatchState.DENIED
        case GatewayDispatchResult():
            pass
        case unreachable:
            assert_never(unreachable)

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
    if not command.lease.issued_at <= receipt.dispatched_at < command.lease.expires_at:
        raise ExecutionContractError("Gateway dispatch occurred outside the lease window")
    if receipt.response_status is not None and not 100 <= receipt.response_status <= 599:
        raise ExecutionContractError("Gateway returned an invalid HTTP status")

    observation = result.observation
    if observation is None:
        if receipt.outcome is DispatchOutcome.COMPLETED:
            raise ExecutionContractError("Gateway response bytes require semantic observation")
    else:
        response_ref = observation.response_ref
        if response_ref is not None:
            if receipt.response_digest != response_ref.cas_digest:
                raise ExecutionContractError("response observation digest differs from the receipt")
            if response_ref.run_id != command.intent.run_id:
                raise ExecutionContractError("response observation belongs to another run")
            if response_ref.byte_length != receipt.bytes_received:
                raise ExecutionContractError("response observation length differs from the receipt")
        if observation.raw_response_digest is not None:
            if receipt.response_digest != observation.raw_response_digest:
                raise ExecutionContractError("semantic response digest differs from the receipt")
            if observation.raw_response_length != receipt.bytes_received:
                raise ExecutionContractError("semantic response length differs from the receipt")
            if observation.status_code != receipt.response_status:
                raise ExecutionContractError("semantic response status differs from the receipt")
        for child in observation.child_candidates:
            if child.parent_action_id != command.intent.action_id:
                raise ExecutionContractError("browser child belongs to another parent action")
            if child.browser_context_id != command.identity.context_id:
                raise ExecutionContractError("browser child escaped its identity context")
        if observation.child_candidates:
            match receipt.outcome:
                case DispatchOutcome.COMPLETED:
                    pass
                case (
                    DispatchOutcome.FAILED
                    | DispatchOutcome.CANCELLED
                    | DispatchOutcome.DISPATCHED
                    | DispatchOutcome.UNKNOWN_OUTCOME
                ):
                    raise ExecutionContractError(
                        "browser children require a completed parent response"
                    )
                case unreachable:
                    assert_never(unreachable)

    match receipt.outcome:
        case DispatchOutcome.COMPLETED:
            if receipt.response_status is None:
                raise ExecutionContractError(
                    "completed semantic HTTP receipt requires a status"
                )
            if receipt.completed_at is None:
                raise ExecutionContractError("terminal Gateway receipt requires completed_at")
            return LocalDispatchState.COMPLETED
        case DispatchOutcome.FAILED | DispatchOutcome.CANCELLED:
            if receipt.completed_at is None:
                raise ExecutionContractError("terminal Gateway receipt requires completed_at")
            return LocalDispatchState.FAILED
        case DispatchOutcome.DISPATCHED:
            return LocalDispatchState.PENDING
        case DispatchOutcome.UNKNOWN_OUTCOME:
            return LocalDispatchState.UNKNOWN
        case unreachable:
            assert_never(unreachable)
