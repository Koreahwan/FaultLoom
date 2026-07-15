from __future__ import annotations

import hashlib
import hmac
from enum import Enum
from typing import Self, assert_never

from pydantic import PositiveInt, model_validator

from faultloom_protocol import (
    SCHEMA_VERSION,
    DispatchReceipt,
    canonical_json_bytes,
    sha256_digest,
)
from faultloom_protocol.base import Identifier, Sha256Digest

from .contracts import (
    ExecutionModel,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
)


class ExecutionFlowKind(str, Enum):
    DIRECT = "direct"
    NAVIGATION = "navigation"
    REDIRECT = "redirect"
    IFRAME = "iframe"
    SUBRESOURCE = "subresource"
    SERVICE_WORKER = "service_worker"
    DOWNLOAD = "download"


class CancellationReason(str, Enum):
    CONTEXT_CLOSED = "context_closed"
    SCOPE_REVOKED = "scope_revoked"


class GatewayDispatchFrame(ExecutionModel):
    command: GatewayDispatchCommand
    context_generation: PositiveInt
    flow_kind: ExecutionFlowKind
    parent_action_id: Identifier | None = None

    @model_validator(mode="after")
    def _bind_flow(self) -> Self:
        parents = self.command.intent.parent_action_ids
        match self.flow_kind:
            case ExecutionFlowKind.DIRECT | ExecutionFlowKind.NAVIGATION:
                if self.parent_action_id is not None or parents:
                    raise ValueError("top-level dispatch cannot claim a parent action")
            case (
                ExecutionFlowKind.REDIRECT
                | ExecutionFlowKind.IFRAME
                | ExecutionFlowKind.SUBRESOURCE
                | ExecutionFlowKind.SERVICE_WORKER
                | ExecutionFlowKind.DOWNLOAD
            ):
                if self.parent_action_id is None or self.parent_action_id not in parents:
                    raise ValueError("child dispatch requires its approved parent action")
            case unreachable:
                assert_never(unreachable)
        return self


class GatewayResponseEnvelope(ExecutionModel):
    response_id: Identifier
    request_frame_digest: Sha256Digest
    result: GatewayResult
    response_mac: Sha256Digest

    @model_validator(mode="after")
    def _canonical_response_id(self) -> Self:
        expected = canonical_gateway_response_id(self.result)
        if self.response_id != expected:
            raise ValueError("Gateway response ID is not canonical")
        match self.result:
            case GatewayDispatchResult(receipt=receipt):
                if receipt.receipt_id != canonical_dispatch_receipt_id(receipt):
                    raise ValueError("Gateway receipt ID is not canonical")
            case GatewayDeniedResult():
                pass
            case unreachable:
                assert_never(unreachable)
        return self


class GatewayCancellationRequest(ExecutionModel):
    context_id: Identifier
    context_generation: PositiveInt
    reason: CancellationReason


class GatewayCancellationReceipt(ExecutionModel):
    request_digest: Sha256Digest
    cancelled_action_ids: tuple[Identifier, ...] = ()
    response_mac: Sha256Digest

    @model_validator(mode="after")
    def _unique_actions(self) -> Self:
        if len(self.cancelled_action_ids) != len(set(self.cancelled_action_ids)):
            raise ValueError("Gateway cancellation action IDs must be unique")
        return self


def gateway_dispatch_frame(
    command: GatewayDispatchCommand,
    *,
    context_generation: int = 1,
) -> GatewayDispatchFrame:
    return GatewayDispatchFrame(
        schema_version=SCHEMA_VERSION,
        command=command,
        context_generation=context_generation,
        flow_kind=ExecutionFlowKind.DIRECT,
    )


def gateway_frame_digest(frame: GatewayDispatchFrame) -> str:
    return sha256_digest(frame)


def canonical_dispatch_receipt_id(receipt: DispatchReceipt) -> str:
    values = receipt.model_dump(mode="python", exclude={"receipt_id"})
    return _prefixed_identifier("receipt", sha256_digest(values))


def canonical_gateway_response_id(result: GatewayResult) -> str:
    match result:
        case GatewayDispatchResult(receipt=receipt):
            return canonical_dispatch_receipt_id(receipt)
        case GatewayDeniedResult():
            return _prefixed_identifier("denial", sha256_digest(result))
        case unreachable:
            assert_never(unreachable)


def bind_gateway_response(
    frame: GatewayDispatchFrame,
    result: GatewayResult,
    channel_key: bytes,
) -> GatewayResponseEnvelope:
    response_id = canonical_gateway_response_id(result)
    request_digest = gateway_frame_digest(frame)
    return GatewayResponseEnvelope(
        schema_version=SCHEMA_VERSION,
        response_id=response_id,
        request_frame_digest=request_digest,
        result=result,
        response_mac=_response_mac(response_id, request_digest, result, channel_key),
    )


def gateway_response_is_authentic(
    envelope: GatewayResponseEnvelope,
    channel_key: bytes,
) -> bool:
    expected = _response_mac(
        envelope.response_id,
        envelope.request_frame_digest,
        envelope.result,
        channel_key,
    )
    return hmac.compare_digest(envelope.response_mac, expected)


def bind_gateway_cancellation(
    request: GatewayCancellationRequest,
    cancelled_action_ids: tuple[str, ...],
    channel_key: bytes,
) -> GatewayCancellationReceipt:
    request_digest = sha256_digest(request)
    return GatewayCancellationReceipt(
        schema_version=SCHEMA_VERSION,
        request_digest=request_digest,
        cancelled_action_ids=cancelled_action_ids,
        response_mac=_cancellation_mac(request_digest, cancelled_action_ids, channel_key),
    )


def gateway_cancellation_is_authentic(
    receipt: GatewayCancellationReceipt,
    channel_key: bytes,
) -> bool:
    expected = _cancellation_mac(
        receipt.request_digest,
        receipt.cancelled_action_ids,
        channel_key,
    )
    return hmac.compare_digest(receipt.response_mac, expected)


def _response_mac(
    response_id: str,
    request_frame_digest: str,
    result: GatewayResult,
    channel_key: bytes,
) -> str:
    payload = canonical_json_bytes(
        {
            "request_frame_digest": request_frame_digest,
            "response_id": response_id,
            "result": result,
        }
    )
    return f"sha256:{hmac.new(channel_key, payload, hashlib.sha256).hexdigest()}"


def _cancellation_mac(
    request_digest: str,
    cancelled_action_ids: tuple[str, ...],
    channel_key: bytes,
) -> str:
    payload = canonical_json_bytes(
        {
            "cancelled_action_ids": cancelled_action_ids,
            "request_digest": request_digest,
        }
    )
    return f"sha256:{hmac.new(channel_key, payload, hashlib.sha256).hexdigest()}"


def _prefixed_identifier(prefix: str, digest: str) -> str:
    return f"{prefix}.{digest.removeprefix('sha256:')}"
