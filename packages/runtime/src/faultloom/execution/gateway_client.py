from __future__ import annotations

import hashlib
import hmac
import secrets
from enum import Enum
from threading import Lock
from types import TracebackType
from typing import Self, assert_never

from pydantic import PositiveInt, model_validator

from faultloom_protocol import SCHEMA_VERSION, canonical_json_bytes
from faultloom_protocol.base import Identifier, Sha256Digest

from .contracts import ExecutionModel
from .gateway import (
    GatewayCancellationReceipt,
    GatewayCancellationRequest,
    GatewayDispatchFrame,
    GatewayResponseEnvelope,
)
from .gateway_pipe import GatewayPipeChannel, GatewayPipeChannels
from .http_validation import ExecutionContractError, GatewayChannelError


class GatewayRpcOperation(str, Enum):
    DISPATCH = "dispatch"
    CANCEL_CONTEXT = "cancel_context"
    RECONCILE = "reconcile"


class GatewayRpcPayload(ExecutionModel):
    operation: GatewayRpcOperation
    sequence: PositiveInt
    nonce: Identifier
    dispatch_frame: GatewayDispatchFrame | None = None
    cancellation_request: GatewayCancellationRequest | None = None

    @model_validator(mode="after")
    def _exact_payload(self) -> Self:
        match self.operation:
            case GatewayRpcOperation.DISPATCH | GatewayRpcOperation.RECONCILE:
                if self.dispatch_frame is None or self.cancellation_request is not None:
                    raise ValueError("dispatch RPC requires exactly one dispatch frame")
            case GatewayRpcOperation.CANCEL_CONTEXT:
                if self.dispatch_frame is not None or self.cancellation_request is None:
                    raise ValueError("cancellation RPC requires exactly one cancellation request")
            case unreachable:
                assert_never(unreachable)
        return self


class GatewayRpcRequest(GatewayRpcPayload):
    request_id: Identifier
    request_mac: Sha256Digest

    @model_validator(mode="after")
    def _canonical_request_id(self) -> Self:
        if self.request_id != canonical_gateway_rpc_request_id(self):
            raise ValueError("Gateway RPC request ID is not canonical")
        return self


class GatewayRpcResponse(ExecutionModel):
    operation: GatewayRpcOperation
    request_id: Identifier
    gateway_response: GatewayResponseEnvelope | None = None
    cancellation_receipt: GatewayCancellationReceipt | None = None

    @model_validator(mode="after")
    def _exact_payload(self) -> Self:
        match self.operation:
            case GatewayRpcOperation.DISPATCH:
                if self.gateway_response is None or self.cancellation_receipt is not None:
                    raise ValueError("dispatch RPC requires one Gateway response")
            case GatewayRpcOperation.RECONCILE:
                if self.cancellation_receipt is not None:
                    raise ValueError("reconciliation RPC cannot carry cancellation data")
            case GatewayRpcOperation.CANCEL_CONTEXT:
                if self.gateway_response is not None or self.cancellation_receipt is None:
                    raise ValueError("cancellation RPC requires one cancellation receipt")
            case unreachable:
                assert_never(unreachable)
        return self


class AuthenticatedGatewayClient:
    def __init__(self, channels: GatewayPipeChannels, channel_key: bytes) -> None:
        if len(channel_key) < 32:
            raise ExecutionContractError("Gateway channel key must contain at least 256 bits")
        descriptors = (
            channels.dispatch.read_fd,
            channels.dispatch.write_fd,
            channels.control.read_fd,
            channels.control.write_fd,
        )
        if len(set(descriptors)) != len(descriptors):
            raise ExecutionContractError("Gateway dispatch and control pipes must be disjoint")
        dispatch_channel = GatewayPipeChannel(channels.dispatch)
        try:
            control_channel = GatewayPipeChannel(channels.control)
        except (OSError, ExecutionContractError):
            dispatch_channel.close()
            raise
        self._dispatch_channel = dispatch_channel
        self._control_channel = control_channel
        self._channel_key = bytes(channel_key)
        self._dispatch_lock = Lock()
        self._control_lock = Lock()
        self._dispatch_sequence = 0
        self._control_sequence = 0

    @property
    def channel_key(self) -> bytes:
        return self._channel_key

    def dispatch(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope:
        response = self._exchange_dispatch(GatewayRpcOperation.DISPATCH, frame)
        if response.gateway_response is None:
            raise GatewayChannelError("Gateway dispatch response is absent")
        return response.gateway_response

    def cancel_context(
        self,
        request: GatewayCancellationRequest,
    ) -> GatewayCancellationReceipt:
        response = self._exchange_control(request)
        if response.cancellation_receipt is None:
            raise GatewayChannelError("Gateway cancellation receipt is absent")
        return response.cancellation_receipt

    def reconcile(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope | None:
        response = self._exchange_dispatch(GatewayRpcOperation.RECONCILE, frame)
        return response.gateway_response

    def close(self) -> None:
        self._control_channel.close()
        self._dispatch_channel.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _exchange_dispatch(
        self,
        operation: GatewayRpcOperation,
        frame: GatewayDispatchFrame,
    ) -> GatewayRpcResponse:
        with self._dispatch_lock:
            self._dispatch_sequence += 1
            payload = GatewayRpcPayload(
                schema_version=SCHEMA_VERSION,
                operation=operation,
                sequence=self._dispatch_sequence,
                nonce=_rpc_nonce(),
                dispatch_frame=frame,
            )
            request = bind_gateway_rpc_request(payload, self._channel_key)
            return self._exchange(self._dispatch_channel, request)

    def _exchange_control(
        self,
        cancellation: GatewayCancellationRequest,
    ) -> GatewayRpcResponse:
        with self._control_lock:
            self._control_sequence += 1
            payload = GatewayRpcPayload(
                schema_version=SCHEMA_VERSION,
                operation=GatewayRpcOperation.CANCEL_CONTEXT,
                sequence=self._control_sequence,
                nonce=_rpc_nonce(),
                cancellation_request=cancellation,
            )
            request = bind_gateway_rpc_request(payload, self._channel_key)
            return self._exchange(self._control_channel, request)

    @staticmethod
    def _exchange(
        channel: GatewayPipeChannel,
        request: GatewayRpcRequest,
    ) -> GatewayRpcResponse:
        response_payload = channel.exchange(canonical_json_bytes(request))
        try:
            response = GatewayRpcResponse.model_validate_json(response_payload)
        except ValueError as exc:
            raise GatewayChannelError("Gateway RPC response is invalid") from exc
        if response.operation is not request.operation:
            raise GatewayChannelError("Gateway RPC response operation mismatch")
        if response.request_id != request.request_id:
            raise GatewayChannelError("Gateway RPC response request binding mismatch")
        return response


def bind_gateway_rpc_request(
    payload: GatewayRpcPayload,
    channel_key: bytes,
) -> GatewayRpcRequest:
    request_id = canonical_gateway_rpc_request_id(payload)
    return GatewayRpcRequest(
        schema_version=payload.schema_version,
        operation=payload.operation,
        sequence=payload.sequence,
        nonce=payload.nonce,
        dispatch_frame=payload.dispatch_frame,
        cancellation_request=payload.cancellation_request,
        request_id=request_id,
        request_mac=_gateway_rpc_request_mac(request_id, payload, channel_key),
    )


def gateway_rpc_request_is_authentic(
    request: GatewayRpcRequest,
    channel_key: bytes,
) -> bool:
    expected = _gateway_rpc_request_mac(request.request_id, request, channel_key)
    return hmac.compare_digest(request.request_mac, expected)


def canonical_gateway_rpc_request_id(payload: GatewayRpcPayload) -> str:
    values = payload.model_dump(
        mode="python",
        exclude={"request_id", "request_mac"},
    )
    digest = hashlib.sha256(canonical_json_bytes(values)).hexdigest()
    return f"rpc_request.{digest}"


def _gateway_rpc_request_mac(
    request_id: str,
    payload: GatewayRpcPayload,
    channel_key: bytes,
) -> str:
    values = payload.model_dump(
        mode="python",
        exclude={"request_id", "request_mac"},
    )
    message = canonical_json_bytes({"payload": values, "request_id": request_id})
    return f"sha256:{hmac.new(channel_key, message, hashlib.sha256).hexdigest()}"


def _rpc_nonce() -> str:
    return f"rpc_nonce.{secrets.token_hex(32)}"
