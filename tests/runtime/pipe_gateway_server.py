from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, Thread
from typing import Protocol, assert_never

from faultloom.execution import (
    GatewayDeniedResult,
    GatewayDispatchFrame,
    GatewayPipeChannels,
    GatewayPipeFds,
    bind_gateway_cancellation,
    bind_gateway_response,
    gateway_frame_digest,
)
from faultloom.execution.gateway import GatewayResponseEnvelope
from faultloom.execution.gateway_client import (
    GatewayRpcOperation,
    GatewayRpcRequest,
    GatewayRpcResponse,
    gateway_rpc_request_is_authentic,
)
from faultloom_protocol import SCHEMA_VERSION

from .loopback_gateway_http import perform_http
from .pipe_gateway_wire import (
    close_fds,
    pipe_fds,
    read_request,
    required_frame,
    write_response,
)


class EventLike(Protocol):
    def set(self) -> None: ...

    def wait(self, timeout: float | None = None) -> bool: ...


@dataclass(frozen=True, slots=True)
class GatewayProcessConfig:
    channels: GatewayPipeChannels
    runtime_fds: tuple[int, ...]
    channel_key: bytes
    scope_epoch: int
    dispatch_ready: EventLike
    dispatch_release: EventLike
    cancellation_ready: EventLike


@dataclass(slots=True)
class _GatewayState:
    config: GatewayProcessConfig
    lock: Lock = field(default_factory=Lock)
    cancelled: set[tuple[str, int]] = field(default_factory=set)
    active: dict[str, tuple[str, int]] = field(default_factory=dict)
    reconciled: dict[str, GatewayResponseEnvelope] = field(default_factory=dict)
    request_nonces: set[str] = field(default_factory=set)

    def admit_request(self, request: GatewayRpcRequest, expected_sequence: int) -> None:
        if request.sequence != expected_sequence:
            raise RuntimeError("Gateway RPC sequence is not contiguous")
        if not gateway_rpc_request_is_authentic(request, self.config.channel_key):
            raise RuntimeError("Gateway RPC request authentication failed")
        with self.lock:
            if request.nonce in self.request_nonces:
                raise RuntimeError("Gateway RPC nonce was replayed")
            self.request_nonces.add(request.nonce)

    def begin(self, frame: GatewayDispatchFrame) -> None:
        owner = (frame.command.identity.context_id, frame.context_generation)
        with self.lock:
            self.active[frame.command.intent.action_id] = owner

    def finish(self, action_id: str) -> None:
        with self.lock:
            self.active.pop(action_id, None)

    def cancel(self, context_id: str, generation: int) -> tuple[str, ...]:
        owner = (context_id, generation)
        with self.lock:
            self.cancelled.add(owner)
            return tuple(
                sorted(
                    action
                    for action, active_owner in self.active.items()
                    if active_owner == owner
                )
            )

    def is_cancelled(self, frame: GatewayDispatchFrame) -> bool:
        owner = (frame.command.identity.context_id, frame.context_generation)
        with self.lock:
            return owner in self.cancelled

    def record(self, action_id: str, envelope: GatewayResponseEnvelope) -> None:
        with self.lock:
            self.reconciled[action_id] = envelope

    def reconcile(self, action_id: str) -> GatewayResponseEnvelope | None:
        with self.lock:
            return self.reconciled.get(action_id)


def gateway_process(config: GatewayProcessConfig) -> None:
    close_fds(config.runtime_fds)
    state = _GatewayState(config=config)
    workers = (
        Thread(target=_serve_dispatch, args=(config.channels.dispatch, state)),
        Thread(target=_serve_control, args=(config.channels.control, state)),
    )
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    close_fds(pipe_fds(config.channels.dispatch) + pipe_fds(config.channels.control))


def _serve_dispatch(channel: GatewayPipeFds, state: _GatewayState) -> None:
    expected_sequence = 1
    while (request := read_request(channel.read_fd)) is not None:
        state.admit_request(request, expected_sequence)
        expected_sequence += 1
        match request.operation:
            case GatewayRpcOperation.DISPATCH:
                response = _dispatch(request, state)
            case GatewayRpcOperation.RECONCILE:
                frame = required_frame(request)
                response = GatewayRpcResponse(
                    schema_version=SCHEMA_VERSION,
                    operation=GatewayRpcOperation.RECONCILE,
                    request_id=request.request_id,
                    gateway_response=state.reconcile(frame.command.intent.action_id),
                )
            case GatewayRpcOperation.CANCEL_CONTEXT:
                raise RuntimeError("cancellation request crossed onto the dispatch channel")
            case unreachable:
                assert_never(unreachable)
        write_response(channel.write_fd, response)


def _serve_control(channel: GatewayPipeFds, state: _GatewayState) -> None:
    expected_sequence = 1
    while (request := read_request(channel.read_fd)) is not None:
        state.admit_request(request, expected_sequence)
        expected_sequence += 1
        match request.operation:
            case GatewayRpcOperation.CANCEL_CONTEXT:
                cancellation = request.cancellation_request
            case GatewayRpcOperation.DISPATCH | GatewayRpcOperation.RECONCILE:
                raise RuntimeError("non-cancellation request crossed onto the control channel")
            case unreachable:
                assert_never(unreachable)
        if cancellation is None:
            raise RuntimeError("typed cancellation request is absent")
        action_ids = state.cancel(cancellation.context_id, cancellation.context_generation)
        receipt = bind_gateway_cancellation(cancellation, action_ids, state.config.channel_key)
        state.config.cancellation_ready.set()
        write_response(
            channel.write_fd,
            GatewayRpcResponse(
                schema_version=SCHEMA_VERSION,
                operation=GatewayRpcOperation.CANCEL_CONTEXT,
                request_id=request.request_id,
                cancellation_receipt=receipt,
            ),
        )


def _dispatch(request: GatewayRpcRequest, state: _GatewayState) -> GatewayRpcResponse:
    frame = required_frame(request)
    state.begin(frame)
    try:
        if frame.command.request.endpoint.path == "/pause":
            state.config.dispatch_ready.set()
            if not state.config.dispatch_release.wait(timeout=5):
                raise RuntimeError("loopback Gateway dispatch barrier timed out")
        if state.is_cancelled(frame) or frame.command.lease.scope_epoch != state.config.scope_epoch:
            result = GatewayDeniedResult(
                schema_version=SCHEMA_VERSION,
                action_id=frame.command.intent.action_id,
                request_digest=gateway_frame_digest(frame),
                reason_code="scope.revoked",
            )
        else:
            result = perform_http(frame)
        envelope = bind_gateway_response(frame, result, state.config.channel_key)
        state.record(frame.command.intent.action_id, envelope)
        return GatewayRpcResponse(
            schema_version=SCHEMA_VERSION,
            operation=GatewayRpcOperation.DISPATCH,
            request_id=request.request_id,
            gateway_response=envelope,
        )
    finally:
        state.finish(frame.command.intent.action_id)
