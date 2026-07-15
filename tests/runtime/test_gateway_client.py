from __future__ import annotations

import hashlib
import socket
from queue import Queue
from threading import Thread
from typing import Never

import faultloom_protocol.models as m
import pytest

from faultloom.execution import (
    AuthenticatedGatewayClient,
    BrowserExecutionCoordinator,
    EndpointScheme,
    ExecutionContractError,
    GatewayCancellationReceipt,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayPipeChannels,
    GatewayPipeFds,
    GatewayResult,
    SemanticEndpoint,
    SemanticHttpExecutor,
    SemanticHttpRequest,
    gateway_dispatch_frame,
)
from faultloom.execution.gateway_client import (
    GatewayRpcOperation,
    GatewayRpcPayload,
    bind_gateway_rpc_request,
    gateway_rpc_request_is_authentic,
)
from faultloom_protocol import SCHEMA_VERSION

from .browser_execution_helpers import browser_context
from .execution_helpers import CHANNEL_KEY, NOW, command
from .loopback_target_fixture import LOOPBACK_BODY, start_loopback_target
from .pipe_gateway_fixture import start_loopback_gateway


def test_gateway_client_rejects_socket_descriptors() -> None:
    dispatch_read, dispatch_write = socket.socketpair()
    control_read, control_write = socket.socketpair()
    with dispatch_read, dispatch_write, control_read, control_write:
        channels = GatewayPipeChannels(
            dispatch=GatewayPipeFds(
                read_fd=dispatch_read.fileno(),
                write_fd=dispatch_write.fileno(),
            ),
            control=GatewayPipeFds(
                read_fd=control_read.fileno(),
                write_fd=control_write.fileno(),
            ),
        )
        with pytest.raises(ExecutionContractError, match="anonymous pipes"):
            AuthenticatedGatewayClient(channels, CHANNEL_KEY)


def test_gateway_rpc_request_authentication_detects_mutation() -> None:
    frame = gateway_dispatch_frame(command())
    payload = GatewayRpcPayload(
        schema_version=SCHEMA_VERSION,
        operation=GatewayRpcOperation.DISPATCH,
        sequence=1,
        nonce="rpc_nonce.fixture",
        dispatch_frame=frame,
    )
    request = bind_gateway_rpc_request(payload, CHANNEL_KEY)
    mutated = request.model_copy(update={"sequence": 2})

    assert gateway_rpc_request_is_authentic(request, CHANNEL_KEY)
    assert not gateway_rpc_request_is_authentic(mutated, CHANNEL_KEY)
    assert not gateway_rpc_request_is_authentic(request, bytes.fromhex("cd" * 32))
    with pytest.raises(ValueError, match="request ID is not canonical"):
        type(request).model_validate(mutated.model_dump(mode="python"))


def test_separate_gateway_is_the_only_loopback_target_egress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    direct_socket_calls = 0
    with start_loopback_target() as target, start_loopback_gateway(CHANNEL_KEY) as gateway:
        approved = command(request=_loopback_request(target.port, "/canary"))
        executor = SemanticHttpExecutor(gateway.client, now=lambda: NOW)

        def forbidden_socket(*args: int, **kwargs: int) -> Never:
            nonlocal direct_socket_calls
            direct_socket_calls += 1
            raise AssertionError("runtime process attempted direct target egress")

        monkeypatch.setattr(socket, "socket", forbidden_socket)
        result = executor.execute(approved)

        assert isinstance(result, GatewayDispatchResult)
        assert result.receipt.response_status == 200
        assert result.receipt.response_digest == _byte_digest(LOOPBACK_BODY)
        assert result.receipt.bytes_received == len(LOOPBACK_BODY)
        assert target.read_path() == "/canary"
        assert direct_socket_calls == 0

    assert gateway.process.exitcode == 0


def test_gateway_rechecks_current_scope_epoch_before_target_egress() -> None:
    with start_loopback_target() as target, start_loopback_gateway(CHANNEL_KEY) as gateway:
        approved = command(request=_loopback_request(target.port, "/stale"))
        stale = _with_scope_epoch(approved, 6)
        executor = SemanticHttpExecutor(gateway.client, now=lambda: NOW)

        result = executor.execute(stale)

        assert isinstance(result, GatewayDeniedResult)
        assert result.reason_code == "scope.revoked"
        assert target.read_path(timeout=0.2) is None

    assert gateway.process.exitcode == 0


def test_control_pipe_cancels_paused_navigation_before_target_egress() -> None:
    with start_loopback_target() as target, start_loopback_gateway(CHANNEL_KEY) as gateway:
        context = browser_context()
        approved = command(
            request=_loopback_request(target.port, "/pause"),
            identity=context.identity,
        )
        browser = BrowserExecutionCoordinator(
            SemanticHttpExecutor(gateway.client, now=lambda: NOW)
        )
        browser.register_context(context)
        navigation: Queue[GatewayResult | Exception] = Queue()
        cancellation: Queue[GatewayCancellationReceipt | Exception] = Queue()

        def navigate() -> None:
            try:
                navigation.put(browser.navigate(context.browser_context_id, approved))
            except Exception as exc:
                navigation.put(exc)

        def close() -> None:
            try:
                cancellation.put(browser.close_context(context.browser_context_id))
            except Exception as exc:
                cancellation.put(exc)

        navigation_worker = Thread(target=navigate)
        navigation_worker.start()
        assert gateway.dispatch_ready.wait(timeout=5)
        cancellation_worker = Thread(target=close)
        cancellation_worker.start()
        assert gateway.cancellation_ready.wait(timeout=5)
        gateway.dispatch_release.set()
        navigation_worker.join(timeout=5)
        cancellation_worker.join(timeout=5)

        assert not navigation_worker.is_alive()
        assert not cancellation_worker.is_alive()
        navigation_result = navigation.get_nowait()
        cancellation_result = cancellation.get_nowait()
        assert isinstance(navigation_result, GatewayDeniedResult)
        if isinstance(cancellation_result, Exception):
            raise cancellation_result
        assert cancellation_result.cancelled_action_ids == (approved.intent.action_id,)
        assert target.read_path(timeout=0.2) is None

    assert gateway.process.exitcode == 0


def _loopback_request(port: int, path: str) -> SemanticHttpRequest:
    return SemanticHttpRequest(
        schema_version=SCHEMA_VERSION,
        endpoint=SemanticEndpoint(
            schema_version=SCHEMA_VERSION,
            scheme=EndpointScheme.HTTP,
            hostname="127.0.0.1",
            port=port,
            path=path,
        ),
        method="GET",
    )


def _with_scope_epoch(
    approved: GatewayDispatchCommand,
    scope_epoch: int,
) -> GatewayDispatchCommand:
    lease_values = approved.lease.model_dump(mode="python")
    lease_values["scope_epoch"] = scope_epoch
    decision_values = approved.decision.model_dump(mode="python")
    decision_values["scope_epoch"] = scope_epoch
    command_values = approved.model_dump(mode="python")
    command_values["lease"] = m.ActionLease.model_validate(lease_values)
    command_values["decision"] = m.PolicyDecision.model_validate(decision_values)
    return GatewayDispatchCommand.model_validate(command_values)


def _byte_digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
