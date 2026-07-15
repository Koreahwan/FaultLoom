from __future__ import annotations

import multiprocessing
import os
from dataclasses import dataclass
from multiprocessing.process import BaseProcess
from types import TracebackType
from typing import Self

from faultloom.execution import (
    AuthenticatedGatewayClient,
    ExecutionContractError,
    GatewayPipeChannels,
    GatewayPipeFds,
)

from .pipe_gateway_server import EventLike, GatewayProcessConfig, gateway_process
from .pipe_gateway_wire import close_fds, pipe_fds


@dataclass(frozen=True, slots=True)
class _PipeEndpoints:
    runtime: GatewayPipeFds
    gateway: GatewayPipeFds


@dataclass(slots=True)
class LoopbackGatewayHarness:
    client: AuthenticatedGatewayClient
    process: BaseProcess
    dispatch_ready: EventLike
    dispatch_release: EventLike
    cancellation_ready: EventLike

    def close(self) -> None:
        self.client.close()
        self.process.join(timeout=5)
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=5)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def start_loopback_gateway(
    channel_key: bytes,
    *,
    scope_epoch: int = 7,
) -> LoopbackGatewayHarness:
    dispatch = _new_pipe_endpoints()
    control = _new_pipe_endpoints()
    context = multiprocessing.get_context("fork")
    dispatch_ready = context.Event()
    dispatch_release = context.Event()
    cancellation_ready = context.Event()
    runtime_fds = pipe_fds(dispatch.runtime) + pipe_fds(control.runtime)
    gateway_channels = GatewayPipeChannels(
        dispatch=dispatch.gateway,
        control=control.gateway,
    )
    config = GatewayProcessConfig(
        channels=gateway_channels,
        runtime_fds=runtime_fds,
        channel_key=channel_key,
        scope_epoch=scope_epoch,
        dispatch_ready=dispatch_ready,
        dispatch_release=dispatch_release,
        cancellation_ready=cancellation_ready,
    )
    process = context.Process(target=gateway_process, args=(config,), daemon=True)
    process.start()
    close_fds(pipe_fds(dispatch.gateway) + pipe_fds(control.gateway))
    try:
        client = AuthenticatedGatewayClient(
            GatewayPipeChannels(dispatch=dispatch.runtime, control=control.runtime),
            channel_key,
        )
    except (OSError, ExecutionContractError):
        process.terminate()
        process.join(timeout=5)
        raise
    finally:
        close_fds(runtime_fds)
    return LoopbackGatewayHarness(
        client=client,
        process=process,
        dispatch_ready=dispatch_ready,
        dispatch_release=dispatch_release,
        cancellation_ready=cancellation_ready,
    )


def _new_pipe_endpoints() -> _PipeEndpoints:
    request_read, request_write = os.pipe()
    response_read, response_write = os.pipe()
    return _PipeEndpoints(
        runtime=GatewayPipeFds(read_fd=response_read, write_fd=request_write),
        gateway=GatewayPipeFds(read_fd=request_read, write_fd=response_write),
    )
