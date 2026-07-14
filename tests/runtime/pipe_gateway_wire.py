from __future__ import annotations

import os

from faultloom.execution import GatewayDispatchFrame, GatewayPipeFds
from faultloom.execution.gateway_client import GatewayRpcRequest, GatewayRpcResponse
from faultloom_protocol import canonical_json_bytes


def required_frame(request: GatewayRpcRequest) -> GatewayDispatchFrame:
    if request.dispatch_frame is None:
        raise RuntimeError("typed dispatch frame is absent")
    return request.dispatch_frame


def read_request(fd: int) -> GatewayRpcRequest | None:
    header = _read_exact(fd, 4, allow_eof=True)
    if header is None:
        return None
    length = int.from_bytes(header, "big")
    payload = _read_exact(fd, length, allow_eof=False)
    if payload is None:
        raise RuntimeError("Gateway request body is absent")
    return GatewayRpcRequest.model_validate_json(payload)


def write_response(fd: int, response: GatewayRpcResponse) -> None:
    payload = canonical_json_bytes(response)
    _write_all(fd, len(payload).to_bytes(4, "big") + payload)


def pipe_fds(pipes: GatewayPipeFds) -> tuple[int, int]:
    return pipes.read_fd, pipes.write_fd


def close_fds(fds: tuple[int, ...]) -> None:
    for fd in fds:
        os.close(fd)


def _read_exact(fd: int, length: int, *, allow_eof: bool) -> bytes | None:
    payload = bytearray()
    while len(payload) < length:
        chunk = os.read(fd, length - len(payload))
        if not chunk:
            if allow_eof and not payload:
                return None
            raise RuntimeError("Gateway fixture pipe closed mid-frame")
        payload.extend(chunk)
    return bytes(payload)


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        offset += os.write(fd, payload[offset:])
