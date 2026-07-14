from __future__ import annotations

import fcntl
import os
import stat
from dataclasses import dataclass
from threading import Lock

from .http_validation import ExecutionContractError, GatewayChannelError

MAX_RPC_FRAME_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class GatewayPipeFds:
    read_fd: int
    write_fd: int


@dataclass(frozen=True, slots=True)
class GatewayPipeChannels:
    dispatch: GatewayPipeFds
    control: GatewayPipeFds


class GatewayPipeChannel:
    def __init__(self, pipes: GatewayPipeFds) -> None:
        _validate_pipe_fd(pipes.read_fd, os.O_RDONLY)
        _validate_pipe_fd(pipes.write_fd, os.O_WRONLY)
        if pipes.read_fd == pipes.write_fd:
            raise ExecutionContractError("Gateway RPC requires distinct pipe descriptors")
        read_fd = os.dup(pipes.read_fd)
        try:
            write_fd = os.dup(pipes.write_fd)
        except OSError:
            os.close(read_fd)
            raise
        self._read_fd = read_fd
        self._write_fd = write_fd
        self._closed = False
        self._lock = Lock()

    def exchange(self, payload: bytes) -> bytes:
        if len(payload) > MAX_RPC_FRAME_BYTES:
            raise GatewayChannelError("Gateway request frame exceeds the RPC limit")
        with self._lock:
            if self._closed:
                raise GatewayChannelError("Gateway RPC client is closed")
            try:
                _write_all(self._write_fd, len(payload).to_bytes(4, "big") + payload)
                response_length = int.from_bytes(_read_exact(self._read_fd, 4), "big")
                if response_length > MAX_RPC_FRAME_BYTES:
                    raise GatewayChannelError("Gateway response frame exceeds the RPC limit")
                return _read_exact(self._read_fd, response_length)
            except GatewayChannelError:
                raise
            except OSError as exc:
                raise GatewayChannelError("Gateway RPC exchange failed") from exc

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            os.close(self._read_fd)
            os.close(self._write_fd)


def _validate_pipe_fd(fd: int, expected_mode: int) -> None:
    try:
        descriptor_mode = os.fstat(fd).st_mode
        access_mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        descriptor_name = os.readlink(f"/proc/self/fd/{fd}")
    except OSError as exc:
        raise ExecutionContractError("Gateway pipe descriptor is invalid") from exc
    if (
        not stat.S_ISFIFO(descriptor_mode)
        or access_mode != expected_mode
        or not descriptor_name.startswith("pipe:[")
    ):
        raise ExecutionContractError("Gateway RPC accepts only directional anonymous pipes")


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written == 0:
            raise GatewayChannelError("Gateway RPC pipe closed during write")
        offset += written


def _read_exact(fd: int, length: int) -> bytes:
    payload = bytearray()
    while len(payload) < length:
        chunk = os.read(fd, length - len(payload))
        if not chunk:
            raise GatewayChannelError("Gateway RPC pipe closed during read")
        payload.extend(chunk)
    return bytes(payload)
