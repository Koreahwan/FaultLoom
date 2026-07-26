"""Bounded byte transport for one isolated local model process."""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import IO, Literal


class BoundedProcessError(RuntimeError):
    """A child exceeded its configured local byte boundary."""


@dataclass(frozen=True, slots=True)
class BoundedProcessLaunch:
    """Exact process launch inputs with finite stdio and time limits."""

    argv: tuple[str, ...]
    stdin: bytes
    environment: Mapping[str, str]
    pass_fds: tuple[int, ...]
    timeout_seconds: int
    maximum_stdout_bytes: int
    maximum_stderr_bytes: int
    shell: Literal[False] = False


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes


def _close_stream(
    selector: selectors.BaseSelector,
    descriptor: int,
    stream: IO[bytes],
) -> None:
    if descriptor in selector.get_map():
        _ = selector.unregister(descriptor)
    stream.close()


def _exchange_bytes(
    process: subprocess.Popen[bytes],
    launch: BoundedProcessLaunch,
    deadline: float,
) -> bytes:
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise BoundedProcessError("bounded process pipes are unavailable")
    selector = selectors.DefaultSelector()
    stdin_fd = process.stdin.fileno()
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    streams: dict[int, IO[bytes]] = {
        stdin_fd: process.stdin,
        stdout_fd: process.stdout,
        stderr_fd: process.stderr,
    }
    _ = selector.register(process.stdin, selectors.EVENT_WRITE)
    _ = selector.register(process.stdout, selectors.EVENT_READ)
    _ = selector.register(process.stderr, selectors.EVENT_READ)
    pending = memoryview(launch.stdin)
    offset = 0
    stdout = bytearray()
    stderr_bytes = 0
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(launch.argv, launch.timeout_seconds)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(launch.argv, launch.timeout_seconds)
            for key, _mask in events:
                stream = streams[key.fd]
                if key.fd == stdin_fd:
                    try:
                        written = os.write(key.fd, pending[offset : offset + 65_536])
                    except BrokenPipeError:
                        _close_stream(selector, key.fd, stream)
                        continue
                    offset += written
                    if offset == len(pending):
                        _close_stream(selector, key.fd, stream)
                    continue
                chunk = os.read(key.fd, 65_536)
                if not chunk:
                    _close_stream(selector, key.fd, stream)
                    continue
                if key.fd == stdout_fd:
                    stdout.extend(chunk)
                    if len(stdout) > launch.maximum_stdout_bytes:
                        raise BoundedProcessError("child stdout exceeds its byte limit")
                else:
                    stderr_bytes += len(chunk)
                    if stderr_bytes > launch.maximum_stderr_bytes:
                        raise BoundedProcessError("child stderr exceeds its byte limit")
    finally:
        selector.close()
    return bytes(stdout)


def run_bounded_process(launch: BoundedProcessLaunch) -> BoundedProcessResult:
    process = subprocess.Popen(
        launch.argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd="/",
        env=launch.environment,
        close_fds=True,
        pass_fds=launch.pass_fds,
        start_new_session=True,
        shell=launch.shell,
    )
    deadline = time.monotonic() + launch.timeout_seconds
    try:
        stdout = _exchange_bytes(process, launch, deadline)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(launch.argv, launch.timeout_seconds)
        returncode = process.wait(timeout=remaining)
        return BoundedProcessResult(returncode=returncode, stdout=stdout)
    finally:
        if process.poll() is None:
            process.kill()
        _ = process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


__all__ = [
    "BoundedProcessError",
    "BoundedProcessLaunch",
    "BoundedProcessResult",
    "run_bounded_process",
]
