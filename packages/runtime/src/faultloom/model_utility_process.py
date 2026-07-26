"""Bounded byte transport for one isolated local model process."""

from __future__ import annotations

import os
import selectors
import subprocess
import sys
import time
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
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


_SUPERVISOR_PACKAGE = "faultloom"
_SUPERVISOR_FILENAME = "model_utility_process_supervisor.py"
_SUPERVISOR_SOURCE = "source"
_SUPERVISOR_WHEEL = "wheel"
_SUPERVISOR_BOOTSTRAP = """import __future__,ctypes,os,pkgutil,runpy,signal,subprocess,sys,time,zipimport
from pathlib import Path
root=sys.argv.pop(1)
kind=sys.argv.pop(1)
sys.argv[0]=root+\"/faultloom/model_utility_process_supervisor.py\"
sys.path[:]=[root]
if kind == \"source\":
    runpy.run_path(sys.argv[0],run_name=\"__main__\")
elif kind == \"wheel\":
    code=zipimport.zipimporter(root+\"/faultloom\").get_code(\"model_utility_process_supervisor\")
    if code is None: raise RuntimeError(\"supervisor code is unavailable\")
    exec(code,{\"__name__\":\"__main__\",\"__file__\":sys.argv[0],\"__package__\":None})
else:
    raise RuntimeError(\"supervisor origin kind is invalid\")
"""


def _supervisor_import_root(origin: object) -> tuple[str, str]:
    if type(origin) is not str:
        raise BoundedProcessError("supervisor module origin is invalid")
    module = Path(origin)
    if not module.is_absolute() or module.name != "model_utility_process.py":
        raise BoundedProcessError("supervisor module origin is invalid")

    if module.parent.name == _SUPERVISOR_PACKAGE:
        try:
            source_module = module.resolve(strict=True)
        except OSError:
            source_module = None
        if source_module is not None:
            source_root = source_module.parents[1]
            expected = source_root / _SUPERVISOR_PACKAGE / module.name
            supervisor = source_root / _SUPERVISOR_PACKAGE / _SUPERVISOR_FILENAME
            try:
                source_supervisor = supervisor.resolve(strict=True)
            except OSError:
                source_supervisor = None
            if (
                source_module == expected
                and source_root.is_dir()
                and source_supervisor == supervisor
                and supervisor.is_file()
            ):
                return _SUPERVISOR_SOURCE, str(source_root)

    suffix = f"{os.sep}{_SUPERVISOR_PACKAGE}{os.sep}{module.name}"
    if not origin.endswith(suffix):
        raise BoundedProcessError("supervisor module origin is invalid")
    archive = Path(origin[: -len(suffix)])
    if not archive.is_absolute() or archive.suffix != ".whl":
        raise BoundedProcessError("supervisor module origin is invalid")
    try:
        archive = archive.resolve(strict=True)
        regular_archive = archive.is_file()
    except OSError:
        regular_archive = False
    if not regular_archive or not zipfile.is_zipfile(archive):
        raise BoundedProcessError("supervisor module origin is invalid")
    try:
        with zipfile.ZipFile(archive) as wheel:
            members: set[str] = {str(member) for member in wheel.namelist()}
    except OSError:
        members = set()
    package = f"{_SUPERVISOR_PACKAGE}/"
    if {
        f"{package}{module.name}",
        f"{package}{_SUPERVISOR_FILENAME}",
    } - members:
        raise BoundedProcessError("supervisor module origin is invalid")
    return _SUPERVISOR_WHEEL, str(archive)


def _supervisor_argv(launch: BoundedProcessLaunch) -> tuple[str, ...]:
    kind, root = _supervisor_import_root(__file__)
    descriptors = ",".join(str(value) for value in launch.pass_fds)
    return (
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-c",
        _SUPERVISOR_BOOTSTRAP,
        root,
        kind,
        "--pass-fds",
        descriptors,
        "--",
        *launch.argv,
    )


def _finish_supervisor(process: subprocess.Popen[bytes]) -> bool:
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            return False
        try:
            _ = process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                _ = process.wait(timeout=1.0)
            except (OSError, subprocess.TimeoutExpired):
                return False
            return False
    return process.returncode is not None and process.returncode >= 0 and process.returncode != 125


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
        _supervisor_argv(launch),
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
        cleanup_ok = _finish_supervisor(process)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()
        if not cleanup_ok:
            raise BoundedProcessError("child process cleanup failed")


__all__ = [
    "BoundedProcessError",
    "BoundedProcessLaunch",
    "BoundedProcessResult",
    "run_bounded_process",
]
