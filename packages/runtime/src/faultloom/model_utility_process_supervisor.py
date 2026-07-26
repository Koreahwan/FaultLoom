#!/usr/bin/python3
"""Short-lived Linux subreaper for one model-utility target process."""

from __future__ import annotations

import ctypes
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

_PR_SET_CHILD_SUBREAPER = 36
_MAX_PROCESSES = 4096
_CLEANUP_FAILURE = 125
_stop_requested = False


class SupervisorError(RuntimeError):
    """The supervisor could not prove complete descendant cleanup."""


def _set_subreaper() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    prctl.restype = ctypes.c_int
    if prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise SupervisorError("subreaper unavailable")


def _process_record(pid: int) -> tuple[int, int] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SupervisorError("process identity unavailable") from error
    end = raw.rfind(")")
    fields = raw[end + 2 :].split() if end >= 0 else []
    if len(fields) < 20:
        raise SupervisorError("process identity invalid")
    try:
        return int(fields[1]), int(fields[19])
    except ValueError as error:
        raise SupervisorError("process identity invalid") from error


def _descendants() -> dict[int, int]:
    try:
        pids = [int(entry.name) for entry in Path("/proc").iterdir() if entry.name.isdigit()]
    except OSError as error:
        raise SupervisorError("process inventory unavailable") from error
    if len(pids) > _MAX_PROCESSES:
        raise SupervisorError("process inventory exceeds its limit")
    records: dict[int, tuple[int, int]] = {}
    for pid in pids:
        record = _process_record(pid)
        if record is not None:
            records[pid] = record
    parents = {os.getpid()}
    descendants: dict[int, int] = {}
    while True:
        found = {
            pid: start_time
            for pid, (parent, start_time) in records.items()
            if parent in parents and pid not in descendants
        }
        if not found:
            return descendants
        descendants.update(found)
        parents = set(found)


def _signal_identity(pid: int, start_time: int, sent_signal: int) -> bool:
    current = _process_record(pid)
    if current is None or current[1] != start_time:
        return True
    try:
        os.kill(pid, sent_signal)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return True


def _reap_exited() -> tuple[bool, bool]:
    """Return (operation_succeeded, no_children_remain)."""
    while True:
        try:
            waited, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True, True
        except OSError:
            return False, False
        if waited == 0:
            return True, False


def _cleanup_descendants() -> bool:
    for sent_signal, duration in ((signal.SIGTERM, 0.2), (signal.SIGKILL, 1.5)):
        deadline = time.monotonic() + duration
        while True:
            try:
                descendants = _descendants()
                signaled = all(
                    _signal_identity(pid, start_time, sent_signal)
                    for pid, start_time in descendants.items()
                )
            except SupervisorError:
                return False
            if descendants and not signaled:
                return False
            reaped, no_children = _reap_exited()
            if not reaped:
                return False
            if not descendants and no_children:
                return True
            if time.monotonic() >= deadline:
                break
            time.sleep(0.01)
    try:
        descendants = _descendants()
    except SupervisorError:
        return False
    reaped, no_children = _reap_exited()
    return not descendants and reaped and no_children


def _request_stop(_signal_number: int, _frame: object) -> None:
    global _stop_requested
    _stop_requested = True


def _parse_arguments() -> tuple[tuple[int, ...], tuple[str, ...]]:
    if len(sys.argv) < 4 or sys.argv[1] != "--pass-fds" or "--" not in sys.argv[3:]:
        raise SupervisorError("supervisor arguments invalid")
    separator = sys.argv.index("--", 3)
    if separator != 3 or not sys.argv[separator + 1 :]:
        raise SupervisorError("supervisor arguments invalid")
    try:
        descriptors = tuple(int(value) for value in sys.argv[2].split(",") if value)
    except ValueError as error:
        raise SupervisorError("supervisor descriptors invalid") from error
    if any(value < 3 for value in descriptors) or len(set(descriptors)) != len(descriptors):
        raise SupervisorError("supervisor descriptors invalid")
    try:
        for descriptor in descriptors:
            _ = os.fstat(descriptor)
    except OSError as error:
        raise SupervisorError("supervisor descriptor unavailable") from error
    return descriptors, tuple(sys.argv[separator + 1 :])


def _normalized_returncode(returncode: int) -> int:
    if returncode < 0:
        return min(255, 128 - returncode)
    return returncode if returncode != _CLEANUP_FAILURE else 126


def main() -> int:
    try:
        descriptors, target_argv = _parse_arguments()
        _set_subreaper()
        signal.signal(signal.SIGTERM, _request_stop)
        signal.signal(signal.SIGINT, _request_stop)
        target = subprocess.Popen(
            target_argv,
            stdin=0,
            stdout=1,
            stderr=2,
            cwd="/",
            env=dict(os.environ),
            close_fds=True,
            pass_fds=descriptors,
            start_new_session=True,
        )
        returncode: int | None = None
        while not _stop_requested:
            returncode = target.poll()
            if returncode is not None:
                break
            time.sleep(0.01)
        if not _cleanup_descendants():
            return _CLEANUP_FAILURE
        if _stop_requested:
            return 128 + signal.SIGTERM
        if returncode is None:
            return _CLEANUP_FAILURE
        return _normalized_returncode(returncode)
    except (OSError, SupervisorError):
        return _CLEANUP_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())
