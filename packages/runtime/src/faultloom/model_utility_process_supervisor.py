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


def _children_of(pid: int, start_time: int) -> tuple[int, ...]:
    current = _process_record(pid)
    if current is None or current[1] != start_time:
        return ()
    try:
        tasks = tuple(
            entry for entry in Path(f"/proc/{pid}/task").iterdir() if entry.name.isdigit()
        )
    except FileNotFoundError:
        return ()
    except OSError as error:
        raise SupervisorError("known child inventory unavailable") from error
    values: list[str] = []
    for task in tasks:
        try:
            values.extend((task / "children").read_text().split())
        except FileNotFoundError:
            continue
        except OSError as error:
            raise SupervisorError("known child inventory unavailable") from error
    after = _process_record(pid)
    if after is None or after[1] != start_time:
        return ()
    try:
        children = tuple(int(value) for value in values)
    except ValueError as error:
        raise SupervisorError("known child inventory invalid") from error
    if any(child <= 0 for child in children) or len(set(children)) != len(children):
        raise SupervisorError("known child inventory invalid")
    return children


def _descendants() -> dict[int, int]:
    root = _process_record(os.getpid())
    if root is None:
        raise SupervisorError("supervisor identity unavailable")
    pending = [(os.getpid(), root[1])]
    descendants: dict[int, int] = {}
    while pending:
        parent_pid, parent_start = pending.pop()
        for child in _children_of(parent_pid, parent_start):
            if child == os.getpid() or child in descendants:
                continue
            record = _process_record(child)
            if record is None:
                continue
            descendants[child] = record[1]
            pending.append((child, record[1]))
    return descendants


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


def _signal_target_group(pid: int, start_time: int | None, sent_signal: int) -> bool:
    if start_time is None:
        return True
    current = _process_record(pid)
    if current is None or current[1] != start_time:
        return True
    try:
        process_group = os.getpgid(pid)
        if process_group != pid or process_group == os.getpgrp():
            return False
        os.killpg(process_group, sent_signal)
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


def _cleanup_descendants(target_pid: int, target_start: int | None) -> bool:
    for sent_signal, duration in ((signal.SIGTERM, 0.2), (signal.SIGKILL, 1.5)):
        try:
            if not _signal_target_group(target_pid, target_start, sent_signal):
                return False
        except SupervisorError:
            return False
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
        try:
            target_record = _process_record(target.pid)
        except SupervisorError:
            _ = _cleanup_descendants(target.pid, None)
            return _CLEANUP_FAILURE
        target_start = None if target_record is None else target_record[1]
        returncode: int | None = None
        while not _stop_requested:
            returncode = target.poll()
            if returncode is not None:
                break
            time.sleep(0.01)
        if not _cleanup_descendants(target.pid, target_start):
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
