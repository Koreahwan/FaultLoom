from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from faultloom import model_utility_process as bounded_process
from faultloom.model_utility_process import (
    BoundedProcessError,
    BoundedProcessLaunch,
    run_bounded_process,
)


def _launch(script: str, *, timeout: int = 2, stdout_limit: int = 4096) -> BoundedProcessLaunch:
    return BoundedProcessLaunch(
        argv=(sys.executable, "-c", script),
        stdin=b"",
        environment={"PATH": os.environ.get("PATH", "")},
        pass_fds=(),
        timeout_seconds=timeout,
        maximum_stdout_bytes=stdout_limit,
        maximum_stderr_bytes=4096,
    )


def _setsid_double_fork_script(pid_file: Path, action: str) -> str:
    return f"""
import os
import pathlib
import signal
import sys
import time

first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second == 0:
        descriptor = os.open(os.devnull, os.O_RDWR)
        for target in (0, 1, 2):
            os.dup2(descriptor, target)
        os.close(descriptor)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid()))
        time.sleep(60)
        os._exit(0)
    os._exit(0)
os.waitpid(first, 0)
deadline = time.monotonic() + 2
while not pathlib.Path({str(pid_file)!r}).exists() and time.monotonic() < deadline:
    time.sleep(0.01)
{action}
"""


def _assert_pid_gone(pid_file: Path) -> None:
    assert pid_file.is_file()
    pid = int(pid_file.read_text())
    deadline = time.monotonic() + 2.0
    while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not Path(f"/proc/{pid}").exists()


def test_timeout_reaps_setsid_double_fork_without_signaling_caller(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "timeout.pid"
    caller_group = os.getpgrp()
    script = _setsid_double_fork_script(pid_file, "time.sleep(60)")
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_process(_launch(script, timeout=1))
    _assert_pid_gone(pid_file)
    assert os.getpgrp() == caller_group


def test_stdout_limit_reaps_setsid_double_fork(tmp_path: Path) -> None:
    pid_file = tmp_path / "stdout.pid"
    script = _setsid_double_fork_script(
        pid_file,
        "sys.stdout.write('x'*100000);sys.stdout.flush();time.sleep(60)",
    )
    with pytest.raises(BoundedProcessError, match="stdout exceeds"):
        run_bounded_process(_launch(script, stdout_limit=1024))
    _assert_pid_gone(pid_file)


def test_nonzero_leader_reaps_setsid_double_fork(tmp_path: Path) -> None:
    pid_file = tmp_path / "nonzero.pid"
    script = _setsid_double_fork_script(pid_file, "sys.exit(9)")
    result = run_bounded_process(_launch(script))
    assert result.returncode == 9
    _assert_pid_gone(pid_file)


def test_cleanup_failure_surfaces_stable_bounded_process_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "faultloom.model_utility_process._finish_supervisor", lambda _process: False
    )
    with pytest.raises(BoundedProcessError, match="child process cleanup failed"):
        run_bounded_process(_launch("pass"))


def test_supervisor_cleanup_eperm_and_timeout_fail_closed() -> None:
    class PermissionDeniedProcess:
        returncode = None

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            raise PermissionError

    class TimedOutProcess:
        returncode = None

        def poll(self) -> None:
            return None

        def terminate(self) -> None:
            return None

        def wait(self, *, timeout: float) -> int:
            raise subprocess.TimeoutExpired("supervisor", timeout)

        def kill(self) -> None:
            return None

    assert bounded_process._finish_supervisor(PermissionDeniedProcess()) is False  # type: ignore[arg-type]
    assert bounded_process._finish_supervisor(TimedOutProcess()) is False  # type: ignore[arg-type]
