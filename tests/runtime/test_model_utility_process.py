from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

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


def _grandchild_script(pid_file: Path, action: str) -> str:
    return (
        "import pathlib,subprocess,sys,time;"
        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
        f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid));"
        + action
    )


def _assert_pid_gone(pid_file: Path) -> None:
    assert pid_file.is_file()
    pid = int(pid_file.read_text())
    deadline = time.monotonic() + 2.0
    while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not Path(f"/proc/{pid}").exists()


def test_timeout_kills_owned_process_group_without_signaling_caller(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "timeout.pid"
    caller_group = os.getpgrp()
    script = _grandchild_script(pid_file, "time.sleep(60)")
    with pytest.raises(subprocess.TimeoutExpired):
        run_bounded_process(_launch(script, timeout=1))
    _assert_pid_gone(pid_file)
    assert os.getpgrp() == caller_group


def test_stdout_limit_kills_owned_process_group(tmp_path: Path) -> None:
    pid_file = tmp_path / "stdout.pid"
    script = _grandchild_script(
        pid_file,
        "sys.stdout.write('x'*100000);sys.stdout.flush();time.sleep(60)",
    )
    with pytest.raises(BoundedProcessError, match="stdout exceeds"):
        run_bounded_process(_launch(script, stdout_limit=1024))
    _assert_pid_gone(pid_file)


def test_nonzero_leader_still_kills_detached_stdio_grandchild(tmp_path: Path) -> None:
    pid_file = tmp_path / "nonzero.pid"
    script = _grandchild_script(pid_file, "sys.exit(9)")
    result = run_bounded_process(_launch(script))
    assert result.returncode == 9
    _assert_pid_gone(pid_file)
