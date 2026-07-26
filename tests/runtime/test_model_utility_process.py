from __future__ import annotations

import os
import signal
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import pytest
from faultloom import model_utility_process as bounded_process
from faultloom import model_utility_process_supervisor as process_supervisor
from faultloom.model_utility_process import (
    BoundedProcessError,
    BoundedProcessLaunch,
    run_bounded_process,
)


_ROOT = Path(__file__).resolve().parents[2]
_RUNTIME = _ROOT / "packages/runtime"


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


def _built_poisoned_runtime_wheel(tmp_path: Path) -> Path:
    source = tmp_path / "runtime"
    shutil.copytree(_RUNTIME, source)
    (source / "src/faultloom/__init__.py").write_text(
        "raise RuntimeError('faultloom package import is forbidden')\n",
        encoding="utf-8",
    )
    output = tmp_path / "wheels"
    result = subprocess.run(
        (
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(output),
            str(source),
        ),
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    wheels = tuple(output.glob("faultloom-*.whl"))
    assert len(wheels) == 1
    return wheels[0]


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
    pid = int(pid_file.read_text().split(":", 1)[0])
    deadline = time.monotonic() + 2.0
    while Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not Path(f"/proc/{pid}").exists()


def test_source_supervisor_bootstrap_is_isolated_and_keeps_target_argv() -> None:
    launch = _launch("print('source-supervisor')")
    supervisor = bounded_process._supervisor_argv(launch)
    source_root = Path(bounded_process.__file__).resolve().parents[1]
    assert supervisor[:8] == (
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-c",
        bounded_process._SUPERVISOR_BOOTSTRAP,
        str(source_root),
        "source",
    )
    assert supervisor[8:] == ("--pass-fds", "", "--", *launch.argv)
    result = run_bounded_process(launch)
    assert result.returncode == 0
    assert result.stdout == b"source-supervisor\n"


@pytest.mark.parametrize(
    "origin",
    (
        "faultloom/model_utility_process.py",
        "/tmp/not-faultloom.py",
        "/tmp/not-a-wheel.whl/faultloom/model_utility_process.py",
    ),
)
def test_supervisor_origin_tampering_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, origin: str
) -> None:
    if origin.startswith("/tmp/not-a-wheel"):
        archive = tmp_path / "not-a-wheel.whl"
        with zipfile.ZipFile(archive, "w") as wheel:
            wheel.writestr("faultloom/model_utility_process.py", "")
        origin = f"{archive}/faultloom/model_utility_process.py"
    monkeypatch.setattr(bounded_process, "__file__", origin)
    with pytest.raises(BoundedProcessError, match="supervisor module origin is invalid"):
        bounded_process._supervisor_argv(_launch("pass"))


def test_source_supervisor_symlink_tampering_fails_closed(tmp_path: Path) -> None:
    source = tmp_path / "source"
    package = source / "faultloom"
    package.mkdir(parents=True)
    module = package / "model_utility_process.py"
    module.write_text("", encoding="utf-8")
    escaped = tmp_path / "escaped_supervisor.py"
    escaped.write_text("", encoding="utf-8")
    (package / "model_utility_process_supervisor.py").symlink_to(escaped)
    with pytest.raises(BoundedProcessError, match="supervisor module origin is invalid"):
        bounded_process._supervisor_import_root(str(module))


def test_built_wheel_supervisor_uses_only_its_zip_root_and_reaps_passed_fd_target(
    tmp_path: Path,
) -> None:
    wheel = _built_poisoned_runtime_wheel(tmp_path)
    ambient = tmp_path / "ambient"
    (ambient / "faultloom").mkdir(parents=True)
    (ambient / "faultloom/model_utility_process_supervisor.py").write_text(
        "raise RuntimeError('ambient supervisor import is forbidden')\n",
        encoding="utf-8",
    )
    pid_file = tmp_path / "wheel.pid"
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"wheel-fd")
    os.close(write_fd)
    child = r'''
import os
import subprocess
import sys
import types
import zipimport

wheel, descriptor, pid_file = sys.argv[1:]
loader = zipimport.zipimporter(wheel + "/faultloom")
code = loader.get_code("model_utility_process")
if code is None:
    raise RuntimeError("wheel process module is unavailable")
module = types.ModuleType("wheel_model_utility_process")
module.__file__ = wheel + "/faultloom/model_utility_process.py"
module.__package__ = None
sys.modules[module.__name__] = module
exec(code, module.__dict__)
script = r"""
import os
import pathlib
import sys
import time

descriptor = int(sys.argv[1])
pid_file = pathlib.Path(sys.argv[2])
first = os.fork()
if first == 0:
    os.setsid()
    second = os.fork()
    if second == 0:
        pid_file.write_text(f"{os.getpid()}:{os.read(descriptor, 8).decode()}")
        time.sleep(60)
        os._exit(0)
    os._exit(0)
os.waitpid(first, 0)
deadline = time.monotonic() + 2
while not pid_file.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
time.sleep(60)
"""
launch = module.BoundedProcessLaunch(
    argv=(sys.executable, "-c", script, descriptor, pid_file),
    stdin=b"",
    environment={"PATH": os.environ["PATH"]},
    pass_fds=(int(descriptor),),
    timeout_seconds=1,
    maximum_stdout_bytes=4096,
    maximum_stderr_bytes=4096,
)
try:
    module.run_bounded_process(launch)
except subprocess.TimeoutExpired:
    print("wheel-timeout")
else:
    raise RuntimeError("wheel target unexpectedly completed")
'''
    result = subprocess.run(
        (sys.executable, "-I", "-S", "-B", "-c", child, str(wheel), str(read_fd), str(pid_file)),
        check=False,
        capture_output=True,
        text=True,
        cwd=ambient,
        env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(ambient)},
        pass_fds=(read_fd,),
    )
    os.close(read_fd)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == "wheel-timeout\n"
    pid, received = pid_file.read_text().split(":", 1)
    assert pid.isdigit()
    assert received == "wheel-fd"
    _assert_pid_gone(pid_file)


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


@pytest.mark.parametrize("unrelated", ("over-limit", "unreadable-stat"))
def test_supervisor_targeted_cleanup_ignores_unrelated_proc_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unrelated: str,
) -> None:
    pid_file = tmp_path / f"supervisor-{unrelated}.pid"
    process_supervisor._set_subreaper()
    process = subprocess.Popen(
        (sys.executable, "-c", _setsid_double_fork_script(pid_file, "time.sleep(60)")),
        start_new_session=True,
    )
    record = process_supervisor._process_record(process.pid)
    assert record is not None
    deadline = time.monotonic() + 2
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert pid_file.exists()

    class UnrelatedEntry:
        def __init__(self, name: str) -> None:
            self.name = name

    if unrelated == "over-limit":
        entries = tuple(UnrelatedEntry(str(900_000 + index)) for index in range(5000))
    else:
        entries = (UnrelatedEntry("999999"),)
        original_read_text = Path.read_text

        def unreadable_unrelated(path: Path, *args: object, **kwargs: object) -> str:
            if str(path) == "/proc/999999/stat":
                raise PermissionError
            return original_read_text(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "read_text", unreadable_unrelated)
    original_iterdir = Path.iterdir

    def unrelated_inventory(path: Path):
        if str(path) == "/proc":
            return iter(entries)
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", unrelated_inventory)

    cleanup_ok = process_supervisor._cleanup_descendants(process.pid, record[1])
    process.returncode = -signal.SIGKILL
    assert cleanup_ok is True
    _assert_pid_gone(pid_file)


def test_supervisor_signals_known_target_group_before_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(
        process_supervisor,
        "_signal_target_group",
        lambda _pid, _start, _signal: events.append("target-group") or True,
    )
    monkeypatch.setattr(
        process_supervisor,
        "_descendants",
        lambda: events.append("inventory") or {},
    )
    monkeypatch.setattr(process_supervisor, "_reap_exited", lambda: (True, True))
    assert process_supervisor._cleanup_descendants(123, 456) is True
    assert events == ["target-group", "inventory"]
