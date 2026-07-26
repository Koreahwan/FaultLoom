"""Pinned artifact verification and bubblewrap argv construction."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import stat
from collections.abc import Generator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .model_utility_process import BoundedProcessLaunch
from .model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
    FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
    FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
    MODEL_SNAPSHOT_TOKEN,
    LocalModelProcessConfig,
    LocalModelProcessError,
    LocalModelRuntimeProfile,
)

_PROFILE_ROOT = Path("/opt/faultloom/model-utility-v1")
_SANDBOX_MODEL_PATH = "/opt/faultloom/model-snapshot"
_SANDBOX_RUNTIME_PATH = "/opt/faultloom/runtime"
_RUNTIME_ARGUMENTS = ("--model", MODEL_SNAPSHOT_TOKEN, "--json")
_MAX_ARTIFACT_BYTES = 128 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class _ArtifactSpec:
    path: Path
    expected_digest: str
    executable: bool
    label: str


def _open_source(spec: _ArtifactSpec) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(spec.path, flags)
    except OSError:
        error = LocalModelProcessError(f"{spec.label} is unavailable")
    raise error


def _open_pinned_artifact(spec: _ArtifactSpec) -> int:
    source = _open_source(spec)
    staged = -1
    try:
        before = os.fstat(source)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > _MAX_ARTIFACT_BYTES
            or (spec.executable and before.st_mode & 0o111 == 0)
        ):
            raise LocalModelProcessError(
                f"{spec.label} is not an admissible artifact"
            )
        staged = os.memfd_create(
            f"faultloom-{spec.label.replace(' ', '-')}",
            os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING,
        )
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(source, 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
            pending = memoryview(chunk)
            offset = 0
            while offset < len(pending):
                offset += os.write(staged, pending[offset:])
        after = os.fstat(source)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or size != before.st_size:
            raise LocalModelProcessError(
                f"{spec.label} changed during verification"
            )
        observed = f"sha256:{digest.hexdigest()}"
        if not hmac.compare_digest(observed, spec.expected_digest):
            raise LocalModelProcessError(f"{spec.label} digest mismatch")
        os.fchmod(staged, 0o500 if spec.executable else 0o400)
        seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        _ = fcntl.fcntl(staged, fcntl.F_ADD_SEALS, seals)
        if fcntl.fcntl(staged, fcntl.F_GET_SEALS) != seals:
            raise LocalModelProcessError(f"{spec.label} could not be sealed")
        _ = os.lseek(staged, 0, os.SEEK_SET)
        pinned = os.dup(staged)
        os.close(staged)
        staged = -1
        return pinned
    except LocalModelProcessError:
        raise
    except OSError:
        error = LocalModelProcessError(f"{spec.label} is unavailable")
    finally:
        os.close(source)
        if staged >= 0:
            os.close(staged)
    raise error


def _artifact_specs(_profile: LocalModelRuntimeProfile) -> tuple[_ArtifactSpec, ...]:
    return (
        _ArtifactSpec(
            _PROFILE_ROOT / "bwrap",
            FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
            True,
            "sandbox executable",
        ),
        _ArtifactSpec(
            _PROFILE_ROOT / "runtime",
            FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
            True,
            "runtime executable",
        ),
        _ArtifactSpec(
            _PROFILE_ROOT / "model.gguf",
            FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
            False,
            "model snapshot",
        ),
    )


def _launch(
    config: LocalModelProcessConfig,
    encoded: bytes,
    descriptors: tuple[int, int, int],
) -> BoundedProcessLaunch:
    sandbox, runtime, model = (f"/proc/self/fd/{value}" for value in descriptors)
    runtime_arguments = tuple(
        _SANDBOX_MODEL_PATH if value == MODEL_SNAPSHOT_TOKEN else value
        for value in _RUNTIME_ARGUMENTS
    )
    argv = (
        sandbox,
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--uid",
        "0",
        "--gid",
        "0",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/opt",
        "--dir",
        "/opt/faultloom",
        "--ro-bind",
        runtime,
        _SANDBOX_RUNTIME_PATH,
        "--ro-bind",
        model,
        _SANDBOX_MODEL_PATH,
        "--chdir",
        "/tmp",
        "--",
        _SANDBOX_RUNTIME_PATH,
        *runtime_arguments,
    )
    return BoundedProcessLaunch(
        argv=argv,
        stdin=encoded,
        environment=MappingProxyType(
            {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}
        ),
        pass_fds=descriptors,
        timeout_seconds=config.timeout_seconds,
        maximum_stdout_bytes=config.maximum_response_bytes,
        maximum_stderr_bytes=config.maximum_response_bytes,
    )


@contextmanager
def pinned_process_launch(
    config: LocalModelProcessConfig,
    encoded: bytes,
) -> Generator[BoundedProcessLaunch, None, None]:
    """Hold verified descriptors open for exactly one process launch."""

    specs = _artifact_specs(config.profile)
    with ExitStack() as stack:
        descriptors: list[int] = []
        for spec in specs:
            descriptor = _open_pinned_artifact(spec)
            _ = stack.callback(os.close, descriptor)
            descriptors.append(descriptor)
        if len(descriptors) != 3:
            raise LocalModelProcessError("local model artifact set is incomplete")
        exact_descriptors = (descriptors[0], descriptors[1], descriptors[2])
        yield _launch(config, encoded, exact_descriptors)


__all__ = ["pinned_process_launch"]
