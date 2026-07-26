"""One-shot inherited-descriptor worker and networkless process launcher."""

from __future__ import annotations

import fcntl
import os
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import MappingProxyType

import pydantic
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from .model_utility_process import BoundedProcessLaunch, run_bounded_process
from .t40_arm_runtime import (
    T40ArmPolicy,
    T40ArmRequest,
    T40ArmRuntimeError,
    T40ResourceBudget,
    _execute_kernel_probe,
    _KernelProbeExecution,
    canonical_json_bytes,
)


class T40ArmWorkerError(RuntimeError):
    """A one-shot worker could not produce a complete trusted response."""


class T40ArmWorkerTimeout(TimeoutError):
    """The process group timed out; partial bytes are diagnostic only."""

    partial_response: bytes

    def __init__(self, partial_response: bytes) -> None:
        super().__init__("T40 arm worker timed out")
        self.partial_response = partial_response


_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_KEY_BYTES = 32
_KERNEL_PROBE_SETTLE_SECONDS = 1.25
_SANDBOX_RUNTIME_ROOT = "/opt/faultloom-runtime"
_SANDBOX_SITE_ROOT = "/opt/faultloom-site"
_RESOURCE_BOOTSTRAP = """import os,resource,sys
cpu=int(sys.argv[1]); memory=int(sys.argv[2]); argv=sys.argv[3:]
resource.setrlimit(resource.RLIMIT_CPU,(cpu,cpu))
resource.setrlimit(resource.RLIMIT_AS,(memory,memory))
os.execv(argv[0],argv)
"""


def _read_regular_fd(descriptor: int, maximum_bytes: int, label: str) -> bytes:
    if type(descriptor) is not int or descriptor < 3:
        raise T40ArmWorkerError(f"{label} descriptor is invalid")
    try:
        status = os.fstat(descriptor)
        if status.st_size > maximum_bytes:
            raise T40ArmWorkerError(f"{label} exceeds its byte limit")
        _ = os.lseek(descriptor, 0, os.SEEK_SET)
        encoded = bytearray()
        while chunk := os.read(descriptor, min(65_536, maximum_bytes + 1 - len(encoded))):
            encoded.extend(chunk)
            if len(encoded) > maximum_bytes:
                raise T40ArmWorkerError(f"{label} exceeds its byte limit")
        return bytes(encoded)
    except OSError as exc:
        raise T40ArmWorkerError(f"{label} descriptor is unreadable") from exc


def _apply_resource_limits(budget: T40ResourceBudget) -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (budget.cpu_seconds, budget.cpu_seconds))
        resource.setrlimit(
            resource.RLIMIT_AS,
            (budget.maximum_address_space_bytes, budget.maximum_address_space_bytes),
        )
    except (OSError, ValueError) as exc:
        raise T40ArmWorkerError("worker resource limits are unavailable") from exc


def serve_one(
    *,
    request_fd: int,
    response_fd: int,
    signing_key_fd: int,
    policy: T40ArmPolicy,
) -> None:
    """Read one private request and execute only the fixed zero-model probe."""

    if type(policy) is not T40ArmPolicy:
        raise T40ArmWorkerError("worker requires an exact shared policy")
    if type(response_fd) is not int or response_fd < 3:
        raise T40ArmWorkerError("response descriptor is invalid")
    _apply_resource_limits(policy.budget)
    encoded = _read_regular_fd(request_fd, _MAX_REQUEST_BYTES, "private request")
    key_bytes = _read_regular_fd(signing_key_fd, _KEY_BYTES, "signing key")
    if len(key_bytes) != _KEY_BYTES:
        raise T40ArmWorkerError("signing key length is invalid")
    try:
        request = T40ArmRequest.model_validate_json(encoded)
        signing_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    except (ValidationError, ValueError) as exc:
        raise T40ArmWorkerError("worker input is malformed") from exc
    if encoded != canonical_json_bytes(request.model_dump(mode="json")):
        raise T40ArmWorkerError("private request is not canonical JSON")
    execution = _kernel_probe_execution(response_fd, request)
    response = _execute_kernel_probe(
        request=request,
        policy=policy,
        execution=execution,
        signing_key=signing_key,
    )
    output = canonical_json_bytes(response.model_dump(mode="json")) + b"\n"
    if len(output) > policy.budget.maximum_response_bytes:
        raise T40ArmWorkerError("worker response exceeds its byte limit")
    try:
        os.ftruncate(response_fd, 0)
        _ = os.lseek(response_fd, 0, os.SEEK_SET)
        pending = memoryview(output)
        offset = 0
        while offset < len(pending):
            offset += os.write(response_fd, pending[offset:])
    except OSError as exc:
        raise T40ArmWorkerError("response descriptor is unwritable") from exc


def _seal_input(name: str, payload: bytes) -> int:
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        pending = memoryview(payload)
        offset = 0
        while offset < len(pending):
            offset += os.write(descriptor, pending[offset:])
        _ = os.lseek(descriptor, 0, os.SEEK_SET)
        seals = (
            fcntl.F_SEAL_WRITE
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_SEAL
        )
        _ = fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        return descriptor
    except OSError:
        os.close(descriptor)
        raise


def _fixed_runtime_roots() -> tuple[str, str]:
    module = Path(__file__).resolve(strict=True)
    runtime_root = module.parents[1]
    expected = runtime_root / "faultloom" / "t40_arm_worker.py"
    runtime_module = runtime_root / "faultloom" / "t40_arm_runtime.py"
    if module != expected or not runtime_module.is_file():
        raise T40ArmWorkerError("fixed worker source root is invalid")
    site_root = Path(pydantic.__file__).resolve(strict=True).parents[1]
    if not (site_root / "pydantic_core").is_dir():
        raise T40ArmWorkerError("fixed worker dependency root is invalid")
    return str(runtime_root), str(site_root)


def _sandbox_argv(descriptors: tuple[int, int, int, int]) -> tuple[str, ...]:
    runtime_root, site_root = _fixed_runtime_roots()
    return (
        "/usr/bin/bwrap",
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
        "--setenv",
        "PYTHONPATH",
        f"{_SANDBOX_RUNTIME_ROOT}:{_SANDBOX_SITE_ROOT}:/usr/lib/python3/dist-packages",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        runtime_root,
        _SANDBOX_RUNTIME_ROOT,
        "--ro-bind",
        site_root,
        _SANDBOX_SITE_ROOT,
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--chdir",
        "/tmp",
        "--",
        "/usr/bin/python3",
        "-S",
        "-B",
        "-m",
        "faultloom.t40_arm_worker",
        *(str(value) for value in descriptors),
    )


def run_isolated_worker(
    *,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    signing_key: bytes,
) -> bytes:
    """Run the fixed non-formal kernel probe and reap its complete process tree."""

    if type(request) is not T40ArmRequest or type(policy) is not T40ArmPolicy:
        raise TypeError("fixed worker requires exact request and policy values")
    if type(signing_key) is not bytes or len(signing_key) != _KEY_BYTES:
        raise ValueError("signing key bytes are invalid")
    request_bytes = canonical_json_bytes(request.model_dump(mode="json"))
    policy_bytes = canonical_json_bytes(policy.model_dump(mode="json"))
    request_fd = _seal_input("faultloom-t40-private-request", request_bytes)
    key_fd = _seal_input("faultloom-t40-signing-key", signing_key)
    policy_fd = _seal_input("faultloom-t40-policy", policy_bytes)
    response_fd = os.memfd_create("faultloom-t40-response", os.MFD_CLOEXEC)
    descriptors = (request_fd, response_fd, key_fd, policy_fd)
    budget = policy.budget
    try:
        sandbox = _sandbox_argv(descriptors)
        argv = (
            sys.executable,
            "-I",
            "-S",
            "-B",
            "-c",
            _RESOURCE_BOOTSTRAP,
            str(budget.cpu_seconds),
            str(budget.maximum_address_space_bytes),
            *sandbox,
        )
        launch = BoundedProcessLaunch(
            argv=argv,
            stdin=b"",
            environment=MappingProxyType({"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}),
            pass_fds=descriptors,
            timeout_seconds=budget.timeout_seconds,
            maximum_stdout_bytes=4096,
            maximum_stderr_bytes=4096,
        )
        try:
            completed = run_bounded_process(launch)
        except subprocess.TimeoutExpired as exc:
            partial = _read_regular_fd(
                response_fd,
                budget.maximum_response_bytes,
                "partial response",
            )
            raise T40ArmWorkerTimeout(partial) from exc
        if completed.returncode != 0 or completed.stdout:
            raise T40ArmWorkerError("isolated worker returned an invalid process result")
        response = _read_regular_fd(
            response_fd,
            budget.maximum_response_bytes,
            "worker response",
        )
        if not response:
            raise T40ArmWorkerError("isolated worker returned no response")
        return response
    except T40ArmWorkerTimeout:
        raise
    except OSError as exc:
        raise T40ArmWorkerError("isolated worker launch failed") from exc
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def _host_pid(namespace_pid: int) -> int:
    try:
        lines = Path(f"/proc/{namespace_pid}/status").read_text().splitlines()
        raw = next(line for line in lines if line.startswith("NSpid:\t"))
        values = raw.split()[1:]
        if not values or any(not value.isdigit() for value in values):
            raise ValueError
        return int(values[0])
    except (OSError, StopIteration, ValueError) as exc:
        raise T40ArmWorkerError("kernel probe process identity is unavailable") from exc


def _network_namespace_identity() -> str:
    try:
        identity = os.readlink("/proc/self/ns/net")
    except OSError as exc:
        raise T40ArmWorkerError("kernel probe network namespace is unavailable") from exc
    if not identity.startswith("net:[") or not identity.endswith("]"):
        raise T40ArmWorkerError("kernel probe network namespace identity is invalid")
    return identity


def _kernel_probe_execution(
    response_fd: int,
    request: T40ArmRequest,
) -> _KernelProbeExecution:
    if request.requested_tools:
        raise T40ArmWorkerError("kernel probe cannot dispatch tools")
    child = os.fork()
    if child == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(60)
        os._exit(0)
    diagnostic = canonical_json_bytes(
        {
            "descendant_pid": _host_pid(child),
            "network_namespace": _network_namespace_identity(),
        }
    )
    _ = os.write(response_fd, diagnostic)
    time.sleep(_KERNEL_PROBE_SETTLE_SECONDS)
    return _KernelProbeExecution(
        observation=diagnostic.decode("ascii"),
        input_tokens=0,
        output_tokens=0,
        dispatch_trace=(),
        dispatched_oos=0,
        escaped_oos=0,
    )


def main() -> int:
    """Execute the fixed kernel probe over four inherited numeric descriptors."""

    if len(sys.argv) != 5 or any(not value.isdigit() for value in sys.argv[1:]):
        return 64
    request_fd, response_fd, signing_key_fd, policy_fd = (
        int(value) for value in sys.argv[1:]
    )
    try:
        encoded_policy = _read_regular_fd(policy_fd, 65_536, "shared policy")
        policy = T40ArmPolicy.model_validate_json(encoded_policy)
        if encoded_policy != canonical_json_bytes(policy.model_dump(mode="json")):
            raise T40ArmWorkerError("shared policy is not canonical JSON")
        serve_one(
            request_fd=request_fd,
            response_fd=response_fd,
            signing_key_fd=signing_key_fd,
            policy=policy,
        )
    except (T40ArmRuntimeError, T40ArmWorkerError, ValidationError, OSError):
        return 70
    return 0


__all__ = [
    "T40ArmWorkerError",
    "T40ArmWorkerTimeout",
    "run_isolated_worker",
    "serve_one",
]


if __name__ == "__main__":
    raise SystemExit(main())
