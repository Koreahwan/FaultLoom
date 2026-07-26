"""Fixed, stateless thin-frontier worker for one formal T40 model call."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import os
import resource
import stat
import subprocess
import sys
from pathlib import Path
from types import MappingProxyType

import cryptography
import faultloom_protocol
import faultloom_sdk
import pydantic
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from faultloom_protocol import AuthoritySigner
from pydantic import ValidationError

from .model_utility_attestation_state import MonotonicAttestationState
from .model_utility_attestor import (
    AttestedModelUtilityExchange,
    TransientModelUtilityAttestor,
)
from .model_utility_process import BoundedProcessLaunch, run_bounded_process
from .model_utility_proxy import DigestPinnedLocalProcessProxy
from .model_utility_proxy_models import (
    LocalModelProcessConfig,
    LocalModelRuntimeProfile,
)
from .t40_arm_runtime import (
    T40ArmPolicy,
    T40ArmRequest,
    T40ArmRuntimeError,
    canonical_json_bytes,
)
from .t40_real_arm_protocol import (
    _sign_thin_frontier_response,
    _thin_frontier_model_request,
)

_KEY_BYTES = 32
_MAX_INPUT_FD_BYTES = 1_048_576
_MAX_POLICY_FD_BYTES = 65_536
_MODULE_NAME = "faultloom.t40_thin_frontier_arm"
_ATTESTATION_STATE_PATH = Path(
    "/var/lib/faultloom/t40-formal-v1/producer-attestation.sequence"
)
_PRODUCER_SIGNING_KEY_PATH = Path(
    "/etc/faultloom/t40-formal-v1/producer-signing-key"
)


class T40ThinFrontierError(T40ArmRuntimeError):
    """The fixed thin-frontier call failed before a signed response existed."""


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def thin_frontier_implementation_digest() -> str:
    """Return the digest of the exact fixed thin-frontier module bytes."""

    try:
        source = Path(__file__).resolve(strict=True)
        expected = source.parent / "t40_thin_frontier_arm.py"
        if source != expected or not source.is_file():
            raise OSError
        return _digest_bytes(source.read_bytes())
    except OSError:
        raise T40ThinFrontierError("thin-frontier implementation is unavailable") from None


def _fixed_model_exchange(
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    producer_signer: AuthoritySigner,
) -> AttestedModelUtilityExchange:
    """Perform the only admitted fixed-profile model exchange."""

    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=policy.budget.timeout_seconds,
        maximum_request_bytes=65_536,
        maximum_response_bytes=policy.budget.maximum_response_bytes,
    )
    if (
        request.model_snapshot_digest != config.model_snapshot_digest
        or request.model_runtime_digest != config.runtime_executable_digest
    ):
        raise T40ThinFrontierError("thin-frontier request does not bind the fixed model profile")
    if (
        request.session_id is None
        or request.evaluator_challenge is None
        or request.allocation_id is None
        or request.trusted_minimum_sequence is None
        or request.core_wheel_digest is None
    ):
        raise T40ThinFrontierError("thin-frontier producer attestation context is incomplete")
    model_request = _thin_frontier_model_request(request, policy)
    with MonotonicAttestationState(_ATTESTATION_STATE_PATH) as state:
        return TransientModelUtilityAttestor(
            proxy=DigestPinnedLocalProcessProxy(config),
            signer=producer_signer,
            sequence_state=state,
            core_wheel_digest=request.core_wheel_digest,
        ).exchange(
            model_request,
            session_id=request.session_id,
            evaluator_challenge=request.evaluator_challenge,
            allocation_id=request.allocation_id,
            trusted_minimum_sequence=request.trusted_minimum_sequence,
        )


def _execute_and_sign(
    *,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    signing_key: Ed25519PrivateKey,
    producer_signer: AuthoritySigner,
) -> bytes:
    if request.arm_id != "thin_frontier":
        raise T40ThinFrontierError("thin-frontier worker rejects a different arm")
    implementation_digest = thin_frontier_implementation_digest()
    if request.arm_runtime_digest != implementation_digest:
        raise T40ThinFrontierError("thin-frontier implementation digest mismatch")
    if request.requested_tools and policy.budget.maximum_tool_dispatches == 0:
        raise T40ThinFrontierError("requested tools exceed the shared dispatch budget")
    model_request = _thin_frontier_model_request(request, policy)
    exchange = _fixed_model_exchange(request, policy, producer_signer)
    response = _sign_thin_frontier_response(
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=exchange.response,
        producer_receipt=exchange.producer_receipt,
        runtime_implementation_digest=implementation_digest,
        signing_key=signing_key,
    )
    return canonical_json_bytes(response.model_dump(mode="json")) + b"\n"


def _read_regular_fd(descriptor: int, maximum_bytes: int, label: str) -> bytes:
    if type(descriptor) is not int or descriptor < 3:
        raise T40ThinFrontierError(f"{label} descriptor is invalid")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise T40ThinFrontierError(f"{label} descriptor is not regular")
        _ = os.lseek(descriptor, 0, os.SEEK_SET)
        raw = os.read(descriptor, maximum_bytes + 1)
        after = os.fstat(descriptor)
    except OSError:
        raise T40ThinFrontierError(f"{label} descriptor is unavailable") from None
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if len(raw) > maximum_bytes or len(raw) != before.st_size or identity_before != identity_after:
        raise T40ThinFrontierError(f"{label} descriptor changed during read")
    return raw


def _load_operator_producer_signing_key() -> bytes:
    """Load the one root-owned producer key installed for formal T40 calls."""

    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(_PRODUCER_SIGNING_KEY_PATH, flags)
    except OSError:
        raise T40ThinFrontierError("operator producer signing key is unavailable") from None
    try:
        before = os.fstat(descriptor)
        raw = os.read(descriptor, _KEY_BYTES + 1)
        after = os.fstat(descriptor)
        named = os.stat(_PRODUCER_SIGNING_KEY_PATH, follow_symlinks=False)
    except OSError:
        raise T40ThinFrontierError("operator producer signing key is unavailable") from None
    finally:
        os.close(descriptor)
    metadata = (before, after, named)
    if any(
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != 0
        or value.st_gid != 0
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_nlink != 1
        for value in metadata
    ):
        raise T40ThinFrontierError("operator producer signing key metadata is unsafe")
    identities = tuple(
        (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        for value in metadata
    )
    if len(set(identities)) != 1:
        raise T40ThinFrontierError("operator producer signing key changed during read")
    if len(raw) != _KEY_BYTES:
        raise T40ThinFrontierError("operator producer signing key length is invalid")
    return raw


def _apply_resource_limits(policy: T40ArmPolicy) -> None:
    budget = policy.budget
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (budget.cpu_seconds, budget.cpu_seconds))
        resource.setrlimit(
            resource.RLIMIT_AS,
            (budget.maximum_address_space_bytes, budget.maximum_address_space_bytes),
        )
    except (OSError, ValueError):
        raise T40ThinFrontierError("thin-frontier resource limits are unavailable") from None


def _serve_one(
    request_fd: int,
    response_fd: int,
    signing_key_fd: int,
    producer_signing_key_fd: int,
    policy_fd: int,
) -> None:
    encoded_request = _read_regular_fd(request_fd, _MAX_INPUT_FD_BYTES, "private request")
    encoded_policy = _read_regular_fd(policy_fd, _MAX_POLICY_FD_BYTES, "shared policy")
    key_bytes = _read_regular_fd(signing_key_fd, _KEY_BYTES, "signing key")
    producer_key_bytes = _read_regular_fd(
        producer_signing_key_fd, _KEY_BYTES, "producer signing key"
    )
    if len(key_bytes) != _KEY_BYTES or len(producer_key_bytes) != _KEY_BYTES:
        raise T40ThinFrontierError("signing key length is invalid")
    if hmac.compare_digest(key_bytes, producer_key_bytes):
        raise T40ThinFrontierError("arm and producer signing keys must be distinct")
    try:
        request = T40ArmRequest.model_validate_json(encoded_request)
        policy = T40ArmPolicy.model_validate_json(encoded_policy)
        signing_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        producer_signer = AuthoritySigner.from_private_bytes(producer_key_bytes)
    except (ValidationError, ValueError):
        raise T40ThinFrontierError("thin-frontier input is malformed") from None
    if encoded_request != canonical_json_bytes(request.model_dump(mode="json")):
        raise T40ThinFrontierError("private request is not canonical JSON")
    if encoded_policy != canonical_json_bytes(policy.model_dump(mode="json")):
        raise T40ThinFrontierError("shared policy is not canonical JSON")
    _apply_resource_limits(policy)
    output = _execute_and_sign(
        request=request,
        policy=policy,
        signing_key=signing_key,
        producer_signer=producer_signer,
    )
    if len(output) > policy.budget.maximum_response_bytes:
        raise T40ThinFrontierError("thin-frontier response exceeds its shared limit")
    try:
        os.ftruncate(response_fd, 0)
        _ = os.lseek(response_fd, 0, os.SEEK_SET)
        pending = memoryview(output)
        offset = 0
        while offset < len(pending):
            offset += os.write(response_fd, pending[offset:])
    except OSError:
        raise T40ThinFrontierError("response descriptor is unwritable") from None


def _seal_input(name: str, payload: bytes) -> int:
    descriptor = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        _ = os.lseek(descriptor, 0, os.SEEK_SET)
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        _ = fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        return descriptor
    except OSError:
        os.close(descriptor)
        raise


def _package_root(module_file: str, package: str) -> str:
    path = Path(module_file).resolve(strict=True)
    if path.parent.name != package or path.suffix != ".py":
        raise T40ThinFrontierError("fixed dependency root is invalid")
    return str(path.parents[1])


def _fixed_pythonpath() -> str:
    protocol_file = faultloom_protocol.__file__
    sdk_file = faultloom_sdk.__file__
    pydantic_file = pydantic.__file__
    cryptography_file = cryptography.__file__
    if None in (protocol_file, sdk_file, pydantic_file, cryptography_file):
        raise T40ThinFrontierError("fixed dependency origin is unavailable")
    roots = (
        _package_root(__file__, "faultloom"),
        _package_root(protocol_file, "faultloom_protocol"),
        _package_root(sdk_file, "faultloom_sdk"),
        str(Path(pydantic_file).resolve(strict=True).parents[1]),
        str(Path(cryptography_file).resolve(strict=True).parents[1]),
    )
    return os.pathsep.join(dict.fromkeys(roots))


def _fixed_worker_argv(descriptors: tuple[int, int, int, int, int]) -> tuple[str, ...]:
    return (
        "/usr/bin/python3",
        "-S",
        "-B",
        "-m",
        _MODULE_NAME,
        *(str(value) for value in descriptors),
    )


def _run_thin_frontier_arm_with_producer_key(
    *,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    signing_key: bytes,
    producer_signing_key: bytes,
) -> bytes:
    """Launch only the fixed thin module with five inherited descriptors."""

    if type(request) is not T40ArmRequest or type(policy) is not T40ArmPolicy:
        raise TypeError("fixed thin-frontier launcher requires exact request and policy values")
    if type(signing_key) is not bytes or len(signing_key) != _KEY_BYTES:
        raise ValueError("signing key bytes are invalid")
    if type(producer_signing_key) is not bytes or len(producer_signing_key) != _KEY_BYTES:
        raise ValueError("producer signing key bytes are invalid")
    if hmac.compare_digest(signing_key, producer_signing_key):
        raise ValueError("arm and producer signing keys must be distinct")
    if request.arm_id != "thin_frontier":
        raise T40ThinFrontierError("thin-frontier launcher rejects a different arm")
    opened: list[int] = []
    try:
        opened.append(
            _seal_input(
                "faultloom-t40-thin-request",
                canonical_json_bytes(request.model_dump(mode="json")),
            )
        )
        opened.append(os.memfd_create("faultloom-t40-thin-response", os.MFD_CLOEXEC))
        opened.append(_seal_input("faultloom-t40-thin-key", signing_key))
        opened.append(
            _seal_input("faultloom-t40-thin-producer-key", producer_signing_key)
        )
        opened.append(
            _seal_input(
                "faultloom-t40-thin-policy",
                canonical_json_bytes(policy.model_dump(mode="json")),
            )
        )
        descriptors = (opened[0], opened[1], opened[2], opened[3], opened[4])
        launch = BoundedProcessLaunch(
            argv=_fixed_worker_argv(descriptors),
            stdin=b"",
            environment=MappingProxyType(
                {
                    "LANG": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                    "PYTHONPATH": _fixed_pythonpath(),
                }
            ),
            pass_fds=descriptors,
            timeout_seconds=policy.budget.timeout_seconds,
            maximum_stdout_bytes=4096,
            maximum_stderr_bytes=4096,
        )
        completed = run_bounded_process(launch)
        if completed.returncode != 0 or completed.stdout:
            raise T40ThinFrontierError("thin-frontier worker returned an invalid process result")
        response = _read_regular_fd(
            descriptors[1], policy.budget.maximum_response_bytes, "thin-frontier response"
        )
        if not response:
            raise T40ThinFrontierError("thin-frontier worker returned no response")
        return response
    except subprocess.TimeoutExpired:
        raise T40ThinFrontierError("thin-frontier worker timed out") from None
    except OSError:
        raise T40ThinFrontierError("thin-frontier worker launch failed") from None
    finally:
        for descriptor in opened:
            os.close(descriptor)


def run_thin_frontier_arm(
    *,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    signing_key: bytes,
) -> bytes:
    """Launch the fixed thin module using only the installed producer authority."""

    producer_signing_key = _load_operator_producer_signing_key()
    return _run_thin_frontier_arm_with_producer_key(
        request=request,
        policy=policy,
        signing_key=signing_key,
        producer_signing_key=producer_signing_key,
    )


def main() -> int:
    """Serve exactly one request over five predetermined numeric descriptors."""

    if len(sys.argv) != 6 or any(not value.isdigit() for value in sys.argv[1:]):
        return 64
    descriptors = tuple(int(value) for value in sys.argv[1:])
    if len(set(descriptors)) != 5 or any(value < 3 for value in descriptors):
        return 64
    try:
        _serve_one(*descriptors)
    except (T40ArmRuntimeError, OSError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "T40ThinFrontierError",
    "run_thin_frontier_arm",
    "thin_frontier_implementation_digest",
]
