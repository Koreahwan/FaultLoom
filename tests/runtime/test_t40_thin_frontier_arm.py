from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import resource
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from faultloom import t40_real_arm_protocol as protocol
from faultloom import t40_thin_frontier_arm as thin
from faultloom.model_utility_attestor import AttestedModelUtilityExchange
from faultloom.model_utility_process import BoundedProcessLaunch, BoundedProcessResult
from faultloom.model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
    FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
    FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
    LocalModelProcessConfig,
    LocalModelProcessRequest,
    LocalModelProcessResponse,
    LocalModelRuntimeProfile,
)
from faultloom.t40_arm_runtime import T40ArmPolicy, T40ArmRequest, T40ResourceBudget
from faultloom.t40_real_arm_protocol import verify_real_arm_response
from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    ModelProducerAttestation,
    SignedModelProducerAttestation,
    attestation_signing_bytes,
    sha256_digest,
)
from faultloom_sdk import UtilityDecision

_SESSION_ID = "formal.thin.session.1"
_CHALLENGE = "0123456789abcdef" * 4


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _policy() -> T40ArmPolicy:
    return T40ArmPolicy(
        model_snapshot_digest=FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
        model_runtime_digest=FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
        tool_schema_digest=_digest(b"common tools"),
        gateway_policy_digest=_digest(b"common gateway"),
        safety_policy_digest=_digest(b"common safety"),
        generation_config_digest=_digest(b"common generation"),
        allowed_tools=("lab.http.get",),
        budget=T40ResourceBudget(
            maximum_input_tokens=1024,
            maximum_output_tokens=256,
            maximum_model_calls=1,
            maximum_tool_dispatches=1,
            timeout_seconds=300,
            cpu_seconds=300,
            maximum_address_space_bytes=8_589_934_592,
            maximum_response_bytes=65_536,
        ),
    )


def _request(policy: T40ArmPolicy) -> T40ArmRequest:
    private_input = "Assess the supplied owned case and return a final decision."
    return T40ArmRequest(
        request_id="formal.thin.1",
        arm_id="thin_frontier",
        arm_runtime_digest=thin.thin_frontier_implementation_digest(),
        case_digest=_digest(b"sealed case"),
        private_input_digest=_digest(private_input.encode()),
        policy_digest=policy.policy_digest,
        model_snapshot_digest=policy.model_snapshot_digest,
        model_runtime_digest=policy.model_runtime_digest,
        tool_schema_digest=policy.tool_schema_digest,
        gateway_policy_digest=policy.gateway_policy_digest,
        safety_policy_digest=policy.safety_policy_digest,
        generation_config_digest=policy.generation_config_digest,
        budget_digest=policy.budget_digest,
        requested_tools=(),
        private_input=private_input,
        session_id=_SESSION_ID,
        evaluator_challenge=_CHALLENGE,
        allocation_id="formal-thin-allocation-1",
        trusted_minimum_sequence=0,
        core_wheel_digest=_digest(b"core wheel"),
    )


def _response(
    request: T40ArmRequest,
    output: str = "bounded final model answer",
) -> LocalModelProcessResponse:
    return LocalModelProcessResponse(
        request_id=request.request_id,
        model_snapshot_digest=request.model_snapshot_digest,
        runtime_artifact_digest=request.model_runtime_digest,
        decision=UtilityDecision.INCONCLUSIVE,
        output=output,
        output_digest=_digest(output.encode()),
        raw_llama_stdout_digest=_digest(b"raw stdout"),
        input_tokens=31,
        output_tokens=5,
    )


def _producer_receipt(
    signer: AuthoritySigner,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    model_request: LocalModelProcessRequest,
    model_response: LocalModelProcessResponse,
) -> SignedModelProducerAttestation:
    assert request.session_id is not None
    assert request.evaluator_challenge is not None
    assert request.core_wheel_digest is not None
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=policy.budget.timeout_seconds,
        maximum_request_bytes=65_536,
        maximum_response_bytes=policy.budget.maximum_response_bytes,
    )
    payload = ModelProducerAttestation(
        schema_version=SCHEMA_VERSION,
        producer_key_id=signer.key_id,
        producer_key_fingerprint=protocol._digest_bytes(
            base64.urlsafe_b64decode(signer.public_key_record.public_key + "==")
        ),
        session_id=request.session_id,
        sequence=1,
        evaluator_challenge=request.evaluator_challenge,
        canonical_request_digest=protocol._digest_bytes(
            protocol._canonical_local_model_bytes(model_request)
        ),
        parsed_response_digest=protocol._digest_bytes(
            protocol._canonical_local_model_bytes(model_response)
        ),
        raw_llama_stdout_digest=model_response.raw_llama_stdout_digest,
        output_digest=model_response.output_digest,
        model_digest=model_request.model_snapshot_digest,
        runtime_wrapper_digest=model_request.runtime_artifact_digest,
        runtime_bundle_digest=config.runtime_bundle_digest,
        bwrap_digest=FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
        fixed_argv_digest=_digest(b"fixed argv"),
        core_wheel_digest=request.core_wheel_digest,
        profile_digest=protocol._profile_digest(config),
        status="accepted",
        prompt_tokens=model_response.input_tokens,
        completion_tokens=model_response.output_tokens,
        total_tokens=model_response.input_tokens + model_response.output_tokens,
    )
    payload_digest = sha256_digest(payload)
    return SignedModelProducerAttestation(
        schema_version=SCHEMA_VERSION,
        payload=payload,
        payload_digest=payload_digest,
        signature=signer.sign(attestation_signing_bytes(payload, payload_digest)),
    )


def _forked_worker(launch: BoundedProcessLaunch) -> BoundedProcessResult:
    child = os.fork()
    if child == 0:
        try:
            thin._serve_one(*launch.pass_fds)
        except Exception:  # noqa: BLE001 - child harness must map every failure to an exit code
            os._exit(2)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    return BoundedProcessResult(returncode=os.waitstatus_to_exitcode(status), stdout=b"")


def test_real_dispatch_emits_thin_runtime_and_policy_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    request = _request(policy)
    launches: list[BoundedProcessLaunch] = []

    def fixed_exchange(
        actual_request: T40ArmRequest,
        actual_policy: T40ArmPolicy,
        producer_signer: AuthoritySigner,
    ) -> AttestedModelUtilityExchange:
        forbidden = (
            "faultloom.context",
            "faultloom.semantic_depth",
            "faultloom.research.specialist",
            "faultloom.tool_planner.planner",
            "faultloom.patch_variant.engine",
            "faultloom.chain.engine",
        )
        observation = json.dumps(
            {
                "calls": 1,
                "cpu_limit": resource.getrlimit(resource.RLIMIT_CPU),
                "memory_limit": resource.getrlimit(resource.RLIMIT_AS),
                "forbidden_loaded": tuple(name for name in forbidden if name in sys.modules),
                "worker_pid": os.getpid(),
            },
            sort_keys=True,
        )
        assert actual_policy == policy
        model_request = protocol._thin_frontier_model_request(
            actual_request, actual_policy
        )
        model_response = _response(actual_request, observation)
        return AttestedModelUtilityExchange(
            response=model_response,
            producer_receipt=_producer_receipt(
                producer_signer,
                actual_request,
                actual_policy,
                model_request,
                model_response,
            ),
        )

    def run_spy(launch: BoundedProcessLaunch) -> BoundedProcessResult:
        launches.append(launch)
        return _forked_worker(launch)

    monkeypatch.setattr(thin, "_fixed_model_exchange", fixed_exchange)
    monkeypatch.setattr(thin, "run_bounded_process", run_spy)
    key = Ed25519PrivateKey.generate()
    producer_key = Ed25519PrivateKey.generate()
    producer_signer = AuthoritySigner.from_private_bytes(producer_key.private_bytes_raw())
    monkeypatch.setattr(
        thin,
        "_load_operator_producer_signing_key",
        lambda: producer_key.private_bytes_raw(),
    )
    encoded = thin.run_thin_frontier_arm(
        request=request,
        policy=policy,
        signing_key=key.private_bytes_raw(),
    )
    response = verify_real_arm_response(
        encoded=encoded,
        request=request,
        policy=policy,
        public_key=key.public_key(),
        producer_trust_registry={
            producer_signer.key_id: producer_signer.public_key_record
        },
        minimum_producer_sequence=1,
        expected_session_id=_SESSION_ID,
        expected_evaluator_challenge=_CHALLENGE,
    )
    assert len(launches) == 1
    launch = launches[0]
    assert launch.argv == thin._fixed_worker_argv(
        cast(tuple[int, int, int, int, int], launch.pass_fds)
    )
    observation = json.loads(response.observation)
    assert observation["calls"] == 1
    assert tuple(observation["cpu_limit"]) == (policy.budget.cpu_seconds,) * 2
    assert tuple(observation["memory_limit"]) == (
        policy.budget.maximum_address_space_bytes,
    ) * 2
    assert observation["forbidden_loaded"] == []
    assert observation["worker_pid"] != os.getpid()
    for descriptor in launch.pass_fds:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert response.dispatch_count == response.model_calls == response.model_snapshot_loads == 1
    assert response.runtime_class == "thin_frontier_reference"
    assert response.runtime_implementation_digest == thin.thin_frontier_implementation_digest()
    assert response.policy_digest == policy.policy_digest
    assert response.tool_dispatches == 0
    assert all(item.status == "absent" for item in response.component_trace)
    assert not any(response.component_use.model_dump(mode="python").values())


def test_rejects_a_model_response_with_different_request_binding() -> None:
    policy = _policy()
    request = _request(policy)
    key = Ed25519PrivateKey.generate()
    response = thin._execute_and_sign
    assert tuple(inspect.signature(response).parameters) == (
        "request",
        "policy",
        "signing_key",
        "producer_signer",
    )
    contaminated = _response(request).model_copy(update={"request_id": "other.request"})
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            thin,
            "_fixed_model_exchange",
            lambda _request, _policy, _producer_signer: AttestedModelUtilityExchange(
                response=contaminated,
                producer_receipt=_producer_receipt(
                    AuthoritySigner.generate(),
                    request,
                    policy,
                    protocol._thin_frontier_model_request(request, policy),
                    _response(request),
                ),
            ),
        )
        with pytest.raises(ValueError, match="response binding"):
            response(
                request=request,
                policy=policy,
                signing_key=key,
                producer_signer=AuthoritySigner.generate(),
            )


def test_resource_limit_failure_stops_before_exchange_and_cleans_public_fds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    request = _request(policy)
    audit_read, audit_write = os.pipe()
    launches: list[BoundedProcessLaunch] = []

    def fail_limit(kind: int, _limits: tuple[int, int]) -> None:
        _ = os.write(audit_write, str(kind).encode("ascii"))
        raise OSError("denied")

    def forbidden_exchange(
        _request: T40ArmRequest,
        _policy: T40ArmPolicy,
        _producer_signer: AuthoritySigner,
    ) -> AttestedModelUtilityExchange:
        raise AssertionError("model exchange must not run after limit failure")

    def run_spy(launch: BoundedProcessLaunch) -> BoundedProcessResult:
        launches.append(launch)
        result = _forked_worker(launch)
        os.close(audit_write)
        return result

    monkeypatch.setattr(thin.resource, "setrlimit", fail_limit)
    monkeypatch.setattr(thin, "_fixed_model_exchange", forbidden_exchange)
    monkeypatch.setattr(thin, "run_bounded_process", run_spy)
    with pytest.raises(thin.T40ThinFrontierError, match="invalid process result"):
        thin._run_thin_frontier_arm_with_producer_key(
            request=request,
            policy=policy,
            signing_key=Ed25519PrivateKey.generate().private_bytes_raw(),
            producer_signing_key=Ed25519PrivateKey.generate().private_bytes_raw(),
        )
    assert os.read(audit_read, 64) == str(resource.RLIMIT_CPU).encode("ascii")
    os.close(audit_read)
    assert len(launches) == 1
    for descriptor in launches[0].pass_fds:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_fixed_launcher_rejects_callable_argv_path_and_arm_injection() -> None:
    assert tuple(inspect.signature(thin.run_thin_frontier_arm).parameters) == (
        "request",
        "policy",
        "signing_key",
    )
    assert not {
        "handler",
        "worker_argv",
        "module",
        "path",
        "resolver",
        "environment",
    }.intersection(inspect.signature(thin.run_thin_frontier_arm).parameters)
    argv = thin._fixed_worker_argv((10, 11, 12, 13, 14))
    assert argv == (
        "/usr/bin/python3",
        "-S",
        "-B",
        "-m",
        "faultloom.t40_thin_frontier_arm",
        "10",
        "11",
        "12",
        "13",
        "14",
    )
    assert thin.main.__doc__ and "five predetermined numeric descriptors" in thin.main.__doc__


def test_public_launcher_rejects_caller_selected_producer_authority() -> None:
    policy = _policy()
    request = _request(policy)
    caller_key = Ed25519PrivateKey.generate().private_bytes_raw()
    public_launcher = cast(Any, thin.run_thin_frontier_arm)
    with pytest.raises(TypeError):
        public_launcher(
            request=request,
            policy=policy,
            signing_key=Ed25519PrivateKey.generate().private_bytes_raw(),
            producer_signing_key=caller_key,
        )
    assert "_run_thin_frontier_arm_with_producer_key" not in thin.__all__
    assert "_load_operator_producer_signing_key" not in thin.__all__


def _root_metadata(value: os.stat_result, **updates: int) -> SimpleNamespace:
    fields = {
        "st_mode": value.st_mode,
        "st_uid": 0,
        "st_gid": 0,
        "st_nlink": value.st_nlink,
        "st_dev": value.st_dev,
        "st_ino": value.st_ino,
        "st_size": value.st_size,
        "st_mtime_ns": value.st_mtime_ns,
        "st_ctime_ns": value.st_ctime_ns,
    }
    fields.update(updates)
    return SimpleNamespace(**fields)


def test_operator_key_loader_rejects_symlink_owner_mode_size_and_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = os.fspath(tmp_path)
    target = os.path.join(directory, "producer-key")
    link = os.path.join(directory, "producer-key-link")
    with open(target, "wb") as stream:
        stream.write(b"K" * 32)
    os.chmod(target, 0o600)
    os.symlink(target, link)

    monkeypatch.setattr(thin, "_PRODUCER_SIGNING_KEY_PATH", thin.Path(link))
    with pytest.raises(ValueError, match="unavailable"):
        thin._load_operator_producer_signing_key()

    monkeypatch.setattr(thin, "_PRODUCER_SIGNING_KEY_PATH", thin.Path(target))
    with pytest.raises(ValueError, match="metadata"):
        thin._load_operator_producer_signing_key()

    original_fstat = os.fstat
    original_stat = os.stat
    actual = original_stat(target, follow_symlinks=False)
    monkeypatch.setattr(
        thin.os,
        "fstat",
        lambda descriptor: _root_metadata(
            original_fstat(descriptor), st_mode=stat.S_IFREG | 0o644
        ),
    )
    monkeypatch.setattr(
        thin.os,
        "stat",
        lambda _path, *, follow_symlinks: _root_metadata(
            actual, st_mode=stat.S_IFREG | 0o644
        ),
    )
    with pytest.raises(ValueError, match="metadata"):
        thin._load_operator_producer_signing_key()

    monkeypatch.setattr(
        thin.os,
        "fstat",
        lambda descriptor: _root_metadata(original_fstat(descriptor)),
    )
    monkeypatch.setattr(
        thin.os,
        "stat",
        lambda _path, *, follow_symlinks: _root_metadata(actual),
    )
    with open(target, "wb") as stream:
        stream.write(b"S" * 31)
    os.chmod(target, 0o600)
    actual = original_stat(target, follow_symlinks=False)
    with pytest.raises(ValueError, match="length"):
        thin._load_operator_producer_signing_key()

    with open(target, "wb") as stream:
        stream.write(b"R" * 32)
    os.chmod(target, 0o600)
    actual = original_stat(target, follow_symlinks=False)
    calls = 0

    def replaced_fstat(descriptor: int) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        return _root_metadata(
            original_fstat(descriptor),
            st_ino=actual.st_ino if calls == 1 else actual.st_ino + 1,
        )

    monkeypatch.setattr(thin.os, "fstat", replaced_fstat)
    monkeypatch.setattr(
        thin.os,
        "stat",
        lambda _path, *, follow_symlinks: _root_metadata(actual, st_ino=actual.st_ino + 1),
    )
    with pytest.raises(ValueError, match="changed"):
        thin._load_operator_producer_signing_key()


@pytest.mark.skipif(
    os.environ.get("FAULTLOOM_T40_REAL_PROFILE_SMOKE") != "1",
    reason="opt-in single heavy fixed-profile model call",
)
def test_opt_in_real_profile_smoke_performs_one_model_call() -> None:
    policy = _policy()
    request = _request(policy)
    key = Ed25519PrivateKey.generate()
    producer_key = thin._load_operator_producer_signing_key()
    producer_signer = AuthoritySigner.from_private_bytes(producer_key)
    encoded = thin.run_thin_frontier_arm(
        request=request,
        policy=policy,
        signing_key=key.private_bytes_raw(),
    )
    response = verify_real_arm_response(
        encoded=encoded,
        request=request,
        policy=policy,
        public_key=key.public_key(),
        producer_trust_registry={
            producer_signer.key_id: producer_signer.public_key_record
        },
        minimum_producer_sequence=1,
        expected_session_id=_SESSION_ID,
        expected_evaluator_challenge=_CHALLENGE,
    )
    assert response.model_calls == response.dispatch_count == 1
    assert response.tool_dispatches == 0
