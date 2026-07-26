from __future__ import annotations

import hashlib
import inspect

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from faultloom import t40_arm_runtime as arm_runtime
from faultloom.t40_arm_runtime import (
    T40ArmPolicy,
    T40ArmRequest,
    T40ArmResponse,
    T40ResourceBudget,
    verify_arm_response,
)
from faultloom.t40_arm_worker import (
    T40ArmWorkerError,
    run_isolated_worker,
    serve_one,
)
from pydantic import ValidationError


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _policy() -> T40ArmPolicy:
    return T40ArmPolicy(
        model_snapshot_digest=_digest("1"),
        model_runtime_digest=_digest("2"),
        tool_schema_digest=_digest("3"),
        gateway_policy_digest=_digest("4"),
        safety_policy_digest=_digest("5"),
        generation_config_digest=_digest("6"),
        allowed_tools=("lab.browser.inspect", "lab.http.get"),
        budget=T40ResourceBudget(
            maximum_input_tokens=256,
            maximum_output_tokens=128,
            maximum_model_calls=1,
            maximum_tool_dispatches=2,
            timeout_seconds=3,
            cpu_seconds=2,
            maximum_address_space_bytes=1_073_741_824,
            maximum_response_bytes=65_536,
        ),
    )


def _request(
    *,
    policy: T40ArmPolicy | None = None,
    private_input: str = "owned sealed case",
    requested_tools: tuple[str, ...] = (),
) -> T40ArmRequest:
    policy = _policy() if policy is None else policy
    return T40ArmRequest(
        request_id="request.0001",
        arm_id="faultloom",
        arm_runtime_digest=_digest("7"),
        case_digest=_digest("8"),
        private_input_digest=f"sha256:{hashlib.sha256(private_input.encode()).hexdigest()}",
        policy_digest=policy.policy_digest,
        model_snapshot_digest=policy.model_snapshot_digest,
        model_runtime_digest=policy.model_runtime_digest,
        tool_schema_digest=policy.tool_schema_digest,
        gateway_policy_digest=policy.gateway_policy_digest,
        safety_policy_digest=policy.safety_policy_digest,
        generation_config_digest=policy.generation_config_digest,
        budget_digest=policy.budget_digest,
        requested_tools=requested_tools,
        private_input=private_input,
    )


def _run(
    request: T40ArmRequest,
    policy: T40ArmPolicy,
) -> tuple[bytes, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    return (
        run_isolated_worker(
            request=request,
            policy=policy,
            signing_key=private_key.private_bytes_raw(),
        ),
        private_key,
    )


def test_round_trip_uses_inherited_descriptors_and_canonical_response() -> None:
    policy = _policy()
    request = _request(policy=policy)
    encoded, private_key = _run(request, policy)
    response = verify_arm_response(
        encoded=encoded,
        request=request,
        policy=policy,
        public_key=private_key.public_key(),
    )
    assert response.request_digest
    assert response.private_input_digest == request.private_input_digest
    assert response.model_snapshot_digest == request.model_snapshot_digest
    assert response.model_runtime_digest == request.model_runtime_digest
    assert response.policy_digest == request.policy_digest
    assert response.budget_digest == request.budget_digest
    assert response.provenance_kind == "kernel_probe"
    assert response.model_snapshot_loads == response.model_calls == 0
    assert response.dispatch_trace == ()
    assert response.tool_dispatches == 0
    assert response.dispatched_oos == response.escaped_oos == 0


def test_independently_constructed_policy_mismatch_fails_closed() -> None:
    admitted = _policy()
    adversarial = T40ArmPolicy(
        model_snapshot_digest=admitted.model_snapshot_digest,
        model_runtime_digest=admitted.model_runtime_digest,
        tool_schema_digest=admitted.tool_schema_digest,
        gateway_policy_digest=admitted.gateway_policy_digest,
        safety_policy_digest=_digest("a"),
        generation_config_digest=admitted.generation_config_digest,
        allowed_tools=admitted.allowed_tools,
        budget=admitted.budget,
    )
    request = _request(policy=admitted)
    assert request.policy_digest != adversarial.policy_digest
    with pytest.raises(T40ArmWorkerError, match="invalid process result"):
        _run(request, adversarial)


def test_signed_response_cannot_be_replayed_for_a_different_valid_private_input() -> None:
    policy = _policy()
    request_a = _request(policy=policy, private_input="private case A")
    request_b = _request(policy=policy, private_input="private case B")
    encoded_a, private_key = _run(request_a, policy)
    with pytest.raises(ValueError, match="arm response binding mismatch"):
        verify_arm_response(
            encoded=encoded_a,
            request=request_b,
            policy=policy,
            public_key=private_key.public_key(),
        )


def test_rejects_path_based_private_input_and_unknown_tools() -> None:
    raw = _request().model_dump(mode="json")
    raw["private_input_path"] = "/private/case.json"
    with pytest.raises(ValidationError, match="private_input_path"):
        T40ArmRequest.model_validate(raw)

    policy = _policy()
    unknown = _request(policy=policy, requested_tools=("host.shell",))
    with pytest.raises(T40ArmWorkerError, match="invalid process result"):
        _run(unknown, policy)


def test_reviewer_callable_injection_exploit_is_unreachable() -> None:
    assert tuple(inspect.signature(serve_one).parameters) == (
        "request_fd",
        "response_fd",
        "signing_key_fd",
        "policy",
    )
    assert "execute_arm_request" not in arm_runtime.__dict__
    assert "real_arm" not in T40ArmResponse.model_json_schema()["properties"][
        "provenance_kind"
    ]["const"]
    with pytest.raises(TypeError, match="unexpected keyword argument 'handler'"):
        serve_one(  # type: ignore[call-arg]
            request_fd=3,
            response_fd=4,
            signing_key_fd=5,
            policy=_policy(),
            handler=lambda _request: object(),
        )


def test_rejects_arm_specific_policy_binding() -> None:
    policy = _policy()
    request = _request(policy=policy).model_copy(
        update={"gateway_policy_digest": _digest("a")}
    )
    with pytest.raises(T40ArmWorkerError, match="invalid process result"):
        _run(request, policy)
