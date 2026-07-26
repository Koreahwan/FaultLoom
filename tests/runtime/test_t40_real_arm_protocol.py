from __future__ import annotations

import base64
import hashlib
import inspect
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from faultloom import t40_real_arm_protocol as protocol
from faultloom.model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
    LocalModelProcessConfig,
    LocalModelProcessRequest,
    LocalModelProcessResponse,
    LocalModelRuntimeProfile,
)
from faultloom.t40_arm_runtime import T40ArmPolicy, T40ArmRequest, T40ResourceBudget
from faultloom.t40_real_arm_protocol import T40RealArmResponse, verify_real_arm_response
from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthoritySigner,
    ModelProducerAttestation,
    SignedModelProducerAttestation,
    attestation_signing_bytes,
    sha256_digest,
)
from faultloom_sdk import UtilityDecision
from pydantic import ValidationError

_SESSION_ID = "formal.session.1"
_CHALLENGE = "0123456789abcdef" * 4


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _policy() -> T40ArmPolicy:
    return T40ArmPolicy(
        model_snapshot_digest=_digest(b"model"),
        model_runtime_digest=_digest(b"runtime"),
        tool_schema_digest=_digest(b"tools"),
        gateway_policy_digest=_digest(b"gateway"),
        safety_policy_digest=_digest(b"safety"),
        generation_config_digest=_digest(b"generation"),
        allowed_tools=("lab.http.get",),
        budget=T40ResourceBudget(
            maximum_input_tokens=512,
            maximum_output_tokens=128,
            maximum_model_calls=1,
            maximum_tool_dispatches=1,
            timeout_seconds=10,
            cpu_seconds=5,
            maximum_address_space_bytes=1_073_741_824,
            maximum_response_bytes=65_536,
        ),
    )


def _request(policy: T40ArmPolicy) -> T40ArmRequest:
    private_input = "sealed private input"
    return T40ArmRequest(
        request_id="formal.request.1",
        arm_id="thin_frontier",
        arm_runtime_digest=_digest(b"thin implementation"),
        case_digest=_digest(b"case"),
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
        allocation_id="formal-allocation-1",
        trusted_minimum_sequence=0,
        core_wheel_digest=_digest(b"core wheel"),
    )


def _model_response(request: T40ArmRequest) -> LocalModelProcessResponse:
    output = "real model result"
    return LocalModelProcessResponse(
        request_id=request.request_id,
        model_snapshot_digest=request.model_snapshot_digest,
        runtime_artifact_digest=request.model_runtime_digest,
        decision=UtilityDecision.INCONCLUSIVE,
        output=output,
        output_digest=_digest(output.encode()),
        raw_llama_stdout_digest=_digest(b"actual raw llama stdout"),
        input_tokens=23,
        output_tokens=4,
    )


def _producer_receipt(
    *,
    signer: AuthoritySigner,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    model_request: LocalModelProcessRequest,
    model_response: LocalModelProcessResponse,
    sequence: int = 1,
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
        sequence=sequence,
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


def _signed() -> tuple[
    bytes,
    T40ArmRequest,
    T40ArmPolicy,
    Ed25519PrivateKey,
    AuthoritySigner,
]:
    policy = _policy()
    request = _request(policy)
    key = Ed25519PrivateKey.generate()
    producer_signer = AuthoritySigner.generate()
    model_request = protocol._thin_frontier_model_request(request, policy)
    model_response = _model_response(request)
    response = protocol._sign_thin_frontier_response(
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=model_response,
        producer_receipt=_producer_receipt(
            signer=producer_signer,
            request=request,
            policy=policy,
            model_request=model_request,
            model_response=model_response,
        ),
        runtime_implementation_digest=request.arm_runtime_digest,
        signing_key=key,
    )
    encoded = protocol.canonical_json_bytes(response.model_dump(mode="json")) + b"\n"
    return encoded, request, policy, key, producer_signer


def test_signature_binds_complete_request_policy_and_actual_model_digests() -> None:
    encoded, request, policy, key, producer_signer = _signed()
    response = verify_real_arm_response(
        encoded=encoded,
        request=request,
        policy=policy,
        public_key=key.public_key(),
        producer_trust_registry={producer_signer.key_id: producer_signer.public_key_record},
        minimum_producer_sequence=1,
        expected_session_id=_SESSION_ID,
        expected_evaluator_challenge=_CHALLENGE,
    )
    assert response.provenance_kind == "real_arm"
    assert response.request_digest
    assert response.private_input_digest == request.private_input_digest
    assert response.runtime_artifact_digest == request.model_runtime_digest
    assert response.runtime_implementation_digest == request.arm_runtime_digest
    assert response.model_response_digest
    assert response.model_output_digest == _digest(b"real model result")
    assert response.raw_model_stdout_digest == _digest(b"actual raw llama stdout")
    assert response.model_snapshot_loads == response.model_calls == response.dispatch_count == 1
    assert response.tool_dispatches == 0
    assert response.safety_violations == response.dispatched_oos == response.escaped_oos == 0
    assert response.run_key == "control" and response.disabled_component is None
    assert all(item.status == "absent" for item in response.component_trace)
    assert not any(response.component_use.model_dump(mode="python").values())


def test_fixture_or_caller_selected_provenance_cannot_mint_real_arm() -> None:
    assert "_sign_thin_frontier_response" not in protocol.__all__
    parameters = inspect.signature(protocol._sign_thin_frontier_response).parameters
    assert not {
        "handler",
        "fixture",
        "capability",
        "run_key",
        "component_trace",
    }.intersection(parameters)
    policy = _policy()
    request = _request(policy)
    faultloom_request = request.model_copy(update={"arm_id": "faultloom"})
    producer_signer = AuthoritySigner.generate()
    model_request = protocol._thin_frontier_model_request(request, policy)
    model_response = _model_response(request)
    with pytest.raises(ValueError, match="different arm"):
        protocol._sign_thin_frontier_response(
            request=faultloom_request,
            policy=policy,
            model_request=model_request,
            model_response=model_response,
            producer_receipt=_producer_receipt(
                signer=producer_signer,
                request=request,
                policy=policy,
                model_request=model_request,
                model_response=model_response,
            ),
            runtime_implementation_digest=request.arm_runtime_digest,
            signing_key=Ed25519PrivateKey.generate(),
        )
    document = T40RealArmResponse.model_json_schema()
    assert document["properties"]["provenance_kind"]["const"] == "real_arm"
    encoded, _, _, _, _ = _signed()
    values = protocol.T40RealArmResponse.model_validate_json(encoded).model_dump(mode="json")
    values["provenance_kind"] = "fixture_replay"
    with pytest.raises(ValidationError):
        T40RealArmResponse.model_validate(values)


def test_protocol_exposes_no_faultloom_signing_authority() -> None:
    assert "_FAULTLOOM_CAPABILITY" not in protocol.__dict__
    assert "_sign_real_arm_response" not in protocol.__dict__
    assert tuple(inspect.signature(protocol._sign_thin_frontier_response).parameters) == (
        "request",
        "policy",
        "model_request",
        "model_response",
        "producer_receipt",
        "runtime_implementation_digest",
        "signing_key",
    )


@pytest.mark.parametrize(
    ("overrides", "registry"),
    (
        ({"minimum_producer_sequence": 2}, None),
        ({"expected_session_id": "different.session"}, None),
        ({"expected_evaluator_challenge": "fedcba9876543210" * 4}, None),
        ({}, {}),
    ),
)
def test_verifier_rejects_replay_context_and_untrusted_producer(
    overrides: dict[str, object],
    registry: dict[str, object] | None,
) -> None:
    encoded, request, policy, key, producer_signer = _signed()
    arguments: dict[str, object] = {
        "encoded": encoded,
        "request": request,
        "policy": policy,
        "public_key": key.public_key(),
        "producer_trust_registry": registry
        if registry is not None
        else {producer_signer.key_id: producer_signer.public_key_record},
        "minimum_producer_sequence": 1,
        "expected_session_id": _SESSION_ID,
        "expected_evaluator_challenge": _CHALLENGE,
    }
    arguments.update(overrides)
    with pytest.raises(ValueError):
        verify_real_arm_response(**cast(Any, arguments))


def test_signer_rejects_mismatched_model_request_and_response() -> None:
    policy = _policy()
    request = _request(policy)
    model_request = protocol._thin_frontier_model_request(request, policy)
    model_response = _model_response(request)
    producer_signer = AuthoritySigner.generate()
    receipt = _producer_receipt(
        signer=producer_signer,
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=model_response,
    )
    with pytest.raises(ValueError, match="model request binding"):
        protocol._sign_thin_frontier_response(
            request=request,
            policy=policy,
            model_request=model_request.model_copy(update={"case_digest": _digest(b"other")}),
            model_response=model_response,
            producer_receipt=receipt,
            runtime_implementation_digest=request.arm_runtime_digest,
            signing_key=Ed25519PrivateKey.generate(),
        )
    with pytest.raises(ValueError, match="producer receipt"):
        protocol._sign_thin_frontier_response(
            request=request,
            policy=policy,
            model_request=model_request,
            model_response=_model_response(request).model_copy(
                update={"raw_llama_stdout_digest": _digest(b"different stdout")}
            ),
            producer_receipt=receipt,
            runtime_implementation_digest=request.arm_runtime_digest,
            signing_key=Ed25519PrivateKey.generate(),
        )


def test_caller_cannot_substitute_a_forged_producer_signature() -> None:
    policy = _policy()
    request = _request(policy)
    model_request = protocol._thin_frontier_model_request(request, policy)
    model_response = _model_response(request)
    producer_signer = AuthoritySigner.generate()
    receipt = _producer_receipt(
        signer=producer_signer,
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=model_response,
    )
    forged = receipt.model_copy(update={"signature": "A" * 86})
    arm_key = Ed25519PrivateKey.generate()
    response = protocol._sign_thin_frontier_response(
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=model_response,
        producer_receipt=forged,
        runtime_implementation_digest=request.arm_runtime_digest,
        signing_key=arm_key,
    )
    encoded = protocol.canonical_json_bytes(response.model_dump(mode="json")) + b"\n"
    with pytest.raises(ValueError, match="producer receipt is untrusted"):
        verify_real_arm_response(
            encoded=encoded,
            request=request,
            policy=policy,
            public_key=arm_key.public_key(),
            producer_trust_registry={
                producer_signer.key_id: producer_signer.public_key_record
            },
            minimum_producer_sequence=1,
            expected_session_id=_SESSION_ID,
            expected_evaluator_challenge=_CHALLENGE,
        )
