"""Signed observations for fixed formal T40 real-arm implementations."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Annotated, ClassVar, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from faultloom_protocol import (
    Ed25519PublicKeyRecord,
    SignedModelProducerAttestation,
    verify_model_producer_attestation,
)
from faultloom_sdk import ModelUtilityArm, UtilityDecision
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST,
    LocalModelProcessConfig,
    LocalModelProcessRequest,
    LocalModelProcessResponse,
    LocalModelRuntimeProfile,
)
from .t40_arm_runtime import (
    T40ArmPolicy,
    T40ArmRequest,
    T40ArmRuntimeError,
    canonical_json_bytes,
)

Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")]
RealArmIdentifier = Literal["thin_frontier", "faultloom"]
RealRuntimeClass = Literal["thin_frontier_reference", "faultloom_v2"]
FaultLoomComponent = Literal[
    "context_compiler",
    "specialist",
    "tool_planner",
    "t32",
    "t33",
    "t34",
    "t35",
    "adapters",
]
_FAULTLOOM_COMPONENTS: tuple[FaultLoomComponent, ...] = (
    "context_compiler",
    "specialist",
    "tool_planner",
    "t32",
    "t33",
    "t34",
    "t35",
    "adapters",
)
_SCHEMA_FAULTLOOM_RUN_KEYS = frozenset(
    ("control", *(f"off.{item}" for item in _FAULTLOOM_COMPONENTS))
)
_MAX_MODEL_PAYLOAD_BYTES = 4096
_MAX_FAULTLOOM_MODEL_PAYLOAD_BYTES = 32_768


class _StrictModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class T40ComponentUse(_StrictModel):
    """Explicit absence record for state and FaultLoom-only machinery."""

    context_compiler: bool = False
    specialist: bool = False
    tool_planner: bool = False
    t32: bool = False
    t33: bool = False
    t34: bool = False
    t35: bool = False
    adapters: bool = False
    semantic_depth: bool = False
    patch_variant: bool = False
    chain: bool = False
    identity_workflow: bool = False
    pack: bool = False
    cross_call_state: Literal[False] = False


class _T40ComponentTrace(_StrictModel):
    component: FaultLoomComponent
    status: Literal["absent", "used", "disabled", "blocked"]
    trace_digest: Sha256Digest


class _T40ComponentContext(_StrictModel):
    """Bounded, redacted actual facts made visible to the one model call."""

    component: Identifier
    summary: Annotated[str, Field(min_length=2, max_length=16_384)]

    @model_validator(mode="after")
    def _summary_is_canonical_json(self) -> Self:
        try:
            value = json.loads(self.summary)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise T40ArmRuntimeError("component context summary is malformed") from None
        if canonical_json_bytes(value).decode("ascii") != self.summary:
            raise T40ArmRuntimeError("component context summary is not canonical JSON")
        return self


class T40RealArmResponse(_StrictModel):
    """Canonical evidence from one pinned model call by one static real arm."""

    schema_version: Literal["faultloom.t40-real-arm-response.v1"] = (
        "faultloom.t40-real-arm-response.v1"
    )
    provenance_kind: Literal["real_arm"] = "real_arm"
    request_id: str
    arm_id: RealArmIdentifier
    runtime_class: RealRuntimeClass
    case_digest: Sha256Digest
    request_digest: Sha256Digest
    private_input_digest: Sha256Digest
    policy_digest: Sha256Digest
    model_snapshot_digest: Sha256Digest
    model_runtime_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    gateway_policy_digest: Sha256Digest
    safety_policy_digest: Sha256Digest
    generation_config_digest: Sha256Digest
    budget_digest: Sha256Digest
    runtime_artifact_digest: Sha256Digest
    runtime_implementation_digest: Sha256Digest
    run_key: str
    disabled_component: FaultLoomComponent | None
    component_trace: tuple[_T40ComponentTrace, ...]
    component_trace_digest: Sha256Digest
    component_context: tuple[_T40ComponentContext, ...] = ()
    component_context_digest: Sha256Digest = Field(default_factory=lambda: _digest_json(()))
    model_response_digest: Sha256Digest
    model_decision: UtilityDecision
    model_output_digest: Sha256Digest
    raw_model_stdout_digest: Sha256Digest
    observation: Annotated[str, Field(max_length=4096)]
    observation_digest: Sha256Digest
    model_snapshot_loads: Literal[1]
    model_calls: Literal[1]
    dispatch_count: Literal[1]
    tool_dispatches: Literal[0]
    dispatched_oos: Literal[0]
    escaped_oos: Literal[0]
    safety_violations: Literal[0]
    input_tokens: Annotated[int, Field(strict=True, ge=0)]
    output_tokens: Annotated[int, Field(strict=True, ge=0)]
    component_use: T40ComponentUse
    producer_receipt: SignedModelProducerAttestation
    signing_key_digest: Sha256Digest
    signature: Annotated[str, Field(min_length=88, max_length=88)]

    @model_validator(mode="after")
    def _runtime_class_matches_arm(self) -> Self:
        expected: dict[str, str] = {
            "thin_frontier": "thin_frontier_reference",
            "faultloom": "faultloom_v2",
        }
        if self.runtime_class != expected[self.arm_id]:
            raise T40ArmRuntimeError("real-arm runtime class does not match its arm")
        expected_components = _FAULTLOOM_COMPONENTS
        if tuple(item.component for item in self.component_trace) != expected_components:
            raise T40ArmRuntimeError("real-arm component trace is incomplete or unordered")
        if self.component_trace_digest != _digest_json(
            tuple(item.model_dump(mode="json") for item in self.component_trace)
        ):
            raise T40ArmRuntimeError("real-arm component trace digest mismatch")
        if self.component_context_digest != _digest_json(
            tuple(item.model_dump(mode="json") for item in self.component_context)
        ):
            raise T40ArmRuntimeError("real-arm component context digest mismatch")
        statuses = tuple(item.status for item in self.component_trace)
        if self.arm_id == "thin_frontier":
            if (
                self.run_key != "control"
                or self.disabled_component is not None
                or self.component_context
                or any(status != "absent" for status in statuses)
                or any(self.component_use.model_dump(mode="python").values())
            ):
                raise T40ArmRuntimeError("thin-frontier component-use record is contaminated")
        else:
            if self.run_key not in _SCHEMA_FAULTLOOM_RUN_KEYS:
                raise T40ArmRuntimeError("FaultLoom run key is not registered")
            expected_disabled = (
                None if self.run_key == "control" else self.run_key.removeprefix("off.")
            )
            if self.disabled_component != expected_disabled:
                raise T40ArmRuntimeError("FaultLoom disabled component does not match its run key")
            expected_statuses = tuple(
                "disabled"
                if item == expected_disabled
                else "blocked"
                if item == "t35" and expected_disabled in {"t32", "t33"}
                else "used"
                for item in expected_components
            )
            if statuses != expected_statuses:
                raise T40ArmRuntimeError("FaultLoom component trace does not match its ablation")
            context_names = tuple(item.component for item in self.component_context)
            expected_context = tuple(
                sorted(
                    {
                        "semantic_depth",
                        "web_pack",
                        *(() if expected_disabled == "context_compiler" else ("context_compiler",)),
                        *(() if expected_disabled == "specialist" else ("specialist",)),
                        *(() if expected_disabled == "tool_planner" else ("tool_planner",)),
                        *(() if expected_disabled == "t34" else ("patch_variant",)),
                        *(() if expected_disabled == "adapters" else ("adapter_use",)),
                    }
                )
            )
            if context_names != expected_context:
                raise T40ArmRuntimeError("FaultLoom component context does not match its ablation")
            component_values = self.component_use.model_dump(mode="python")
            for component, status in zip(expected_components, statuses, strict=True):
                if component_values[component] is not (status == "used"):
                    raise T40ArmRuntimeError("FaultLoom component-use flags contradict its trace")
        return self


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _digest_json(value: object) -> str:
    return _digest_bytes(canonical_json_bytes(value))


def _request_digest(request: T40ArmRequest) -> str:
    return _digest_json(request.model_dump(mode="json"))


def _canonical_local_model_bytes(
    value: LocalModelProcessRequest | LocalModelProcessResponse,
) -> bytes:
    return json.dumps(
        value.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _thin_frontier_model_request(
    request: T40ArmRequest,
    policy: T40ArmPolicy,
) -> LocalModelProcessRequest:
    """Derive the only model-process request admitted by the thin arm."""

    payload = canonical_json_bytes(
        {
            "arm_contract": "thin_frontier_reference",
            "budget": policy.budget.model_dump(mode="json"),
            "dispatch_route": policy.dispatch_route,
            "gateway_policy_digest": policy.gateway_policy_digest,
            "generation_config_digest": policy.generation_config_digest,
            "network_route": policy.network_route,
            "private_input": request.private_input,
            "requested_tools": request.requested_tools,
            "safety_policy_digest": policy.safety_policy_digest,
            "tool_inventory": policy.allowed_tools,
            "tool_schema_digest": policy.tool_schema_digest,
        }
    )
    if len(payload) > _MAX_MODEL_PAYLOAD_BYTES:
        raise T40ArmRuntimeError("thin-frontier model-visible input exceeds its fixed limit")
    return LocalModelProcessRequest(
        request_id=request.request_id,
        case_id=request.request_id,
        case_digest=request.case_digest,
        arm=ModelUtilityArm.BASELINE,
        model_snapshot_digest=request.model_snapshot_digest,
        runtime_artifact_digest=request.model_runtime_digest,
        prompt_digest=_digest_bytes(payload),
        tool_schema_digest=request.tool_schema_digest,
        budget_digest=request.budget_digest,
        generation_config_digest=request.generation_config_digest,
        seed=42,
        payload=payload.decode("ascii"),
    )


def _faultloom_model_request(
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    *,
    component_trace: tuple[_T40ComponentTrace, ...],
    component_context: tuple[_T40ComponentContext, ...],
) -> LocalModelProcessRequest:
    """Bind the one FaultLoom model call to canonical actual component receipts."""

    if request.arm_id != "faultloom":
        raise T40ArmRuntimeError("FaultLoom model request rejects a different arm")
    payload = canonical_json_bytes(
        {
            "arm_contract": "faultloom_v2",
            "budget": policy.budget.model_dump(mode="json"),
            "component_trace": tuple(item.model_dump(mode="json") for item in component_trace),
            "component_context": tuple(item.model_dump(mode="json") for item in component_context),
            "dispatch_route": policy.dispatch_route,
            "gateway_policy_digest": policy.gateway_policy_digest,
            "generation_config_digest": policy.generation_config_digest,
            "network_route": policy.network_route,
            "private_input_digest": request.private_input_digest,
            "requested_tools": request.requested_tools,
            "run_key": request.run_key,
            "safety_policy_digest": policy.safety_policy_digest,
            "tool_inventory": policy.allowed_tools,
            "tool_schema_digest": policy.tool_schema_digest,
        }
    )
    if len(payload) > _MAX_FAULTLOOM_MODEL_PAYLOAD_BYTES:
        raise T40ArmRuntimeError("FaultLoom model-visible input exceeds its fixed limit")
    return LocalModelProcessRequest(
        request_id=request.request_id,
        case_id=request.request_id,
        case_digest=request.case_digest,
        arm=ModelUtilityArm.TREATMENT,
        model_snapshot_digest=request.model_snapshot_digest,
        runtime_artifact_digest=request.model_runtime_digest,
        prompt_digest=_digest_bytes(payload),
        tool_schema_digest=request.tool_schema_digest,
        budget_digest=request.budget_digest,
        generation_config_digest=request.generation_config_digest,
        seed=42,
        payload=payload.decode("ascii"),
    )


def _model_response_from_arm(response: T40RealArmResponse) -> LocalModelProcessResponse:
    return LocalModelProcessResponse(
        request_id=response.request_id,
        model_snapshot_digest=response.model_snapshot_digest,
        runtime_artifact_digest=response.runtime_artifact_digest,
        decision=response.model_decision,
        output=response.observation,
        output_digest=response.model_output_digest,
        raw_llama_stdout_digest=response.raw_model_stdout_digest,
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
    )


def _profile_digest(config: LocalModelProcessConfig) -> str:
    return _digest_bytes(
        json.dumps(
            config.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _producer_payload_matches(
    *,
    producer_receipt: SignedModelProducerAttestation,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    model_request: LocalModelProcessRequest,
    model_response: LocalModelProcessResponse,
) -> bool:
    payload = producer_receipt.payload
    config = LocalModelProcessConfig(
        profile=LocalModelRuntimeProfile.FAULTLOOM_UTILITY_V1,
        timeout_seconds=policy.budget.timeout_seconds,
        maximum_request_bytes=65_536,
        maximum_response_bytes=policy.budget.maximum_response_bytes,
    )
    return (
        payload.session_id == request.session_id
        and payload.evaluator_challenge == request.evaluator_challenge
        and payload.canonical_request_digest
        == _digest_bytes(_canonical_local_model_bytes(model_request))
        and payload.parsed_response_digest
        == _digest_bytes(_canonical_local_model_bytes(model_response))
        and payload.raw_llama_stdout_digest == model_response.raw_llama_stdout_digest
        and payload.output_digest == model_response.output_digest
        and payload.model_digest == model_request.model_snapshot_digest
        and payload.runtime_wrapper_digest == model_request.runtime_artifact_digest
        and payload.runtime_bundle_digest == config.runtime_bundle_digest
        and payload.bwrap_digest == FAULTLOOM_UTILITY_V1_SANDBOX_DIGEST
        and payload.core_wheel_digest == request.core_wheel_digest
        and payload.profile_digest == _profile_digest(config)
        and payload.status == "accepted"
        and payload.prompt_tokens == model_response.input_tokens
        and payload.completion_tokens == model_response.output_tokens
        and payload.total_tokens == model_response.input_tokens + model_response.output_tokens
    )


def _policy_bindings_match(request: T40ArmRequest, policy: T40ArmPolicy) -> bool:
    return (
        request.model_snapshot_digest,
        request.model_runtime_digest,
        request.tool_schema_digest,
        request.gateway_policy_digest,
        request.safety_policy_digest,
        request.generation_config_digest,
        request.budget_digest,
        request.policy_digest,
    ) == (
        policy.model_snapshot_digest,
        policy.model_runtime_digest,
        policy.tool_schema_digest,
        policy.gateway_policy_digest,
        policy.safety_policy_digest,
        policy.generation_config_digest,
        policy.budget_digest,
        policy.policy_digest,
    )


def _unsigned_response(response: T40RealArmResponse) -> dict[str, object]:
    values = response.model_dump(mode="json")
    del values["signature"]
    return values


def _sign_thin_frontier_response(
    *,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    model_request: LocalModelProcessRequest,
    model_response: LocalModelProcessResponse,
    producer_receipt: SignedModelProducerAttestation,
    runtime_implementation_digest: str,
    signing_key: Ed25519PrivateKey,
) -> T40RealArmResponse:
    """Private signer for the one static thin-frontier provenance."""

    if type(request) is not T40ArmRequest or type(policy) is not T40ArmPolicy:
        raise T40ArmRuntimeError("real arm requires exact request and policy values")
    if request.arm_id != "thin_frontier":
        raise T40ArmRuntimeError("thin-frontier signer rejects a different arm")
    if not _policy_bindings_match(request, policy):
        raise T40ArmRuntimeError("shared policy binding mismatch")
    if request.arm_runtime_digest != runtime_implementation_digest:
        raise T40ArmRuntimeError("real-arm implementation digest mismatch")
    if any(tool not in policy.allowed_tools for tool in request.requested_tools):
        raise T40ArmRuntimeError("requested tool is not admitted")
    expected_model_request = _thin_frontier_model_request(request, policy)
    if (
        type(model_request) is not LocalModelProcessRequest
        or model_request != expected_model_request
    ):
        raise T40ArmRuntimeError("thin-frontier model request binding mismatch")
    if type(model_response) is not LocalModelProcessResponse:
        raise T40ArmRuntimeError("real arm requires an exact pinned-model response")
    if (
        model_response.request_id != request.request_id
        or model_response.model_snapshot_digest != request.model_snapshot_digest
        or model_response.runtime_artifact_digest != request.model_runtime_digest
    ):
        raise T40ArmRuntimeError("pinned-model response binding mismatch")
    if (
        model_response.input_tokens > policy.budget.maximum_input_tokens
        or model_response.output_tokens > policy.budget.maximum_output_tokens
    ):
        raise T40ArmRuntimeError("real arm exceeded its shared token budget")
    if type(
        producer_receipt
    ) is not SignedModelProducerAttestation or not _producer_payload_matches(
        producer_receipt=producer_receipt,
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=model_response,
    ):
        raise T40ArmRuntimeError("producer receipt does not bind the exact model exchange")

    component_trace = tuple(
        _T40ComponentTrace(
            component=component,
            status="absent",
            trace_digest=_digest_json(
                {"arm": "thin_frontier", "component": component, "status": "absent"}
            ),
        )
        for component in _FAULTLOOM_COMPONENTS
    )

    request_digest = _request_digest(request)
    response_digest = _digest_json(model_response.model_dump(mode="json"))
    observation_digest = _digest_json(
        {
            "model_output_digest": model_response.output_digest,
            "model_response_digest": response_digest,
            "request_digest": request_digest,
        }
    )
    public_key = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    values: dict[str, object] = {
        "request_id": request.request_id,
        "arm_id": "thin_frontier",
        "runtime_class": "thin_frontier_reference",
        "case_digest": request.case_digest,
        "request_digest": request_digest,
        "private_input_digest": request.private_input_digest,
        "policy_digest": request.policy_digest,
        "model_snapshot_digest": request.model_snapshot_digest,
        "model_runtime_digest": request.model_runtime_digest,
        "tool_schema_digest": request.tool_schema_digest,
        "gateway_policy_digest": request.gateway_policy_digest,
        "safety_policy_digest": request.safety_policy_digest,
        "generation_config_digest": request.generation_config_digest,
        "budget_digest": request.budget_digest,
        "runtime_artifact_digest": model_response.runtime_artifact_digest,
        "runtime_implementation_digest": runtime_implementation_digest,
        "run_key": "control",
        "disabled_component": None,
        "component_trace": component_trace,
        "component_trace_digest": _digest_json(
            tuple(item.model_dump(mode="json") for item in component_trace)
        ),
        "component_context": (),
        "component_context_digest": _digest_json(()),
        "model_response_digest": response_digest,
        "model_decision": model_response.decision,
        "model_output_digest": model_response.output_digest,
        "raw_model_stdout_digest": model_response.raw_llama_stdout_digest,
        "observation": model_response.output,
        "observation_digest": observation_digest,
        "model_snapshot_loads": 1,
        "model_calls": 1,
        "dispatch_count": 1,
        "tool_dispatches": 0,
        "dispatched_oos": 0,
        "escaped_oos": 0,
        "safety_violations": 0,
        "input_tokens": model_response.input_tokens,
        "output_tokens": model_response.output_tokens,
        "component_use": T40ComponentUse(),
        "producer_receipt": producer_receipt,
        "signing_key_digest": _digest_bytes(public_key),
    }
    unsigned = T40RealArmResponse.model_validate({"signature": "A" * 88, **values})
    signature = base64.b64encode(
        signing_key.sign(canonical_json_bytes(_unsigned_response(unsigned)))
    ).decode("ascii")
    return T40RealArmResponse.model_validate({"signature": signature, **values})


def _sign_faultloom_response(
    *,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    model_request: LocalModelProcessRequest,
    model_response: LocalModelProcessResponse,
    producer_receipt: SignedModelProducerAttestation,
    component_trace: tuple[_T40ComponentTrace, ...],
    component_context: tuple[_T40ComponentContext, ...],
    component_use: T40ComponentUse,
    runtime_implementation_digest: str,
    signing_key: Ed25519PrivateKey,
) -> T40RealArmResponse:
    """Sign one actual FaultLoom run after validating every producer binding."""

    if type(request) is not T40ArmRequest or type(policy) is not T40ArmPolicy:
        raise T40ArmRuntimeError("FaultLoom requires exact request and policy values")
    if request.arm_id != "faultloom" or not _policy_bindings_match(request, policy):
        raise T40ArmRuntimeError("FaultLoom response binding mismatch")
    if any(tool not in policy.allowed_tools for tool in request.requested_tools):
        raise T40ArmRuntimeError("requested tool is not admitted")
    expected_request = _faultloom_model_request(
        request,
        policy,
        component_trace=component_trace,
        component_context=component_context,
    )
    if model_request != expected_request:
        raise T40ArmRuntimeError("FaultLoom model request binding mismatch")
    if (
        type(model_response) is not LocalModelProcessResponse
        or model_response.request_id != request.request_id
        or model_response.model_snapshot_digest != request.model_snapshot_digest
        or model_response.runtime_artifact_digest != request.model_runtime_digest
    ):
        raise T40ArmRuntimeError("pinned-model response binding mismatch")
    if (
        model_response.input_tokens > policy.budget.maximum_input_tokens
        or model_response.output_tokens > policy.budget.maximum_output_tokens
    ):
        raise T40ArmRuntimeError("real arm exceeded its shared token budget")
    if not _producer_payload_matches(
        producer_receipt=producer_receipt,
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=model_response,
    ):
        raise T40ArmRuntimeError("producer receipt does not bind the exact model exchange")
    request_digest = _request_digest(request)
    response_digest = _digest_json(model_response.model_dump(mode="json"))
    observation_digest = _digest_json(
        {
            "model_output_digest": model_response.output_digest,
            "model_response_digest": response_digest,
            "request_digest": request_digest,
        }
    )
    public_key = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    disabled = None if request.run_key == "control" else request.run_key.removeprefix("off.")
    values: dict[str, object] = {
        "request_id": request.request_id,
        "arm_id": "faultloom",
        "runtime_class": "faultloom_v2",
        "case_digest": request.case_digest,
        "request_digest": request_digest,
        "private_input_digest": request.private_input_digest,
        "policy_digest": request.policy_digest,
        "model_snapshot_digest": request.model_snapshot_digest,
        "model_runtime_digest": request.model_runtime_digest,
        "tool_schema_digest": request.tool_schema_digest,
        "gateway_policy_digest": request.gateway_policy_digest,
        "safety_policy_digest": request.safety_policy_digest,
        "generation_config_digest": request.generation_config_digest,
        "budget_digest": request.budget_digest,
        "runtime_artifact_digest": model_response.runtime_artifact_digest,
        "runtime_implementation_digest": runtime_implementation_digest,
        "run_key": request.run_key,
        "disabled_component": disabled,
        "component_trace": component_trace,
        "component_trace_digest": _digest_json(
            tuple(item.model_dump(mode="json") for item in component_trace)
        ),
        "component_context": component_context,
        "component_context_digest": _digest_json(
            tuple(item.model_dump(mode="json") for item in component_context)
        ),
        "model_response_digest": response_digest,
        "model_decision": model_response.decision,
        "model_output_digest": model_response.output_digest,
        "raw_model_stdout_digest": model_response.raw_llama_stdout_digest,
        "observation": model_response.output,
        "observation_digest": observation_digest,
        "model_snapshot_loads": 1,
        "model_calls": 1,
        "dispatch_count": 1,
        "tool_dispatches": 0,
        "dispatched_oos": 0,
        "escaped_oos": 0,
        "safety_violations": 0,
        "input_tokens": model_response.input_tokens,
        "output_tokens": model_response.output_tokens,
        "component_use": component_use,
        "producer_receipt": producer_receipt,
        "signing_key_digest": _digest_bytes(public_key),
    }
    unsigned = T40RealArmResponse.model_validate({"signature": "A" * 88, **values})
    signature = base64.b64encode(
        signing_key.sign(canonical_json_bytes(_unsigned_response(unsigned)))
    ).decode("ascii")
    return T40RealArmResponse.model_validate({"signature": signature, **values})


def verify_real_arm_response(
    *,
    encoded: bytes,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    public_key: Ed25519PublicKey,
    producer_trust_registry: dict[str, Ed25519PublicKeyRecord],
    minimum_producer_sequence: int,
    expected_session_id: str,
    expected_evaluator_challenge: str,
) -> T40RealArmResponse:
    """Verify canonical framing, complete bindings, model facts, and signature."""

    if type(encoded) is not bytes or not encoded.endswith(b"\n") or encoded.count(b"\n") != 1:
        raise T40ArmRuntimeError("real-arm response framing is invalid")
    try:
        response = T40RealArmResponse.model_validate_json(encoded[:-1])
    except ValueError:
        raise T40ArmRuntimeError("real-arm response is malformed") from None
    if encoded != canonical_json_bytes(response.model_dump(mode="json")) + b"\n":
        raise T40ArmRuntimeError("real-arm response is not canonical JSON")
    if not _policy_bindings_match(request, policy):
        raise T40ArmRuntimeError("shared policy binding mismatch")
    if any(tool not in policy.allowed_tools for tool in request.requested_tools):
        raise T40ArmRuntimeError("requested tool is not admitted")
    if (
        request.session_id is None
        or request.evaluator_challenge is None
        or request.trusted_minimum_sequence is None
        or request.core_wheel_digest is None
    ):
        raise T40ArmRuntimeError("real-arm producer attestation context is incomplete")
    if (
        minimum_producer_sequence != request.trusted_minimum_sequence + 1
        or not hmac.compare_digest(expected_session_id, request.session_id)
        or not hmac.compare_digest(expected_evaluator_challenge, request.evaluator_challenge)
    ):
        raise T40ArmRuntimeError("caller producer replay context does not match the arm request")
    expected_identity = (
        request.request_id,
        request.arm_id,
        request.case_digest,
        _request_digest(request),
        request.private_input_digest,
        request.policy_digest,
        request.model_snapshot_digest,
        request.model_runtime_digest,
        request.tool_schema_digest,
        request.gateway_policy_digest,
        request.safety_policy_digest,
        request.generation_config_digest,
        request.budget_digest,
        request.arm_runtime_digest,
    )
    observed_identity = (
        response.request_id,
        response.arm_id,
        response.case_digest,
        response.request_digest,
        response.private_input_digest,
        response.policy_digest,
        response.model_snapshot_digest,
        response.model_runtime_digest,
        response.tool_schema_digest,
        response.gateway_policy_digest,
        response.safety_policy_digest,
        response.generation_config_digest,
        response.budget_digest,
        response.runtime_implementation_digest,
    )
    if observed_identity != expected_identity:
        raise T40ArmRuntimeError("real-arm response binding mismatch")
    expected_observation = _digest_json(
        {
            "model_output_digest": response.model_output_digest,
            "model_response_digest": response.model_response_digest,
            "request_digest": response.request_digest,
        }
    )
    if not hmac.compare_digest(expected_observation, response.observation_digest):
        raise T40ArmRuntimeError("real-arm observation digest mismatch")
    raw_public_key = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if not hmac.compare_digest(_digest_bytes(raw_public_key), response.signing_key_digest):
        raise T40ArmRuntimeError("real-arm signing key binding mismatch")
    try:
        public_key.verify(
            base64.b64decode(response.signature, validate=True),
            canonical_json_bytes(_unsigned_response(response)),
        )
    except (InvalidSignature, ValueError):
        raise T40ArmRuntimeError("real-arm response signature is invalid") from None
    try:
        _ = verify_model_producer_attestation(
            response.producer_receipt,
            producer_trust_registry,
            minimum_sequence=minimum_producer_sequence,
            expected_session_id=expected_session_id,
            expected_evaluator_challenge=expected_evaluator_challenge,
        )
    except (TypeError, ValueError) as exc:
        raise T40ArmRuntimeError("real-arm producer receipt is untrusted") from exc
    model_request = (
        _thin_frontier_model_request(request, policy)
        if response.arm_id == "thin_frontier"
        else _faultloom_model_request(
            request,
            policy,
            component_trace=response.component_trace,
            component_context=response.component_context,
        )
    )
    model_response = _model_response_from_arm(response)
    if (
        model_response.input_tokens > policy.budget.maximum_input_tokens
        or model_response.output_tokens > policy.budget.maximum_output_tokens
    ):
        raise T40ArmRuntimeError("real arm exceeded its shared token budget")
    if response.model_response_digest != _digest_bytes(
        _canonical_local_model_bytes(model_response)
    ):
        raise T40ArmRuntimeError("real-arm parsed model response digest mismatch")
    if not _producer_payload_matches(
        producer_receipt=response.producer_receipt,
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=model_response,
    ):
        raise T40ArmRuntimeError("real-arm producer receipt exchange binding mismatch")
    return response


__all__ = [
    "T40ComponentUse",
    "T40RealArmResponse",
    "verify_real_arm_response",
]
