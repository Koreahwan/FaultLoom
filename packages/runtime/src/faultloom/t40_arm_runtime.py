"""Shared, fail-closed protocol for one formal T40 arm call."""

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
from pydantic import BaseModel, ConfigDict, Field, model_validator


class T40ArmRuntimeError(ValueError):
    """A formal arm call failed before a trusted observation existed."""


class _StrictModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9._-]*$")]
AttestationIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"),
]
EvaluatorChallenge = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ArmIdentifier = Literal["legacy", "thin_frontier", "faultloom"]
T40RunKey = Literal[
    "control",
    "off.context_compiler",
    "off.specialist",
    "off.tool_planner",
    "off.t32",
    "off.t33",
    "off.t34",
    "off.t35",
    "off.adapters",
]


def canonical_json_bytes(value: object) -> bytes:
    """Encode a JSON-compatible value with the one accepted wire representation."""

    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise T40ArmRuntimeError("value is not canonical JSON") from exc


def _sha256(value: object) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


class T40ResourceBudget(_StrictModel):
    """Identical finite generation and host-resource budget for every arm."""

    maximum_input_tokens: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]
    maximum_output_tokens: Annotated[int, Field(strict=True, ge=1, le=1_000_000)]
    maximum_model_calls: Literal[1]
    maximum_tool_dispatches: Annotated[int, Field(strict=True, ge=0, le=1_000)]
    timeout_seconds: Annotated[int, Field(strict=True, ge=1, le=300)]
    cpu_seconds: Annotated[int, Field(strict=True, ge=1, le=300)]
    maximum_address_space_bytes: Annotated[
        int, Field(strict=True, ge=268_435_456, le=137_438_953_472)
    ]
    maximum_response_bytes: Annotated[int, Field(strict=True, ge=1, le=65_536)]


class T40ArmPolicy(_StrictModel):
    """The model-visible bindings shared unchanged by all three runtimes."""

    schema_version: Literal["faultloom.t40-arm-policy.v1"] = (
        "faultloom.t40-arm-policy.v1"
    )
    model_snapshot_digest: Sha256Digest
    model_runtime_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    gateway_policy_digest: Sha256Digest
    safety_policy_digest: Sha256Digest
    generation_config_digest: Sha256Digest
    allowed_tools: tuple[Identifier, ...]
    budget: T40ResourceBudget
    network_route: Literal["none"] = "none"
    dispatch_route: Literal["gateway"] = "gateway"

    @model_validator(mode="after")
    def _tool_inventory_is_canonical(self) -> Self:
        if not self.allowed_tools or tuple(sorted(set(self.allowed_tools))) != self.allowed_tools:
            raise T40ArmRuntimeError("allowed tool inventory must be sorted and unique")
        return self

    @property
    def policy_digest(self) -> str:
        return _sha256(self.model_dump(mode="json"))

    @property
    def budget_digest(self) -> str:
        return _sha256(self.budget.model_dump(mode="json"))


class T40ArmRequest(_StrictModel):
    """One private request read only from an inherited descriptor."""

    schema_version: Literal["faultloom.t40-arm-request.v1"] = (
        "faultloom.t40-arm-request.v1"
    )
    request_id: Identifier
    arm_id: ArmIdentifier
    run_key: T40RunKey = "control"
    arm_runtime_digest: Sha256Digest
    case_digest: Sha256Digest
    private_input_digest: Sha256Digest
    policy_digest: Sha256Digest
    model_snapshot_digest: Sha256Digest
    model_runtime_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    gateway_policy_digest: Sha256Digest
    safety_policy_digest: Sha256Digest
    generation_config_digest: Sha256Digest
    budget_digest: Sha256Digest
    requested_tools: tuple[Identifier, ...]
    private_input: Annotated[str, Field(min_length=1, max_length=1_048_576)]
    session_id: AttestationIdentifier | None = None
    evaluator_challenge: EvaluatorChallenge | None = None
    allocation_id: AttestationIdentifier | None = None
    trusted_minimum_sequence: Annotated[int, Field(strict=True, ge=0, lt=(2**63) - 1)] | None = None
    core_wheel_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def _private_input_digest_is_exact(self) -> Self:
        observed = f"sha256:{hashlib.sha256(self.private_input.encode()).hexdigest()}"
        if not hmac.compare_digest(observed, self.private_input_digest):
            raise T40ArmRuntimeError("private input digest mismatch")
        if tuple(sorted(set(self.requested_tools))) != self.requested_tools:
            raise T40ArmRuntimeError("requested tools must be sorted and unique")
        attestation_context = (
            self.session_id,
            self.evaluator_challenge,
            self.allocation_id,
            self.trusted_minimum_sequence,
            self.core_wheel_digest,
        )
        if self.arm_id == "thin_frontier" and any(value is None for value in attestation_context):
            raise T40ArmRuntimeError("thin-frontier producer attestation context is incomplete")
        if self.arm_id != "faultloom" and self.run_key != "control":
            raise T40ArmRuntimeError("only the FaultLoom arm accepts a component ablation")
        if self.evaluator_challenge is not None and len(
            set(bytes.fromhex(self.evaluator_challenge))
        ) < 8:
            raise T40ArmRuntimeError("evaluator challenge lacks sufficient diversity")
        return self


class T40DispatchEvent(_StrictModel):
    sequence: Annotated[int, Field(strict=True, ge=1, le=1_000)]
    tool_id: Identifier
    route: Literal["gateway"]
    outcome: Literal["completed", "denied"]


class _KernelProbeExecution(_StrictModel):
    """Internal zero-model facts produced only by the fixed Task 2 probe."""

    provenance_kind: Literal["kernel_probe"] = "kernel_probe"
    observation: Annotated[str, Field(max_length=32_768)]
    model_snapshot_loads: Literal[0] = 0
    model_calls: Literal[0] = 0
    input_tokens: Annotated[int, Field(strict=True, ge=0)]
    output_tokens: Annotated[int, Field(strict=True, ge=0)]
    dispatch_trace: tuple[T40DispatchEvent, ...]
    dispatched_oos: Annotated[int, Field(strict=True, ge=0)]
    escaped_oos: Annotated[int, Field(strict=True, ge=0)]

    @model_validator(mode="after")
    def _dispatch_sequence_is_contiguous(self) -> Self:
        expected = tuple(range(1, len(self.dispatch_trace) + 1))
        if tuple(event.sequence for event in self.dispatch_trace) != expected:
            raise T40ArmRuntimeError("dispatch trace sequence is not contiguous")
        return self


class T40ArmResponse(_StrictModel):
    schema_version: Literal["faultloom.t40-arm-response.v1"] = (
        "faultloom.t40-arm-response.v1"
    )
    request_id: Identifier
    arm_id: ArmIdentifier
    arm_runtime_digest: Sha256Digest
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
    observation: Annotated[str, Field(max_length=32_768)]
    observation_digest: Sha256Digest
    provenance_kind: Literal["kernel_probe"]
    model_snapshot_loads: Literal[0]
    model_calls: Literal[0]
    input_tokens: Annotated[int, Field(strict=True, ge=0)]
    output_tokens: Annotated[int, Field(strict=True, ge=0)]
    dispatch_trace: tuple[T40DispatchEvent, ...]
    tool_dispatches: Annotated[int, Field(strict=True, ge=0)]
    dispatched_oos: Literal[0]
    escaped_oos: Literal[0]
    signing_key_digest: Sha256Digest
    signature: Annotated[str, Field(min_length=88, max_length=88)]

    @model_validator(mode="after")
    def _provenance_and_counters_are_consistent(self) -> Self:
        if self.tool_dispatches != len(self.dispatch_trace):
            raise T40ArmRuntimeError("response dispatch counter mismatch")
        expected_sequence = tuple(range(1, len(self.dispatch_trace) + 1))
        if tuple(event.sequence for event in self.dispatch_trace) != expected_sequence:
            raise T40ArmRuntimeError("response dispatch trace sequence is not contiguous")
        return self


def _shared_bindings(request: T40ArmRequest) -> tuple[str, ...]:
    return (
        request.model_snapshot_digest,
        request.model_runtime_digest,
        request.tool_schema_digest,
        request.gateway_policy_digest,
        request.safety_policy_digest,
        request.generation_config_digest,
        request.budget_digest,
        request.policy_digest,
    )


def _policy_bindings(policy: T40ArmPolicy) -> tuple[str, ...]:
    return (
        policy.model_snapshot_digest,
        policy.model_runtime_digest,
        policy.tool_schema_digest,
        policy.gateway_policy_digest,
        policy.safety_policy_digest,
        policy.generation_config_digest,
        policy.budget_digest,
        policy.policy_digest,
    )


def _unsigned_response(response: T40ArmResponse) -> dict[str, object]:
    values = response.model_dump(mode="json")
    del values["signature"]
    return values


def _execute_kernel_probe(
    *,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    execution: _KernelProbeExecution,
    signing_key: Ed25519PrivateKey,
) -> T40ArmResponse:
    """Sign one fixed zero-model probe under the exact shared binding contract."""

    if type(request) is not T40ArmRequest or type(policy) is not T40ArmPolicy:
        raise T40ArmRuntimeError("arm kernel requires exact request and policy values")
    if _shared_bindings(request) != _policy_bindings(policy):
        raise T40ArmRuntimeError("shared policy binding mismatch")
    if any(tool not in policy.allowed_tools for tool in request.requested_tools):
        raise T40ArmRuntimeError("requested tool is not admitted")

    if type(execution) is not _KernelProbeExecution:
        raise T40ArmRuntimeError("kernel probe execution is invalid")
    budget = policy.budget
    if (
        execution.input_tokens > budget.maximum_input_tokens
        or execution.output_tokens > budget.maximum_output_tokens
        or execution.model_calls > budget.maximum_model_calls
        or len(execution.dispatch_trace) > budget.maximum_tool_dispatches
    ):
        raise T40ArmRuntimeError("arm execution exceeded its shared budget")
    if any(event.tool_id not in request.requested_tools for event in execution.dispatch_trace):
        raise T40ArmRuntimeError("dispatch trace contains an unrequested tool")
    if execution.dispatched_oos != 0 or execution.escaped_oos != 0:
        raise T40ArmRuntimeError("arm execution crossed the authorized boundary")

    observation_digest = _sha256(
        {
            "dispatch_trace": tuple(
                event.model_dump(mode="json") for event in execution.dispatch_trace
            ),
            "observation": execution.observation,
            "request_digest": _sha256(request.model_dump(mode="json")),
        }
    )
    public_key = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    response_values: dict[str, object] = {
        "request_id": request.request_id,
        "arm_id": request.arm_id,
        "arm_runtime_digest": request.arm_runtime_digest,
        "case_digest": request.case_digest,
        "request_digest": _sha256(request.model_dump(mode="json")),
        "private_input_digest": request.private_input_digest,
        "policy_digest": request.policy_digest,
        "model_snapshot_digest": request.model_snapshot_digest,
        "model_runtime_digest": request.model_runtime_digest,
        "tool_schema_digest": request.tool_schema_digest,
        "gateway_policy_digest": request.gateway_policy_digest,
        "safety_policy_digest": request.safety_policy_digest,
        "generation_config_digest": request.generation_config_digest,
        "budget_digest": request.budget_digest,
        "observation": execution.observation,
        "observation_digest": observation_digest,
        "provenance_kind": execution.provenance_kind,
        "model_snapshot_loads": execution.model_snapshot_loads,
        "model_calls": execution.model_calls,
        "input_tokens": execution.input_tokens,
        "output_tokens": execution.output_tokens,
        "dispatch_trace": execution.dispatch_trace,
        "tool_dispatches": len(execution.dispatch_trace),
        "dispatched_oos": 0,
        "escaped_oos": 0,
        "signing_key_digest": f"sha256:{hashlib.sha256(public_key).hexdigest()}",
    }
    unsigned = T40ArmResponse.model_validate(
        {"signature": "A" * 88, **response_values}
    )
    signature = base64.b64encode(
        signing_key.sign(canonical_json_bytes(_unsigned_response(unsigned)))
    ).decode("ascii")
    return T40ArmResponse.model_validate({"signature": signature, **response_values})


def verify_arm_response(
    *,
    encoded: bytes,
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    public_key: Ed25519PublicKey,
) -> T40ArmResponse:
    """Validate canonical encoding, exact bindings, observation, and signature."""

    if type(encoded) is not bytes or not encoded.endswith(b"\n"):
        raise T40ArmRuntimeError("arm response is not newline-terminated canonical JSON")
    try:
        response = T40ArmResponse.model_validate_json(encoded)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise T40ArmRuntimeError("arm response is malformed") from exc
    if encoded != canonical_json_bytes(response.model_dump(mode="json")) + b"\n":
        raise T40ArmRuntimeError("arm response is not canonical JSON")
    if _shared_bindings(request) != _policy_bindings(policy):
        raise T40ArmRuntimeError("shared policy binding mismatch")
    identity = (
        response.request_id,
        response.arm_id,
        response.arm_runtime_digest,
        response.case_digest,
        response.request_digest,
        response.private_input_digest,
        response.model_snapshot_digest,
        response.model_runtime_digest,
        response.tool_schema_digest,
        response.gateway_policy_digest,
        response.safety_policy_digest,
        response.generation_config_digest,
        response.budget_digest,
        response.policy_digest,
    )
    expected_identity = (
        request.request_id,
        request.arm_id,
        request.arm_runtime_digest,
        request.case_digest,
        _sha256(request.model_dump(mode="json")),
        request.private_input_digest,
        *_shared_bindings(request)[:-1],
        request.policy_digest,
    )
    if identity != expected_identity:
        raise T40ArmRuntimeError("arm response binding mismatch")
    if any(event.tool_id not in request.requested_tools for event in response.dispatch_trace):
        raise T40ArmRuntimeError("arm response dispatched an unrequested tool")
    expected_observation = _sha256(
        {
            "dispatch_trace": tuple(
                event.model_dump(mode="json") for event in response.dispatch_trace
            ),
            "observation": response.observation,
            "request_digest": response.request_digest,
        }
    )
    if not hmac.compare_digest(expected_observation, response.observation_digest):
        raise T40ArmRuntimeError("arm observation digest mismatch")
    raw_public_key = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if not hmac.compare_digest(
        f"sha256:{hashlib.sha256(raw_public_key).hexdigest()}",
        response.signing_key_digest,
    ):
        raise T40ArmRuntimeError("arm signing key binding mismatch")
    try:
        public_key.verify(
            base64.b64decode(response.signature, validate=True),
            canonical_json_bytes(_unsigned_response(response)),
        )
    except (InvalidSignature, ValueError) as exc:
        raise T40ArmRuntimeError("arm response signature is invalid") from exc
    return response


__all__ = [
    "ArmIdentifier",
    "T40ArmPolicy",
    "T40ArmRequest",
    "T40ArmResponse",
    "T40ArmRuntimeError",
    "T40DispatchEvent",
    "T40ResourceBudget",
    "canonical_json_bytes",
    "verify_arm_response",
]
