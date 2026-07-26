"""Fixed, stateless production FaultLoom arm for formal T40 evaluation."""

from __future__ import annotations

import hashlib
import hmac
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from faultloom_protocol import (
    SCHEMA_VERSION,
    AuthorityGrant,
    AuthoritySigner,
    HypothesisRecord,
    ObservationRef,
    sha256_digest,
)
from faultloom_sdk import ReferenceProcessClient, reference_registry
from faultloom_web.web_api.inputs import WebApiRunRequest
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from faultloom.context import (
    ContextCompiler,
    ContextState,
    ProviderContextMetadata,
    ScopeTrustAnchor,
)
from faultloom.patch_variant import PatchVariantEngine, PatchVariantRequest
from faultloom.research import (
    PersistentResearcher,
    ProposalMergeRequest,
    ResearchBinding,
    ResearchProposal,
)
from faultloom.semantic_depth import SearchConfig, SemanticDepthEngine, SemanticGraph
from faultloom.state import EngagementKey, StateStore
from faultloom.tool_planner import PlanningBudget, ToolCandidate, ToolPlanner

from .model_utility_attestation_state import MonotonicAttestationState
from .model_utility_attestor import AttestedModelUtilityExchange, TransientModelUtilityAttestor
from .model_utility_process import BoundedProcessLaunch, run_bounded_process
from .model_utility_proxy import DigestPinnedLocalProcessProxy
from .model_utility_proxy_models import LocalModelProcessConfig, LocalModelRuntimeProfile
from .t40_arm_runtime import T40ArmPolicy, T40ArmRequest, T40ArmRuntimeError, canonical_json_bytes
from .t40_faultloom_admission import admitted_registry
from .t40_faultloom_install import FORMAL_SITE_ROOT, validate_formal_installation
from .t40_real_arm_protocol import (
    T40ComponentUse,
    _faultloom_model_request,
    _sign_faultloom_response,
    _T40ComponentContext,
    _T40ComponentTrace,
)
from .t40_thin_frontier_arm import (
    _ATTESTATION_STATE_PATH,
    _apply_resource_limits,
    _load_operator_producer_signing_key,
    _read_regular_fd,
    _seal_input,
)
from .t40_web_pack_process import WebPackProcessClient, WebPackRunKey

_KEY_BYTES = 32
_MODULE_NAME = "faultloom.t40_faultloom_arm"
_FORMAL_CONFIG_ROOT = Path("/etc/faultloom/t40-formal-v1")
_FORMAL_STATE_ROOT = Path("/var/lib/faultloom/t40-formal-v1")


class T40FaultLoomError(T40ArmRuntimeError):
    pass


class _StrictModel(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid",
        frozen=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
        strict=True,
    )


class _ContextInput(_StrictModel):
    state: ContextState
    provider: ProviderContextMetadata
    scope_anchors: tuple[ScopeTrustAnchor, ...] = Field(min_length=1)
    retrieval_binding_key_hex: str = Field(pattern=r"^(?:[0-9a-f]{2}){32,}$")
    live: bool
    verification_time: datetime


class _SpecialistInput(_StrictModel):
    binding: ResearchBinding
    proposal: ResearchProposal
    merge_request: ProposalMergeRequest


class _PlannerInput(_StrictModel):
    hypothesis: HypothesisRecord
    grant: AuthorityGrant
    budget: PlanningBudget
    candidates: tuple[ToolCandidate, ...] = Field(min_length=1)


class T40FaultLoomPrivateInput(_StrictModel):
    """Closed typed owned inputs; it contains no path, callable, or network seam."""

    schema_version: Literal["faultloom.t40-private-input.v1"]
    context: _ContextInput
    specialist: _SpecialistInput
    planner: _PlannerInput
    semantic_graph: dict[str, object]
    semantic_config: dict[str, object]
    patch_variant: PatchVariantRequest
    web: WebApiRunRequest


def _digest(value: object) -> str:
    return sha256_digest(value)


def faultloom_implementation_digest() -> str:
    source = Path(__file__).resolve(strict=True)
    if source.name != "t40_faultloom_arm.py" or source.parent.name != "faultloom":
        raise T40FaultLoomError("FaultLoom implementation origin is invalid")
    return f"sha256:{hashlib.sha256(source.read_bytes()).hexdigest()}"


def _parse_private(request: T40ArmRequest) -> T40FaultLoomPrivateInput:
    try:
        parsed = T40FaultLoomPrivateInput.model_validate_json(request.private_input)
    except ValidationError:
        raise T40FaultLoomError("FaultLoom private input is malformed") from None
    if request.private_input.encode() != canonical_json_bytes(parsed.model_dump(mode="json")):
        raise T40FaultLoomError("FaultLoom private input is not canonical JSON")
    return parsed


def _component_status(
    request: T40ArmRequest, component: str
) -> Literal["used", "disabled", "blocked"]:
    disabled = None if request.run_key == "control" else request.run_key.removeprefix("off.")
    if component == disabled:
        return "disabled"
    if component == "t35" and disabled in {"t32", "t33"}:
        return "blocked"
    return "used"


def _execute_components(
    request: T40ArmRequest,
    private: T40FaultLoomPrivateInput,
) -> tuple[
    tuple[_T40ComponentTrace, ...],
    tuple[_T40ComponentContext, ...],
    T40ComponentUse,
]:
    disabled = None if request.run_key == "control" else request.run_key.removeprefix("off.")
    outputs: dict[str, str] = {}
    summaries: dict[str, object] = {}
    manifests = reference_registry()
    admissions, admission_bundle_digest = admitted_registry(manifests)

    if disabled != "context_compiler":
        context = private.context
        compiler = ContextCompiler(
            scope_anchors=context.scope_anchors,
            retrieval_binding_keys={
                context.state.engagement_id: bytes.fromhex(context.retrieval_binding_key_hex)
            },
        )
        compiled = compiler.compile(
            context.state,
            context.provider,
            live=context.live,
            verification_time=context.verification_time.astimezone(UTC),
        )
        outputs["context_compiler"] = compiled.context_id
        summaries["context_compiler"] = {
            "compiled_context_digest": _digest(compiled.text),
            "context_id": compiled.context_id,
            "input_tokens": compiled.input_tokens,
        }

    with tempfile.TemporaryDirectory(prefix="faultloom-t40-state-") as root:
        state_root = Path(root) / "state"
        anchor_root = Path(root) / "anchor"
        with StateStore(
            state_root,
            private.specialist.binding.run_id,
            EngagementKey.generate(),
            anchor_root=anchor_root,
        ) as store:
            if disabled != "specialist":
                researcher = PersistentResearcher.open(store, private.specialist.binding)
                researcher.submit_proposal(private.specialist.proposal)
                specialist = researcher.merge_specialist_proposal(private.specialist.merge_request)
                outputs["specialist"] = _digest(specialist.model_dump(mode="json"))
                summaries["specialist"] = {
                    "merge_receipt_digest": outputs["specialist"],
                }

    if disabled != "tool_planner":
        plan = ToolPlanner(manifests, admissions).select(
            hypothesis=private.planner.hypothesis,
            grant=private.planner.grant,
            budget=private.planner.budget,
            candidates=private.planner.candidates,
        )
        outputs["tool_planner"] = _digest(plan.model_dump(mode="json"))
        summaries["tool_planner"] = {
            "plan_digest": outputs["tool_planner"],
            "selected_candidate_id": plan.selected.candidate.candidate_id,
        }

    semantic = SemanticDepthEngine(SemanticGraph.from_document(private.semantic_graph)).search(
        SearchConfig.from_document(private.semantic_config)
    )
    semantic_digest = _digest(semantic.checkpoint.document())
    summaries["semantic_depth"] = {
        "checkpoint_digest": semantic_digest,
        "longest_verified_prefix": semantic.longest_verified_prefix,
        "terminal_reason": semantic.terminal_reason,
    }

    if disabled != "t34":
        patch = PatchVariantEngine().run(private.patch_variant)
        outputs["t34"] = _digest(patch.model_dump(mode="json"))
        summaries["patch_variant"] = {
            "claim_status": patch.claim_status,
            "result_digest": outputs["t34"],
        }

    web_run_key: WebPackRunKey = "control"
    if disabled == "t32":
        web_run_key = "off.identity_workflow"
    elif disabled == "t33":
        web_run_key = "off.api_async"
    elif disabled == "t35":
        web_run_key = "off.cross_surface_chain"
    web = WebPackProcessClient().run(private.web, run_key=web_run_key)
    outputs["t32"] = web.component_digests.identity_workflow
    outputs["t33"] = web.component_digests.api_async
    outputs["t35"] = web.component_digests.cross_surface_chain
    summaries["web_pack"] = {
        "component_use": web.component_use.model_dump(mode="json"),
        "result_digest": web.result_digest,
    }

    if disabled != "adapters":
        manifest = admissions.require_candidate_source("adapter.reference")
        observation = ObservationRef(
            schema_version=SCHEMA_VERSION,
            observation_id=f"{request.request_id}.semantic",
            run_id=private.specialist.binding.run_id,
            cas_digest=semantic_digest,
            media_type="application/vnd.faultloom.semantic-checkpoint+json",
            byte_length=len(canonical_json_bytes(semantic.checkpoint.document())),
            created_at=private.context.verification_time,
        )
        normalize_request = manifests.prepare_normalize(
            request_id=f"{request.request_id}.adapter",
            grant=private.planner.grant,
            adapter_id=manifest.adapter_id,
            capability="reference.digest_normalizer",
            observation=observation,
        )
        normalized_response = ReferenceProcessClient(
            expected_adapter_manifest=manifest
        ).normalize(normalize_request)
        normalized = normalized_response.normalized_observation
        outputs["adapters"] = _digest(normalized_response.model_dump(mode="json"))
        summaries["adapter_use"] = {
            "adapter_id": manifest.adapter_id,
            "admission_bundle_digest": admission_bundle_digest,
            "manifest_digest": _digest(manifest.model_dump(mode="json")),
            "response_digest": outputs["adapters"],
            "source_digest": normalized.source_digest,
        }

    components = (
        "context_compiler",
        "specialist",
        "tool_planner",
        "t32",
        "t33",
        "t34",
        "t35",
        "adapters",
    )
    trace = tuple(
        _T40ComponentTrace(
            component=component,
            status=_component_status(request, component),
            trace_digest=outputs.get(
                component,
                _digest({"component": component, "status": _component_status(request, component)}),
            ),
        )
        for component in components
    )
    context = tuple(
        _T40ComponentContext(
            component=name,
            summary=canonical_json_bytes(value).decode("ascii"),
        )
        for name, value in sorted(summaries.items())
    )
    return (
        trace,
        context,
        T40ComponentUse(
            context_compiler=_component_status(request, "context_compiler") == "used",
            specialist=_component_status(request, "specialist") == "used",
            tool_planner=_component_status(request, "tool_planner") == "used",
            t32=_component_status(request, "t32") == "used",
            t33=_component_status(request, "t33") == "used",
            t34=_component_status(request, "t34") == "used",
            t35=_component_status(request, "t35") == "used",
            adapters=_component_status(request, "adapters") == "used",
            semantic_depth=True,
            patch_variant=disabled != "t34",
            chain=web.component_use.cross_surface_chain,
            identity_workflow=web.component_use.identity_workflow,
            pack=True,
        ),
    )


def _fixed_model_exchange(
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    producer_signer: AuthoritySigner,
    trace: tuple[_T40ComponentTrace, ...],
    context: tuple[_T40ComponentContext, ...],
) -> AttestedModelUtilityExchange:
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
        raise T40FaultLoomError("FaultLoom request does not bind the fixed model profile")
    session_id = request.session_id
    challenge = request.evaluator_challenge
    allocation_id = request.allocation_id
    minimum_sequence = request.trusted_minimum_sequence
    core_wheel_digest = request.core_wheel_digest
    if (
        session_id is None
        or challenge is None
        or allocation_id is None
        or minimum_sequence is None
        or core_wheel_digest is None
    ):
        raise T40FaultLoomError("FaultLoom producer attestation context is incomplete")
    model_request = _faultloom_model_request(
        request,
        policy,
        component_trace=trace,
        component_context=context,
    )
    with MonotonicAttestationState(_ATTESTATION_STATE_PATH) as state:
        return TransientModelUtilityAttestor(
            proxy=DigestPinnedLocalProcessProxy(config),
            signer=producer_signer,
            sequence_state=state,
            core_wheel_digest=core_wheel_digest,
        ).exchange(
            model_request,
            session_id=session_id,
            evaluator_challenge=challenge,
            allocation_id=allocation_id,
            trusted_minimum_sequence=minimum_sequence,
        )


def _execute_and_sign(
    request: T40ArmRequest,
    policy: T40ArmPolicy,
    signing_key: Ed25519PrivateKey,
    producer_signer: AuthoritySigner,
) -> bytes:
    if (
        request.arm_id != "faultloom"
        or request.arm_runtime_digest != faultloom_implementation_digest()
    ):
        raise T40FaultLoomError("FaultLoom implementation binding mismatch")
    private = _parse_private(request)
    trace, context, use = _execute_components(request, private)
    model_request = _faultloom_model_request(
        request,
        policy,
        component_trace=trace,
        component_context=context,
    )
    exchange = _fixed_model_exchange(request, policy, producer_signer, trace, context)
    response = _sign_faultloom_response(
        request=request,
        policy=policy,
        model_request=model_request,
        model_response=exchange.response,
        producer_receipt=exchange.producer_receipt,
        component_trace=trace,
        component_context=context,
        component_use=use,
        runtime_implementation_digest=faultloom_implementation_digest(),
        signing_key=signing_key,
    )
    return canonical_json_bytes(response.model_dump(mode="json")) + b"\n"


def _serve_one(
    request_fd: int, response_fd: int, signing_key_fd: int, producer_key_fd: int, policy_fd: int
) -> None:
    encoded_request = _read_regular_fd(request_fd, 1_048_576, "private request")
    encoded_policy = _read_regular_fd(policy_fd, 65_536, "shared policy")
    key = _read_regular_fd(signing_key_fd, _KEY_BYTES, "signing key")
    producer_key = _read_regular_fd(producer_key_fd, _KEY_BYTES, "producer signing key")
    if (
        len(key) != _KEY_BYTES
        or len(producer_key) != _KEY_BYTES
        or hmac.compare_digest(key, producer_key)
    ):
        raise T40FaultLoomError("FaultLoom signing keys are invalid")
    try:
        request = T40ArmRequest.model_validate_json(encoded_request)
        policy = T40ArmPolicy.model_validate_json(encoded_policy)
    except ValidationError:
        raise T40FaultLoomError("FaultLoom input is malformed") from None
    if encoded_request != canonical_json_bytes(
        request.model_dump(mode="json")
    ) or encoded_policy != canonical_json_bytes(policy.model_dump(mode="json")):
        raise T40FaultLoomError("FaultLoom input is not canonical JSON")
    _apply_resource_limits(policy)
    output = _execute_and_sign(
        request,
        policy,
        Ed25519PrivateKey.from_private_bytes(key),
        AuthoritySigner.from_private_bytes(producer_key),
    )
    if len(output) > policy.budget.maximum_response_bytes:
        raise T40FaultLoomError("FaultLoom response exceeds its byte limit")
    os.ftruncate(response_fd, 0)
    os.lseek(response_fd, 0, os.SEEK_SET)
    os.write(response_fd, output)


def _sandbox_argv(descriptors: tuple[int, int, int, int, int]) -> tuple[str, ...]:
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
        FORMAL_SITE_ROOT.as_posix(),
        "--ro-bind",
        "/usr",
        "/usr",
        "--dir",
        "/opt",
        "--dir",
        "/opt/faultloom",
        "--dir",
        "/opt/faultloom/t40-formal-v1",
        "--dir",
        "/opt/faultloom/t40-formal-v1/lib",
        "--dir",
        "/opt/faultloom/t40-formal-v1/lib/python3.12",
        "--ro-bind",
        FORMAL_SITE_ROOT.as_posix(),
        FORMAL_SITE_ROOT.as_posix(),
        "--dir",
        "/etc",
        "--dir",
        "/etc/faultloom",
        "--ro-bind",
        str(_FORMAL_CONFIG_ROOT),
        str(_FORMAL_CONFIG_ROOT),
        "--dir",
        "/var",
        "--dir",
        "/var/lib",
        "--dir",
        "/var/lib/faultloom",
        "--bind",
        str(_FORMAL_STATE_ROOT),
        str(_FORMAL_STATE_ROOT),
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
        "/usr/bin/python3.12",
        "-S",
        "-B",
        "-m",
        _MODULE_NAME,
        *(str(item) for item in descriptors),
    )


def _run_with_producer_key(
    *, request: T40ArmRequest, policy: T40ArmPolicy, signing_key: bytes, producer_key: bytes
) -> bytes:
    opened: list[int] = []
    try:
        opened.extend(
            (
                _seal_input(
                    "faultloom-t40-request", canonical_json_bytes(request.model_dump(mode="json"))
                ),
                os.memfd_create("faultloom-t40-response", os.MFD_CLOEXEC),
                _seal_input("faultloom-t40-key", signing_key),
                _seal_input("faultloom-t40-producer-key", producer_key),
                _seal_input(
                    "faultloom-t40-policy", canonical_json_bytes(policy.model_dump(mode="json"))
                ),
            )
        )
        descriptors = (opened[0], opened[1], opened[2], opened[3], opened[4])
        completed = run_bounded_process(
            BoundedProcessLaunch(
                argv=_sandbox_argv(descriptors),
                stdin=b"",
                environment=MappingProxyType({"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"}),
                pass_fds=descriptors,
                timeout_seconds=policy.budget.timeout_seconds,
                maximum_stdout_bytes=4096,
                maximum_stderr_bytes=4096,
            )
        )
        if completed.returncode != 0 or completed.stdout:
            raise T40FaultLoomError("FaultLoom worker returned an invalid process result")
        response = _read_regular_fd(
            descriptors[1], policy.budget.maximum_response_bytes, "FaultLoom response"
        )
        if not response:
            raise T40FaultLoomError("FaultLoom worker returned no response")
        return response
    except (OSError, subprocess.TimeoutExpired):
        raise T40FaultLoomError("FaultLoom worker did not complete safely") from None
    finally:
        for descriptor in opened:
            os.close(descriptor)


def run_faultloom_arm(*, request: T40ArmRequest, policy: T40ArmPolicy, signing_key: bytes) -> bytes:
    """Launch exactly one fixed child and use only installed producer authority."""
    if type(request) is not T40ArmRequest or type(policy) is not T40ArmPolicy:
        raise TypeError("FaultLoom launcher requires exact request and policy values")
    validate_formal_installation()
    producer_key = _load_operator_producer_signing_key()
    return _run_with_producer_key(
        request=request, policy=policy, signing_key=signing_key, producer_key=producer_key
    )


def main() -> int:
    if len(sys.argv) != 6 or any(not value.isdigit() for value in sys.argv[1:]):
        return 64
    descriptors = tuple(int(value) for value in sys.argv[1:])
    if len(set(descriptors)) != 5 or any(value < 3 for value in descriptors):
        return 64
    try:
        _serve_one(*descriptors)
    except (OSError, T40ArmRuntimeError, ValueError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "T40FaultLoomError",
    "T40FaultLoomPrivateInput",
    "faultloom_implementation_digest",
    "run_faultloom_arm",
]
