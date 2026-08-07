"""Offline-only compilation of an operator-supplied automation turn."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from faultloom_protocol import (
    AuthorityGrant,
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    EvidenceRef,
    ResourceRef,
    SubjectRef,
    TargetAsset,
    sha256_digest,
)
from faultloom_sdk import AdapterAdmissionRegistry, reference_registry
from pydantic import ValidationError

from faultloom.automation import (
    ActionContext,
    AuthorizedAutomationCoordinator,
    AuthorizedAutomationError,
    AutomationLimits,
    AutomationRequest,
    CandidateOutboxError,
    ModelDisclosureApproval,
    ObservationBundle,
    ObservationExcerpt,
    SafePoCContext,
    parse_model_turn,
    sign_model_disclosure_approval,
    verify_model_disclosure_approval,
    write_automation_result_bundle,
)
from faultloom.tool_planner import PlanningBudget, ToolPlanner


class AutomationCompileError(RuntimeError):
    """Expected compile failure, classified for the top-level CLI."""

    def __init__(self, detail: str, *, authority: bool) -> None:
        super().__init__(detail)
        self.authority = authority


@dataclass(frozen=True, slots=True)
class AutomationCompileDependencies:
    verify_workspace: Callable[
        [Path, Path], tuple[dict[str, object], AuthorityGrant, TargetAsset, datetime]
    ]
    capture_file: Callable[[Path], bytes]
    emit_json: Callable[[object], None]


@dataclass(frozen=True, slots=True)
class AutomationExportHandoffDependencies:
    verify_workspace: Callable[
        [Path, Path], tuple[dict[str, object], AuthorityGrant, TargetAsset, datetime]
    ]
    capture_file: Callable[[Path], bytes]
    parse_disclosure_key: Callable[[Path, bytes], Ed25519PublicKeyRecord]
    write_new_file: Callable[[Path, bytes], None]
    emit_json: Callable[[object], None]


@dataclass(frozen=True, slots=True)
class ArchivedHttpExchange:
    """Strictly revalidated bytes and accounting metadata for one archived exchange."""

    evidence_id: str
    created_at: datetime
    request_content: bytes
    request_sha256: str
    response_sha256: str
    response_limit: int


@dataclass(frozen=True, slots=True)
class AutomationPrepareHttp1RequestDependencies:
    verify_workspace: Callable[
        [Path, Path], tuple[dict[str, object], AuthorityGrant, TargetAsset, datetime]
    ]
    load_exchange: Callable[
        [
            Path,
            dict[str, object],
            AuthorityGrant,
            TargetAsset,
            str,
            str,
            int,
            str,
            str,
            str,
        ],
        ArchivedHttpExchange,
    ]
    capture_file: Callable[[Path], bytes]
    load_signer: Callable[[Path], AuthoritySigner]
    write_new_file: Callable[[Path, bytes], None]
    emit_json: Callable[[object], None]


@dataclass(frozen=True, slots=True)
class AutomationPrepareHttp1RequestArguments:
    """Typed subset of argparse inputs consumed by the offline request builder."""

    workspace: Path
    trusted_key: Path
    evidence_id: str
    excerpt_file: Path
    provider_id: str
    disclosure_private_key: Path
    hostname: str
    port: int
    scheme: str
    method: str
    path: str
    out: Path
    confirm_redacted_non_sensitive: bool


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _validate_json_depth(text: str, *, maximum: int = 128) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > maximum:
                raise ValueError(f"JSON nesting exceeds {maximum} levels")
        elif character in "]}":
            depth -= 1


def parse_automation_request(
    path: Path,
    content: bytes,
    *,
    missing_disclosure_is_authority: bool = False,
) -> AutomationRequest:
    raw_value: object = None
    try:
        text = content.decode("utf-8")
        _validate_json_depth(text)
        raw_value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        return AutomationRequest.model_validate_json(text)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValidationError,
        ValueError,
    ) as exc:
        if missing_disclosure_is_authority and _request_has_missing_disclosure(raw_value):
            raise AutomationCompileError(
                "handoff evidence lacks a model disclosure approval", authority=True
            ) from exc
        raise AutomationCompileError(
            f"invalid automation request file {path}: {exc}", authority=False
        ) from exc


def _request_has_missing_disclosure(value: object) -> bool:
    if type(value) is not dict:
        return False
    observations = value.get("observations")
    if type(observations) is not dict:
        return False
    excerpts = observations.get("excerpts")
    return type(excerpts) is list and any(
        type(excerpt) is dict and "approval" not in excerpt for excerpt in excerpts
    )


def _validate_request_binding(
    *,
    manifest: dict[str, object],
    grant: AuthorityGrant,
    target: TargetAsset,
    now: datetime,
    minimum_grant_version: int,
    request: AutomationRequest,
) -> None:
    if grant.grant_version < minimum_grant_version:
        raise AutomationCompileError("signed grant version is below the required minimum", authority=True)
    if request.provider_network_access != "none":
        raise AutomationCompileError("automation compile requires provider_network_access=none", authority=True)
    if request.issued_at > now:
        raise AutomationCompileError("automation request is issued in the future", authority=True)
    if request.authority_grant != grant:
        raise AutomationCompileError("automation request authority grant differs from signed authority", authority=True)
    grant_digest = sha256_digest(grant)
    if sha256_digest(request.authority_grant) != grant_digest:
        raise AutomationCompileError("automation request authority digest mismatch", authority=True)
    if (
        manifest.get("grant_id") != grant.grant_id
        or manifest.get("grant_version") != grant.grant_version
        or request.authority_grant.grant_id != grant.grant_id
        or request.authority_grant.grant_version != grant.grant_version
    ):
        raise AutomationCompileError("automation request grant identity is not bound to run.json", authority=True)
    if request.observations.run_id != manifest.get("run_id"):
        raise AutomationCompileError("automation request run does not match run.json", authority=True)
    if (
        request.action_context.target_id != target.target_id
        or request.action_context.pack_id != manifest.get("pack_id")
    ):
        raise AutomationCompileError("automation request target or pack does not match run.json", authority=True)
    if request.poc_context is not None and (
        request.poc_context.target_id != target.target_id
        or request.poc_context.pack_id != manifest.get("pack_id")
    ):
        raise AutomationCompileError("automation PoC context target or pack does not match run.json", authority=True)


def prepare_automation_http1_request(
    arguments: AutomationPrepareHttp1RequestArguments,
    *,
    dependencies: AutomationPrepareHttp1RequestDependencies,
) -> int:
    """Create one signed, offline automation request from a completed HTTP exchange."""

    workspace = arguments.workspace
    trusted_key = arguments.trusted_key
    evidence_id = arguments.evidence_id
    excerpt_file = arguments.excerpt_file
    provider_id = arguments.provider_id
    disclosure_private_key = arguments.disclosure_private_key
    hostname = arguments.hostname
    port = arguments.port
    scheme = arguments.scheme
    method = arguments.method
    path = arguments.path
    out_path = arguments.out
    confirmed = arguments.confirm_redacted_non_sensitive
    if (
        not isinstance(workspace, Path)
        or not isinstance(trusted_key, Path)
        or type(evidence_id) is not str
        or not evidence_id
        or not isinstance(excerpt_file, Path)
        or type(provider_id) is not str
        or not provider_id
        or not isinstance(disclosure_private_key, Path)
        or type(hostname) is not str
        or type(port) is not int
        or type(scheme) is not str
        or type(method) is not str
        or type(path) is not str
        or not isinstance(out_path, Path)
        or confirmed is not True
    ):
        raise AutomationCompileError(
            "automation prepare-http1-request arguments or confirmation are invalid",
            authority=False,
        )

    manifest, grant, target, now = dependencies.verify_workspace(workspace, trusted_key)
    if provider_id not in grant.provider_policy.allowed_providers:
        raise AutomationCompileError(
            "selected provider is outside the signed provider policy", authority=True
        )
    exchange = dependencies.load_exchange(
        workspace,
        manifest,
        grant,
        target,
        evidence_id,
        hostname,
        port,
        scheme,
        method,
        path,
    )
    try:
        excerpt = dependencies.capture_file(excerpt_file).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AutomationCompileError(
            "operator-redacted excerpt is not UTF-8", authority=False
        ) from exc
    if not excerpt or "\x00" in excerpt:
        raise AutomationCompileError(
            "operator-redacted excerpt is empty or contains NUL", authority=False
        )

    request_digest = f"sha256:{exchange.request_sha256}"
    response_digest = f"sha256:{exchange.response_sha256}"
    composite = (
        "UNTRUSTED OPERATOR-REDACTED HTTP OBSERVATION\n"
        f"endpoint={scheme}://{hostname}:{port}{path}\n"
        f"method={method}\n"
        f"request_sha256={request_digest}\n"
        f"response_sha256={response_digest}\n"
        "operator_redacted_excerpt_begin\n"
        f"{excerpt}\n"
        "operator_redacted_excerpt_end"
    )
    if len(composite) > 3_072:
        raise AutomationCompileError(
            "composite redacted observation exceeds 3072 characters", authority=False
        )
    content_digest = "sha256:" + hashlib.sha256(composite.encode("utf-8")).hexdigest()
    token = content_digest.removeprefix("sha256:")[:24]
    active_window_ends = [
        window.ends_at
        for window in grant.execution_windows
        if window.starts_at <= now < window.ends_at
    ]
    if not active_window_ends:
        raise AutomationCompileError(
            "current time is outside every signed execution window", authority=True
        )
    approval_expires = min(
        now + timedelta(hours=1), grant.expires_at, min(active_window_ends)
    )
    signer = dependencies.load_signer(disclosure_private_key)
    approval = sign_model_disclosure_approval(
        ModelDisclosureApproval(
            approval_id=f"model-disclosure.{token}",
            run_id=str(manifest["run_id"]),
            evidence_id=exchange.evidence_id,
            source_cas_digest=response_digest,
            redaction_digest=content_digest,
            content_digest=content_digest,
            media_type="text/plain",
            data_policy_id=grant.provider_policy.data_policy_id,
            allowed_provider_ids=(provider_id,),
            approved_at=now,
            expires_at=approval_expires,
            approver_key_id=signer.key_id,
        ),
        signer,
    )
    run_id = str(manifest["run_id"])
    target_id = target.target_id
    pack_id = str(manifest["pack_id"])
    subject = SubjectRef(
        schema_version="0.1.0",
        subject_id=grant.issued_to,
        subject_kind="authorized.operator",
        identity_id=grant.identities[0] if grant.identities else None,
    )
    route = ResourceRef(
        schema_version="0.1.0",
        resource_id=f"resource.http.{token}",
        resource_kind="http.route",
        target_id=target_id,
    )
    cleanup_ref = f"cleanup.read-only.{token}"
    prerequisite_id = f"prerequisite.archived-exchange.{token}"
    experiment_digest = sha256_digest(
        {
            "evidence_id": exchange.evidence_id,
            "hostname": hostname,
            "method": method,
            "path": path,
            "port": port,
            "request_sha256": request_digest,
            "response_sha256": response_digest,
            "scheme": scheme,
        }
    )
    request = AutomationRequest(
        observations=ObservationBundle(
            run_id=run_id,
            evidence_refs=(
                EvidenceRef(
                    schema_version="0.1.0",
                    evidence_id=exchange.evidence_id,
                    run_id=run_id,
                    cas_digest=response_digest,
                    observation_ids=(f"observation.http.{token}",),
                    redaction_digest=content_digest,
                    created_at=exchange.created_at,
                ),
            ),
            excerpts=(
                ObservationExcerpt(
                    evidence_id=exchange.evidence_id,
                    media_type="text/plain",
                    content=composite,
                    content_digest=content_digest,
                    redacted=True,
                    untrusted=True,
                    model_disclosure_approved=True,
                    approval=approval,
                ),
            ),
            observed_experiment_digests=(experiment_digest,),
        ),
        issued_at=now,
        authority_grant=grant,
        planning_budget=PlanningBudget(
            rate_slots=1,
            duration_seconds=min(20, grant.budget.max_duration_seconds),
            bytes=len(exchange.request_content) + exchange.response_limit,
            concurrency=1,
            actions=1,
            cost_microunits=0,
        ),
        action_context=ActionContext(
            run_id=run_id,
            target_id=target_id,
            pack_id=pack_id,
            subject=subject,
            resource=route,
            protocol=scheme,
            method=method,
            path=path,
            payload_digest=request_digest,
            cleanup_plan_ref=cleanup_ref,
        ),
        poc_context=SafePoCContext(
            run_id=run_id,
            target_id=target_id,
            pack_id=pack_id,
            route_ref=route,
            route_path=path,
            subject=subject,
            transport=scheme,
            prerequisite_ids=(prerequisite_id,),
            prerequisites=("Use only the exact operator-authored archived request bytes.",),
            cleanup_plan_ref=cleanup_ref,
            advisory_match_id=f"advisory.observed.{token}",
        ),
        limits=AutomationLimits(max_actions=0, max_poc_steps=1),
        provider_network_access="none",
    )
    content = request.model_dump_json(indent=2).encode("utf-8") + b"\n"
    dependencies.write_new_file(out_path, content)
    dependencies.emit_json(
        {
            "automatic_submission": False,
            "digest": sha256_digest(request.model_dump(mode="json")),
            "evidence_id": exchange.evidence_id,
            "network_access": "none",
            "out": str(out_path),
            "provider_id": provider_id,
            "schema": "faultloom.automation-http1-request-prepare.v1",
            "target_dispatch": False,
        }
    )
    return 0


def _handoff_generation() -> object:
    """Return the fixed, provider-neutral settings for a manual model handoff."""

    from faultloom.provider import GenerationConfig

    return GenerationConfig(
        max_output_tokens=1_024,
        temperature_milli=0,
        top_p_milli=1_000,
        seed=0,
        response_format="json",
    )


def _model_handoff_bytes(
    request: AutomationRequest,
    *,
    provider_id: str,
    model_snapshot: str,
) -> bytes:
    """Build the canonical offline bundle given to an operator-selected model."""

    from faultloom.automation import (
        ReasoningTurnRequest,
        build_reasoning_chat_payload,
        model_turn_function_schema,
        model_turn_provider_tool_spec,
        model_turn_schema_digest,
    )
    from faultloom.provider import provider_canonical_json_bytes

    context = ReasoningTurnRequest.from_request(request)
    generation = _handoff_generation()
    payload = build_reasoning_chat_payload(context, generation=generation)
    tool = model_turn_provider_tool_spec()
    document: dict[str, object] = {
        "messages": [message.as_wire() for message in payload.messages],
        "function_tool": {
            "id": tool.tool_id,
            "name": tool.wire_name,
            "parameters": model_turn_function_schema(),
        },
        "generation": payload.generation.model_dump(mode="json"),
        "instructions": [
            (
                "Give this bundle only to the approved provider/service "
                f"{provider_id} using exact model snapshot {model_snapshot}."
            ),
            "Save exactly the one function-arguments object as model-turn.json.",
            "Run faultloom automation compile with this request and model-turn.json.",
        ],
        "limits": request.limits.model_dump(mode="json"),
        "model_provenance": "unattested_manual_handoff",
        "network_access": "none",
        "output_schema_digest": model_turn_schema_digest(),
        "approved_model_snapshot": model_snapshot,
        "approved_provider_id": provider_id,
        "provider_disclosure_verification": "verified",
        "request_digest": sha256_digest(request.model_dump(mode="json")),
        "run_id": context.run_id,
        "schema": "faultloom.model-handoff.v1",
        "tool_schema_digest": tool.input_schema_digest,
    }
    return provider_canonical_json_bytes(document) + b"\n"


def _trusted_disclosure_keys(
    paths: object,
    *,
    dependencies: AutomationExportHandoffDependencies,
) -> dict[str, Ed25519PublicKeyRecord]:
    if (
        type(paths) is not list
        or not paths
        or any(not isinstance(path, Path) for path in paths)
    ):
        raise AutomationCompileError(
            "automation export-handoff requires one or more trusted disclosure keys",
            authority=False,
        )
    registry: dict[str, Ed25519PublicKeyRecord] = {}
    seen_paths: set[str] = set()
    for path in paths:
        normalized_path = os.path.normcase(os.path.abspath(path))
        if normalized_path in seen_paths:
            raise AutomationCompileError(
                "trusted disclosure-key path is repeated", authority=True
            )
        seen_paths.add(normalized_path)
        record = dependencies.parse_disclosure_key(
            path, dependencies.capture_file(path)
        )
        if type(record) is not Ed25519PublicKeyRecord:
            raise AutomationCompileError(
                "trusted disclosure-key record has the wrong type", authority=True
            )
        if record.key_id in registry:
            raise AutomationCompileError(
                "trusted disclosure-key ID is duplicated", authority=True
            )
        registry[record.key_id] = record
    return registry


def _verify_handoff_disclosures(
    request: AutomationRequest,
    *,
    provider_id: str,
    trusted_disclosure_keys: dict[str, Ed25519PublicKeyRecord],
    verification_time: datetime,
) -> None:
    evidence_refs = {
        item.evidence_id: item for item in request.observations.evidence_refs
    }
    try:
        for excerpt in request.observations.excerpts:
            reference = evidence_refs.get(excerpt.evidence_id)
            if reference is None or reference.redaction_digest is None:
                raise ValueError("handoff evidence lacks a redaction digest")
            _ = verify_model_disclosure_approval(
                excerpt.approval,
                trusted_disclosure_keys,
                expected_run_id=request.observations.run_id,
                expected_evidence_id=excerpt.evidence_id,
                expected_source_cas_digest=reference.cas_digest,
                expected_redaction_digest=reference.redaction_digest,
                expected_content_digest=excerpt.content_digest,
                expected_media_type=excerpt.media_type,
                expected_data_policy_id=request.authority_grant.provider_policy.data_policy_id,
                expected_provider_id=provider_id,
                verification_time=verification_time,
            )
    except (TypeError, ValueError) as exc:
        raise AutomationCompileError(
            "handoff evidence lacks a trusted model disclosure approval", authority=True
        ) from exc


def export_automation_handoff(
    arguments: object,
    *,
    dependencies: AutomationExportHandoffDependencies,
) -> int:
    """Create one offline, provider-neutral model-turn handoff bundle."""

    workspace = getattr(arguments, "workspace")
    trusted_key = getattr(arguments, "trusted_key")
    request_path = getattr(arguments, "request")
    out_path = getattr(arguments, "out")
    provider_id = getattr(arguments, "provider_id")
    model_snapshot = getattr(arguments, "model_snapshot", None)
    disclosure_key_paths = getattr(arguments, "trusted_disclosure_key")
    minimum_grant_version = getattr(arguments, "minimum_grant_version")
    if (
        not isinstance(workspace, Path)
        or not isinstance(trusted_key, Path)
        or not isinstance(request_path, Path)
        or not isinstance(out_path, Path)
        or type(provider_id) is not str
        or not provider_id
        or type(model_snapshot) is not str
        or not model_snapshot
        or type(minimum_grant_version) is not int
    ):
        raise AutomationCompileError("automation export-handoff arguments are invalid", authority=False)

    manifest, grant, target, now = dependencies.verify_workspace(workspace, trusted_key)
    request = parse_automation_request(
        request_path,
        dependencies.capture_file(request_path),
        missing_disclosure_is_authority=True,
    )
    _validate_request_binding(
        manifest=manifest,
        grant=grant,
        target=target,
        now=now,
        minimum_grant_version=minimum_grant_version,
        request=request,
    )
    if provider_id not in grant.provider_policy.allowed_providers:
        raise AutomationCompileError(
            "selected handoff provider is outside the signed authority grant",
            authority=True,
        )
    if model_snapshot not in grant.provider_policy.allowed_model_snapshots:
        raise AutomationCompileError(
            "selected handoff model snapshot is outside the signed authority grant",
            authority=True,
        )
    trusted_disclosure_keys = _trusted_disclosure_keys(
        disclosure_key_paths, dependencies=dependencies
    )
    _verify_handoff_disclosures(
        request,
        provider_id=provider_id,
        trusted_disclosure_keys=trusted_disclosure_keys,
        verification_time=now,
    )
    content = _model_handoff_bytes(
        request,
        provider_id=provider_id,
        model_snapshot=model_snapshot,
    )
    dependencies.write_new_file(out_path, content)
    dependencies.emit_json(
        {
            "automatic_submission": False,
            "handoff": str(out_path),
            "independent_verification": False,
            "network_access": "none",
            "model_snapshot": model_snapshot,
            "provider_dispatch": False,
            "sha256": hashlib.sha256(content).hexdigest(),
            "target_dispatch": False,
        }
    )
    return 0


def compile_automation_result(
    arguments: object,
    *,
    dependencies: AutomationCompileDependencies,
) -> AuthorizedAutomationResult:
    """Compile one local model turn without publishing or emitting output."""

    workspace = getattr(arguments, "workspace")
    trusted_key = getattr(arguments, "trusted_key")
    request_path = getattr(arguments, "request")
    model_turn_path = getattr(arguments, "model_turn")
    minimum_grant_version = getattr(arguments, "minimum_grant_version")
    if (
        not isinstance(workspace, Path)
        or not isinstance(trusted_key, Path)
        or not isinstance(request_path, Path)
        or not isinstance(model_turn_path, Path)
        or type(minimum_grant_version) is not int
    ):
        raise AutomationCompileError("automation compile arguments are invalid", authority=False)

    manifest, grant, target, now = dependencies.verify_workspace(workspace, trusted_key)
    request = parse_automation_request(request_path, dependencies.capture_file(request_path))
    model_turn = dependencies.capture_file(model_turn_path)
    try:
        _ = parse_model_turn(model_turn, limits=request.limits)
    except AuthorizedAutomationError as exc:
        raise AutomationCompileError(
            f"invalid automation model-turn file {model_turn_path}: {exc}", authority=False
        ) from exc
    _validate_request_binding(
        manifest=manifest,
        grant=grant,
        target=target,
        now=now,
        minimum_grant_version=minimum_grant_version,
        request=request,
    )
    registry = reference_registry()
    coordinator = AuthorizedAutomationCoordinator(
        planner=ToolPlanner(registry, AdapterAdmissionRegistry(registry))
    )
    try:
        result = coordinator.run(request=request, raw_model_turn=model_turn)
    except AuthorizedAutomationError as exc:
        raise AutomationCompileError(str(exc), authority=True) from exc
    return result


def compile_automation(
    arguments: object,
    *,
    dependencies: AutomationCompileDependencies,
) -> int:
    """Compile one local model turn and atomically publish an offline bundle."""

    workspace = getattr(arguments, "workspace")
    if not isinstance(workspace, Path):
        raise AutomationCompileError("automation compile arguments are invalid", authority=False)
    result = compile_automation_result(arguments, dependencies=dependencies)
    try:
        publication = write_automation_result_bundle(result, workspace / "automation")
    except CandidateOutboxError as exc:
        raise AutomationCompileError(str(exc), authority=False) from exc
    dependencies.emit_json(
        {
            "automatic_submission": False,
            "candidate": None
            if publication.candidate_path is None
            else str(publication.candidate_path),
            "digest": publication.result_digest,
            "evidence_existence_independently_verified": False,
            "independent_verification": False,
            "network_access": "none",
            "receipt": str(publication.receipt_path),
            "result": str(publication.result_path),
            "target_dispatch": False,
        }
    )
    return 0
