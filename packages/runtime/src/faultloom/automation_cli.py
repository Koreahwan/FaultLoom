"""Offline-only compilation of an operator-supplied automation turn."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from faultloom.automation import (
    AuthorizedAutomationCoordinator,
    AuthorizedAutomationError,
    AutomationRequest,
    CandidateOutboxError,
    parse_model_turn,
    write_automation_result_bundle,
)
from faultloom.tool_planner import ToolPlanner
from faultloom_protocol import AuthorityGrant, TargetAsset, sha256_digest
from faultloom_sdk import AdapterAdmissionRegistry, reference_registry


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
    write_new_file: Callable[[Path, bytes], None]
    emit_json: Callable[[object], None]


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


def _parse_request(path: Path, content: bytes) -> AutomationRequest:
    try:
        text = content.decode("utf-8")
        _validate_json_depth(text)
        _ = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        return AutomationRequest.model_validate_json(text)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValidationError,
        ValueError,
    ) as exc:
        raise AutomationCompileError(
            f"invalid automation request file {path}: {exc}", authority=False
        ) from exc


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


def _model_handoff_bytes(request: AutomationRequest) -> bytes:
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
            "Give this bundle to any model UI, CLI, or official API.",
            "Save exactly the one function-arguments object as model-turn.json.",
            "Run faultloom automation compile with this request and model-turn.json.",
        ],
        "limits": request.limits.model_dump(mode="json"),
        "model_provenance": "unattested_manual_handoff",
        "network_access": "none",
        "output_schema_digest": model_turn_schema_digest(),
        "provider_disclosure_verification": "not_performed_by_export",
        "request_digest": sha256_digest(request.model_dump(mode="json")),
        "run_id": context.run_id,
        "schema": "faultloom.model-handoff.v1",
        "tool_schema_digest": tool.input_schema_digest,
    }
    return provider_canonical_json_bytes(document) + b"\n"


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
    minimum_grant_version = getattr(arguments, "minimum_grant_version")
    if (
        not isinstance(workspace, Path)
        or not isinstance(trusted_key, Path)
        or not isinstance(request_path, Path)
        or not isinstance(out_path, Path)
        or type(minimum_grant_version) is not int
    ):
        raise AutomationCompileError("automation export-handoff arguments are invalid", authority=False)

    manifest, grant, target, now = dependencies.verify_workspace(workspace, trusted_key)
    request = _parse_request(request_path, dependencies.capture_file(request_path))
    _validate_request_binding(
        manifest=manifest,
        grant=grant,
        target=target,
        now=now,
        minimum_grant_version=minimum_grant_version,
        request=request,
    )
    content = _model_handoff_bytes(request)
    dependencies.write_new_file(out_path, content)
    dependencies.emit_json(
        {
            "automatic_submission": False,
            "handoff": str(out_path),
            "independent_verification": False,
            "network_access": "none",
            "provider_dispatch": False,
            "sha256": hashlib.sha256(content).hexdigest(),
            "target_dispatch": False,
        }
    )
    return 0


def compile_automation(
    arguments: object,
    *,
    dependencies: AutomationCompileDependencies,
) -> int:
    """Compile one local model turn and atomically publish an offline bundle."""

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
    request = _parse_request(request_path, dependencies.capture_file(request_path))
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
