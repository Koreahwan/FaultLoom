from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import assert_never

from faultloom_protocol import (
    ActionClass,
    ActionIntent,
    DeploymentAdaptation,
    PoCRecipe,
    PoCStep,
)
from faultloom_protocol.base import Identifier

from .errors import PatchVariantError
from .inputs import AdaptationRequest, CandidatePoCStep, StepHazard
from .results import AdaptationResult


class _StepDisposition(StrEnum):
    INCLUDE = "include"
    OMIT_OPTIONAL = "omit_optional"
    REMOVE_UNSAFE = "remove_unsafe"


def adapt_recipe(
    advisory_match_id: str,
    version_hypothesis_id: str,
    request: AdaptationRequest,
) -> AdaptationResult:
    included: list[CandidatePoCStep] = []
    omitted: list[Identifier] = []
    removed_digests: list[str] = []
    semantic_keys: set[tuple[str, str, str | None]] = set()
    for step in request.candidate_steps:
        match _step_disposition(step):
            case _StepDisposition.INCLUDE:
                key = (step.action_kind, step.method, step.payload_digest)
                if key not in semantic_keys:
                    semantic_keys.add(key)
                    included.append(step)
            case _StepDisposition.OMIT_OPTIONAL:
                omitted.append(step.step_id)
            case _StepDisposition.REMOVE_UNSAFE:
                removed_digests.append(_text_digest(step.model_dump_json()))
            case unreachable:
                assert_never(unreachable)
    if not included:
        raise PatchVariantError("adaptation contains no safe required verification step")
    poc_steps = tuple(_compile_step(step, request) for step in included)
    adaptation = DeploymentAdaptation(
        schema_version="0.1.0",
        adaptation_id=request.adaptation_id,
        advisory_match_id=advisory_match_id,
        target_id=request.target_id,
        version_hypothesis_id=version_hypothesis_id,
        route_ref=request.route_ref,
        identity_context_id=request.identity_context_id,
        transport=request.transport,
        prerequisite_ids=request.prerequisite_ids,
        removed_unsafe_step_digests=tuple(removed_digests),
        evidence_refs=request.evidence_refs,
    )
    recipe = PoCRecipe(
        schema_version="0.1.0",
        recipe_id=request.recipe_id,
        adaptation_id=request.adaptation_id,
        prerequisites=request.prerequisites,
        steps=poc_steps,
        expected_observable_effect=request.expected_observable_effect,
        negative_controls=request.negative_controls,
        cleanup_plan_ref=request.cleanup_plan_ref,
        evidence_refs=request.evidence_refs,
    )
    return AdaptationResult(
        adaptation=adaptation,
        recipe=recipe,
        omitted_nonessential_step_ids=tuple(omitted),
    )


def _step_disposition(step: CandidatePoCStep) -> _StepDisposition:
    match step.hazard:
        case StepHazard.SAFE:
            pass
        case (
            StepHazard.SHELL
            | StepHazard.DATA_DUMP
            | StepHazard.PERSISTENCE
            | StepHazard.DESTRUCTIVE
            | StepHazard.EXTERNAL_MESSAGE
            | StepHazard.PAYMENT
        ):
            return _StepDisposition.REMOVE_UNSAFE
        case unreachable:
            assert_never(unreachable)
    match step.action_class:
        case ActionClass.OBSERVE | ActionClass.SAFE_PROBE:
            return (
                _StepDisposition.INCLUDE
                if step.required
                else _StepDisposition.OMIT_OPTIONAL
            )
        case ActionClass.STATE_CHANGE | ActionClass.HIGH_LOAD | ActionClass.DESTRUCTIVE:
            return _StepDisposition.REMOVE_UNSAFE
        case unreachable:
            assert_never(unreachable)


def _compile_step(step: CandidatePoCStep, request: AdaptationRequest) -> PoCStep:
    intent = ActionIntent(
        schema_version="0.1.0",
        action_id=f"{request.run_id}.{step.step_id}",
        run_id=request.run_id,
        target_id=request.target_id,
        pack_id=request.pack_id,
        action_kind=step.action_kind,
        action_class=step.action_class,
        subject=request.subject,
        resource=request.route_ref,
        protocol=request.transport,
        method=step.method,
        path=request.route_path,
        payload_digest=step.payload_digest,
        requested_at=request.requested_at,
        cleanup_plan_ref=request.cleanup_plan_ref,
    )
    return PoCStep(
        schema_version="0.1.0",
        step_id=step.step_id,
        action_intent=intent,
        expected_effect=step.expected_effect,
        negative_control=step.negative_control,
    )


def _text_digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"
