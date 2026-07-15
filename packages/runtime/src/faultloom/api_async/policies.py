from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from typing import Final, assert_never

from faultloom_protocol import CallbackLease, FilePipeline
from .contracts import (
    CallbackAdmission,
    FilePipelineRecord,
    InertFileCanary,
    JobAccessAssessment,
    JobAccessProbe,
    SequenceMutation,
    SequencePlanRequest,
    SequenceVariant,
    SessionState,
    StatefulSequencePlan,
    SurfaceConflictError,
    SurfacePolicyError,
)

_SAFE_MEDIA_TYPES: Final = frozenset({"text/plain", "application/json"})
_SAFE_SUFFIXES: Final = frozenset({".txt", ".json"})
_FILE_STAGE_ORDER: Final = ("upload", "processing", "storage", "preview", "download")


def require_callback_eligible(
    admission: CallbackAdmission,
) -> CallbackLease:
    binding = admission.binding
    lease = admission.lease
    if not admission.scope_active:
        raise SurfacePolicyError("scope is revoked; callback is ineligible")
    if lease.engagement_id != binding.engagement_id:
        raise SurfacePolicyError("callback belongs to another engagement")
    if lease.grant_id != binding.grant_id or lease.scope_epoch != binding.scope_epoch:
        raise SurfacePolicyError("callback authority binding differs")
    if lease.owned_domain not in binding.owned_callback_domains:
        raise SurfacePolicyError("callback domain is not owned by this engagement")
    if (
        lease.revoked
        or admission.observed_at >= lease.expires_at
        or admission.observed_at < lease.issued_at
    ):
        raise SurfacePolicyError("callback lease is revoked, expired, or not yet valid")
    return lease


def assess_job_access(probe: JobAccessProbe) -> JobAccessAssessment:
    same_identity = (
        probe.owner_identity_context_id == probe.requester_identity_context_id
    )
    same_tenant = probe.owner_tenant_id == probe.requester_tenant_id
    match probe.session_state:
        case SessionState.ACTIVE:
            active = True
        case SessionState.STALE:
            active = False
        case unreachable:
            assert_never(unreachable)
    expected = same_identity and same_tenant and active
    material = (
        f"{probe.observation.job_observation_id}\0"
        f"{probe.requester_identity_context_id}\0{probe.session_state.value}"
    ).encode()
    return JobAccessAssessment(
        assessment_id=f"job-assessment.{hashlib.sha256(material).hexdigest()}",
        probe=probe,
        expected_allowed=expected,
        authorization_mismatch=probe.server_allowed != expected,
    )


def validate_file_pipeline(
    canary: InertFileCanary,
    pipeline: FilePipeline,
) -> FilePipelineRecord:
    suffix = PurePosixPath(canary.filename).suffix.lower()
    if canary.media_type not in _SAFE_MEDIA_TYPES or suffix not in _SAFE_SUFFIXES:
        raise SurfacePolicyError("file canary must be inert text or JSON")
    expected_suffix = {"text/plain": ".txt", "application/json": ".json"}[
        canary.media_type
    ]
    if suffix != expected_suffix:
        raise SurfacePolicyError("file canary extension and media type differ")
    if not pipeline.inert_canary or pipeline.canary_id != canary.canary_id:
        raise SurfacePolicyError("file pipeline is not bound to the inert canary")
    if pipeline.media_type != canary.media_type:
        raise SurfacePolicyError("file pipeline media type differs from the canary")
    stage_kinds = tuple(stage.stage_kind for stage in pipeline.stages)
    expected_prefix = _FILE_STAGE_ORDER[: len(stage_kinds)]
    if stage_kinds != expected_prefix:
        raise SurfacePolicyError("file stages must follow the semantic pipeline order")
    if any(stage.tenant_id != canary.tenant_id for stage in pipeline.stages):
        raise SurfacePolicyError("file stage crosses the canary tenant binding")
    if any(stage.artifact_digest != canary.artifact_digest for stage in pipeline.stages):
        raise SurfacePolicyError("file stage artifact differs from the inert canary")
    material = f"{pipeline.file_pipeline_id}\0{canary.path_digest}\0{canary.metadata_digest}"
    return FilePipelineRecord(
        record_id=f"file-record.{hashlib.sha256(material.encode()).hexdigest()}",
        canary=canary,
        pipeline=pipeline,
    )


def plan_stateful_sequence(
    request: SequencePlanRequest,
    run_id: str,
) -> StatefulSequencePlan:
    operation_ids = request.operation_ids
    if len(operation_ids) < 2 or len(set(operation_ids)) != len(operation_ids):
        raise SurfaceConflictError("sequence baseline needs two or more unique operations")
    variants = tuple(
        _sequence_variant(request.plan_id, mutation, operation_ids)
        for mutation in SequenceMutation
    )
    return StatefulSequencePlan(
        plan_id=request.plan_id,
        run_id=run_id,
        baseline_operation_ids=operation_ids,
        variants=variants,
        created_at=request.created_at,
    )


def _sequence_variant(
    plan_id: str,
    mutation: SequenceMutation,
    operation_ids: tuple[str, ...],
) -> SequenceVariant:
    match mutation:
        case SequenceMutation.REORDER:
            mutated = tuple(reversed(operation_ids))
            stale_token = False
        case SequenceMutation.REPLAY:
            mutated = operation_ids + operation_ids
            stale_token = False
        case SequenceMutation.DUPLICATE:
            mutated = operation_ids + (operation_ids[-1],)
            stale_token = False
        case SequenceMutation.STALE_TOKEN:
            mutated = operation_ids
            stale_token = True
        case unreachable:
            assert_never(unreachable)
    return SequenceVariant(
        variant_id=f"{plan_id}.{mutation.value}",
        mutation=mutation,
        operation_ids=mutated,
        stale_token=stale_token,
    )
