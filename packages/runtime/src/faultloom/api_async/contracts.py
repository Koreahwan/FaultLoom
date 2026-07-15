from __future__ import annotations

from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import (
    AsyncFlow,
    CallbackLease,
    FilePipeline,
    JobObservation,
    OperationRef,
    SchemaEvidence,
)
from faultloom_protocol.base import AwareDatetime, Identifier, Sha256Digest, ShortStr


class _SurfaceModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class SurfaceError(ValueError):
    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class SurfaceConflictError(SurfaceError):
    pass


class SurfaceIntegrityError(SurfaceError):
    pass


class SurfacePolicyError(SurfaceError):
    pass


class SchemaIngestError(SurfaceError):
    pass


class CorrelationKind(StrEnum):
    REQUEST_ID = "request_id"
    JOB_ID = "job_id"
    CALLBACK_ID = "callback_id"
    OBJECT_ID = "object_id"
    MESSAGE_ID = "message_id"
    TIMESTAMP = "timestamp"


class FollowUpKind(StrEnum):
    CALLBACK = "callback"
    POLL = "poll"
    WEBSOCKET = "websocket"


class SessionState(StrEnum):
    ACTIVE = "active"
    STALE = "stale"


class SequenceMutation(StrEnum):
    REORDER = "reorder"
    REPLAY = "replay"
    DUPLICATE = "duplicate"
    STALE_TOKEN = "stale_token"


class SurfaceBinding(_SurfaceModel):
    format_version: Literal[1] = 1
    engagement_id: Identifier
    run_id: Identifier
    target_id: Identifier
    graph_id: Identifier
    grant_id: Identifier
    scope_epoch: int = Field(ge=1)
    owned_callback_domains: tuple[ShortStr, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_callback_domains(self) -> Self:
        if len(set(self.owned_callback_domains)) != len(self.owned_callback_domains):
            raise SurfaceConflictError("owned callback domains must be unique")
        return self


class SchemaBatch(_SurfaceModel):
    batch_id: Identifier
    operations: tuple[OperationRef, ...] = Field(min_length=1)
    evidence: SchemaEvidence

    @model_validator(mode="after")
    def _binds_evidence(self) -> Self:
        operation_ids = tuple(item.operation_id for item in self.operations)
        if len(set(operation_ids)) != len(operation_ids):
            raise SurfaceConflictError("schema batch operation IDs must be unique")
        if frozenset(operation_ids) != frozenset(self.evidence.operation_ids):
            raise SurfaceConflictError("schema evidence does not bind the batch operations")
        return self


class OpaqueCorrelation(_SurfaceModel):
    kind: CorrelationKind
    value: bytes = Field(min_length=1, max_length=4096)


class CallbackAdmission(_SurfaceModel):
    binding: SurfaceBinding
    lease: CallbackLease
    observed_at: AwareDatetime
    scope_active: bool


class FollowUpAction(_SurfaceModel):
    follow_up_id: Identifier
    async_flow_id: Identifier
    operation_id: Identifier
    kind: FollowUpKind
    callback_lease_id: Identifier | None = None

    @model_validator(mode="after")
    def _callback_has_lease(self) -> Self:
        requires_lease = self.kind is FollowUpKind.CALLBACK
        if requires_lease != (self.callback_lease_id is not None):
            raise SurfaceConflictError("callback follow-up requires exactly one lease")
        return self


class FlowCompletion(_SurfaceModel):
    async_flow_id: Identifier
    terminal_operation_id: Identifier
    completed_at: AwareDatetime
    effect_id: Identifier


class FlowStart(_SurfaceModel):
    flow: AsyncFlow
    follow_ups: tuple[FollowUpAction, ...] = ()

    @model_validator(mode="after")
    def _pending_and_bound(self) -> Self:
        if not self.flow.pending:
            raise SurfaceConflictError("new async flow must be pending")
        if self.flow.initiating_operation_id not in self.flow.operation_ids:
            raise SurfaceConflictError("initiating operation must belong to the async flow")
        if any(item.async_flow_id != self.flow.async_flow_id for item in self.follow_ups):
            raise SurfaceConflictError("follow-up belongs to another async flow")
        return self


class JobAccessProbe(_SurfaceModel):
    observation: JobObservation
    owner_identity_context_id: Identifier
    owner_tenant_id: Identifier
    requester_identity_context_id: Identifier
    requester_tenant_id: Identifier
    session_state: SessionState
    server_allowed: bool

    @model_validator(mode="after")
    def _requester_matches_observation(self) -> Self:
        if self.observation.identity_context_id != self.requester_identity_context_id:
            raise SurfaceConflictError("job observation is not bound to its requester")
        return self


class JobAccessAssessment(_SurfaceModel):
    assessment_id: Identifier
    probe: JobAccessProbe
    expected_allowed: bool
    authorization_mismatch: bool


class InertFileCanary(_SurfaceModel):
    canary_id: Identifier
    filename: ShortStr
    media_type: ShortStr
    artifact_digest: Sha256Digest
    path_digest: Sha256Digest
    metadata_digest: Sha256Digest
    tenant_id: Identifier


class FilePipelineRecord(_SurfaceModel):
    record_id: Identifier
    canary: InertFileCanary
    pipeline: FilePipeline


class SequenceVariant(_SurfaceModel):
    variant_id: Identifier
    mutation: SequenceMutation
    operation_ids: tuple[Identifier, ...] = Field(min_length=1)
    stale_token: bool = False


class StatefulSequencePlan(_SurfaceModel):
    plan_id: Identifier
    run_id: Identifier
    baseline_operation_ids: tuple[Identifier, ...] = Field(min_length=2)
    variants: tuple[SequenceVariant, ...] = Field(min_length=4, max_length=4)
    created_at: AwareDatetime

    @model_validator(mode="after")
    def _has_each_mutation_once(self) -> Self:
        if {item.mutation for item in self.variants} != set(SequenceMutation):
            raise SurfaceConflictError("sequence plan must contain each mutation once")
        if len({item.variant_id for item in self.variants}) != len(self.variants):
            raise SurfaceConflictError("sequence variant IDs must be unique")
        return self


class SequencePlanRequest(_SurfaceModel):
    plan_id: Identifier
    operation_ids: tuple[Identifier, ...] = Field(min_length=2)
    created_at: AwareDatetime


class SurfaceDifferential(_SurfaceModel):
    differential_id: Identifier
    operation_id: Identifier
    baseline_identity_context_id: Identifier
    comparison_identity_context_id: Identifier
    baseline_tenant_id: Identifier
    comparison_tenant_id: Identifier
    baseline_effect_digest: Sha256Digest
    comparison_effect_digest: Sha256Digest
    comparison_authorized: bool
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def _uses_distinct_contexts(self) -> Self:
        if self.baseline_identity_context_id == self.comparison_identity_context_id:
            raise SurfaceConflictError("differential identities must be distinct")
        return self


class ScopeRevocation(_SurfaceModel):
    scope_epoch: int = Field(ge=1)
    revoked_at: AwareDatetime


class UndocumentedObservation(_SurfaceModel):
    operation: OperationRef
    source_kind: Literal["traffic", "javascript", "operator"]
    source_digest: Sha256Digest
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def _is_undocumented(self) -> Self:
        if self.operation.documented:
            raise SurfaceConflictError("observed undocumented operation cannot be documented")
        return self
