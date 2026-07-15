from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from faultloom_protocol import (
    CallbackLease,
    MessageEnvelope,
    SCHEMA_VERSION,
    SurfaceGraph,
)
from faultloom_protocol.base import AwareDatetime, Sha256Digest

from .contracts import (
    FilePipelineRecord,
    FollowUpAction,
    JobAccessAssessment,
    ScopeRevocation,
    StatefulSequencePlan,
    SurfaceBinding,
    SurfaceConflictError,
    SurfaceDifferential,
    _SurfaceModel,
)


class SurfaceState(_SurfaceModel):
    format_version: Literal[1] = 1
    binding: SurfaceBinding
    graph: SurfaceGraph
    messages: tuple[MessageEnvelope, ...] = ()
    callback_leases: tuple[CallbackLease, ...] = ()
    job_assessments: tuple[JobAccessAssessment, ...] = ()
    file_pipelines: tuple[FilePipelineRecord, ...] = ()
    sequence_plans: tuple[StatefulSequencePlan, ...] = ()
    differentials: tuple[SurfaceDifferential, ...] = ()
    follow_ups: tuple[FollowUpAction, ...] = ()
    completed_effect_ids: tuple[str, ...] = ()
    revocation: ScopeRevocation | None = None
    watermark: int = Field(ge=0)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.graph.graph_id != self.binding.graph_id:
            raise SurfaceConflictError("surface graph differs from its binding")
        if self.graph.run_id != self.binding.run_id:
            raise SurfaceConflictError("surface graph belongs to another run")
        collections = (
            tuple(item.message_id for item in self.messages),
            tuple(item.callback_lease_id for item in self.callback_leases),
            tuple(item.assessment_id for item in self.job_assessments),
            tuple(item.record_id for item in self.file_pipelines),
            tuple(item.plan_id for item in self.sequence_plans),
            tuple(item.differential_id for item in self.differentials),
            tuple(item.follow_up_id for item in self.follow_ups),
            self.completed_effect_ids,
        )
        if any(len(values) != len(set(values)) for values in collections):
            raise SurfaceConflictError("surface state contains duplicate record IDs")
        if self.revocation is not None and self.revocation.scope_epoch != self.binding.scope_epoch:
            raise SurfaceConflictError("scope revocation belongs to another epoch")
        return self


class SurfaceSnapshot(_SurfaceModel):
    format_version: Literal[1] = 1
    sequence: int = Field(ge=1)
    previous_snapshot_digest: Sha256Digest | None
    state: SurfaceState
    recorded_at: AwareDatetime


def empty_surface_state(binding: SurfaceBinding) -> SurfaceState:
    return SurfaceState(
        binding=binding,
        graph=SurfaceGraph(
            schema_version=SCHEMA_VERSION,
            graph_id=binding.graph_id,
            run_id=binding.run_id,
            operations=(),
            schema_evidence=(),
            async_flows=(),
            edges=(),
            version=1,
        ),
        watermark=0,
    )
