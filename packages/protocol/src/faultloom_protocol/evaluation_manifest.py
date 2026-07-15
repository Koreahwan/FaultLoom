"""Public, non-secret inputs for reproducible three-arm evaluation."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .base import (
    AwareDatetime,
    Identifier,
    MAX_INT64,
    ProtocolModel,
    Sha256Digest,
)
from .evaluation_enums import (
    ArtifactKind,
    ChainDepthBand,
    EvaluationArm,
    EvaluationDomain,
    EvaluationFindingKind,
    ExecutionTiming,
    IdentityCardinality,
    TenantCardinality,
)

PositiveInt = Annotated[int, Field(ge=1, le=MAX_INT64)]
NonNegativeInt = Annotated[int, Field(ge=0, le=MAX_INT64)]
ContextLoadBps = Annotated[int, Field(ge=0, le=MAX_INT64)]
ContextResetCount = Annotated[
    Literal[0, 1, 3, 10],
    Field(json_schema_extra={"maximum": MAX_INT64}),
]
StableVersion = Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
SourceCommit = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]


class EvaluationTaxonomy(ProtocolModel):
    domain: EvaluationDomain
    finding_kind: EvaluationFindingKind
    chain_depth: ChainDepthBand
    identity_cardinality: IdentityCardinality
    tenant_cardinality: TenantCardinality
    execution_timing: ExecutionTiming


class EvaluationCaseDescriptor(ProtocolModel):
    """Opaque case metadata; fixture bytes and oracle material are deliberately absent."""

    case_id: Identifier
    case_revision: PositiveInt
    taxonomy: EvaluationTaxonomy
    pack_ids: tuple[Identifier, ...]
    adapter_ids: tuple[Identifier, ...] = ()
    context_reset_count: ContextResetCount
    workload_context_bps: ContextLoadBps
    fixture_visibility: Literal["public_loopback", "private_holdout"]

    @model_validator(mode="after")
    def _descriptor_is_unambiguous(self) -> "EvaluationCaseDescriptor":
        if not self.pack_ids:
            raise ValueError("evaluation case requires at least one pack")
        if len(self.pack_ids) != len(set(self.pack_ids)):
            raise ValueError("evaluation case pack IDs must be unique")
        if len(self.adapter_ids) != len(set(self.adapter_ids)):
            raise ValueError("evaluation case adapter IDs must be unique")
        return self


class EvaluationBudget(ProtocolModel):
    action_limit: PositiveInt
    duration_seconds: PositiveInt
    model_token_limit: PositiveInt
    cost_microunits: PositiveInt


class EvaluationArmConfig(ProtocolModel):
    arm: EvaluationArm
    runtime_artifact_digest: Sha256Digest
    model_snapshot_digest: Sha256Digest
    tool_inventory_digest: Sha256Digest
    gateway_artifact_digest: Sha256Digest
    budget: EvaluationBudget


class EvaluationManifest(ProtocolModel):
    """Sealed public comparison plan with no private fixture or scoring payload."""

    manifest_id: Identifier
    manifest_version: PositiveInt
    sealed_plan_digest: Sha256Digest
    protocol_artifact_digest: Sha256Digest
    cases: tuple[EvaluationCaseDescriptor, ...]
    arms: tuple[EvaluationArmConfig, ...]
    created_at: AwareDatetime

    @model_validator(mode="after")
    def _honest_three_arm_comparison(self) -> "EvaluationManifest":
        expected_arms = set(EvaluationArm)
        actual_arms = {arm.arm for arm in self.arms}
        if len(self.arms) != len(expected_arms) or actual_arms != expected_arms:
            raise ValueError("manifest requires exactly the three evaluation arms")
        if not self.cases:
            raise ValueError("evaluation manifest requires at least one case")
        case_ids = {case.case_id for case in self.cases}
        if len(case_ids) != len(self.cases):
            raise ValueError("evaluation manifest case IDs must be unique")

        reference = self.arms[0]
        if any(
            arm.model_snapshot_digest != reference.model_snapshot_digest
            or arm.tool_inventory_digest != reference.tool_inventory_digest
            or arm.gateway_artifact_digest != reference.gateway_artifact_digest
            or arm.budget != reference.budget
            for arm in self.arms[1:]
        ):
            raise ValueError(
                "three-arm evaluation requires identical model, tools, gateway, and budget"
            )
        return self


class ArtifactAttestation(ProtocolModel):
    """Public artifact identity; private fixtures are not a representable artifact kind."""

    attestation_id: Identifier
    artifact_kind: ArtifactKind
    artifact_id: Identifier
    artifact_version: StableVersion
    artifact_digest: Sha256Digest
    source_commit: SourceCommit
    sbom_digest: Sha256Digest
    built_at: AwareDatetime
