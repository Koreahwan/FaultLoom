from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import (
    CapabilityPrimitive,
    IdentityGraph,
    PrimitiveRecord,
    ReachabilityClaim,
    SurfaceGraph,
    VariantHypothesis,
    WorkflowGraph,
)
from faultloom_protocol.base import Identifier

from .errors import ChainIntegrityError


class _AdmissionModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    schema_version: Literal["0.1.0"] = "0.1.0"


class PrimitiveStatus(StrEnum):
    CANDIDATE = "candidate"
    VERIFIED = "verified"


class _PrimitiveAdmission(_AdmissionModel):
    admission_id: Identifier
    capability_id: Identifier
    primitive: PrimitiveRecord
    capability_kind: Identifier
    source_pack_id: Identifier
    status: PrimitiveStatus
    precondition_ids: tuple[Identifier, ...] = ()
    effect_ids: tuple[Identifier, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _status_matches_primitive(self) -> Self:
        if len(set(self.precondition_ids)) != len(self.precondition_ids):
            raise ChainIntegrityError(
                "chain.duplicate_precondition",
                "primitive precondition IDs must be unique",
            )
        if len(set(self.effect_ids)) != len(self.effect_ids):
            raise ChainIntegrityError(
                "chain.duplicate_effect",
                "primitive effect IDs must be unique",
            )
        match self.status:
            case PrimitiveStatus.CANDIDATE:
                if self.primitive.verified:
                    raise ChainIntegrityError(
                        "chain.candidate_marked_verified",
                        "candidate admission cannot contain a verified primitive",
                    )
            case PrimitiveStatus.VERIFIED:
                if not self.primitive.verified:
                    raise ChainIntegrityError(
                        "chain.verified_without_replay",
                        "verified admission requires a verified primitive",
                    )
        return self


class IdentityWorkflowPrimitive(_PrimitiveAdmission):
    source_kind: Literal["identity_workflow"] = "identity_workflow"
    identity_graph: IdentityGraph
    workflow_graph: WorkflowGraph

    @model_validator(mode="after")
    def _run_is_closed(self) -> Self:
        run_ids = {
            self.primitive.run_id,
            self.identity_graph.run_id,
            self.workflow_graph.run_id,
        }
        if len(run_ids) != 1:
            raise ChainIntegrityError(
                "chain.identity_run_mismatch",
                "identity/workflow source artifacts must share one run",
            )
        return self


class ApiAsyncPrimitive(_PrimitiveAdmission):
    source_kind: Literal["api_async"] = "api_async"
    surface_graph: SurfaceGraph

    @model_validator(mode="after")
    def _run_is_closed(self) -> Self:
        if self.surface_graph.run_id != self.primitive.run_id:
            raise ChainIntegrityError(
                "chain.surface_run_mismatch",
                "API/async source artifact must share the primitive run",
            )
        return self


class PatchVariantPrimitive(_PrimitiveAdmission):
    source_kind: Literal["patch_variant"] = "patch_variant"
    reachability: ReachabilityClaim
    variant: VariantHypothesis | None = None

    @model_validator(mode="after")
    def _verified_source_is_reachable(self) -> Self:
        if (
            self.status is PrimitiveStatus.VERIFIED
            and self.reachability.conclusion != "reachable"
        ):
            raise ChainIntegrityError(
                "chain.patch_not_reachable",
                "verified patch/CVE primitive requires reachable deployment evidence",
            )
        return self


class SyntheticLlmPrimitive(_PrimitiveAdmission):
    source_kind: Literal["synthetic_llm"] = "synthetic_llm"
    contract_id: Identifier
    synthetic_fixture_only: Literal[True] = True


type PrimitiveAdmission = Annotated[
    IdentityWorkflowPrimitive
    | ApiAsyncPrimitive
    | PatchVariantPrimitive
    | SyntheticLlmPrimitive,
    Field(discriminator="source_kind"),
]


class PrimitiveRegistry(_AdmissionModel):
    capabilities: tuple[CapabilityPrimitive, ...]
    candidate_capability_ids: tuple[Identifier, ...]
    verified_capability_ids: tuple[Identifier, ...]

    @model_validator(mode="after")
    def _partitions_capabilities(self) -> Self:
        capability_ids = tuple(item.capability_id for item in self.capabilities)
        if len(capability_ids) != len(set(capability_ids)):
            raise ChainIntegrityError(
                "chain.duplicate_capability",
                "registry capability IDs must be unique",
            )
        expected_verified = {
            item.capability_id for item in self.capabilities if item.verified
        }
        expected_candidates = set(capability_ids).difference(expected_verified)
        if set(self.verified_capability_ids) != expected_verified:
            raise ChainIntegrityError(
                "chain.verified_partition_mismatch",
                "verified registry partition differs from capabilities",
            )
        if set(self.candidate_capability_ids) != expected_candidates:
            raise ChainIntegrityError(
                "chain.candidate_partition_mismatch",
                "candidate registry partition differs from capabilities",
            )
        return self

    def capability(self, capability_id: str) -> CapabilityPrimitive:
        for capability in self.capabilities:
            if capability.capability_id == capability_id:
                return capability
        raise ChainIntegrityError(
            "chain.unknown_capability",
            f"registry has no capability {capability_id}",
        )
