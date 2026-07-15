from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import ActionIntent, sha256_digest
from faultloom_protocol.base import Identifier, Sha256Digest


class _ToolPlannerModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class ToolPlanModelError(ValueError):
    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class ToolEvidenceRole(StrEnum):
    CANDIDATE = "candidate_only"
    CORROBORATING_REQUIRES_INDEPENDENT_REPLAY = (
        "corroborating_requires_independent_replay"
    )


class PlanningBudget(_ToolPlannerModel):
    rate_slots: Annotated[int, Field(ge=0)]
    duration_seconds: Annotated[int, Field(ge=0)]
    bytes: Annotated[int, Field(ge=0)]
    concurrency: Annotated[int, Field(ge=0)]
    actions: Annotated[int, Field(ge=0)]
    cost_microunits: Annotated[int, Field(ge=0)]

    def consume(self, estimate: ToolEstimate) -> PlanningBudget:
        return PlanningBudget(
            rate_slots=self.rate_slots - estimate.rate_slots,
            duration_seconds=self.duration_seconds - estimate.duration_seconds,
            bytes=self.bytes - estimate.bytes,
            concurrency=self.concurrency - estimate.concurrency,
            actions=self.actions - estimate.actions,
            cost_microunits=self.cost_microunits - estimate.cost_microunits,
        )


class ToolEstimate(_ToolPlannerModel):
    rate_slots: Annotated[int, Field(ge=1)]
    duration_seconds: Annotated[int, Field(ge=1)]
    bytes: Annotated[int, Field(ge=1)]
    concurrency: Annotated[int, Field(ge=1)]
    actions: Literal[1]
    cost_microunits: Annotated[int, Field(ge=0)]


class ToolCandidate(_ToolPlannerModel):
    candidate_id: Identifier
    hypothesis_id: Identifier
    intent: ActionIntent
    adapter_id: Identifier
    capability: Identifier
    expected_information_gain_bps: Annotated[int, Field(ge=1, le=10_000)]
    estimate: ToolEstimate


class ToolPlanReceipt(_ToolPlannerModel):
    candidate_id: Identifier
    candidate_digest: Sha256Digest
    hypothesis_id: Identifier
    hypothesis_digest: Sha256Digest
    authority_digest: Sha256Digest
    adapter_id: Identifier
    manifest_digest: Sha256Digest
    admission_snapshot_digest: Sha256Digest
    utility_receipt_digest: Sha256Digest
    budget_digest: Sha256Digest


class ToolPlanItem(_ToolPlannerModel):
    candidate: ToolCandidate
    evidence_role: ToolEvidenceRole
    receipt: ToolPlanReceipt

    @model_validator(mode="after")
    def _receipt_is_bound(self) -> Self:
        expected_digest = sha256_digest(self.candidate.model_dump(mode="json"))
        if self.receipt.candidate_digest != expected_digest:
            raise ToolPlanModelError("tool-plan receipt candidate digest mismatch")
        if (
            self.receipt.candidate_id != self.candidate.candidate_id
            or self.receipt.hypothesis_id != self.candidate.hypothesis_id
            or self.receipt.adapter_id != self.candidate.adapter_id
        ):
            raise ToolPlanModelError("tool-plan receipt identity mismatch")
        return self


class ToolPlan(_ToolPlannerModel):
    hypothesis_id: Identifier
    selected: ToolPlanItem
    remaining: PlanningBudget

    @model_validator(mode="after")
    def _hypothesis_is_bound(self) -> Self:
        if self.selected.candidate.hypothesis_id != self.hypothesis_id:
            raise ToolPlanModelError("tool plan belongs to another hypothesis")
        return self
