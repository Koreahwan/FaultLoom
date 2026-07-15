from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import (
    EvidenceRef,
    HypothesisRecord,
    NegativeResult,
    ProvenanceKind,
)
from faultloom_protocol.base import AwareDatetime, Identifier, NonEmptyStr, Sha256Digest


class _ResearchModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class ResearchError(ValueError):
    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class ResearchIntegrityError(ResearchError):
    pass


class WriterConflictError(ResearchError):
    pass


class ResearchSequenceError(ResearchError):
    pass


class ResearchPassError(ResearchError):
    pass


class ProposalConflictError(ResearchError):
    pass


class ResearchPass(StrEnum):
    BEHAVIOR = "behavior"
    KNOWLEDGE = "knowledge"
    CHAIN = "chain"


class ProposalActorRole(StrEnum):
    SPECIALIST = "specialist"
    VERIFIER = "verifier"


class ResearchBinding(_ResearchModel):
    run_id: Identifier
    researcher_id: Identifier


class ResearchProposal(_ResearchModel):
    proposal_id: Identifier
    run_id: Identifier
    actor_id: Identifier
    actor_role: ProposalActorRole
    pass_kind: ResearchPass
    summary: NonEmptyStr
    provenance: tuple[ProvenanceKind, ...] = Field(min_length=1)
    evidence_refs: tuple[EvidenceRef, ...] = ()
    proposed_hypotheses: tuple[HypothesisRecord, ...] = ()
    proposed_negative_results: tuple[NegativeResult, ...] = ()
    created_at: AwareDatetime

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.provenance)) != len(self.provenance):
            raise ResearchError("proposal provenance must be unique")
        records = (
            self.evidence_refs
            + tuple(
                reference
                for hypothesis in self.proposed_hypotheses
                for reference in (
                    hypothesis.supporting_evidence
                    + hypothesis.contradicting_evidence
                )
            )
            + tuple(
                reference
                for negative in self.proposed_negative_results
                for reference in negative.evidence_refs
            )
        )
        if any(reference.run_id != self.run_id for reference in records):
            raise ResearchError("proposal evidence belongs to another run")
        if any(item.run_id != self.run_id for item in self.proposed_hypotheses):
            raise ResearchError("proposed hypothesis belongs to another run")
        if any(item.run_id != self.run_id for item in self.proposed_negative_results):
            raise ResearchError("proposed negative result belongs to another run")
        return self


class ResearchJournalState(_ResearchModel):
    binding: ResearchBinding
    current_pass: ResearchPass
    next_delta_sequence: int = Field(ge=1)
    last_delta_digest: Sha256Digest | None
    behavior_delta_count: int = Field(ge=0)
    knowledge_delta_count: int = Field(ge=0)
    chain_delta_count: int = Field(ge=0)
    proposal_count: int = Field(ge=0)
    watermark: int = Field(ge=0)
