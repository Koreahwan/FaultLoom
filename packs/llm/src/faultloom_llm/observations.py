from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from faultloom_protocol import EvidenceRef, ResourceRef, StateRef, SubjectRef, sha256_digest
from faultloom_protocol.base import Identifier, Sha256Digest

from ._base import LlmPackModel
from .content import UntrustedContent
from .errors import LlmPackError


class AgentObservation(LlmPackModel):
    observation_id: Identifier
    run_id: Identifier
    capability_kind: Identifier
    subject: SubjectRef
    resource: ResourceRef
    pre_state: StateRef | None = None
    post_state: StateRef | None = None
    action_intent_digest: Sha256Digest
    dispatch_receipt_digest: Sha256Digest
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)
    content_provenance: tuple[UntrustedContent, ...] = Field(min_length=1)
    precondition_ids: tuple[Identifier, ...] = ()
    effect_ids: tuple[Identifier, ...] = Field(min_length=1)
    final_effect_observed: bool
    clean_replay: bool
    negative_control_passed: bool
    authorized_lease_observed: bool

    @model_validator(mode="after")
    def _evidence_is_run_closed(self) -> Self:
        if len(set(self.precondition_ids)) != len(self.precondition_ids):
            raise LlmPackError(
                "llm.observation_duplicate_precondition",
                "agent observation preconditions must be unique",
            )
        if len(set(self.effect_ids)) != len(self.effect_ids):
            raise LlmPackError(
                "llm.observation_duplicate_effect",
                "agent observation effects must be unique",
            )
        if any(item.run_id != self.run_id for item in self.evidence_refs):
            raise LlmPackError(
                "llm.observation_evidence_run_mismatch",
                "agent observation evidence belongs to another run",
            )
        if any(item.run_id != self.run_id for item in self.content_provenance):
            raise LlmPackError(
                "llm.observation_content_run_mismatch",
                "agent observation content belongs to another run",
            )
        return self

    @property
    def verification_ready(self) -> bool:
        return (
            self.final_effect_observed
            and self.clean_replay
            and self.negative_control_passed
            and self.authorized_lease_observed
        )


class ObservationStatus(StrEnum):
    CANDIDATE = "candidate"
    VERIFIED_PRIMITIVE = "verified_primitive"


class NormalizedAgentObservation(LlmPackModel):
    source: AgentObservation
    status: ObservationStatus
    normalizer_id: Identifier
    normalization_digest: Sha256Digest


class AgentObservationNormalizer:
    def normalize(self, source: AgentObservation) -> NormalizedAgentObservation:
        status = (
            ObservationStatus.VERIFIED_PRIMITIVE
            if source.verification_ready
            else ObservationStatus.CANDIDATE
        )
        return NormalizedAgentObservation(
            source=source,
            status=status,
            normalizer_id="llm.agent_observation.v1",
            normalization_digest=sha256_digest(source.model_dump(mode="json")),
        )
