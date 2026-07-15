from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from faultloom_protocol import (
    ClaimPacket,
    Ed25519PublicKeyRecord,
    EvidenceRef,
    FindingCandidate,
    ReplayPlan,
    SignedAuthorityGrant,
    StateRef,
    VerificationVerdict,
)

from .authority import AuthorizedVerifier


@dataclass(frozen=True, slots=True)
class ControlResult:
    edge_id: str
    passed: bool
    evidence_refs: tuple[EvidenceRef, ...]


@dataclass(frozen=True, slots=True)
class ReplayExecutionRequest:
    verifier_run_id: str
    verifier_actor_id: str
    verifier_authority_digest: str
    claim_packet_digest: str
    replay_plan: ReplayPlan


@dataclass(frozen=True, slots=True)
class ReplayExecutionResult:
    verifier_run_id: str
    reset_state_refs: tuple[StateRef, ...]
    positive_controls: tuple[ControlResult, ...]
    negative_controls: tuple[ControlResult, ...]
    final_effect_observed: bool
    cleanup_receipt_digests: tuple[str, ...] = ()


class ReplayExecutor(Protocol):
    def execute(self, request: ReplayExecutionRequest) -> ReplayExecutionResult: ...


@dataclass(frozen=True, slots=True)
class ClaimDraft:
    claim_id: str
    claim: str
    prerequisites: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    negative_control_refs: tuple[EvidenceRef, ...]
    replay_plan: ReplayPlan
    cleanup_plan_ref: str | None
    created_at: datetime


@dataclass(frozen=True, slots=True)
class VerificationCase:
    candidate: FindingCandidate
    claim: ClaimPacket
    replay_plan: ReplayPlan
    source_authority_digest: str
    verifier: AuthorizedVerifier
    verified_at: datetime


@dataclass(frozen=True, slots=True)
class ResultArtifactContext:
    bundle_id: str
    bundle_version: int
    engagement_id: str
    run_manifest_digest: str
    source_authority_digest: str
    final_checkpoint_digest: str
    generated_at: datetime
    expires_at: datetime | None


@dataclass(frozen=True, slots=True)
class ResultArtifactDraft:
    context: ResultArtifactContext
    candidate: FindingCandidate
    claim: ClaimPacket
    verdict: VerificationVerdict
    cleanup_receipt_digests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResultExpectations:
    engagement_id: str
    run_id: str
    run_manifest_digest: str
    source_authority_digest: str
    source_actor_id: str
    verifier_actor_id: str
    verifier_authority_digest: str
    signed_verifier_authority: SignedAuthorityGrant
    trusted_verifier_authority_key: Ed25519PublicKeyRecord
    verification_time: datetime
    minimum_bundle_version: int = 1


@dataclass(frozen=True, slots=True)
class VerifierBinding:
    actor_id: str
    authority_digest: str


class ReportFormat(StrEnum):
    MARKDOWN = "md"
    JSON = "json"


@dataclass(frozen=True, slots=True)
class ReportReceipt:
    candidate_id: str
    claim_id: str
    verdict_id: str
    report_format: ReportFormat
    report_digest: str
    result_artifact_digest: str


@dataclass(frozen=True, slots=True)
class ReportArtifact:
    content: str
    receipt: ReportReceipt


@dataclass(frozen=True, slots=True)
class VerificationSummary:
    candidate_id: str
    claim_id: str
    verdict_id: str
    verifier_run_id: str
    outcome: str
    result_artifact_digest: str
