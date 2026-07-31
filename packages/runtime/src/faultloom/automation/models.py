from __future__ import annotations

import hashlib
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom.provider import OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES
from faultloom.patch_variant import AdaptationResult
from faultloom_protocol import (
    ActionClass,
    ActionIntent,
    AuthorityGrant,
    EvidenceRef,
    HypothesisRecord,
    NegativeResult,
    ProvenanceKind,
    ResourceRef,
    SubjectRef,
    sha256_digest,
)
from faultloom_protocol.base import AwareDatetime, Identifier, NonEmptyStr, Sha256Digest, ShortStr
from faultloom.tool_planner import PlanningBudget, ToolPlan


class _AutomationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class AuthorizedAutomationError(ValueError):
    __slots__ = ("detail",)

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail

    def __str__(self) -> str:
        return self.detail


class AutomationLimits(_AutomationModel):
    # The current OpenAI-compatible function-call wire contract accepts at
    # most 4 KiB of arguments.  A larger local-only limit would make the same
    # model turn behave differently when routed through a provider.
    max_response_bytes: Annotated[
        int, Field(ge=1, le=OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES)
    ] = OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES
    max_json_depth: Annotated[int, Field(ge=1, le=32)] = 12
    max_hypotheses: Annotated[int, Field(ge=1, le=8)] = 4
    max_negative_results: Annotated[int, Field(ge=0, le=8)] = 4
    max_actions: Annotated[int, Field(ge=0, le=8)] = 4
    max_poc_steps: Annotated[int, Field(ge=1, le=4)] = 3


class ModelDisclosureApproval(_AutomationModel):
    """Digest-bound operator approval for one redacted provider excerpt."""

    approval_id: Identifier
    run_id: Identifier
    evidence_id: Identifier
    source_cas_digest: Sha256Digest
    redaction_digest: Sha256Digest
    content_digest: Sha256Digest
    media_type: ShortStr
    data_policy_id: Identifier
    allowed_provider_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=16)
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    approver_key_id: Annotated[
        str, Field(pattern=r"^ed25519:sha256:[0-9a-f]{64}$")
    ]

    @model_validator(mode="after")
    def _validity_and_providers_are_exact(self) -> Self:
        if self.expires_at <= self.approved_at:
            raise AuthorizedAutomationError(
                "model disclosure approval expiry must follow approval"
            )
        if len(self.allowed_provider_ids) != len(set(self.allowed_provider_ids)):
            raise AuthorizedAutomationError(
                "model disclosure approval provider IDs must be unique"
            )
        return self


class SignedModelDisclosureApproval(_AutomationModel):
    payload: ModelDisclosureApproval
    payload_digest: Sha256Digest
    signature: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")]

    @model_validator(mode="after")
    def _payload_digest_is_exact(self) -> Self:
        if self.payload_digest != sha256_digest(self.payload.model_dump(mode="json")):
            raise AuthorizedAutomationError(
                "model disclosure approval payload digest mismatch"
            )
        return self


class ObservationExcerpt(_AutomationModel):
    """Operator-approved, redacted evidence content exposed to a model.

    Evidence is always untrusted data: it may contain prompt-injection text.
    The digest prevents a caller from relabeling different content as an
    already reviewed excerpt.
    """

    evidence_id: Identifier
    media_type: ShortStr
    content: Annotated[str, Field(min_length=1, max_length=3_072)]
    content_digest: Sha256Digest
    redacted: Literal[True]
    untrusted: Literal[True]
    model_disclosure_approved: Literal[True]
    approval: SignedModelDisclosureApproval

    @model_validator(mode="after")
    def _digest_is_exact(self) -> Self:
        observed = "sha256:" + hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        if observed != self.content_digest:
            raise AuthorizedAutomationError("observation excerpt digest mismatch")
        approval = self.approval.payload
        if (
            approval.evidence_id != self.evidence_id
            or approval.media_type != self.media_type
            or approval.content_digest != self.content_digest
        ):
            raise AuthorizedAutomationError(
                "observation excerpt differs from its disclosure approval"
            )
        return self


class ObservationBundle(_AutomationModel):
    run_id: Identifier
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1, max_length=16)
    excerpts: tuple[ObservationExcerpt, ...] = Field(min_length=1, max_length=16)
    observed_experiment_digests: tuple[Sha256Digest, ...] = Field(max_length=16)

    @model_validator(mode="after")
    def _references_are_unique_and_bound(self) -> Self:
        ids = tuple(item.evidence_id for item in self.evidence_refs)
        if len(ids) != len(set(ids)):
            raise AuthorizedAutomationError("observation evidence IDs must be unique")
        if any(item.run_id != self.run_id for item in self.evidence_refs):
            raise AuthorizedAutomationError("observation evidence belongs to another run")
        excerpt_ids = tuple(item.evidence_id for item in self.excerpts)
        if len(excerpt_ids) != len(set(excerpt_ids)):
            raise AuthorizedAutomationError("observation excerpt evidence IDs must be unique")
        if not set(excerpt_ids).issubset(ids):
            raise AuthorizedAutomationError("observation excerpt references unknown evidence")
        references = {item.evidence_id: item for item in self.evidence_refs}
        for excerpt in self.excerpts:
            reference = references[excerpt.evidence_id]
            approval = excerpt.approval.payload
            if approval.run_id != self.run_id:
                raise AuthorizedAutomationError(
                    "model disclosure approval belongs to another run"
                )
            if (
                reference.cas_digest != approval.source_cas_digest
                or reference.redaction_digest is None
                or reference.redaction_digest != approval.redaction_digest
            ):
                raise AuthorizedAutomationError(
                    "model disclosure approval is not bound to the evidence redaction"
                )
        if len(self.observed_experiment_digests) != len(
            set(self.observed_experiment_digests)
        ):
            raise AuthorizedAutomationError("observed experiment digests must be unique")
        return self


class ActionContext(_AutomationModel):
    run_id: Identifier
    target_id: Identifier
    pack_id: Identifier
    subject: SubjectRef
    resource: ResourceRef
    protocol: ShortStr
    method: ShortStr | None = None
    path: NonEmptyStr | None = None
    payload_digest: Sha256Digest | None = None
    cleanup_plan_ref: Identifier | None = None

    @model_validator(mode="after")
    def _resource_is_bound_to_target(self) -> Self:
        if self.resource.target_id != self.target_id:
            raise AuthorizedAutomationError("action context resource belongs to another target")
        return self


class SafePoCContext(_AutomationModel):
    run_id: Identifier
    target_id: Identifier
    pack_id: Identifier
    route_ref: ResourceRef
    route_path: Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$")]
    subject: SubjectRef
    transport: ShortStr
    prerequisite_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=8)
    prerequisites: tuple[NonEmptyStr, ...] = Field(min_length=1, max_length=8)
    cleanup_plan_ref: Identifier
    advisory_match_id: Identifier

    @model_validator(mode="after")
    def _route_is_bound_to_target(self) -> Self:
        if self.route_ref.target_id != self.target_id:
            raise AuthorizedAutomationError("PoC route belongs to another target")
        return self


class AutomationRequest(_AutomationModel):
    observations: ObservationBundle
    issued_at: AwareDatetime
    authority_grant: AuthorityGrant
    planning_budget: PlanningBudget
    action_context: ActionContext
    poc_context: SafePoCContext | None = None
    limits: AutomationLimits = AutomationLimits()
    provider_network_access: Literal["none", "provider_only"] = "none"

    @model_validator(mode="after")
    def _run_is_bound_everywhere(self) -> Self:
        run_id = self.observations.run_id
        if self.action_context.run_id != run_id:
            raise AuthorizedAutomationError("action context belongs to another run")
        if self.poc_context is not None and self.poc_context.run_id != run_id:
            raise AuthorizedAutomationError("PoC context belongs to another run")
        return self


class HypothesisProposal(_AutomationModel):
    proposal_id: Identifier
    statement: NonEmptyStr
    provenance: tuple[ProvenanceKind, ...] = Field(min_length=1, max_length=4)
    supporting_evidence_ids: tuple[Identifier, ...] = Field(max_length=16)
    contradicting_evidence_ids: tuple[Identifier, ...] = Field(max_length=16)
    prerequisite_ids: tuple[Identifier, ...] = Field(max_length=8)


class NegativeConclusionProposal(_AutomationModel):
    hypothesis_proposal_id: Identifier
    experiment_digest: Sha256Digest
    conclusion: NonEmptyStr
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=16)


class ActionEstimateProposal(_AutomationModel):
    rate_slots: Annotated[int, Field(ge=1, le=64)]
    duration_seconds: Annotated[int, Field(ge=1, le=86_400)]
    bytes: Annotated[int, Field(ge=1, le=16_777_216)]
    concurrency: Annotated[int, Field(ge=1, le=16)]
    cost_microunits: Annotated[int, Field(ge=0, le=10_000_000)]


class ToolActionProposal(_AutomationModel):
    candidate_id: Identifier
    hypothesis_proposal_id: Identifier
    adapter_id: Identifier
    capability: Identifier
    action_kind: Identifier
    action_class: ActionClass
    expected_information_gain_bps: Annotated[int, Field(ge=1, le=10_000)]
    estimate: ActionEstimateProposal


class SafePoCStepProposal(_AutomationModel):
    step_id: Identifier
    action_class: ActionClass
    action_kind: Identifier
    method: ShortStr
    payload_digest: Sha256Digest | None = None
    expected_effect: NonEmptyStr
    negative_control: NonEmptyStr
    required: bool = True
    hazard: Literal["safe"]


class SafePoCProposal(_AutomationModel):
    adaptation_id: Identifier
    recipe_id: Identifier
    hypothesis_proposal_id: Identifier
    expected_observable_effect: NonEmptyStr
    negative_controls: tuple[NonEmptyStr, ...] = Field(min_length=1, max_length=4)
    evidence_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=16)
    steps: tuple[SafePoCStepProposal, ...] = Field(min_length=1, max_length=4)


class FindingDraftProposal(_AutomationModel):
    hypothesis_proposal_id: Identifier
    poc_recipe_id: Identifier | None = None
    title: Annotated[str, Field(min_length=1, max_length=200)]
    severity: Literal["info", "low", "medium", "high", "critical"]
    summary: Annotated[str, Field(min_length=1, max_length=2_000)]
    impact: Annotated[str, Field(min_length=1, max_length=2_000)]
    reproduction_steps: tuple[NonEmptyStr, ...] = Field(min_length=1, max_length=8)
    remediation: Annotated[str, Field(min_length=1, max_length=2_000)]


class CandidateFindingDraft(_AutomationModel):
    hypothesis_id: Identifier
    poc_recipe_id: Identifier | None = None
    title: Annotated[str, Field(min_length=1, max_length=200)]
    severity: Literal["info", "low", "medium", "high", "critical"]
    summary: Annotated[str, Field(min_length=1, max_length=2_000)]
    impact: Annotated[str, Field(min_length=1, max_length=2_000)]
    reproduction_steps: tuple[NonEmptyStr, ...] = Field(min_length=1, max_length=8)
    remediation: Annotated[str, Field(min_length=1, max_length=2_000)]
    status: Literal["draft_unverified"] = "draft_unverified"
    independent_verification_performed: Literal[False] = False
    automatic_submission_performed: Literal[False] = False


class ModelTurn(_AutomationModel):
    hypotheses: tuple[HypothesisProposal, ...] = Field(min_length=1, max_length=8)
    negative_results: tuple[NegativeConclusionProposal, ...] = Field(max_length=8)
    actions: tuple[ToolActionProposal, ...] = Field(max_length=8)
    poc: SafePoCProposal | None = None
    finding_draft: FindingDraftProposal | None = None
    stop_reason: Annotated[str, Field(min_length=1, max_length=256)]

    @model_validator(mode="after")
    def _proposal_ids_are_unique(self) -> Self:
        hypothesis_ids = tuple(item.proposal_id for item in self.hypotheses)
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise AuthorizedAutomationError("hypothesis proposal IDs must be unique")
        candidate_ids = tuple(item.candidate_id for item in self.actions)
        if len(candidate_ids) != len(set(candidate_ids)):
            raise AuthorizedAutomationError("action candidate IDs must be unique")
        step_ids = () if self.poc is None else tuple(item.step_id for item in self.poc.steps)
        if len(step_ids) != len(set(step_ids)):
            raise AuthorizedAutomationError("PoC step IDs must be unique")
        return self


class ReasoningEvidence(_AutomationModel):
    evidence_id: Identifier
    cas_digest: Sha256Digest
    redaction_digest: Sha256Digest | None = None
    media_type: ShortStr
    content: Annotated[str, Field(min_length=1, max_length=3_072)]
    content_digest: Sha256Digest
    redacted: Literal[True]
    untrusted: Literal[True]


class ReasoningScopeSummary(_AutomationModel):
    target_ids: tuple[Identifier, ...]
    pack_ids: tuple[Identifier, ...]
    adapter_ids: tuple[Identifier, ...]
    allowed_action_classes: tuple[ActionClass, ...]
    allowed_action_families: tuple[Identifier, ...]


class ReasoningTurnRequest(_AutomationModel):
    """Canonical, bounded context handed to any structured-output model.

    ``evidence`` contains only operator-approved redacted excerpts and remains
    explicitly marked untrusted so provider prompts cannot treat evidence text
    as instructions.
    """

    run_id: Identifier
    evidence: tuple[ReasoningEvidence, ...] = Field(min_length=1)
    authority_grant_digest: Sha256Digest
    scope: ReasoningScopeSummary
    remaining_budget: PlanningBudget
    active_hypotheses: tuple[HypothesisRecord, ...] = ()
    important_negative_results: tuple[NegativeResult, ...] = ()
    limits: AutomationLimits
    output_schema_digest: Sha256Digest

    @classmethod
    def from_request(
        cls,
        request: AutomationRequest,
        *,
        active_hypotheses: tuple[HypothesisRecord, ...] = (),
        important_negative_results: tuple[NegativeResult, ...] = (),
    ) -> "ReasoningTurnRequest":
        if type(request) is not AutomationRequest:
            raise AuthorizedAutomationError("reasoning context requires an exact automation request")
        if any(item.run_id != request.observations.run_id for item in active_hypotheses):
            raise AuthorizedAutomationError("active hypothesis belongs to another run")
        if any(item.run_id != request.observations.run_id for item in important_negative_results):
            raise AuthorizedAutomationError("negative result belongs to another run")
        grant = request.authority_grant
        references = {
            item.evidence_id: item for item in request.observations.evidence_refs
        }
        return cls(
            run_id=request.observations.run_id,
            evidence=tuple(
                ReasoningEvidence(
                    evidence_id=excerpt.evidence_id,
                    cas_digest=references[excerpt.evidence_id].cas_digest,
                    redaction_digest=references[excerpt.evidence_id].redaction_digest,
                    media_type=excerpt.media_type,
                    content=excerpt.content,
                    content_digest=excerpt.content_digest,
                    redacted=True,
                    untrusted=True,
                )
                for excerpt in request.observations.excerpts
            ),
            authority_grant_digest=sha256_digest(grant),
            scope=ReasoningScopeSummary(
                target_ids=tuple(item.target_id for item in grant.targets),
                pack_ids=grant.pack_ids,
                adapter_ids=grant.adapter_ids,
                allowed_action_classes=grant.action_policy.allowed_classes,
                allowed_action_families=grant.action_policy.allowed_families,
            ),
            remaining_budget=request.planning_budget,
            active_hypotheses=active_hypotheses,
            important_negative_results=important_negative_results,
            limits=request.limits,
            output_schema_digest=model_turn_schema_digest(),
        )


def model_turn_output_schema() -> dict[str, object]:
    """Return the exact strict JSON schema expected from a model turn."""

    return ModelTurn.model_json_schema()


def model_turn_schema_digest() -> str:
    return sha256_digest(model_turn_output_schema())


class AuthorizedAutomationResult(_AutomationModel):
    run_id: Identifier
    authority_grant_id: Identifier
    authority_grant_version: Annotated[int, Field(ge=1)]
    authority_grant_digest: Sha256Digest
    observation_bundle_digest: Sha256Digest
    action_context_digest: Sha256Digest
    poc_context_digest: Sha256Digest | None = None
    hypotheses: tuple[HypothesisRecord, ...]
    negative_results: tuple[NegativeResult, ...]
    admitted_plans: tuple[ToolPlan, ...]
    poc: AdaptationResult | None = None
    finding_draft: CandidateFindingDraft | None = None
    stop_reason: Annotated[str, Field(min_length=1, max_length=256)]
    provider_network_access: Literal["none", "provider_only"]
    verification_status: Literal["candidate_only_requires_independent_verification"] = (
        "candidate_only_requires_independent_verification"
    )
    target_dispatch_performed: Literal[False] = False
    automatic_submission_performed: Literal[False] = False
