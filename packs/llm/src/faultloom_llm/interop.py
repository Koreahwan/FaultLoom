from __future__ import annotations

from faultloom.chain import PrimitiveStatus, SyntheticLlmPrimitive
from faultloom.hypothesis import HypothesisSeed
from faultloom.research import ProposalActorRole, ResearchPass, ResearchProposal
from faultloom_protocol import PrimitiveRecord, ProvenanceKind, SCHEMA_VERSION, sha256_digest
from faultloom_protocol.base import AwareDatetime, Identifier

from .errors import LlmPackError
from .observations import NormalizedAgentObservation, ObservationStatus
from .prompt import PromptAnalysis, PromptOutcome


def candidate_research_proposal(
    analysis: PromptAnalysis,
    created_at: AwareDatetime,
    actor_id: Identifier = "specialist.llm.agent",
) -> ResearchProposal:
    if analysis.outcome is not PromptOutcome.CANDIDATE:
        raise LlmPackError(
            "llm.prompt_not_candidate",
            "negative controls cannot become research proposals",
        )
    hypothesis = HypothesisSeed(
        run_id=analysis.run_id,
        statement="Untrusted content influenced an agent tool selection.",
        provenance=(
            ProvenanceKind.BEHAVIOR,
            ProvenanceKind.TOOL,
            ProvenanceKind.SPECIALIST,
        ),
        created_at=created_at,
        supporting_evidence=analysis.evidence_refs,
    ).as_record()
    token = sha256_digest(analysis.model_dump(mode="json")).removeprefix(
        "sha256:"
    )[:16]
    return ResearchProposal(
        proposal_id=f"proposal.llm.{token}",
        run_id=analysis.run_id,
        actor_id=actor_id,
        actor_role=ProposalActorRole.SPECIALIST,
        pass_kind=ResearchPass.BEHAVIOR,
        summary="Structured prompt-injection candidate from the isolated LLM pack.",
        provenance=hypothesis.provenance,
        evidence_refs=analysis.evidence_refs,
        proposed_hypotheses=(hypothesis,),
        created_at=created_at,
    )


def t35_admission(
    observation: NormalizedAgentObservation,
) -> SyntheticLlmPrimitive:
    source = observation.source
    verified = observation.status is ObservationStatus.VERIFIED_PRIMITIVE
    token = observation.normalization_digest.removeprefix("sha256:")[:16]
    primitive = PrimitiveRecord(
        schema_version=SCHEMA_VERSION,
        primitive_id=f"primitive.llm.{token}",
        run_id=source.run_id,
        primitive_kind=source.capability_kind,
        subject=source.subject,
        resource=source.resource,
        pre_state=source.pre_state,
        post_state=source.post_state,
        action_intent_digest=source.action_intent_digest,
        dispatch_receipt_digest=source.dispatch_receipt_digest,
        evidence_refs=source.evidence_refs,
        verified=verified,
    )
    return SyntheticLlmPrimitive(
        admission_id=f"admission.llm.{token}",
        capability_id=f"capability.llm.{token}",
        primitive=primitive,
        capability_kind=source.capability_kind,
        source_pack_id="pack.llm.agent",
        status=PrimitiveStatus.VERIFIED if verified else PrimitiveStatus.CANDIDATE,
        precondition_ids=source.precondition_ids,
        effect_ids=source.effect_ids,
        contract_id="faultloom.llm.agent.v1",
    )
