from __future__ import annotations

from pathlib import Path

import pytest

from faultloom.hypothesis import HypothesisSeed
from faultloom.research import (
    PersistentResearcher,
    ProposalActorRole,
    ProposalMergeRequest,
    ResearchBinding,
    ResearchPass,
    ResearchProposal,
    SpecialistMergeError,
)
from faultloom_protocol import ProvenanceKind, sha256_digest
from tests.protocol.factories import NOW, sample_models
from tests.runtime.resume_support import open_store


def _proposal(*, role: ProposalActorRole = ProposalActorRole.SPECIALIST) -> ResearchProposal:
    evidence = sample_models()["EvidenceRef"]
    hypothesis = HypothesisSeed(
        run_id="run.1",
        statement="A specialist-derived invariant may be violated.",
        provenance=(ProvenanceKind.BEHAVIOR, ProvenanceKind.SPECIALIST),
        created_at=NOW,
        supporting_evidence=(evidence,),
    ).as_record()
    return ResearchProposal(
        proposal_id=f"proposal.{role.value}",
        run_id="run.1",
        actor_id=f"actor.{role.value}",
        actor_role=role,
        pass_kind=ResearchPass.BEHAVIOR,
        summary="Structured specialist proposal without hidden reasoning.",
        provenance=(ProvenanceKind.BEHAVIOR, ProvenanceKind.SPECIALIST),
        evidence_refs=(evidence,),
        proposed_hypotheses=(hypothesis,),
        created_at=NOW,
    )


def _request(proposal: ResearchProposal, *, summary: str = "Merge accepted proposal."):
    return ProposalMergeRequest(
        run_id=proposal.run_id,
        proposal_id=proposal.proposal_id,
        expected_proposal_digest=sha256_digest(proposal.model_dump(mode="json")),
        selected_hypothesis_ids=(proposal.proposed_hypotheses[0].hypothesis_id,),
        summary=summary,
        created_at=NOW,
    )


def test_specialist_merge_is_authoritative_durable_and_idempotent(tmp_path: Path) -> None:
    proposal = _proposal()
    binding = ResearchBinding(run_id="run.1", researcher_id="researcher.1")

    with open_store(tmp_path) as store:
        researcher = PersistentResearcher.open(store, binding)
        researcher.submit_proposal(proposal)

        receipt = researcher.merge_specialist_proposal(_request(proposal))
        duplicate = researcher.merge_specialist_proposal(_request(proposal))

        assert duplicate == receipt
        assert len(researcher.recent_deltas()) == 1
        delta = researcher.recent_deltas()[0]
        assert delta.actor_id == binding.researcher_id
        assert delta.provenance == proposal.provenance
        assert delta.introduced_hypothesis_ids == receipt.introduced_hypothesis_ids
        assert researcher.graph_state().hypotheses == proposal.proposed_hypotheses


def test_specialist_merge_rejects_conflict_and_non_specialist_actor(tmp_path: Path) -> None:
    proposal = _proposal()
    verifier = _proposal(role=ProposalActorRole.VERIFIER)

    with open_store(tmp_path) as store:
        researcher = PersistentResearcher.open(
            store,
            ResearchBinding(run_id="run.1", researcher_id="researcher.1"),
        )
        researcher.submit_proposal(proposal)
        researcher.submit_proposal(verifier)
        researcher.merge_specialist_proposal(_request(proposal))

        with pytest.raises(SpecialistMergeError, match="different merge state"):
            researcher.merge_specialist_proposal(
                _request(proposal, summary="Conflicting second merge."),
            )
        with pytest.raises(SpecialistMergeError, match="specialist proposal"):
            researcher.merge_specialist_proposal(_request(verifier))
