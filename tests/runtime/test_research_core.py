from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

import faultloom.hypothesis as hypothesis_api
import faultloom.research as research_api
from faultloom.context import ContextState, checkpoint_binding_tag_for
from faultloom.resume import CheckpointController, trust_policy_for
from faultloom_protocol import (
    HypothesisRecord,
    HypothesisStatus,
    ProvenanceKind,
    ResearchDelta,
    SCHEMA_VERSION,
    sha256_digest,
)
from tests.protocol.factories import D3, NOW, sample_models
from tests.runtime.resume_support import open_store, write_checkpoint
from tests.runtime.test_context import DEFAULT_RETRIEVAL_KEY, context_state


def _research_types() -> tuple[type, ...]:
    names = (
        "PersistentResearcher",
        "ProposalActorRole",
        "ResearchBinding",
        "ResearchPass",
        "ResearchPassError",
        "ResearchProposal",
        "WriterConflictError",
    )
    values = tuple(getattr(research_api, name, None) for name in names)
    assert all(value is not None for value in values)
    return values


def _hypothesis_types() -> tuple[type, ...]:
    names = ("HypothesisCursorError", "HypothesisSeed", "NegativeResultSeed")
    values = tuple(getattr(hypothesis_api, name, None) for name in names)
    assert all(value is not None for value in values)
    return values


def _binding():
    _, _, binding_type, *_ = _research_types()
    return binding_type(run_id="run.1", researcher_id="researcher.1")


def _hypothesis_seed():
    _, seed_type, _ = _hypothesis_types()
    evidence = sample_models()["EvidenceRef"]
    return seed_type(
        run_id="run.1",
        statement="Object authorization differs by tenant.",
        provenance=(ProvenanceKind.BEHAVIOR,),
        prerequisite_ids=("identity.owner",),
        created_at=NOW,
        supporting_evidence=(evidence,),
    )


def _negative_seed(hypothesis_id: str):
    _, _, seed_type = _hypothesis_types()
    return seed_type(
        run_id="run.1",
        hypothesis_id=hypothesis_id,
        experiment_digest=D3,
        conclusion="The negative control was denied as expected.",
        evidence_refs=(sample_models()["EvidenceRef"],),
        recorded_at=NOW + timedelta(seconds=1),
    )


def _delta(
    sequence: int,
    provenance: tuple[ProvenanceKind, ...],
    previous: str | None,
    *,
    hypothesis_id: str = "hypothesis.placeholder",
) -> ResearchDelta:
    return ResearchDelta(
        schema_version=SCHEMA_VERSION,
        delta_id=f"delta.{sequence}",
        run_id="run.1",
        actor_id="researcher.1",
        sequence=sequence,
        created_at=NOW + timedelta(seconds=sequence),
        summary=f"Structured research update {sequence}.",
        provenance=provenance,
        evidence_refs=(sample_models()["EvidenceRef"],),
        introduced_hypothesis_ids=(hypothesis_id,) if sequence == 1 else (),
        previous_delta_digest=previous,
    )


def test_single_researcher_owns_authoritative_stream_and_proposals_are_isolated(
    tmp_path: Path,
) -> None:
    (
        researcher_type,
        proposal_role,
        binding_type,
        research_pass,
        _,
        proposal_type,
        writer_error,
    ) = _research_types()
    with open_store(tmp_path) as store:
        researcher = researcher_type.open(store, _binding())
        assert researcher_type.open(store, _binding()).state == researcher.state
        with pytest.raises(writer_error):
            researcher_type.open(
                store,
                binding_type(run_id="run.1", researcher_id="researcher.other"),
            )

        proposal = proposal_type(
            proposal_id="proposal.1",
            run_id="run.1",
            actor_id="specialist.patch",
            actor_role=proposal_role.SPECIALIST,
            pass_kind=research_pass.BEHAVIOR,
            summary="Candidate only; authoritative state is unchanged.",
            provenance=(ProvenanceKind.SPECIALIST,),
            evidence_refs=(sample_models()["EvidenceRef"],),
            proposed_hypotheses=(_hypothesis_seed().as_record(),),
            created_at=NOW,
        )
        researcher.submit_proposal(proposal)

        assert researcher.state.proposal_count == 1
        assert researcher.graph_state().hypotheses == ()


def test_research_pass_order_and_delta_chain_survive_reopen(tmp_path: Path) -> None:
    researcher_type, _, _, research_pass, pass_error, *_ = _research_types()
    with open_store(tmp_path) as store:
        researcher = researcher_type.open(store, _binding())
        first = _delta(1, (ProvenanceKind.BEHAVIOR,), None)
        researcher.record_delta(first)
        with pytest.raises(pass_error):
            researcher.record_delta(
                _delta(2, (ProvenanceKind.KNOWLEDGE,), sha256_digest(first))
            )
        assert researcher.advance_pass() is research_pass.KNOWLEDGE
        second = _delta(2, (ProvenanceKind.KNOWLEDGE,), sha256_digest(first))
        researcher.record_delta(second)
        assert researcher.advance_pass() is research_pass.CHAIN
        third = _delta(
            3,
            (ProvenanceKind.BEHAVIOR, ProvenanceKind.KNOWLEDGE),
            sha256_digest(second),
        )
        researcher.record_delta(third)
        floor = store.checkpoint()

    with open_store(tmp_path, minimum_anchor=floor) as reopened:
        restored = researcher_type.open(reopened, _binding())
        assert restored.state.current_pass is research_pass.CHAIN
        assert restored.state.next_delta_sequence == 4
        assert restored.recent_deltas(limit=3) == (first, second, third)
        with pytest.raises(pass_error):
            restored.advance_pass()


def test_negative_results_are_durable_without_early_hypothesis_deletion(
    tmp_path: Path,
) -> None:
    researcher_type, *_ = _research_types()
    cursor_error, _, _ = _hypothesis_types()
    seed = _hypothesis_seed()
    assert seed.as_record().hypothesis_id == _hypothesis_seed().as_record().hypothesis_id

    with open_store(tmp_path) as store:
        researcher = researcher_type.open(store, _binding())
        hypothesis = researcher.record_hypothesis(seed)
        negative = researcher.record_negative_result(
            _negative_seed(hypothesis.hypothesis_id)
        )
        state = researcher.graph_state()
        assert state.hypotheses == (hypothesis,)
        assert state.negative_results == (negative,)
        assert state.hypotheses[0].status is HypothesisStatus.ACTIVE

        supported = HypothesisRecord.model_validate(
            hypothesis.model_copy(
                update={
                    "status": HypothesisStatus.SUPPORTED,
                    "updated_at": NOW + timedelta(seconds=2),
                }
            ).model_dump(mode="python")
        )
        researcher.update_hypothesis(supported)
        first_page = researcher.hypothesis_page(limit=1)
        assert len(first_page.entries) == 1
        assert first_page.next_cursor is not None
        second_page = researcher.hypothesis_page(
            limit=1,
            cursor=first_page.next_cursor,
        )
        assert len(second_page.entries) == 1
        with pytest.raises(cursor_error):
            researcher.hypothesis_page(
                limit=1,
                cursor=first_page.next_cursor.model_copy(update={"offset": 99}),
            )


def test_graph_ids_and_records_survive_checkpoint_and_crash_resume(tmp_path: Path) -> None:
    researcher_type, *_ = _research_types()
    with open_store(tmp_path) as active:
        researcher = researcher_type.open(active, _binding())
        hypothesis = researcher.record_hypothesis(_hypothesis_seed())
        negative = researcher.record_negative_result(
            _negative_seed(hypothesis.hypothesis_id)
        )
        base = context_state()
        checkpoint = base.checkpoint.model_copy(
            update={
                "active_hypothesis_ids": (hypothesis.hypothesis_id,),
                "important_negative_result_ids": (negative.negative_result_id,),
            }
        )
        context = ContextState.model_validate(
            base.model_copy(
                update={
                    "checkpoint": checkpoint,
                    "checkpoint_binding_tag": checkpoint_binding_tag_for(
                        checkpoint,
                        engagement_id=base.engagement_id,
                        binding_key=DEFAULT_RETRIEVAL_KEY,
                    ),
                    "active_hypotheses": (hypothesis,),
                    "important_negative_results": (negative,),
                }
            ).model_dump(mode="python")
        )
        packet = write_checkpoint(CheckpointController(active), context)
        floor = active.checkpoint()
        policy = trust_policy_for(packet, minimum_anchor=floor)

    with open_store(tmp_path, minimum_anchor=floor) as reopened:
        restored_packet = CheckpointController(reopened).inspect(policy)
        restored = researcher_type.open(reopened, _binding())
        records = restored.context_records(restored_packet.context_state.checkpoint)

    assert records.active_hypotheses == (hypothesis,)
    assert records.important_negative_results == (negative,)
