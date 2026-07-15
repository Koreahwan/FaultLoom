from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom.hypothesis.journal import HypothesisJournal
from faultloom.hypothesis.models import NegativeResultSeed
from faultloom.state import StateStore
from faultloom_protocol import (
    EvidenceRef,
    HypothesisRecord,
    NegativeResult,
    ProvenanceKind,
    ResearchDelta,
    SCHEMA_VERSION,
    sha256_digest,
)
from faultloom_protocol.base import AwareDatetime, Identifier, NonEmptyStr, Sha256Digest

from .journal import ResearchJournal
from .models import (
    ProposalActorRole,
    ResearchBinding,
    ResearchError,
    ResearchProposal,
)


class _SpecialistModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class SpecialistMergeError(ResearchError):
    pass


class ProposalMergeRequest(_SpecialistModel):
    run_id: Identifier
    proposal_id: Identifier
    expected_proposal_digest: Sha256Digest
    selected_hypothesis_ids: tuple[Identifier, ...] = ()
    selected_negative_result_ids: tuple[Identifier, ...] = ()
    summary: NonEmptyStr
    created_at: AwareDatetime

    @model_validator(mode="after")
    def _unique_selection(self) -> Self:
        if len(self.selected_hypothesis_ids) != len(set(self.selected_hypothesis_ids)):
            raise SpecialistMergeError("selected hypothesis IDs must be unique")
        if len(self.selected_negative_result_ids) != len(
            set(self.selected_negative_result_ids)
        ):
            raise SpecialistMergeError("selected negative-result IDs must be unique")
        return self


class ProposalMergeReceipt(_SpecialistModel):
    run_id: Identifier
    proposal_id: Identifier
    proposal_digest: Sha256Digest
    delta_id: Identifier
    delta_digest: Sha256Digest
    introduced_hypothesis_ids: tuple[Identifier, ...] = ()
    updated_hypothesis_ids: tuple[Identifier, ...] = ()
    negative_result_ids: tuple[Identifier, ...] = ()


class SpecialistProposalMerger:
    def __init__(
        self,
        store: StateStore,
        journal: ResearchJournal,
        hypotheses: HypothesisJournal,
        binding: ResearchBinding,
    ) -> None:
        self._store = store
        self._journal = journal
        self._hypotheses = hypotheses
        self._binding = binding

    def merge(self, request: ProposalMergeRequest) -> ProposalMergeReceipt:
        if type(request) is not ProposalMergeRequest:
            raise SpecialistMergeError("merge requires an exact proposal request")
        if request.run_id != self._binding.run_id:
            raise SpecialistMergeError("merge request belongs to another run")
        with self._store.serialized():
            proposal = self._journal.proposal(request.proposal_id)
            self._validate_proposal(proposal, request)
            hypotheses = self._selected_hypotheses(proposal, request)
            negatives = self._selected_negatives(proposal, request)
            evidence = _evidence_refs(proposal, hypotheses, negatives)
            delta_id = _merge_delta_id(proposal)
            prior = self._journal.delta(delta_id)
            if prior is not None:
                return self._existing_receipt(prior, proposal, request)
            if proposal.pass_kind is not self._journal.state().current_pass:
                raise SpecialistMergeError(
                    "specialist proposal belongs to another research pass"
                )
            state = self._hypotheses.state()
            existing_ids = {item.hypothesis_id for item in state.hypotheses}
            introduced = tuple(
                item.hypothesis_id
                for item in hypotheses
                if item.hypothesis_id not in existing_ids
            )
            updated = tuple(
                item.hypothesis_id
                for item in hypotheses
                if item.hypothesis_id in existing_ids
            )
            for record in hypotheses:
                self._hypotheses.update_hypothesis(record)
            for record in negatives:
                self._hypotheses.record_negative_result(
                    NegativeResultSeed(
                        run_id=record.run_id,
                        hypothesis_id=record.hypothesis_id,
                        experiment_digest=record.experiment_digest,
                        conclusion=record.conclusion,
                        evidence_refs=record.evidence_refs,
                        recorded_at=record.recorded_at,
                    )
                )
            journal_state = self._journal.state()
            delta = ResearchDelta(
                schema_version=SCHEMA_VERSION,
                delta_id=delta_id,
                run_id=request.run_id,
                actor_id=self._binding.researcher_id,
                sequence=journal_state.next_delta_sequence,
                created_at=request.created_at,
                summary=request.summary,
                provenance=proposal.provenance,
                evidence_refs=evidence,
                introduced_hypothesis_ids=introduced,
                updated_hypothesis_ids=updated,
                negative_result_ids=tuple(item.negative_result_id for item in negatives),
                previous_delta_digest=journal_state.last_delta_digest,
            )
            self._journal.append_delta(delta)
            return _receipt(proposal, delta)

    def _validate_proposal(
        self,
        proposal: ResearchProposal,
        request: ProposalMergeRequest,
    ) -> None:
        if proposal.actor_role is not ProposalActorRole.SPECIALIST:
            raise SpecialistMergeError("only a specialist proposal may be merged")
        if ProvenanceKind.SPECIALIST not in proposal.provenance:
            raise SpecialistMergeError("specialist proposal lacks explicit provenance")
        if sha256_digest(proposal.model_dump(mode="json")) != request.expected_proposal_digest:
            raise SpecialistMergeError("specialist proposal digest differs from merge request")

    @staticmethod
    def _selected_hypotheses(
        proposal: ResearchProposal,
        request: ProposalMergeRequest,
    ) -> tuple[HypothesisRecord, ...]:
        available = {item.hypothesis_id: item for item in proposal.proposed_hypotheses}
        try:
            selected = tuple(available[item] for item in request.selected_hypothesis_ids)
        except KeyError as exc:
            raise SpecialistMergeError("merge selected an absent proposed hypothesis") from exc
        if any(ProvenanceKind.SPECIALIST not in item.provenance for item in selected):
            raise SpecialistMergeError("selected hypothesis lacks specialist provenance")
        return selected

    @staticmethod
    def _selected_negatives(
        proposal: ResearchProposal,
        request: ProposalMergeRequest,
    ) -> tuple[NegativeResult, ...]:
        available = {
            item.negative_result_id: item for item in proposal.proposed_negative_results
        }
        try:
            return tuple(available[item] for item in request.selected_negative_result_ids)
        except KeyError as exc:
            raise SpecialistMergeError("merge selected an absent negative result") from exc

    def _existing_receipt(
        self,
        delta: ResearchDelta,
        proposal: ResearchProposal,
        request: ProposalMergeRequest,
    ) -> ProposalMergeReceipt:
        hypotheses = self._selected_hypotheses(proposal, request)
        negatives = self._selected_negatives(proposal, request)
        evidence = _evidence_refs(proposal, hypotheses, negatives)
        selected_ids = tuple(item.hypothesis_id for item in hypotheses)
        merged_ids = delta.introduced_hypothesis_ids + delta.updated_hypothesis_ids
        expected = (
            delta.run_id == request.run_id
            and delta.actor_id == self._binding.researcher_id
            and delta.summary == request.summary
            and delta.created_at == request.created_at
            and delta.provenance == proposal.provenance
            and delta.evidence_refs == evidence
            and set(merged_ids) == set(selected_ids)
            and delta.negative_result_ids
            == tuple(item.negative_result_id for item in negatives)
        )
        if not expected:
            raise SpecialistMergeError("proposal ID is bound to different merge state")
        return _receipt(proposal, delta)


def _merge_delta_id(proposal: ResearchProposal) -> str:
    digest = sha256_digest(
        {
            "proposal_id": proposal.proposal_id,
            "purpose": "faultloom.specialist-proposal-merge.v1",
            "run_id": proposal.run_id,
        }
    )
    return f"delta.merge.{digest.removeprefix('sha256:')}"


def _evidence_refs(
    proposal: ResearchProposal,
    hypotheses: tuple[HypothesisRecord, ...],
    negatives: tuple[NegativeResult, ...],
) -> tuple[EvidenceRef, ...]:
    references = list(proposal.evidence_refs)
    for item in hypotheses:
        references.extend(item.supporting_evidence + item.contradicting_evidence)
    for item in negatives:
        references.extend(item.evidence_refs)
    by_id: dict[str, EvidenceRef] = {}
    for reference in references:
        prior = by_id.setdefault(reference.evidence_id, reference)
        if prior != reference:
            raise SpecialistMergeError("evidence ID is bound to conflicting state")
    return tuple(by_id[key] for key in sorted(by_id))


def _receipt(
    proposal: ResearchProposal,
    delta: ResearchDelta,
) -> ProposalMergeReceipt:
    return ProposalMergeReceipt(
        run_id=proposal.run_id,
        proposal_id=proposal.proposal_id,
        proposal_digest=sha256_digest(proposal.model_dump(mode="json")),
        delta_id=delta.delta_id,
        delta_digest=sha256_digest(delta),
        introduced_hypothesis_ids=delta.introduced_hypothesis_ids,
        updated_hypothesis_ids=delta.updated_hypothesis_ids,
        negative_result_ids=delta.negative_result_ids,
    )
