from __future__ import annotations

from faultloom.hypothesis.journal import HypothesisJournal
from faultloom.hypothesis.models import (
    HypothesisCursor,
    HypothesisGraphState,
    HypothesisPage,
    HypothesisSeed,
    NegativeResultSeed,
    ResearchContextRecords,
)
from faultloom.state import StateStore
from faultloom_protocol import (
    ContextCheckpoint,
    HypothesisRecord,
    NegativeResult,
    ResearchDelta,
)

from .journal import ResearchJournal
from .models import ResearchBinding, ResearchJournalState, ResearchPass, ResearchProposal


class PersistentResearcher:
    def __init__(
        self,
        journal: ResearchJournal,
        hypotheses: HypothesisJournal,
    ) -> None:
        self._journal = journal
        self._hypotheses = hypotheses

    @classmethod
    def open(
        cls,
        store: StateStore,
        binding: ResearchBinding,
    ) -> PersistentResearcher:
        exact = ResearchBinding.model_validate(binding.model_dump(mode="python"))
        journal = ResearchJournal(store, exact)
        journal.bind()
        return cls(
            journal,
            HypothesisJournal(store, exact.run_id, exact.researcher_id),
        )

    @property
    def state(self) -> ResearchJournalState:
        return self._journal.state()

    def record_delta(self, delta: ResearchDelta) -> ResearchDelta:
        return self._journal.append_delta(delta)

    def advance_pass(self) -> ResearchPass:
        return self._journal.advance_pass()

    def submit_proposal(self, proposal: ResearchProposal) -> ResearchProposal:
        return self._journal.append_proposal(proposal)

    def recent_deltas(self, *, limit: int = 50) -> tuple[ResearchDelta, ...]:
        return self._journal.recent_deltas(limit=limit)

    def record_hypothesis(self, seed: HypothesisSeed) -> HypothesisRecord:
        return self._hypotheses.record_hypothesis(seed)

    def update_hypothesis(self, record: HypothesisRecord) -> HypothesisRecord:
        return self._hypotheses.update_hypothesis(record)

    def record_negative_result(self, seed: NegativeResultSeed) -> NegativeResult:
        return self._hypotheses.record_negative_result(seed)

    def graph_state(self) -> HypothesisGraphState:
        return self._hypotheses.state()

    def hypothesis_page(
        self,
        *,
        limit: int = 100,
        cursor: HypothesisCursor | None = None,
    ) -> HypothesisPage:
        return self._hypotheses.page(limit=limit, cursor=cursor)

    def context_records(
        self,
        checkpoint: ContextCheckpoint,
    ) -> ResearchContextRecords:
        return self._hypotheses.state().context_records(checkpoint)
