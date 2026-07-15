from __future__ import annotations

from faultloom.state import StateStore, StorageError
from faultloom_protocol import ResearchDelta

from faultloom._research_durable import append_encrypted
from .events import (
    AUTHORITATIVE_ACTOR_STREAM,
    BIND_EVENT_TYPE,
    CONTROL_ACTOR_STREAM,
    PASS_EVENT_TYPE,
    delta_spec,
    proposal_spec,
)
from .models import (
    ProposalConflictError,
    ResearchBinding,
    ResearchJournalState,
    ResearchPass,
    ResearchPassError,
    ResearchProposal,
    WriterConflictError,
)
from .replay import next_pass, replay_research, validate_delta
from .wire import DeltaEvent


class ResearchJournal:
    def __init__(self, store: StateStore, binding: ResearchBinding) -> None:
        self._store = store
        self._binding = binding

    def bind(self) -> None:
        with self._store.serialized():
            replay = replay_research(self._store, self._binding.run_id)
            if replay.binding is not None:
                if replay.binding != self._binding:
                    raise WriterConflictError(
                        "research run is already bound to another researcher"
                    )
                return
            ledger = self._store.ledger
            if ledger is None:
                raise StorageError("state store is closed")
            ledger.append(
                actor_stream=CONTROL_ACTOR_STREAM,
                event_type=BIND_EVENT_TYPE,
                payload=self._binding.model_dump(mode="json"),
            )

    def state(self) -> ResearchJournalState:
        replay = replay_research(self._store, self._binding.run_id)
        if replay.binding != self._binding:
            raise WriterConflictError("research writer binding differs from durable state")
        return replay.state()

    def append_delta(self, delta: ResearchDelta) -> ResearchDelta:
        exact = ResearchDelta.model_validate(delta.model_dump(mode="python"))
        if exact.run_id != self._binding.run_id:
            raise WriterConflictError("research delta belongs to another run")
        with self._store.serialized():
            replay = replay_research(self._store, self._binding.run_id)
            if replay.binding != self._binding:
                raise WriterConflictError("research writer binding differs from durable state")
            envelope = DeltaEvent(pass_kind=replay.current_pass, delta=exact)
            validate_delta(replay, envelope)
            append_encrypted(
                self._store,
                envelope,
                delta_spec(exact.run_id, exact.delta_id),
            )
        return exact

    def advance_pass(self) -> ResearchPass:
        with self._store.serialized():
            replay = replay_research(self._store, self._binding.run_id)
            if replay.binding != self._binding:
                raise WriterConflictError("research writer binding differs from durable state")
            state = replay.state()
            counts = {
                ResearchPass.BEHAVIOR: state.behavior_delta_count,
                ResearchPass.KNOWLEDGE: state.knowledge_delta_count,
                ResearchPass.CHAIN: state.chain_delta_count,
            }
            if counts[state.current_pass] == 0:
                raise ResearchPassError("research pass cannot advance before a delta")
            target = next_pass(state.current_pass)
            ledger = self._store.ledger
            if ledger is None:
                raise StorageError("state store is closed")
            ledger.append(
                actor_stream=AUTHORITATIVE_ACTOR_STREAM,
                event_type=PASS_EVENT_TYPE,
                payload={
                    "from_pass": state.current_pass.value,
                    "researcher_id": self._binding.researcher_id,
                    "run_id": self._binding.run_id,
                    "to_pass": target.value,
                },
            )
        return target

    def append_proposal(self, proposal: ResearchProposal) -> ResearchProposal:
        exact = ResearchProposal.model_validate(proposal.model_dump(mode="python"))
        if exact.run_id != self._binding.run_id:
            raise ProposalConflictError("proposal belongs to another run")
        if exact.actor_id == self._binding.researcher_id:
            raise ProposalConflictError("authoritative researcher cannot use proposal stream")
        with self._store.serialized():
            replay = replay_research(self._store, self._binding.run_id)
            prior = next(
                (item for item in replay.proposals if item.proposal_id == exact.proposal_id),
                None,
            )
            if prior == exact:
                return exact
            if prior is not None:
                raise ProposalConflictError("proposal ID is bound to different state")
            append_encrypted(
                self._store,
                exact,
                proposal_spec(exact.run_id, exact.proposal_id, exact.actor_role),
            )
        return exact

    def proposal(self, proposal_id: str) -> ResearchProposal:
        replay = replay_research(self._store, self._binding.run_id)
        proposal = next(
            (item for item in replay.proposals if item.proposal_id == proposal_id),
            None,
        )
        if proposal is None:
            raise ProposalConflictError("specialist proposal is not in the durable inbox")
        return proposal

    def delta(self, delta_id: str) -> ResearchDelta | None:
        replay = replay_research(self._store, self._binding.run_id)
        return next((item for item in replay.deltas if item.delta_id == delta_id), None)

    def recent_deltas(self, *, limit: int = 50) -> tuple[ResearchDelta, ...]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ResearchPassError("research delta limit must be between 1 and 100")
        replay = replay_research(self._store, self._binding.run_id)
        return replay.deltas[-limit:]
