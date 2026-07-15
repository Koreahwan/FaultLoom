from __future__ import annotations

from dataclasses import dataclass
from typing import assert_never

from pydantic import ValidationError

from faultloom.state import EventRecord, StateStore, StorageError
from faultloom_protocol import ProvenanceKind, ResearchDelta, sha256_digest

from faultloom._research_durable import (
    canonical_model_bytes,
    durable_events,
    load_encrypted,
)
from .events import (
    AUTHORITATIVE_ACTOR_STREAM,
    BIND_EVENT_TYPE,
    CONTROL_ACTOR_STREAM,
    DELTA_EVENT_TYPE,
    PASS_EVENT_TYPE,
    PROPOSAL_EVENT_TYPE,
    delta_spec,
    proposal_spec,
)
from .models import (
    ProposalActorRole,
    ResearchBinding,
    ResearchIntegrityError,
    ResearchJournalState,
    ResearchPass,
    ResearchPassError,
    ResearchProposal,
    ResearchSequenceError,
)
from .wire import DeltaEvent


@dataclass(frozen=True, slots=True)
class ResearchReplay:
    binding: ResearchBinding | None
    current_pass: ResearchPass
    next_delta_sequence: int
    last_delta_digest: str | None
    counts: tuple[int, int, int]
    proposals: tuple[ResearchProposal, ...]
    deltas: tuple[ResearchDelta, ...]
    watermark: int

    def state(self) -> ResearchJournalState:
        if self.binding is None:
            raise ResearchIntegrityError("research writer is not durably bound")
        return ResearchJournalState(
            binding=self.binding,
            current_pass=self.current_pass,
            next_delta_sequence=self.next_delta_sequence,
            last_delta_digest=self.last_delta_digest,
            behavior_delta_count=self.counts[0],
            knowledge_delta_count=self.counts[1],
            chain_delta_count=self.counts[2],
            proposal_count=len(self.proposals),
            watermark=self.watermark,
        )


def replay_research(store: StateStore, run_id: str) -> ResearchReplay:
    binding: ResearchBinding | None = None
    current_pass = ResearchPass.BEHAVIOR
    next_sequence = 1
    last_digest: str | None = None
    counts = [0, 0, 0]
    proposals: list[ResearchProposal] = []
    deltas: list[ResearchDelta] = []
    watermark = 0
    for event in durable_events(store):
        if event.event_type == BIND_EVENT_TYPE:
            candidate = _binding_from_event(event)
            if candidate.run_id != run_id:
                continue
            if binding is not None:
                raise ResearchIntegrityError("research run has multiple writer bindings")
            binding = candidate
            watermark = event.seq
            continue
        if event.event_type == PASS_EVENT_TYPE:
            transition = _transition_from_event(event)
            if transition[0] != run_id:
                continue
            if binding is None or transition[1] != binding.researcher_id:
                raise ResearchIntegrityError("research pass transition has no bound writer")
            if transition[2] is not current_pass:
                raise ResearchIntegrityError("research pass transition starts from stale state")
            if counts[_pass_index(current_pass)] == 0:
                raise ResearchIntegrityError("empty research pass was advanced")
            expected = next_pass(current_pass)
            if transition[3] is not expected:
                raise ResearchIntegrityError("research pass transition skipped a phase")
            current_pass = expected
            watermark = event.seq
            continue
        if event.event_type == DELTA_EVENT_TYPE:
            envelope = _delta_from_event(store, event)
            if envelope.delta.run_id != run_id:
                continue
            if binding is None:
                raise ResearchIntegrityError("research delta has no bound writer")
            candidate = ResearchReplay(
                binding=binding,
                current_pass=current_pass,
                next_delta_sequence=next_sequence,
                last_delta_digest=last_digest,
                counts=tuple(counts),
                proposals=tuple(proposals),
                deltas=tuple(deltas),
                watermark=watermark,
            )
            validate_delta(candidate, envelope)
            counts[_pass_index(current_pass)] += 1
            deltas.append(envelope.delta)
            next_sequence += 1
            last_digest = sha256_digest(envelope.delta)
            watermark = event.seq
            continue
        if event.event_type == PROPOSAL_EVENT_TYPE:
            proposal = _proposal_from_event(store, event)
            if proposal.run_id != run_id:
                continue
            if binding is None or proposal.actor_id == binding.researcher_id:
                raise ResearchIntegrityError("proposal actor is not separate from researcher")
            if any(item.proposal_id == proposal.proposal_id for item in proposals):
                raise ResearchIntegrityError("proposal ID appears more than once")
            proposals.append(proposal)
            watermark = event.seq
    return ResearchReplay(
        binding=binding,
        current_pass=current_pass,
        next_delta_sequence=next_sequence,
        last_delta_digest=last_digest,
        counts=tuple(counts),
        proposals=tuple(proposals),
        deltas=tuple(deltas),
        watermark=watermark,
    )


def validate_delta(replay: ResearchReplay, envelope: DeltaEvent) -> None:
    delta = envelope.delta
    if replay.binding is None or delta.actor_id != replay.binding.researcher_id:
        raise ResearchSequenceError("research delta actor is not the bound researcher")
    if envelope.pass_kind is not replay.current_pass:
        raise ResearchPassError("research delta belongs to a different pass")
    if delta.sequence != replay.next_delta_sequence:
        raise ResearchSequenceError("research delta sequence is not contiguous")
    if delta.previous_delta_digest != replay.last_delta_digest:
        raise ResearchSequenceError("research delta predecessor digest is invalid")
    if any(item.delta_id == delta.delta_id for item in replay.deltas):
        raise ResearchSequenceError("research delta ID appears more than once")
    if replay.current_pass is ResearchPass.BEHAVIOR:
        forbidden = {ProvenanceKind.KNOWLEDGE, ProvenanceKind.PATCH}
        if ProvenanceKind.BEHAVIOR not in delta.provenance or forbidden.intersection(
            delta.provenance
        ):
            raise ResearchPassError("behavior pass must remain knowledge-blind")


def next_pass(current: ResearchPass) -> ResearchPass:
    match current:
        case ResearchPass.BEHAVIOR:
            return ResearchPass.KNOWLEDGE
        case ResearchPass.KNOWLEDGE:
            return ResearchPass.CHAIN
        case ResearchPass.CHAIN:
            raise ResearchPassError("chain pass is the terminal research phase")
        case unreachable:
            assert_never(unreachable)


def _pass_index(value: ResearchPass) -> int:
    match value:
        case ResearchPass.BEHAVIOR:
            return 0
        case ResearchPass.KNOWLEDGE:
            return 1
        case ResearchPass.CHAIN:
            return 2
        case unreachable:
            assert_never(unreachable)


def _binding_from_event(event: EventRecord) -> ResearchBinding:
    if event.actor_stream != CONTROL_ACTOR_STREAM:
        raise ResearchIntegrityError("research writer binding actor stream is invalid")
    if frozenset(event.payload) != {"researcher_id", "run_id"}:
        raise ResearchIntegrityError("research writer binding payload is invalid")
    try:
        return ResearchBinding.model_validate(event.payload)
    except ValidationError as exc:
        raise ResearchIntegrityError("research writer binding is invalid") from exc


def _transition_from_event(
    event: EventRecord,
) -> tuple[str, str, ResearchPass, ResearchPass]:
    if event.actor_stream != AUTHORITATIVE_ACTOR_STREAM:
        raise ResearchIntegrityError("research pass actor stream is invalid")
    expected = {"from_pass", "researcher_id", "run_id", "to_pass"}
    if frozenset(event.payload) != expected:
        raise ResearchIntegrityError("research pass payload is invalid")
    try:
        source = ResearchPass(event.payload["from_pass"])
        target = ResearchPass(event.payload["to_pass"])
        identity = ResearchBinding.model_validate(
            {
                "run_id": event.payload["run_id"],
                "researcher_id": event.payload["researcher_id"],
            }
        )
    except (TypeError, ValueError, ValidationError) as exc:
        raise ResearchIntegrityError("research pass transition is invalid") from exc
    return identity.run_id, identity.researcher_id, source, target


def _delta_from_event(store: StateStore, event: EventRecord) -> DeltaEvent:
    raw = load_encrypted(store, event, delta_spec("run", "delta"))
    try:
        envelope = DeltaEvent.model_validate_json(raw)
    except (ValidationError, ValueError, StorageError) as exc:
        raise ResearchIntegrityError("durable research delta is invalid") from exc
    if canonical_model_bytes(envelope) != raw:
        raise ResearchIntegrityError("durable research delta is not canonical")
    return envelope


def _proposal_from_event(store: StateStore, event: EventRecord) -> ResearchProposal:
    role_by_stream = {
        "research.specialist.proposal": ProposalActorRole.SPECIALIST,
        "research.verifier.proposal": ProposalActorRole.VERIFIER,
    }
    try:
        role = role_by_stream[event.actor_stream]
    except KeyError as exc:
        raise ResearchIntegrityError("proposal actor stream is invalid") from exc
    spec = proposal_spec("run", "proposal", role)
    raw = load_encrypted(store, event, spec)
    try:
        proposal = ResearchProposal.model_validate_json(raw)
    except (ValidationError, ValueError, StorageError) as exc:
        raise ResearchIntegrityError("durable research proposal is invalid") from exc
    if proposal.actor_role is not role or canonical_model_bytes(proposal) != raw:
        raise ResearchIntegrityError("durable research proposal is not canonical")
    return proposal
