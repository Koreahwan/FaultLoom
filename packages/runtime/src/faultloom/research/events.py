from __future__ import annotations

from typing import assert_never

from faultloom._research_durable import EncryptedEventSpec
from .models import ProposalActorRole


BIND_EVENT_TYPE = "research.writer_bound.v1"
PASS_EVENT_TYPE = "research.pass_transition.v1"
DELTA_EVENT_TYPE = "research.delta.v1"
PROPOSAL_EVENT_TYPE = "research.proposal.v1"
CONTROL_ACTOR_STREAM = "research.control"
AUTHORITATIVE_ACTOR_STREAM = "research.authoritative"
DELTA_MEDIA_TYPE = "application/vnd.faultloom.research-delta+json"
PROPOSAL_MEDIA_TYPE = "application/vnd.faultloom.research-proposal+json"


def delta_spec(run_id: str, delta_id: str) -> EncryptedEventSpec:
    return EncryptedEventSpec(
        actor_stream=AUTHORITATIVE_ACTOR_STREAM,
        event_type=DELTA_EVENT_TYPE,
        media_type=DELTA_MEDIA_TYPE,
        run_id=run_id,
        record_id=delta_id,
    )


def proposal_spec(
    run_id: str,
    proposal_id: str,
    role: ProposalActorRole,
) -> EncryptedEventSpec:
    match role:
        case ProposalActorRole.SPECIALIST:
            actor_stream = "research.specialist.proposal"
        case ProposalActorRole.VERIFIER:
            actor_stream = "research.verifier.proposal"
        case unreachable:
            assert_never(unreachable)
    return EncryptedEventSpec(
        actor_stream=actor_stream,
        event_type=PROPOSAL_EVENT_TYPE,
        media_type=PROPOSAL_MEDIA_TYPE,
        run_id=run_id,
        record_id=proposal_id,
    )
