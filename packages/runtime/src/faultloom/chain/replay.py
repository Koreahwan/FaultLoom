from __future__ import annotations

import hashlib
from typing import assert_never

from faultloom_protocol import (
    ChainVerdict,
    EvidenceRef,
    ReplayPlan,
    SCHEMA_VERSION,
    VerdictOutcome,
)

from .contracts import ReplayRequest, ReplaySeed
from .errors import ChainIntegrityError
from .search_state import ChainRuntime


def build_replay_plan(runtime: ChainRuntime, seed: ReplaySeed) -> ReplayPlan:
    """Compile a clean-state replay that assigns a negative control to every edge."""

    plan = seed.planned.plan
    if plan.chain_graph_id != runtime.graph.graph_id:
        raise ChainIntegrityError(
            "chain.replay_graph_mismatch",
            "replay seed belongs to another chain graph",
        )
    unknown = set(plan.edge_ids).difference(runtime.index.edges)
    if unknown:
        raise ChainIntegrityError(
            "chain.replay_unknown_edge",
            "replay seed contains an edge absent from the graph",
        )
    if len(set(seed.fresh_identity_context_ids)) != len(
        seed.fresh_identity_context_ids
    ):
        raise ChainIntegrityError(
            "chain.replay_identity_reused",
            "clean replay identity context IDs must be unique",
        )
    required_states = {
        edge.input_state.state_id
        for edge in (runtime.index.edges[item] for item in plan.edge_ids)
        if edge.input_state is not None
    }
    reset_states = {item.state_id for item in seed.reset_state_refs}
    if not required_states.issubset(reset_states):
        raise ChainIntegrityError(
            "chain.replay_state_not_reset",
            "clean replay must reset every stateful edge input",
        )
    return ReplayPlan(
        schema_version=SCHEMA_VERSION,
        replay_plan_id=_stable_id("replay", plan.chain_plan_id, plan.edge_ids),
        chain_plan_id=plan.chain_plan_id,
        fresh_identity_context_ids=tuple(sorted(seed.fresh_identity_context_ids)),
        reset_state_refs=tuple(
            sorted(seed.reset_state_refs, key=lambda item: item.state_id)
        ),
        edge_ids=plan.edge_ids,
        negative_control_edge_ids=plan.edge_ids,
        cleanup_plan_ref=seed.cleanup_plan_ref or plan.cleanup_plan_ref,
    )


def verify_clean_replay(
    runtime: ChainRuntime,
    request: ReplayRequest,
) -> ChainVerdict:
    """Verify only the contiguous clean replay prefix and gate the final effect."""

    plan = request.planned.plan
    replay = request.replay_plan
    if replay.chain_plan_id != plan.chain_plan_id or replay.edge_ids != plan.edge_ids:
        raise ChainIntegrityError(
            "chain.replay_plan_mismatch",
            "replay observations must target the exact chain plan",
        )
    if replay.negative_control_edge_ids != plan.edge_ids:
        raise ChainIntegrityError(
            "chain.replay_negative_controls_incomplete",
            "every replay edge requires its own negative control",
        )
    observations = {item.edge_id: item for item in request.observations}
    if len(observations) != len(request.observations):
        raise ChainIntegrityError(
            "chain.replay_duplicate_observation",
            "replay edge observations must be unique",
        )
    if set(observations).difference(plan.edge_ids):
        raise ChainIntegrityError(
            "chain.replay_unplanned_observation",
            "replay contains an observation outside the plan",
        )
    verified: list[str] = []
    evidence: dict[str, EvidenceRef] = {}
    explicit_failure = False
    for edge_id in plan.edge_ids:
        observation = observations.get(edge_id)
        if observation is None:
            break
        edge = runtime.index.edges[edge_id]
        bound = (
            observation.action_lease_id == edge.action_lease_id
            and observation.observed_effect_id == edge.observed_effect.effect_id
        )
        passed = (
            bound
            and observation.effect_verified
            and observation.negative_control_passed
            and observation.clean_state_replayed
        )
        for item in observation.evidence_refs:
            evidence[item.evidence_id] = item
        if not passed:
            explicit_failure = True
            break
        verified.append(edge_id)
    final_effect_verified = (
        len(verified) == len(plan.edge_ids)
        and bool(plan.edge_ids)
        and runtime.index.edges[plan.edge_ids[-1]].observed_effect.effect_id
        == plan.final_effect_id
    )
    if final_effect_verified:
        outcome = VerdictOutcome.VERIFIED
    elif explicit_failure:
        outcome = VerdictOutcome.REJECTED
    else:
        outcome = VerdictOutcome.INCONCLUSIVE
    return ChainVerdict(
        schema_version=SCHEMA_VERSION,
        chain_verdict_id=_stable_id(
            "chain-verdict", replay.replay_plan_id, tuple(verified)
        ),
        run_id=runtime.graph.run_id,
        replay_plan_id=replay.replay_plan_id,
        outcome=outcome,
        verified_edge_ids=tuple(verified),
        longest_verified_prefix=len(verified),
        final_effect_verified=final_effect_verified,
        evidence_refs=tuple(evidence[item] for item in sorted(evidence)),
        verified_at=request.verified_at,
    )


def finding_eligible(verdict: ChainVerdict) -> bool:
    match verdict.outcome:
        case VerdictOutcome.VERIFIED:
            return verdict.final_effect_verified
        case VerdictOutcome.REJECTED | VerdictOutcome.INCONCLUSIVE:
            return False
        case unreachable:
            assert_never(unreachable)


def _stable_id(prefix: str, parent_id: str, child_ids: tuple[str, ...]) -> str:
    material = "\0".join((parent_id, *child_ids)).encode()
    return f"{prefix}.{hashlib.sha256(material).hexdigest()[:16]}"
