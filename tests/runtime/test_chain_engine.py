from __future__ import annotations

import pytest

from faultloom.chain import (
    AssetClass,
    ChainBudget,
    ChainIntegrityError,
    ChainPolicyError,
    CrossSurfaceChainEngine,
    ReplayObservation,
    ReplayRequest,
    ReplaySeed,
    finding_eligible,
)
from faultloom_protocol import VerdictOutcome

from tests.protocol.factories import NOW, sample_models
from tests.runtime.chain_support import ChainBuildSpec, BuiltChain, build_chain


def test_normalization_and_per_edge_safety_fail_closed() -> None:
    built = build_chain(
        ChainBuildSpec(sources=("identity", "api"), candidate_indexes=frozenset({1}))
    )
    assert built.registry.verified_capability_ids == ("capability.chain.0",)
    assert built.registry.candidate_capability_ids == ("capability.chain.1",)

    binding = built.authority.edge_bindings[0]
    implicit = binding.model_copy(update={"explicitly_granted": False})
    with pytest.raises(ChainPolicyError, match="implicit_scope_propagation"):
        CrossSurfaceChainEngine.open(
            built.registry,
            built.graph,
            built.authority.model_copy(update={"edge_bindings": (implicit,)}),
        )

    metadata = binding.model_copy(update={"asset_class": AssetClass.CLOUD_METADATA})
    with pytest.raises(ChainPolicyError, match="cloud_metadata_denied"):
        CrossSurfaceChainEngine.open(
            built.registry,
            built.graph,
            built.authority.model_copy(update={"edge_bindings": (metadata,)}),
        )

    edge = built.graph.edges[0].model_copy(update={"negative_control_refs": ()})
    graph = built.graph.model_copy(update={"edges": (edge,)})
    with pytest.raises(ChainIntegrityError, match="edge_evidence_incomplete"):
        CrossSurfaceChainEngine.open(built.registry, graph, built.authority)


def test_depth_one_and_unbounded_budgeted_search_are_deterministic() -> None:
    depth_one = build_chain(ChainBuildSpec(sources=("identity", "api")))
    engine = CrossSurfaceChainEngine.open(
        depth_one.registry, depth_one.graph, depth_one.authority
    )
    result = engine.search(depth_one.settings)
    assert result.forward is not None
    assert result.backward is not None
    assert result.forward.plan.edge_ids == result.backward.plan.edge_ids == (
        "edge.chain.1",
    )

    sources = tuple("identity" if index % 2 == 0 else "api" for index in range(12))
    deep = build_chain(ChainBuildSpec(sources=sources))
    deep_engine = CrossSurfaceChainEngine.open(deep.registry, deep.graph, deep.authority)
    first = deep_engine.search(deep.settings)
    second = deep_engine.search(deep.settings)
    assert first == second
    assert first.forward is not None
    assert first.backward is not None
    assert len(first.forward.plan.edge_ids) == 11
    assert first.forward.plan.edge_ids == first.backward.plan.edge_ids

    insufficient = deep.settings.model_copy(
        update={
            "budget": ChainBudget(actions=10, time_seconds=60, impact=deep.settings.budget.impact)
        }
    )
    bounded = deep_engine.search(insufficient)
    assert bounded.forward is None
    assert bounded.backward is None


def test_bridge_missing_link_cycle_and_minimization() -> None:
    bridge = build_chain(ChainBuildSpec(sources=("identity", "llm")))
    bridge_engine = CrossSurfaceChainEngine.open(
        bridge.registry, bridge.graph, bridge.authority
    )
    bridge_result = bridge_engine.search(bridge.settings)
    assert bridge_result.bridge is not None
    assert bridge_result.bridge.plan.edge_ids == ("edge.chain.1",)

    missing = build_chain(
        ChainBuildSpec(sources=("identity", "api"), missing_at=1)
    )
    missing_result = CrossSurfaceChainEngine.open(
        missing.registry, missing.graph, missing.authority
    ).search(missing.settings)
    assert missing_result.forward is None
    assert tuple(item.missing_precondition for item in missing_result.missing_links) == (
        "prerequisite.missing.1",
    )

    redundant = build_chain(
        ChainBuildSpec(sources=("identity", "api"), redundant_self_loop=True)
    )
    redundant_engine = CrossSurfaceChainEngine.open(
        redundant.registry, redundant.graph, redundant.authority
    )
    redundant_result = redundant_engine.search(redundant.settings)
    assert any(component.cyclic for component in redundant_result.components)
    assert redundant_result.dominated_states_pruned > 0
    assert redundant_result.forward is not None
    assert redundant_result.forward.plan.edge_ids == ("edge.chain.1",)
    unminimized_plan = redundant_result.forward.plan.model_copy(
        update={
            "chain_plan_id": "chain-plan.unminimized",
            "edge_ids": ("edge.chain.0.self", "edge.chain.1"),
            "total_action_cost": 2,
            "total_time_cost_seconds": 2,
        }
    )
    unminimized = redundant_result.forward.model_copy(
        update={"plan": unminimized_plan, "total_impact_cost": 2}
    )
    assert redundant_engine.minimize(unminimized, redundant.settings).plan.edge_ids == (
        "edge.chain.1",
    )


def test_clean_replay_gates_finding_and_checkpoint_preserves_chain_ids() -> None:
    built = build_chain(
        ChainBuildSpec(
            sources=("patch", "identity", "api"),
            capability_kinds=(
                "cve.reachable",
                "workflow.role_transition",
                "api.async_callback",
            ),
        )
    )
    engine = CrossSurfaceChainEngine.open(built.registry, built.graph, built.authority)
    result = engine.search(built.settings)
    assert result.forward is not None
    replay = engine.build_replay(
        ReplaySeed(
            planned=result.forward,
            fresh_identity_context_ids=("identity-context.clean",),
            reset_state_refs=built.states,
        )
    )
    observations = _observations(built, replay.edge_ids)
    verdict = engine.verify_replay(
        ReplayRequest(
            planned=result.forward,
            replay_plan=replay,
            observations=observations,
            verified_at=NOW,
        )
    )
    assert verdict.outcome is VerdictOutcome.VERIFIED
    assert verdict.longest_verified_prefix == 2
    assert finding_eligible(verdict)

    failed = observations[1].model_copy(update={"negative_control_passed": False})
    rejected = engine.verify_replay(
        ReplayRequest(
            planned=result.forward,
            replay_plan=replay,
            observations=(observations[0], failed),
            verified_at=NOW,
        )
    )
    assert rejected.outcome is VerdictOutcome.REJECTED
    assert rejected.longest_verified_prefix == 1
    assert not rejected.final_effect_verified
    assert not finding_eligible(rejected)

    checkpoint = engine.checkpoint(result, (replay,))
    restored = type(checkpoint).model_validate_json(checkpoint.model_dump_json())
    assert tuple(edge.edge_id for edge in restored.graph.edges) == tuple(
        edge.edge_id for edge in built.graph.edges
    )
    assert tuple(item.precondition_ids for item in restored.registry.capabilities) == tuple(
        item.precondition_ids for item in built.registry.capabilities
    )
    assert restored.replay_plans[0].edge_ids == replay.edge_ids


def _observations(
    built: BuiltChain,
    edge_ids: tuple[str, ...],
) -> tuple[ReplayObservation, ...]:
    evidence = sample_models()["EvidenceRef"]
    edges = {item.edge_id: item for item in built.graph.edges}
    bindings = {item.edge_id: item for item in built.authority.edge_bindings}
    return tuple(
        ReplayObservation(
            edge_id=edge_id,
            action_lease_id=bindings[edge_id].lease.lease_id,
            observed_effect_id=edges[edge_id].observed_effect.effect_id,
            effect_verified=True,
            negative_control_passed=True,
            clean_state_replayed=True,
            evidence_refs=(evidence,),
        )
        for edge_id in edge_ids
    )
