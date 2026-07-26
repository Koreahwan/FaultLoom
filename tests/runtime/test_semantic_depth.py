from __future__ import annotations

import json

import pytest

from faultloom.semantic_depth import (
    BudgetVector,
    SearchCheckpoint,
    SearchConfig,
    SemanticDepthEngine,
    SemanticEdge,
    SemanticGraph,
)


EDGE_BUDGET = BudgetVector(actions=1, time=2, cost=3, impact=1)


def _edge(
    source: str,
    target: str,
    index: int,
    *,
    prerequisite: str | None = None,
    effect: str | None = None,
    pre_state: str | None = None,
    post_state: str | None = None,
    primitive: str | None = None,
) -> SemanticEdge:
    required = (
        "seed"
        if prerequisite is None and index == 1
        else prerequisite or f"effect.{index - 1}"
    )
    return SemanticEdge(
        source=source,
        target=target,
        prerequisites=(required,),
        effect=effect or f"effect.{index}",
        pre_state=pre_state or f"state.{index - 1}",
        post_state=post_state or f"state.{index}",
        primitive=primitive or f"primitive.{index}",
        budget=EDGE_BUDGET,
    )


def _chain(depth: int, *, extras: tuple[SemanticEdge, ...] = ()) -> SemanticGraph:
    edges = tuple(
        _edge(f"node.{index - 1}", f"node.{index}", index)
        for index in range(1, depth + 1)
    )
    return SemanticGraph.build(
        initial_node="node.0",
        initial_state="state.0",
        initial_effects=("seed",),
        final_effect=f"effect.{depth}",
        edges=(*edges, *extras),
    )


def _config(depth: int, *, budget_depth: int | None = None) -> SearchConfig:
    available = depth if budget_depth is None else budget_depth
    run_class = "generated_structural_conformance" if depth > 10 else None
    return SearchConfig(
        research_bound=depth,
        budget=BudgetVector(available, available * 2, available * 3, available),
        identity_id="identity.fixture",
        tenant_id="tenant.fixture",
        authority_epoch="epoch.fixture.1",
        pending_effect_disposition="none",
        run_class=run_class,
    )


def _bounded_config(research_bound: int, budget: BudgetVector) -> SearchConfig:
    return SearchConfig(
        research_bound=research_bound,
        budget=budget,
        identity_id="identity.fixture",
        tenant_id="tenant.fixture",
        authority_epoch="epoch.fixture.1",
        pending_effect_disposition="none",
    )


@pytest.mark.parametrize("depth", (4, 5, 6))
def test_exact_v02_depth_witnesses_minimize_and_negative_control(depth: int) -> None:
    graph = _chain(depth)
    engine = SemanticDepthEngine(graph)

    first = engine.search(_config(depth))
    second = engine.search(_config(depth))

    assert first.terminal_reason == "verified"
    assert first.witness == second.witness
    assert first.witness is not None
    assert first.witness.semantic_depth == depth
    assert first.witness.edge_ids == first.witness.semantic_edge_ids
    assert first.longest_verified_prefix == depth
    assert first.witness.consumed == BudgetVector(depth, depth * 2, depth * 3, depth)

    missing_middle = tuple(
        edge.edge_id for index, edge in enumerate(graph.edges) if index != len(graph.edges) // 2
    )
    with pytest.raises(ValueError, match="no dependency-valid final witness"):
        engine.minimize(missing_middle, _config(depth))


def test_content_signatures_padding_minimization_and_lexicographic_tie_break() -> None:
    duplicate_a = SemanticEdge(
        source="node.0",
        target="cycle",
        prerequisites=("seed",),
        effect="seed",
        pre_state="state.0",
        post_state="state.0",
        primitive="bookkeeping",
        budget=BudgetVector(0, 0, 0, 0),
    )
    duplicate_b = SemanticEdge(
        source="cycle",
        target="node.0",
        prerequisites=("seed",),
        effect="seed",
        pre_state="state.0",
        post_state="state.0",
        primitive="bookkeeping",
        budget=BudgetVector(0, 0, 0, 0),
    )
    alternate = _edge(
        "node.1",
        "node.2",
        2,
        primitive="primitive.2.alternate",
    )
    graph = _chain(2, extras=(duplicate_a, duplicate_b, alternate))
    engine = SemanticDepthEngine(graph)
    result = engine.search(_config(2))

    assert duplicate_a.semantic_signature == duplicate_b.semantic_signature
    assert duplicate_a.edge_id != duplicate_b.edge_id
    assert any(component.cyclic for component in engine.components)
    assert result.witness is not None
    assert result.witness.semantic_depth == 2
    assert duplicate_a.edge_id not in result.witness.edge_ids
    assert duplicate_b.edge_id not in result.witness.edge_ids
    tied = tuple(
        edge.edge_id
        for edge in graph.edges
        if edge.source == "node.1" and edge.target == "node.2"
    )
    assert result.witness.edge_ids[-1] == min(tied)

    padded_candidate = (
        duplicate_a.edge_id,
        duplicate_b.edge_id,
        *(
            edge.edge_id
            for edge in graph.edges
            if edge.source.startswith("node.")
            and edge.primitive != "primitive.2.alternate"
        ),
    )
    minimized = engine.minimize(padded_candidate, _config(2))
    assert minimized.semantic_depth == 2
    assert duplicate_a.edge_id not in minimized.edge_ids
    assert duplicate_b.edge_id not in minimized.edge_ids


def test_graph_rejects_final_effect_already_satisfied_by_initial_effects() -> None:
    with pytest.raises(ValueError, match="final_effect must not be present"):
        SemanticGraph.build(
            initial_node="start",
            initial_state="state.0",
            initial_effects=("effect.final", "seed"),
            final_effect="effect.final",
            edges=(),
        )


def test_all_four_budgets_stop_with_honest_longest_prefix() -> None:
    graph = _chain(6)
    engine = SemanticDepthEngine(graph)
    for limit in (
        BudgetVector(5, 12, 18, 6),
        BudgetVector(6, 11, 18, 6),
        BudgetVector(6, 12, 17, 6),
        BudgetVector(6, 12, 18, 5),
    ):
        report = engine.search(_bounded_config(6, limit))
        assert report.terminal_reason == "budget_exhausted"
        assert report.witness is None
        assert report.longest_verified_prefix == 5

    with pytest.raises(ValueError, match="nonnegative"):
        BudgetVector(-1, 0, 0, 0)


def test_depth_bound_exhaustion_reports_the_reached_prefix() -> None:
    report = SemanticDepthEngine(_chain(4)).search(
        _bounded_config(3, BudgetVector(4, 8, 12, 4))
    )
    assert report.terminal_reason == "depth_bound_exhausted"
    assert report.witness is None
    assert report.longest_verified_prefix == 3


def test_checkpoint_round_trip_resumes_same_frontier_ids_without_duplicate_effects() -> None:
    graph = _chain(10)
    engine = SemanticDepthEngine(graph)
    config = _config(10)
    interrupted = engine.search(config, max_expansions=13)

    assert interrupted.terminal_reason == "checkpointed"
    payload = interrupted.checkpoint.to_json()
    assert json.dumps(json.loads(payload), sort_keys=True, separators=(",", ":")) == payload
    restored = SearchCheckpoint.from_json(payload)
    assert restored.to_json() == payload
    assert restored.checkpoint_id == interrupted.checkpoint.checkpoint_id
    assert tuple(state.state_id for state in restored.frontier) == tuple(
        state.state_id for state in interrupted.checkpoint.frontier
    )
    assert tuple(edge.edge_id for edge in restored.graph.edges) == tuple(
        edge.edge_id for edge in graph.edges
    )

    resumed = engine.search(config, checkpoint=restored)
    uninterrupted = engine.search(config)
    assert resumed.terminal_reason == "verified"
    assert resumed.witness == uninterrupted.witness
    assert resumed.witness is not None
    assert len(set(resumed.witness.edge_ids)) == len(resumed.witness.edge_ids)
    effects = [
        next(edge.effect for edge in graph.edges if edge.edge_id == edge_id)
        for edge_id in resumed.witness.edge_ids
    ]
    assert len(effects) == len(set(effects))


def test_same_fingerprint_retains_two_nondominated_budget_tradeoffs() -> None:
    fast_expensive = SemanticEdge(
        source="start",
        target="shared",
        prerequisites=("seed",),
        effect="effect.1",
        pre_state="state.0",
        post_state="state.1",
        primitive="primitive.shared",
        budget=BudgetVector(5, 1, 0, 0),
    )
    slow_cheap = SemanticEdge(
        source="start",
        target="shared",
        prerequisites=("seed",),
        effect="effect.1",
        pre_state="state.0",
        post_state="state.1",
        primitive="primitive.shared",
        budget=BudgetVector(1, 5, 0, 0),
    )
    finish = SemanticEdge(
        source="shared",
        target="done",
        prerequisites=("effect.1",),
        effect="effect.final",
        pre_state="state.1",
        post_state="state.2",
        primitive="primitive.final",
        budget=BudgetVector(1, 1, 0, 0),
    )
    graph = SemanticGraph.build(
        initial_node="start",
        initial_state="state.0",
        initial_effects=("seed",),
        final_effect="effect.final",
        edges=(fast_expensive, slow_cheap, finish),
    )
    config = _bounded_config(2, BudgetVector(6, 6, 0, 0))

    interrupted = SemanticDepthEngine(graph).search(config, max_expansions=2)
    assert interrupted.terminal_reason == "checkpointed"
    shared_states = tuple(
        state for state in interrupted.checkpoint.frontier if state.node == "shared"
    )
    assert len(shared_states) == 2
    assert shared_states[0].fingerprint == shared_states[1].fingerprint
    records_by_fingerprint = dict(interrupted.checkpoint.seen)
    records = records_by_fingerprint[shared_states[0].fingerprint]
    assert len(records) == 2
    assert {record.consumed.as_tuple() for record in records} == {
        (1, 5, 0, 0),
        (5, 1, 0, 0),
    }
    assert {record.remaining.as_tuple() for record in records} == {
        (1, 5, 0, 0),
        (5, 1, 0, 0),
    }

    restored = SearchCheckpoint.from_json(interrupted.checkpoint.to_json())
    assert dict(restored.seen)[shared_states[0].fingerprint] == records
    complete = SemanticDepthEngine(graph).search(config, checkpoint=restored)
    assert complete.terminal_reason == "verified"
    assert complete.witness is not None
    assert complete.witness.semantic_depth == 2


def test_authority_context_is_part_of_state_identity_and_resume_binding() -> None:
    graph = _chain(4)
    first = _config(4)
    second = SearchConfig(
        research_bound=first.research_bound,
        budget=first.budget,
        identity_id="identity.other",
        tenant_id=first.tenant_id,
        authority_epoch=first.authority_epoch,
        pending_effect_disposition="unknown",
        run_class=first.run_class,
    )
    engine = SemanticDepthEngine(graph)
    first_checkpoint = engine.search(first, max_expansions=0).checkpoint
    second_checkpoint = engine.search(second, max_expansions=0).checkpoint

    first_state = first_checkpoint.frontier[0]
    second_state = second_checkpoint.frontier[0]
    assert first_state.identity_id == "identity.fixture"
    assert first_state.tenant_id == "tenant.fixture"
    assert first_state.authority_epoch == "epoch.fixture.1"
    assert first_state.pending_effect_disposition == "none"
    assert first_state.fingerprint != second_state.fingerprint

    restored = SearchCheckpoint.from_json(first_checkpoint.to_json())
    assert restored.config == first
    assert restored.frontier[0].state_id == first_state.state_id
    with pytest.raises(ValueError, match="another search configuration"):
        engine.search(second, checkpoint=restored)


def test_canonical_forged_goal_checkpoint_fails_rederivation() -> None:
    graph = _chain(4)
    config = _config(4)
    engine = SemanticDepthEngine(graph)
    checkpoint = engine.search(config, max_expansions=0).checkpoint
    document = json.loads(checkpoint.to_json())
    forged_goal = dict(document["frontier"][0])
    forged_goal["effects"] = sorted((*forged_goal["effects"], graph.final_effect))
    document["frontier"] = []
    document["goals"] = [forged_goal]
    forged_payload = json.dumps(document, sort_keys=True, separators=(",", ":"))
    forged = SearchCheckpoint.from_json(forged_payload)

    with pytest.raises(ValueError, match="cannot be rederived"):
        engine.search(config, checkpoint=forged)


@pytest.mark.parametrize("depth", (7, 8, 9, 10))
def test_depth_7_to_10_stress_has_no_padding_or_hidden_truncation(depth: int) -> None:
    report = SemanticDepthEngine(_chain(depth)).search(_config(depth))
    assert report.terminal_reason == "verified"
    assert report.witness is not None
    assert report.witness.semantic_depth == depth
    assert report.longest_verified_prefix == depth


def test_generated_depth_24_has_no_fixed_ceiling_and_requires_immutable_run_class() -> None:
    depth = 24
    graph = _chain(depth)
    config = _config(depth)
    interrupted = SemanticDepthEngine(graph).search(config, max_expansions=50)
    assert interrupted.terminal_reason == "checkpointed"
    restored = SearchCheckpoint.from_json(interrupted.checkpoint.to_json())
    complete = SemanticDepthEngine(restored.graph).search(config, checkpoint=restored)

    assert complete.terminal_reason == "verified"
    assert complete.witness is not None
    assert complete.witness.semantic_depth == depth
    assert complete.longest_verified_prefix == depth
    assert restored.config.run_class == "generated_structural_conformance"

    with pytest.raises(ValueError, match="require exactly one run_class"):
        SearchConfig(
            research_bound=depth,
            budget=config.budget,
            identity_id=config.identity_id,
            tenant_id=config.tenant_id,
            authority_epoch=config.authority_epoch,
            pending_effect_disposition=config.pending_effect_disposition,
        )
    with pytest.raises(ValueError, match="another search configuration"):
        SemanticDepthEngine(graph).search(
            SearchConfig(
                research_bound=depth + 1,
                budget=config.budget,
                identity_id=config.identity_id,
                tenant_id=config.tenant_id,
                authority_epoch=config.authority_epoch,
                pending_effect_disposition=config.pending_effect_disposition,
                run_class="generated_structural_conformance",
            ),
            checkpoint=restored,
        )
