from __future__ import annotations

import hashlib
from collections import deque

from faultloom_protocol import ChainPlan, SCHEMA_VERSION

from .contracts import PlannedChain, SearchMode
from .search_state import (
    DominanceIndex,
    PathState,
    SearchEnvironment,
    SearchOutcome,
    advance,
    evaluate_edge_ids,
    initial_paths,
    is_dominated,
    raw_budget_allows,
    record_dominance,
)


def forward_search(
    environment: SearchEnvironment,
    mode: SearchMode,
) -> SearchOutcome:
    """Explore deterministically by increasing leased-action count."""

    queue = deque(initial_paths(environment))
    dominance: DominanceIndex = {}
    for path in queue:
        record_dominance(dominance, path)
    pruned = 0
    while queue:
        path = queue.popleft()
        edges = sorted(
            (
                edge
                for edge in environment.runtime.index.edges.values()
                if edge.source_capability_id == path.current_capability_id
            ),
            key=lambda item: item.edge_id,
        )
        for edge in edges:
            advanced = advance(environment, path, edge)
            if advanced is None:
                continue
            if is_dominated(dominance, advanced):
                pruned += 1
                continue
            record_dominance(dominance, advanced)
            if environment.settings.goal_effect_id in advanced.available_ids:
                if mode is SearchMode.BRIDGE and not _has_bridge(environment, advanced):
                    queue.append(advanced)
                    continue
                return SearchOutcome(_planned(environment, advanced, mode), pruned)
            queue.append(advanced)
    return SearchOutcome(None, pruned)


def backward_search(environment: SearchEnvironment) -> PlannedChain | None:
    """Walk producer edges backward from the requested effect, then replay forward."""

    goal = environment.settings.goal_effect_id
    producers = sorted(
        (
            edge
            for edge in environment.runtime.index.edges.values()
            if goal == edge.observed_effect.effect_id
            or goal
            in environment.runtime.index.capabilities[
                edge.target_capability_id
            ].effect_ids
        ),
        key=lambda item: item.edge_id,
    )
    queue = deque((edge.edge_id,) for edge in producers)
    while queue:
        edge_ids = queue.popleft()
        if not raw_budget_allows(environment, edge_ids):
            continue
        first = environment.runtime.index.edges[edge_ids[0]]
        if first.source_capability_id in environment.settings.start_capability_ids:
            path = evaluate_edge_ids(environment, edge_ids)
            if path is not None and goal in path.available_ids:
                return _planned(environment, path, SearchMode.BACKWARD)
        predecessors = sorted(
            (
                edge
                for edge in environment.runtime.index.edges.values()
                if edge.target_capability_id == first.source_capability_id
                and edge.edge_id not in edge_ids
            ),
            key=lambda item: item.edge_id,
        )
        queue.extend((edge.edge_id, *edge_ids) for edge in predecessors)
    return None


def minimize_chain(
    environment: SearchEnvironment,
    planned: PlannedChain,
) -> PlannedChain:
    """Remove any edge whose absence still yields the same verified goal contract."""

    edge_ids = planned.plan.edge_ids
    changed = True
    while changed:
        changed = False
        for index in range(len(edge_ids)):
            candidate = edge_ids[:index] + edge_ids[index + 1 :]
            if not candidate:
                continue
            path = evaluate_edge_ids(environment, candidate)
            if path is None or environment.settings.goal_effect_id not in path.available_ids:
                continue
            edge_ids = candidate
            changed = True
            break
    path = evaluate_edge_ids(environment, edge_ids)
    if path is None:
        return planned
    return _planned(
        environment,
        path,
        SearchMode(planned.plan.search_modes[0]),
    )


def reachable_capability_ids(environment: SearchEnvironment) -> frozenset[str]:
    queue = deque(initial_paths(environment))
    reached = {path.current_capability_id for path in queue}
    seen = {(path.current_capability_id, path.available_ids) for path in queue}
    while queue:
        path = queue.popleft()
        for edge in sorted(
            environment.runtime.index.edges.values(), key=lambda item: item.edge_id
        ):
            if edge.source_capability_id != path.current_capability_id:
                continue
            advanced = advance(environment, path, edge)
            if advanced is None:
                continue
            key = (advanced.current_capability_id, advanced.available_ids)
            if key in seen:
                continue
            seen.add(key)
            reached.add(advanced.current_capability_id)
            queue.append(advanced)
    return frozenset(reached)


def _planned(
    environment: SearchEnvironment,
    path: PathState,
    mode: SearchMode,
) -> PlannedChain:
    cleanup = next(
        (
            edge.action_intent.cleanup_plan_ref
            for edge in reversed(
                tuple(environment.runtime.index.edges[item] for item in path.edge_ids)
            )
            if edge.action_intent.cleanup_plan_ref is not None
        ),
        None,
    )
    plan = ChainPlan(
        schema_version=SCHEMA_VERSION,
        chain_plan_id=_stable_id(environment.runtime.graph.graph_id, mode, path.edge_ids),
        chain_graph_id=environment.runtime.graph.graph_id,
        edge_ids=path.edge_ids,
        search_modes=(mode.value,),
        final_effect_id=environment.settings.goal_effect_id,
        total_action_cost=path.action_cost,
        total_time_cost_seconds=path.time_cost,
        cleanup_plan_ref=cleanup,
    )
    capability_ids = {
        environment.runtime.index.edges[item].source_capability_id
        for item in path.edge_ids
    } | {
        environment.runtime.index.edges[item].target_capability_id
        for item in path.edge_ids
    }
    candidates = environment.runtime.registry.candidate_capability_ids
    return PlannedChain(
        plan=plan,
        total_impact_cost=path.impact_cost,
        contains_candidate=bool(capability_ids.intersection(candidates)),
    )


def _has_bridge(environment: SearchEnvironment, path: PathState) -> bool:
    for edge_id in path.edge_ids:
        edge = environment.runtime.index.edges[edge_id]
        source = environment.runtime.index.capabilities[edge.source_capability_id]
        target = environment.runtime.index.capabilities[edge.target_capability_id]
        if source.source_pack_id != target.source_pack_id:
            return True
    return False


def _stable_id(graph_id: str, mode: SearchMode, edge_ids: tuple[str, ...]) -> str:
    material = "\0".join((graph_id, mode.value, *edge_ids)).encode()
    return f"chain-plan.{mode.value}.{hashlib.sha256(material).hexdigest()[:16]}"
