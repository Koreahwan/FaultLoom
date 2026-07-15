from __future__ import annotations

from dataclasses import dataclass

from faultloom_protocol import ChainEdge, ChainGraph, StateRef

from .admissions import PrimitiveRegistry
from .authority import ChainIndex
from .contracts import ChainSearchSettings, PlannedChain


@dataclass(frozen=True, slots=True)
class ChainRuntime:
    registry: PrimitiveRegistry
    graph: ChainGraph
    index: ChainIndex


@dataclass(frozen=True, slots=True)
class SearchEnvironment:
    runtime: ChainRuntime
    settings: ChainSearchSettings


@dataclass(frozen=True, slots=True)
class PathState:
    edge_ids: tuple[str, ...]
    current_capability_id: str
    available_ids: frozenset[str]
    states: tuple[StateRef, ...]
    action_cost: int
    time_cost: int
    impact_cost: int


@dataclass(frozen=True, slots=True)
class SearchOutcome:
    plan: PlannedChain | None
    dominated_states_pruned: int


@dataclass(frozen=True, slots=True)
class DominanceRecord:
    available_ids: frozenset[str]
    action_cost: int
    time_cost: int
    impact_cost: int


type DominanceKey = tuple[str, tuple[tuple[str, int, str | None], ...]]
type DominanceIndex = dict[DominanceKey, list[DominanceRecord]]


def initial_paths(environment: SearchEnvironment) -> tuple[PathState, ...]:
    paths: list[PathState] = []
    for capability_id in sorted(environment.settings.start_capability_ids):
        capability = environment.runtime.index.capabilities[capability_id]
        state = capability.primitive.post_state or capability.primitive.pre_state
        states = () if state is None else (state,)
        paths.append(
            PathState(
                edge_ids=(),
                current_capability_id=capability_id,
                available_ids=frozenset(
                    (*environment.settings.available_precondition_ids, *capability.effect_ids)
                ),
                states=states,
                action_cost=0,
                time_cost=0,
                impact_cost=0,
            )
        )
    return tuple(paths)


def advance(
    environment: SearchEnvironment,
    path: PathState,
    edge: ChainEdge,
) -> PathState | None:
    if edge.edge_id in path.edge_ids:
        return None
    target = environment.runtime.index.capabilities[edge.target_capability_id]
    if not set(target.precondition_ids).issubset(path.available_ids):
        return None
    if edge.input_state is not None and edge.input_state not in path.states:
        return None
    binding = environment.runtime.index.bindings[edge.edge_id]
    action_cost = path.action_cost + edge.action_cost
    time_cost = path.time_cost + edge.time_cost_seconds
    impact_cost = path.impact_cost + binding.impact_cost
    budget = environment.settings.budget
    if (
        action_cost > budget.actions
        or time_cost > budget.time_seconds
        or impact_cost > budget.impact
    ):
        return None
    states = _merge_state(path.states, edge.observed_effect.state)
    available = frozenset(
        (*path.available_ids, *target.effect_ids, edge.observed_effect.effect_id)
    )
    return PathState(
        edge_ids=(*path.edge_ids, edge.edge_id),
        current_capability_id=edge.target_capability_id,
        available_ids=available,
        states=states,
        action_cost=action_cost,
        time_cost=time_cost,
        impact_cost=impact_cost,
    )


def evaluate_edge_ids(
    environment: SearchEnvironment,
    edge_ids: tuple[str, ...],
) -> PathState | None:
    if not edge_ids:
        return None
    first = environment.runtime.index.edges[edge_ids[0]]
    paths = {
        path.current_capability_id: path for path in initial_paths(environment)
    }
    path = paths.get(first.source_capability_id)
    if path is None:
        return None
    for edge_id in edge_ids:
        edge = environment.runtime.index.edges.get(edge_id)
        if edge is None or edge.source_capability_id != path.current_capability_id:
            return None
        path = advance(environment, path, edge)
        if path is None:
            return None
    return path


def raw_budget_allows(
    environment: SearchEnvironment,
    edge_ids: tuple[str, ...],
) -> bool:
    edges = tuple(environment.runtime.index.edges[item] for item in edge_ids)
    budget = environment.settings.budget
    return (
        sum(item.action_cost for item in edges) <= budget.actions
        and sum(item.time_cost_seconds for item in edges) <= budget.time_seconds
        and sum(
            environment.runtime.index.bindings[item.edge_id].impact_cost
            for item in edges
        )
        <= budget.impact
    )


def record_dominance(records: DominanceIndex, path: PathState) -> None:
    key = _dominance_key(path)
    candidate = DominanceRecord(
        path.available_ids,
        path.action_cost,
        path.time_cost,
        path.impact_cost,
    )
    current = records.setdefault(key, [])
    current[:] = [
        item
        for item in current
        if not (
            candidate.available_ids.issuperset(item.available_ids)
            and candidate.action_cost <= item.action_cost
            and candidate.time_cost <= item.time_cost
            and candidate.impact_cost <= item.impact_cost
        )
    ]
    current.append(candidate)


def is_dominated(records: DominanceIndex, path: PathState) -> bool:
    return any(
        item.available_ids.issuperset(path.available_ids)
        and item.action_cost <= path.action_cost
        and item.time_cost <= path.time_cost
        and item.impact_cost <= path.impact_cost
        for item in records.get(_dominance_key(path), ())
    )


def _merge_state(
    states: tuple[StateRef, ...],
    observed: StateRef | None,
) -> tuple[StateRef, ...]:
    if observed is None:
        return states
    retained = tuple(item for item in states if item.state_id != observed.state_id)
    return tuple(sorted((*retained, observed), key=lambda item: item.state_id))


def _dominance_key(path: PathState) -> DominanceKey:
    return (
        path.current_capability_id,
        tuple(
            (item.state_id, item.state_version, item.state_digest)
            for item in path.states
        ),
    )
