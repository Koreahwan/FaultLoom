from __future__ import annotations

from typing import assert_never

from faultloom_protocol import ChainGraph, ChainVerdict, ReplayPlan

from .admissions import PrimitiveRegistry
from .authority import validate_chain_authority
from .contracts import (
    ChainAuthority,
    ChainCheckpoint,
    ChainSearchResult,
    ChainSearchSettings,
    PlannedChain,
    ReplayRequest,
    ReplaySeed,
    SearchMode,
)
from .errors import ChainIntegrityError, ChainPolicyError
from .graph_analysis import graph_components, missing_links
from .replay import build_replay_plan, verify_clean_replay
from .search_core import backward_search, forward_search, minimize_chain
from .search_state import ChainRuntime, SearchEnvironment


class CrossSurfaceChainEngine:
    """Deterministic T35 planner over explicit, per-edge Gateway authority."""

    def __init__(self, runtime: ChainRuntime, authority: ChainAuthority) -> None:
        self._runtime = runtime
        self._authority = authority

    @classmethod
    def open(
        cls,
        registry: PrimitiveRegistry,
        graph: ChainGraph,
        authority: ChainAuthority,
    ) -> CrossSurfaceChainEngine:
        index = validate_chain_authority(registry, graph, authority)
        return cls(ChainRuntime(registry, graph, index), authority)

    @property
    def graph(self) -> ChainGraph:
        return self._runtime.graph

    @property
    def registry(self) -> PrimitiveRegistry:
        return self._runtime.registry

    def search(self, settings: ChainSearchSettings) -> ChainSearchResult:
        environment = self._environment(settings)
        forward = None
        backward = None
        bridge = None
        pruned = 0
        for mode in settings.modes:
            match mode:
                case SearchMode.FORWARD:
                    outcome = forward_search(environment, SearchMode.FORWARD)
                    forward = outcome.plan
                    pruned += outcome.dominated_states_pruned
                case SearchMode.BACKWARD:
                    backward = backward_search(environment)
                case SearchMode.BRIDGE:
                    outcome = forward_search(environment, SearchMode.BRIDGE)
                    bridge = outcome.plan
                    pruned += outcome.dominated_states_pruned
                case unreachable:
                    assert_never(unreachable)
        return ChainSearchResult(
            forward=forward,
            backward=backward,
            bridge=bridge,
            missing_links=missing_links(environment),
            components=graph_components(self._runtime),
            dominated_states_pruned=pruned,
        )

    def minimize(
        self,
        planned: PlannedChain,
        settings: ChainSearchSettings,
    ) -> PlannedChain:
        return minimize_chain(self._environment(settings), planned)

    def build_replay(self, seed: ReplaySeed) -> ReplayPlan:
        return build_replay_plan(self._runtime, seed)

    def verify_replay(self, request: ReplayRequest) -> ChainVerdict:
        return verify_clean_replay(self._runtime, request)

    def checkpoint(
        self,
        search_result: ChainSearchResult,
        replay_plans: tuple[ReplayPlan, ...],
    ) -> ChainCheckpoint:
        return ChainCheckpoint(
            graph=self._runtime.graph,
            registry=self._runtime.registry,
            search_result=search_result,
            replay_plans=replay_plans,
        )

    def _environment(self, settings: ChainSearchSettings) -> SearchEnvironment:
        unknown = set(settings.start_capability_ids).difference(
            self._runtime.index.capabilities
        )
        if unknown:
            raise ChainIntegrityError(
                "chain.unknown_start_capability",
                "search starts from a capability absent from the graph",
            )
        budget = settings.budget
        graph = self._runtime.graph
        grant_budget = self._authority.grant.budget
        if budget.actions > graph.action_budget or budget.actions > grant_budget.total_actions:
            raise ChainPolicyError(
                "chain.search_action_budget_exceeds_authority",
                "search action budget exceeds graph or AuthorityGrant",
            )
        if (
            budget.time_seconds > graph.time_budget_seconds
            or budget.time_seconds > grant_budget.max_duration_seconds
        ):
            raise ChainPolicyError(
                "chain.search_time_budget_exceeds_authority",
                "search time budget exceeds graph or AuthorityGrant",
            )
        return SearchEnvironment(self._runtime, settings)
