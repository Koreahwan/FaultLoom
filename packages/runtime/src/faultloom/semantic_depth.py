"""Deterministic semantic-depth search over inert, already-verified graphs.

This module deliberately has no action or network adapter.  It scores only
canonical verified transitions supplied by an owned/simulated fixture.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from collections.abc import Iterable
from typing import Any, Literal, final


RunClass = Literal["generated_structural_conformance", "exploratory_research_run"]
PendingEffectDisposition = Literal["none", "reserved", "unknown", "reconciled"]
TerminalReason = Literal[
    "verified",
    "checkpointed",
    "budget_exhausted",
    "depth_bound_exhausted",
    "unreachable",
]


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(prefix: str, value: object) -> str:
    return f"{prefix}.{hashlib.sha256(_canonical_bytes(value)).hexdigest()}"


def _require_text(value: str, field_name: str) -> None:
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-empty canonical text")


@dataclass(frozen=True, slots=True, order=True)
class BudgetVector:
    """The four monotonic, nonnegative G42 budget dimensions."""

    actions: int
    time: int
    cost: int
    impact: int

    def __post_init__(self) -> None:
        if any(value < 0 for value in self.as_tuple()):
            raise ValueError("semantic-depth budgets must be nonnegative")

    def as_tuple(self) -> tuple[int, int, int, int]:
        return (self.actions, self.time, self.cost, self.impact)

    def add(self, other: BudgetVector) -> BudgetVector:
        values = tuple(
            left + right
            for left, right in zip(self.as_tuple(), other.as_tuple())
        )
        return BudgetVector(*values)

    def fits(self, limit: BudgetVector) -> bool:
        return all(used <= allowed for used, allowed in zip(self.as_tuple(), limit.as_tuple()))

    def remaining(self, limit: BudgetVector) -> BudgetVector:
        if not self.fits(limit):
            raise ValueError("consumed budget exceeds its pinned limit")
        return BudgetVector(
            *(allowed - used for used, allowed in zip(self.as_tuple(), limit.as_tuple()))
        )

    def document(self) -> dict[str, int]:
        return dict(zip(("actions", "time", "cost", "impact"), self.as_tuple()))

    @classmethod
    def from_document(cls, value: object) -> BudgetVector:
        if type(value) is not dict:
            raise ValueError("budget document must be an object")
        keys = ("actions", "time", "cost", "impact")
        if set(value) != set(keys) or any(type(value[key]) is not int for key in keys):
            raise ValueError("budget document has an invalid shape")
        return cls(*(value[key] for key in keys))


ZERO_BUDGET = BudgetVector(0, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class SemanticEdge:
    """A verified transition whose IDs and semantics are content-derived."""

    source: str
    target: str
    prerequisites: tuple[str, ...]
    effect: str
    pre_state: str
    post_state: str
    primitive: str
    budget: BudgetVector = field(default=ZERO_BUDGET)

    def __post_init__(self) -> None:
        for name in ("source", "target", "effect", "pre_state", "post_state", "primitive"):
            _require_text(getattr(self, name), name)
        if self.prerequisites != tuple(sorted(set(self.prerequisites))):
            raise ValueError("prerequisites must be sorted and unique")
        for prerequisite in self.prerequisites:
            _require_text(prerequisite, "prerequisite")

    @property
    def semantic_signature(self) -> str:
        """Ignore presentation/topology IDs while binding all normative semantics."""

        return _digest(
            "semantic",
            {
                "effect": self.effect,
                "post_state": self.post_state,
                "pre_state": self.pre_state,
                "prerequisites": list(self.prerequisites),
                "primitive": self.primitive,
            },
        )

    @property
    def edge_id(self) -> str:
        return _digest(
            "edge",
            {
                "budget": self.budget.document(),
                "semantic_signature": self.semantic_signature,
                "source": self.source,
                "target": self.target,
            },
        )

    def document(self) -> dict[str, object]:
        return {
            "budget": self.budget.document(),
            "effect": self.effect,
            "post_state": self.post_state,
            "pre_state": self.pre_state,
            "prerequisites": list(self.prerequisites),
            "primitive": self.primitive,
            "source": self.source,
            "target": self.target,
        }

    @classmethod
    def from_document(cls, value: object) -> SemanticEdge:
        if type(value) is not dict:
            raise ValueError("edge document must be an object")
        expected = {
            "budget", "effect", "post_state", "pre_state", "prerequisites",
            "primitive", "source", "target",
        }
        if set(value) != expected or type(value["prerequisites"]) is not list:
            raise ValueError("edge document has an invalid shape")
        text_fields = ("effect", "post_state", "pre_state", "primitive", "source", "target")
        if any(type(value[name]) is not str for name in text_fields):
            raise ValueError("edge document contains non-text semantics")
        prerequisites = value["prerequisites"]
        if any(type(item) is not str for item in prerequisites):
            raise ValueError("edge prerequisites must be text")
        return cls(
            source=value["source"],
            target=value["target"],
            prerequisites=tuple(prerequisites),
            effect=value["effect"],
            pre_state=value["pre_state"],
            post_state=value["post_state"],
            primitive=value["primitive"],
            budget=BudgetVector.from_document(value["budget"]),
        )


@dataclass(frozen=True, slots=True)
class SemanticGraph:
    initial_node: str
    initial_state: str
    initial_effects: tuple[str, ...]
    final_effect: str
    edges: tuple[SemanticEdge, ...]

    def __post_init__(self) -> None:
        _require_text(self.initial_node, "initial_node")
        _require_text(self.initial_state, "initial_state")
        _require_text(self.final_effect, "final_effect")
        if self.initial_effects != tuple(sorted(set(self.initial_effects))):
            raise ValueError("initial_effects must be sorted and unique")
        if self.final_effect in self.initial_effects:
            raise ValueError("final_effect must not be present in initial_effects")
        edge_ids = tuple(edge.edge_id for edge in self.edges)
        if edge_ids != tuple(sorted(edge_ids)):
            raise ValueError("edges must be sorted by content-derived edge_id")
        if len(set(edge_ids)) != len(edge_ids):
            raise ValueError("graph contains duplicate canonical edges")

    @property
    def graph_id(self) -> str:
        return _digest("semantic-graph", self.document())

    def document(self) -> dict[str, object]:
        return {
            "edges": [edge.document() for edge in self.edges],
            "final_effect": self.final_effect,
            "initial_effects": list(self.initial_effects),
            "initial_node": self.initial_node,
            "initial_state": self.initial_state,
        }

    @classmethod
    def build(
        cls,
        *,
        initial_node: str,
        initial_state: str,
        initial_effects: tuple[str, ...],
        final_effect: str,
        edges: tuple[SemanticEdge, ...],
    ) -> SemanticGraph:
        return cls(
            initial_node=initial_node,
            initial_state=initial_state,
            initial_effects=tuple(sorted(set(initial_effects))),
            final_effect=final_effect,
            edges=tuple(sorted(edges, key=lambda edge: edge.edge_id)),
        )

    @classmethod
    def from_document(cls, value: object) -> SemanticGraph:
        if type(value) is not dict:
            raise ValueError("graph document must be an object")
        expected = {"edges", "final_effect", "initial_effects", "initial_node", "initial_state"}
        if (
            set(value) != expected
            or type(value["edges"]) is not list
            or type(value["initial_effects"]) is not list
        ):
            raise ValueError("graph document has an invalid shape")
        for name in ("final_effect", "initial_node", "initial_state"):
            if type(value[name]) is not str:
                raise ValueError("graph text field has an invalid type")
        if any(type(item) is not str for item in value["initial_effects"]):
            raise ValueError("initial effects must be text")
        return cls(
            initial_node=value["initial_node"],
            initial_state=value["initial_state"],
            initial_effects=tuple(value["initial_effects"]),
            final_effect=value["final_effect"],
            edges=tuple(SemanticEdge.from_document(item) for item in value["edges"]),
        )


@dataclass(frozen=True, slots=True)
class SearchConfig:
    research_bound: int
    budget: BudgetVector
    identity_id: str
    tenant_id: str
    authority_epoch: str
    pending_effect_disposition: PendingEffectDisposition
    run_class: RunClass | None = None

    def __post_init__(self) -> None:
        if self.research_bound < 0:
            raise ValueError("research_bound must be nonnegative")
        for name in ("identity_id", "tenant_id", "authority_epoch"):
            _require_text(getattr(self, name), name)
        if self.pending_effect_disposition not in (
            "none",
            "reserved",
            "unknown",
            "reconciled",
        ):
            raise ValueError("unknown pending-effect disposition")
        if self.research_bound > 10 and self.run_class not in (
            "generated_structural_conformance",
            "exploratory_research_run",
        ):
            raise ValueError("runs above semantic depth 10 require exactly one run_class")
        if self.run_class == "exploratory_research_run" and self.research_bound < 20:
            raise ValueError("exploratory_research_run requires a bound of at least 20")

    @property
    def config_id(self) -> str:
        return _digest("semantic-config", self.document())

    def document(self) -> dict[str, object]:
        return {
            "authority_epoch": self.authority_epoch,
            "budget": self.budget.document(),
            "identity_id": self.identity_id,
            "pending_effect_disposition": self.pending_effect_disposition,
            "research_bound": self.research_bound,
            "run_class": self.run_class,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_document(cls, value: object) -> SearchConfig:
        expected = {
            "authority_epoch",
            "budget",
            "identity_id",
            "pending_effect_disposition",
            "research_bound",
            "run_class",
            "tenant_id",
        }
        if type(value) is not dict or set(value) != expected:
            raise ValueError("search config has an invalid shape")
        if type(value["research_bound"]) is not int:
            raise ValueError("research_bound must be an integer")
        run_class = value["run_class"]
        if run_class is not None and run_class not in (
            "generated_structural_conformance", "exploratory_research_run"
        ):
            raise ValueError("unknown semantic-depth run_class")
        text_fields = (
            "authority_epoch",
            "identity_id",
            "pending_effect_disposition",
            "tenant_id",
        )
        if any(type(value[name]) is not str for name in text_fields):
            raise ValueError("search context fields must be text")
        return cls(
            research_bound=value["research_bound"],
            budget=BudgetVector.from_document(value["budget"]),
            identity_id=value["identity_id"],
            tenant_id=value["tenant_id"],
            authority_epoch=value["authority_epoch"],
            pending_effect_disposition=value["pending_effect_disposition"],
            run_class=run_class,
        )


@dataclass(frozen=True, slots=True)
class CondensedComponent:
    component_id: str
    members: tuple[str, ...]
    cyclic: bool


@dataclass(frozen=True, slots=True)
class _SearchState:
    identity_id: str
    tenant_id: str
    authority_epoch: str
    pending_effect_disposition: PendingEffectDisposition
    node: str
    state: str
    effects: tuple[str, ...]
    primitives: tuple[str, ...]
    semantic_signatures: tuple[str, ...]
    edge_ids: tuple[str, ...]
    semantic_edge_ids: tuple[str, ...]
    consumed: BudgetVector

    def __post_init__(self) -> None:
        for name in (
            "identity_id",
            "tenant_id",
            "authority_epoch",
            "node",
            "state",
        ):
            _require_text(getattr(self, name), name)
        if self.pending_effect_disposition not in (
            "none",
            "reserved",
            "unknown",
            "reconciled",
        ):
            raise ValueError("unknown pending-effect disposition")

    @property
    def semantic_depth(self) -> int:
        return len(self.semantic_edge_ids)

    @property
    def state_id(self) -> str:
        return _digest("semantic-state", self.document())

    @property
    def fingerprint(self) -> str:
        return _digest(
            "semantic-fingerprint",
            {
                "authority_epoch": self.authority_epoch,
                "effects": list(self.effects),
                "identity_id": self.identity_id,
                "node": self.node,
                "pending_effect_disposition": self.pending_effect_disposition,
                "primitives": list(self.primitives),
                "semantic_signatures": list(self.semantic_signatures),
                "state": self.state,
                "tenant_id": self.tenant_id,
            },
        )

    def document(self) -> dict[str, object]:
        return {
            "authority_epoch": self.authority_epoch,
            "consumed": self.consumed.document(),
            "edge_ids": list(self.edge_ids),
            "effects": list(self.effects),
            "identity_id": self.identity_id,
            "node": self.node,
            "pending_effect_disposition": self.pending_effect_disposition,
            "primitives": list(self.primitives),
            "semantic_edge_ids": list(self.semantic_edge_ids),
            "semantic_signatures": list(self.semantic_signatures),
            "state": self.state,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_document(cls, value: object) -> _SearchState:
        if type(value) is not dict:
            raise ValueError("search state must be an object")
        expected = {
            "authority_epoch", "consumed", "edge_ids", "effects", "identity_id",
            "node", "pending_effect_disposition", "primitives", "semantic_edge_ids",
            "semantic_signatures", "state", "tenant_id",
        }
        if set(value) != expected:
            raise ValueError("search state has an invalid shape")
        sequences = (
            "edge_ids",
            "effects",
            "primitives",
            "semantic_edge_ids",
            "semantic_signatures",
        )
        for key in sequences:
            if type(value[key]) is not list or any(
                type(item) is not str for item in value[key]
            ):
                raise ValueError("search state sequence has an invalid shape")
        text_fields = (
            "authority_epoch",
            "identity_id",
            "node",
            "pending_effect_disposition",
            "state",
            "tenant_id",
        )
        if any(type(value[name]) is not str for name in text_fields):
            raise ValueError("search state text has an invalid shape")
        return cls(
            identity_id=value["identity_id"],
            tenant_id=value["tenant_id"],
            authority_epoch=value["authority_epoch"],
            pending_effect_disposition=value["pending_effect_disposition"],
            node=value["node"], state=value["state"], effects=tuple(value["effects"]),
            primitives=tuple(value["primitives"]),
            semantic_signatures=tuple(value["semantic_signatures"]),
            edge_ids=tuple(value["edge_ids"]),
            semantic_edge_ids=tuple(value["semantic_edge_ids"]),
            consumed=BudgetVector.from_document(value["consumed"]),
        )


@dataclass(frozen=True, slots=True)
class DominanceRecord:
    edge_ids: tuple[str, ...]
    semantic_depth: int
    consumed: BudgetVector
    remaining: BudgetVector

    def document(self) -> dict[str, object]:
        return {
            "consumed": self.consumed.document(),
            "edge_ids": list(self.edge_ids),
            "remaining": self.remaining.document(),
            "semantic_depth": self.semantic_depth,
        }


@dataclass(frozen=True, slots=True)
class SearchCheckpoint:
    graph: SemanticGraph
    config: SearchConfig
    current_bound: int
    frontier: tuple[_SearchState, ...]
    seen: tuple[tuple[str, tuple[DominanceRecord, ...]], ...]
    goals: tuple[_SearchState, ...]
    longest_verified_prefix: int
    expansions: int
    budget_denied: bool
    depth_denied: bool
    components: tuple[CondensedComponent, ...]

    @property
    def checkpoint_id(self) -> str:
        return _digest("semantic-checkpoint", self.document())

    def document(self) -> dict[str, object]:
        return {
            "budget_denied": self.budget_denied,
            "components": [
                {
                    "component_id": item.component_id,
                    "cyclic": item.cyclic,
                    "members": list(item.members),
                }
                for item in self.components
            ],
            "config": self.config.document(),
            "current_bound": self.current_bound,
            "depth_denied": self.depth_denied,
            "expansions": self.expansions,
            "frontier": [item.document() for item in self.frontier],
            "goals": [item.document() for item in self.goals],
            "graph": self.graph.document(),
            "longest_verified_prefix": self.longest_verified_prefix,
            "seen": [
                {
                    "fingerprint": fingerprint,
                    "records": [record.document() for record in records],
                }
                for fingerprint, records in self.seen
            ],
        }

    def to_json(self) -> str:
        return _canonical_bytes(self.document()).decode()

    @classmethod
    def from_json(cls, payload: str) -> SearchCheckpoint:
        try:
            value: Any = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("checkpoint is not valid JSON") from exc
        if type(value) is not dict or _canonical_bytes(value).decode() != payload:
            raise ValueError("checkpoint JSON must use the canonical encoding")
        expected = {
            "budget_denied", "components", "config", "current_bound", "depth_denied",
            "expansions", "frontier", "goals", "graph", "longest_verified_prefix", "seen",
        }
        if set(value) != expected:
            raise ValueError("checkpoint has an invalid shape")
        if any(
            type(value[name]) is not int
            for name in ("current_bound", "expansions", "longest_verified_prefix")
        ):
            raise ValueError("checkpoint counters must be integers")
        if (
            type(value["budget_denied"]) is not bool
            or type(value["depth_denied"]) is not bool
        ):
            raise ValueError("checkpoint flags must be boolean")
        if any(
            type(value[name]) is not list
            for name in ("components", "frontier", "goals", "seen")
        ):
            raise ValueError("checkpoint sequences must be arrays")
        components: list[CondensedComponent] = []
        for item in value["components"]:
            if type(item) is not dict or set(item) != {
                "component_id",
                "cyclic",
                "members",
            }:
                raise ValueError("checkpoint component has an invalid shape")
            if (
                type(item["component_id"]) is not str
                or type(item["cyclic"]) is not bool
                or type(item["members"]) is not list
            ):
                raise ValueError("checkpoint component has invalid values")
            components.append(
                CondensedComponent(
                    item["component_id"], tuple(item["members"]), item["cyclic"]
                )
            )
        config = SearchConfig.from_document(value["config"])
        seen: list[tuple[str, tuple[DominanceRecord, ...]]] = []
        for item in value["seen"]:
            if type(item) is not dict or set(item) != {
                "fingerprint",
                "records",
            }:
                raise ValueError("checkpoint dominance record has an invalid shape")
            if type(item["fingerprint"]) is not str or type(item["records"]) is not list:
                raise ValueError("checkpoint dominance frontier has invalid values")
            records: list[DominanceRecord] = []
            for record in item["records"]:
                expected_record = {
                    "consumed", "edge_ids", "remaining", "semantic_depth"
                }
                if type(record) is not dict or set(record) != expected_record:
                    raise ValueError("checkpoint Pareto record has an invalid shape")
                if (
                    type(record["edge_ids"]) is not list
                    or type(record["semantic_depth"]) is not int
                ):
                    raise ValueError("checkpoint Pareto record has invalid values")
                consumed = BudgetVector.from_document(record["consumed"])
                remaining = BudgetVector.from_document(record["remaining"])
                if consumed.remaining(config.budget) != remaining:
                    raise ValueError("checkpoint Pareto remaining budget is inconsistent")
                records.append(
                    DominanceRecord(
                        edge_ids=tuple(record["edge_ids"]),
                        semantic_depth=record["semantic_depth"],
                        consumed=consumed,
                        remaining=remaining,
                    )
                )
            seen.append((item["fingerprint"], tuple(records)))
        checkpoint = cls(
            graph=SemanticGraph.from_document(value["graph"]),
            config=config,
            current_bound=value["current_bound"],
            frontier=tuple(
                _SearchState.from_document(item) for item in value["frontier"]
            ),
            seen=tuple(seen),
            goals=tuple(_SearchState.from_document(item) for item in value["goals"]),
            longest_verified_prefix=value["longest_verified_prefix"],
            expansions=value["expansions"],
            budget_denied=value["budget_denied"],
            depth_denied=value["depth_denied"],
            components=tuple(components),
        )
        if checkpoint.components != _condense(checkpoint.graph):
            raise ValueError("checkpoint SCC condensation does not match its graph")
        return checkpoint


@dataclass(frozen=True, slots=True)
class SemanticWitness:
    edge_ids: tuple[str, ...]
    semantic_edge_ids: tuple[str, ...]
    semantic_depth: int
    final_effect: str
    consumed: BudgetVector


@dataclass(frozen=True, slots=True)
class SearchReport:
    terminal_reason: TerminalReason
    witness: SemanticWitness | None
    longest_verified_prefix: int
    expansions: int
    checkpoint: SearchCheckpoint


@final
class SemanticDepthEngine:
    """Iterative-deepening verifier with canonical checkpoint/resume."""

    def __init__(self, graph: SemanticGraph) -> None:
        self.graph = graph
        self._edges = {edge.edge_id: edge for edge in graph.edges}
        outgoing: dict[str, list[SemanticEdge]] = {}
        for edge in graph.edges:
            outgoing.setdefault(edge.source, []).append(edge)
        self._outgoing = {
            key: tuple(sorted(value, key=lambda edge: edge.edge_id))
            for key, value in outgoing.items()
        }
        self.components = _condense(graph)

    def search(
        self,
        config: SearchConfig,
        *,
        checkpoint: SearchCheckpoint | None = None,
        max_expansions: int | None = None,
        allowed_edge_ids: frozenset[str] | None = None,
    ) -> SearchReport:
        if max_expansions is not None and max_expansions < 0:
            raise ValueError("max_expansions must be nonnegative")
        if allowed_edge_ids is not None and not allowed_edge_ids.issubset(self._edges):
            raise ValueError("allowed edge set contains an unknown edge")
        current = checkpoint or self._initial_checkpoint(config)
        self._validate_checkpoint(current, config)
        frontier = deque(current.frontier)
        seen = {
            fingerprint: list(records) for fingerprint, records in current.seen
        }
        goals = list(current.goals)
        longest = current.longest_verified_prefix
        expansions = current.expansions
        started_at = expansions
        budget_denied = current.budget_denied
        depth_denied = current.depth_denied

        while True:
            if max_expansions is not None and expansions - started_at >= max_expansions:
                saved = self._checkpoint(
                    config,
                    current.current_bound,
                    frontier,
                    seen,
                    goals,
                    longest,
                    expansions,
                    budget_denied,
                    depth_denied,
                )
                return SearchReport("checkpointed", None, longest, expansions, saved)
            if not frontier:
                if goals:
                    winner = min(goals, key=lambda state: (state.semantic_depth, state.edge_ids))
                    saved = self._checkpoint(
                        config,
                        current.current_bound,
                        (),
                        seen,
                        goals,
                        longest,
                        expansions,
                        budget_denied,
                        depth_denied,
                    )
                    return SearchReport(
                        "verified",
                        _witness(self.graph, winner),
                        longest,
                        expansions,
                        saved,
                    )
                if current.current_bound >= config.research_bound:
                    reason: TerminalReason
                    if budget_denied:
                        reason = "budget_exhausted"
                    elif depth_denied:
                        reason = "depth_bound_exhausted"
                    else:
                        reason = "unreachable"
                    saved = self._checkpoint(
                        config,
                        current.current_bound,
                        (),
                        seen,
                        (),
                        longest,
                        expansions,
                        budget_denied,
                        depth_denied,
                    )
                    return SearchReport(reason, None, longest, expansions, saved)
                current = self._initial_checkpoint(
                    config,
                    bound=current.current_bound + 1,
                    expansions=expansions,
                    longest=longest,
                )
                frontier = deque(current.frontier)
                seen = {
                    fingerprint: list(records)
                    for fingerprint, records in current.seen
                }
                goals = []
                budget_denied = False
                depth_denied = False
                continue

            state = frontier.popleft()
            expansions += 1
            for edge in self._outgoing.get(state.node, ()):
                if allowed_edge_ids is not None and edge.edge_id not in allowed_edge_ids:
                    continue
                advanced, denied = self._advance(state, edge, config.budget)
                if denied == "budget":
                    budget_denied = True
                    continue
                if advanced is None:
                    continue
                if advanced.semantic_depth > current.current_bound:
                    depth_denied = True
                    continue
                longest = max(longest, advanced.semantic_depth)
                if not _record_nondominated(seen, advanced, config.budget):
                    continue
                if self.graph.final_effect in advanced.effects:
                    goals.append(advanced)
                else:
                    frontier.append(advanced)
            frontier = deque(sorted(frontier, key=lambda state: state.edge_ids))

    def minimize(
        self,
        candidate_edge_ids: tuple[str, ...],
        config: SearchConfig,
    ) -> SemanticWitness:
        if not candidate_edge_ids:
            raise ValueError("candidate trace must not be empty")
        allowed = frozenset(candidate_edge_ids)
        if not allowed.issubset(self._edges):
            raise ValueError("candidate trace contains an unknown edge")
        result = self.search(config, allowed_edge_ids=allowed)
        if result.witness is None:
            raise ValueError("candidate trace has no dependency-valid final witness")
        return result.witness

    def _initial_checkpoint(
        self,
        config: SearchConfig,
        *,
        bound: int = 0,
        expansions: int = 0,
        longest: int = 0,
    ) -> SearchCheckpoint:
        initial = self._initial_state(config)
        initial_record = _dominance_record(initial, config.budget)
        return self._checkpoint(
            config,
            bound,
            (initial,),
            {initial.fingerprint: [initial_record]},
            (),
            longest, expansions, False, False,
        )

    def _initial_state(self, config: SearchConfig) -> _SearchState:
        return _SearchState(
            identity_id=config.identity_id,
            tenant_id=config.tenant_id,
            authority_epoch=config.authority_epoch,
            pending_effect_disposition=config.pending_effect_disposition,
            node=self.graph.initial_node,
            state=self.graph.initial_state,
            effects=self.graph.initial_effects,
            primitives=(), semantic_signatures=(), edge_ids=(), semantic_edge_ids=(),
            consumed=ZERO_BUDGET,
        )

    def _checkpoint(
        self,
        config: SearchConfig,
        bound: int,
        frontier: Iterable[_SearchState],
        seen: dict[str, list[DominanceRecord]],
        goals: Iterable[_SearchState],
        longest: int,
        expansions: int,
        budget_denied: bool,
        depth_denied: bool,
    ) -> SearchCheckpoint:
        frontier_states = tuple(frontier)
        goal_states = tuple(goals)
        return SearchCheckpoint(
            graph=self.graph, config=config, current_bound=bound,
            frontier=tuple(sorted(frontier_states, key=lambda state: state.edge_ids)),
            seen=tuple(
                (key, tuple(sorted(records, key=_dominance_order)))
                for key, records in sorted(seen.items())
            ),
            goals=tuple(sorted(goal_states, key=lambda state: state.edge_ids)),
            longest_verified_prefix=longest, expansions=expansions,
            budget_denied=budget_denied, depth_denied=depth_denied,
            components=self.components,
        )

    def _validate_checkpoint(self, checkpoint: SearchCheckpoint, config: SearchConfig) -> None:
        if checkpoint.graph.graph_id != self.graph.graph_id:
            raise ValueError("checkpoint belongs to another semantic graph")
        if checkpoint.config.config_id != config.config_id:
            raise ValueError("checkpoint belongs to another search configuration")
        if checkpoint.components != self.components:
            raise ValueError("checkpoint SCC condensation is inconsistent")
        if not 0 <= checkpoint.current_bound <= config.research_bound:
            raise ValueError("checkpoint iteration bound is invalid")
        expected_context = (
            config.identity_id,
            config.tenant_id,
            config.authority_epoch,
            config.pending_effect_disposition,
        )
        for state in (*checkpoint.frontier, *checkpoint.goals):
            actual_context = (
                state.identity_id,
                state.tenant_id,
                state.authority_epoch,
                state.pending_effect_disposition,
            )
            if actual_context != expected_context:
                raise ValueError("checkpoint state authority context is inconsistent")
            rederived = self._rederive_state(state.edge_ids, config)
            if rederived != state:
                raise ValueError("checkpoint state cannot be rederived from its edge path")
            if state.semantic_depth > checkpoint.current_bound:
                raise ValueError("checkpoint state exceeds its iteration bound")
        if any(self.graph.final_effect in state.effects for state in checkpoint.frontier):
            raise ValueError("checkpoint frontier contains an unclassified goal state")
        if any(self.graph.final_effect not in state.effects for state in checkpoint.goals):
            raise ValueError("checkpoint goal does not contain the final effect")

    def _rederive_state(
        self,
        edge_ids: tuple[str, ...],
        config: SearchConfig,
    ) -> _SearchState:
        state = self._initial_state(config)
        for edge_id in edge_ids:
            edge = self._edges.get(edge_id)
            if edge is None:
                raise ValueError("checkpoint state references an unknown edge")
            advanced, denied = self._advance(state, edge, config.budget)
            if denied is not None or advanced is None:
                raise ValueError("checkpoint edge path cannot be replayed")
            state = advanced
        return state

    @staticmethod
    def _advance(
        state: _SearchState,
        edge: SemanticEdge,
        limit: BudgetVector,
    ) -> tuple[_SearchState | None, Literal["budget"] | None]:
        if edge.edge_id in state.edge_ids or edge.source != state.node:
            return None, None
        if edge.pre_state != state.state or not set(edge.prerequisites).issubset(state.effects):
            return None, None
        consumed = state.consumed.add(edge.budget)
        if not consumed.fits(limit):
            return None, "budget"
        signature_is_new = edge.semantic_signature not in state.semantic_signatures
        # A new label or primitive name alone is padding.  A required security
        # primitive must expose a new verified effect or state transition.
        introduces_semantics = (
            edge.effect not in state.effects or edge.post_state != state.state
        )
        semantic = signature_is_new and introduces_semantics
        return _SearchState(
            identity_id=state.identity_id,
            tenant_id=state.tenant_id,
            authority_epoch=state.authority_epoch,
            pending_effect_disposition=state.pending_effect_disposition,
            node=edge.target,
            state=edge.post_state,
            effects=tuple(sorted(set((*state.effects, edge.effect)))),
            primitives=(
                tuple(sorted((*state.primitives, edge.primitive)))
                if semantic
                else state.primitives
            ),
            semantic_signatures=(
                tuple(sorted((*state.semantic_signatures, edge.semantic_signature)))
                if semantic
                else state.semantic_signatures
            ),
            edge_ids=(*state.edge_ids, edge.edge_id),
            semantic_edge_ids=(
                (*state.semantic_edge_ids, edge.edge_id)
                if semantic
                else state.semantic_edge_ids
            ),
            consumed=consumed,
        ), None


def _dominance_record(state: _SearchState, limit: BudgetVector) -> DominanceRecord:
    return DominanceRecord(
        edge_ids=state.edge_ids,
        semantic_depth=state.semantic_depth,
        consumed=state.consumed,
        remaining=state.consumed.remaining(limit),
    )


def _dominance_order(
    record: DominanceRecord,
) -> tuple[int, tuple[int, int, int, int], tuple[str, ...]]:
    return (record.semantic_depth, record.consumed.as_tuple(), record.edge_ids)


def _strictly_dominates(left: DominanceRecord, right: DominanceRecord) -> bool:
    depth_allows = left.semantic_depth <= right.semantic_depth
    consumed_allows = all(
        left_value <= right_value
        for left_value, right_value in zip(
            left.consumed.as_tuple(), right.consumed.as_tuple()
        )
    )
    remaining_allows = all(
        left_value >= right_value
        for left_value, right_value in zip(
            left.remaining.as_tuple(), right.remaining.as_tuple()
        )
    )
    strictly_better = (
        left.semantic_depth < right.semantic_depth
        or any(
            left_value < right_value
            for left_value, right_value in zip(
                left.consumed.as_tuple(), right.consumed.as_tuple()
            )
        )
        or any(
            left_value > right_value
            for left_value, right_value in zip(
                left.remaining.as_tuple(), right.remaining.as_tuple()
            )
        )
    )
    return depth_allows and consumed_allows and remaining_allows and strictly_better


def _record_nondominated(
    frontiers: dict[str, list[DominanceRecord]],
    state: _SearchState,
    limit: BudgetVector,
) -> bool:
    candidate = _dominance_record(state, limit)
    records = frontiers.setdefault(state.fingerprint, [])
    if any(record == candidate for record in records):
        return False
    if any(_strictly_dominates(record, candidate) for record in records):
        return False
    records[:] = [
        record for record in records if not _strictly_dominates(candidate, record)
    ]
    records.append(candidate)
    records.sort(key=_dominance_order)
    return True


def _witness(graph: SemanticGraph, state: _SearchState) -> SemanticWitness:
    return SemanticWitness(
        edge_ids=state.edge_ids,
        semantic_edge_ids=state.semantic_edge_ids,
        semantic_depth=state.semantic_depth,
        final_effect=graph.final_effect,
        consumed=state.consumed,
    )


def _condense(graph: SemanticGraph) -> tuple[CondensedComponent, ...]:
    nodes = sorted(
        {
            graph.initial_node,
            *(edge.source for edge in graph.edges),
            *(edge.target for edge in graph.edges),
        }
    )
    outgoing = {
        node: tuple(sorted(edge.target for edge in graph.edges if edge.source == node))
        for node in nodes
    }
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indexes[node] = lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in outgoing[node]:
            if target not in indexes:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[target])
        if lowlinks[node] != indexes[node]:
            return
        members: list[str] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            members.append(member)
            if member == node:
                break
        components.append(tuple(sorted(members)))

    for node in nodes:
        if node not in indexes:
            visit(node)
    result = []
    for members in sorted(components):
        self_loop = any(
            edge.source == edge.target and edge.source in members
            for edge in graph.edges
        )
        result.append(
            CondensedComponent(
                component_id=_digest("semantic-scc", list(members)),
                members=members,
                cyclic=len(members) > 1 or self_loop,
            )
        )
    return tuple(result)
