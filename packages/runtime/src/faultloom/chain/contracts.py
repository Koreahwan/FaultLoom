from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import (
    ActionLease,
    AuthorityGrant,
    ChainGraph,
    ChainPlan,
    ChainVerdict,
    EvidenceRef,
    MissingLink,
    PolicyDecision,
    ReplayPlan,
    StateRef,
)
from faultloom_protocol.base import AwareDatetime, Identifier

from .errors import ChainIntegrityError
from .admissions import PrimitiveRegistry

PositiveInt = Annotated[int, Field(ge=1, le=2**63 - 1)]
NonNegativeInt = Annotated[int, Field(ge=0, le=2**63 - 1)]


class _ChainModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    schema_version: Literal["0.1.0"] = "0.1.0"


class AssetClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CLOUD_METADATA = "cloud_metadata"


class SearchMode(StrEnum):
    FORWARD = "forward"
    BACKWARD = "backward"
    BRIDGE = "bridge"


class EdgeAuthorityBinding(_ChainModel):
    binding_id: Identifier
    edge_id: Identifier
    lease: ActionLease
    decision: PolicyDecision
    asset_class: AssetClass
    explicitly_granted: bool
    impact_cost: PositiveInt


class ChainAuthority(_ChainModel):
    grant: AuthorityGrant
    edge_bindings: tuple[EdgeAuthorityBinding, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _bindings_are_one_use(self) -> Self:
        edge_ids = tuple(item.edge_id for item in self.edge_bindings)
        lease_ids = tuple(item.lease.lease_id for item in self.edge_bindings)
        if len(edge_ids) != len(set(edge_ids)):
            raise ChainIntegrityError(
                "chain.duplicate_edge_binding",
                "each edge requires exactly one authority binding",
            )
        if len(lease_ids) != len(set(lease_ids)):
            raise ChainIntegrityError(
                "chain.reused_action_lease",
                "each chain edge requires a fresh ActionLease",
            )
        return self


class ChainBudget(_ChainModel):
    actions: PositiveInt
    time_seconds: PositiveInt
    impact: PositiveInt


class ChainSearchSettings(_ChainModel):
    start_capability_ids: tuple[Identifier, ...] = Field(min_length=1)
    available_precondition_ids: tuple[Identifier, ...] = ()
    goal_effect_id: Identifier
    modes: tuple[SearchMode, ...] = (
        SearchMode.FORWARD,
        SearchMode.BACKWARD,
        SearchMode.BRIDGE,
    )
    budget: ChainBudget

    @model_validator(mode="after")
    def _search_inputs_are_unique(self) -> Self:
        if len(set(self.start_capability_ids)) != len(self.start_capability_ids):
            raise ChainIntegrityError(
                "chain.duplicate_start",
                "start capability IDs must be unique",
            )
        if len(set(self.modes)) != len(self.modes):
            raise ChainIntegrityError(
                "chain.duplicate_search_mode",
                "search modes must be unique",
            )
        return self


class PlannedChain(_ChainModel):
    plan: ChainPlan
    total_impact_cost: NonNegativeInt
    contains_candidate: bool


class GraphComponent(_ChainModel):
    capability_ids: tuple[Identifier, ...] = Field(min_length=1)
    cyclic: bool


class ChainSearchResult(_ChainModel):
    forward: PlannedChain | None
    backward: PlannedChain | None
    bridge: PlannedChain | None
    missing_links: tuple[MissingLink, ...]
    components: tuple[GraphComponent, ...]
    dominated_states_pruned: NonNegativeInt


class ReplaySeed(_ChainModel):
    planned: PlannedChain
    fresh_identity_context_ids: tuple[Identifier, ...] = Field(min_length=1)
    reset_state_refs: tuple[StateRef, ...]
    cleanup_plan_ref: Identifier | None = None


class ReplayObservation(_ChainModel):
    edge_id: Identifier
    action_lease_id: Identifier
    observed_effect_id: Identifier
    effect_verified: bool
    negative_control_passed: bool
    clean_state_replayed: bool
    evidence_refs: tuple[EvidenceRef, ...] = Field(min_length=1)


class ReplayRequest(_ChainModel):
    planned: PlannedChain
    replay_plan: ReplayPlan
    observations: tuple[ReplayObservation, ...]
    verified_at: AwareDatetime


class ChainCheckpoint(_ChainModel):
    graph: ChainGraph
    registry: PrimitiveRegistry
    search_result: ChainSearchResult
    replay_plans: tuple[ReplayPlan, ...]
    verdicts: tuple[ChainVerdict, ...] = ()
