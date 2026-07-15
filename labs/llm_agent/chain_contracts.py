from dataclasses import dataclass

from faultloom.chain import ChainAuthority, ChainSearchSettings, PrimitiveRegistry
from faultloom_protocol import ActionIntent, ChainGraph, StateRef
from faultloom_protocol.base import Identifier, Sha256Digest


@dataclass(frozen=True, slots=True)
class LlmChainFixture:
    registry: PrimitiveRegistry
    graph: ChainGraph
    authority: ChainAuthority
    settings: ChainSearchSettings
    reset_states: tuple[StateRef, ...]


@dataclass(frozen=True, slots=True)
class ObservationSeed:
    observation_id: Identifier
    capability_kind: Identifier
    intent: ActionIntent
    pre_state: StateRef
    post_state: StateRef
    precondition_ids: tuple[Identifier, ...]
    effect_ids: tuple[Identifier, ...]
    dispatch_digest: Sha256Digest


@dataclass(frozen=True, slots=True)
class EdgeSeed:
    edge_id: Identifier
    source_capability_id: Identifier
    target_capability_id: Identifier
    intent: ActionIntent
    input_state: StateRef
    effect_id: Identifier
    effect_kind: Identifier
    effect_state: StateRef
    lease_id: Identifier
