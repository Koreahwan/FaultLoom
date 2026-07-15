from typing import Literal

from pydantic import Field

from faultloom.chain import ChainCheckpoint, ChainSearchResult, PrimitiveRegistry
from faultloom_protocol import (
    ActionIntent,
    ChainGraph,
    IdentityGraph,
    ObservationRef,
    SurfaceGraph,
    WorkflowGraph,
)
from faultloom_protocol.base import Identifier

from ._base import WebApiModel


class NormalizedWebObservation(WebApiModel):
    normalizer_id: Literal["web.api.observation_normalizer"]
    action_id: Identifier
    lease_id: Identifier
    observation: ObservationRef


class WebApiHypothesis(WebApiModel):
    provider_id: Literal["web.api.bridge_hypothesis_provider"]
    hypothesis_id: Identifier
    identity_context_id: Identifier
    identity_graph_id: Identifier
    workflow_graph_id: Identifier
    async_flow_id: Identifier
    chain_graph_id: Identifier


class WebApiCorrelationView(WebApiModel):
    identity_context_id: Identifier
    identity_graph: IdentityGraph
    workflow_graph: WorkflowGraph
    surface_graph: SurfaceGraph
    chain_graph: ChainGraph
    completed_effect_ids: tuple[Identifier, ...]


class WebApiRunResult(WebApiModel):
    correlation: WebApiCorrelationView
    registry: PrimitiveRegistry
    chain_search: ChainSearchResult
    checkpoint: ChainCheckpoint
    compiled_intents: tuple[ActionIntent, ...]
    normalized_observations: tuple[NormalizedWebObservation, ...]
    hypotheses: tuple[WebApiHypothesis, ...]


class WebApiVerification(WebApiModel):
    verifier_id: Literal["web.api.clean_chain_verifier"]
    run_id: Identifier
    identity_async_correlated: bool
    final_effect_reached: bool
    action_boundaries_valid: bool
    passed: bool


class WebApiEvaluation(WebApiModel):
    evaluator_id: Literal["web.api.integration_evaluator"]
    run_id: Identifier
    verified: bool
    chain_edge_count: int = Field(ge=0)
    normalized_observation_count: int = Field(ge=0)


class ResetStability(WebApiModel):
    reset_stable: bool
    identity_graph_id: Identifier
    surface_graph_id: Identifier
    chain_graph_id: Identifier
