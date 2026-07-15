from __future__ import annotations

from dataclasses import dataclass
from typing import assert_never

from faultloom.api_async import ApiAsyncSurfaceEngine, SurfaceState
from faultloom.chain import (
    ApiAsyncPrimitive,
    ChainCheckpoint,
    ChainSearchResult,
    CrossSurfaceChainEngine,
    IdentityWorkflowPrimitive,
    PrimitiveAdmission,
    PrimitiveRegistry,
    normalize_primitives,
)
from faultloom.state import StateStore
from faultloom_protocol import ChainGraph, IdentityGraph, SurfaceGraph, WorkflowGraph
from faultloom_web.identity_workflow import (
    IdentitySessionVault,
    WorkflowMiner,
    build_identity_graph,
)

from ._base import SchemaKind, WebApiSource
from .descriptors import (
    compile_web_action,
    normalize_web_observation,
    provide_bridge_hypotheses,
)
from .inputs import IdentityRunInput, SurfaceRunInput, WebApiRunRequest
from .results import WebApiCorrelationView, WebApiRunResult


@dataclass(frozen=True, slots=True)
class _IdentityArtifacts:
    identity_graph: IdentityGraph
    workflow_graph: WorkflowGraph


@dataclass(frozen=True, slots=True)
class _EngineArtifacts:
    identity: _IdentityArtifacts
    surface: SurfaceState


@dataclass(frozen=True, slots=True)
class _ChainArtifacts:
    registry: PrimitiveRegistry
    graph: ChainGraph
    search: ChainSearchResult
    checkpoint: ChainCheckpoint


class WebApiRunFacade:
    def __init__(self, store: StateStore) -> None:
        self._store = store

    def run(self, request: WebApiRunRequest) -> WebApiRunResult:
        identity = _build_identity(request.identity)
        surface = _run_surface(self._store, request.surface)
        return self._finish(request, _EngineArtifacts(identity, surface))

    def resume(self, request: WebApiRunRequest) -> WebApiRunResult:
        identity = _build_identity(request.identity)
        surface = ApiAsyncSurfaceEngine.open(
            self._store,
            request.surface.binding,
        ).state
        return self._finish(request, _EngineArtifacts(identity, surface))

    def _finish(
        self,
        request: WebApiRunRequest,
        artifacts: _EngineArtifacts,
    ) -> WebApiRunResult:
        chain = _build_chain(request, artifacts)
        view = WebApiCorrelationView(
            identity_context_id=request.identity.actor_context_id,
            identity_graph=artifacts.identity.identity_graph,
            workflow_graph=artifacts.identity.workflow_graph,
            surface_graph=artifacts.surface.graph,
            chain_graph=chain.graph,
            completed_effect_ids=artifacts.surface.completed_effect_ids,
        )
        compiled = tuple(compile_web_action(item) for item in request.actions)
        normalized = tuple(
            normalize_web_observation(item) for item in request.actions
        )
        hypotheses = provide_bridge_hypotheses(view)
        return WebApiRunResult(
            correlation=view,
            registry=chain.registry,
            chain_search=chain.search,
            checkpoint=chain.checkpoint,
            compiled_intents=compiled,
            normalized_observations=normalized,
            hypotheses=hypotheses,
        )


def _build_identity(request: IdentityRunInput) -> _IdentityArtifacts:
    vault = IdentitySessionVault()
    for registration in request.registrations:
        vault.register(registration)
    return _IdentityArtifacts(
        identity_graph=build_identity_graph(request.graph_seed),
        workflow_graph=WorkflowMiner(vault).mine(request.workflow_trace).graph,
    )


def _run_surface(store: StateStore, request: SurfaceRunInput) -> SurfaceState:
    engine = ApiAsyncSurfaceEngine.open(store, request.binding)
    for schema in request.schemas:
        match schema.kind:
            case SchemaKind.OPENAPI:
                engine.ingest_openapi(schema.raw, schema.source)
            case SchemaKind.GRAPHQL:
                engine.ingest_graphql(schema.raw, schema.source)
            case unreachable:
                assert_never(unreachable)
    for observation in request.undocumented:
        engine.observe_undocumented(observation)
    engine.begin_flow(request.flow_start)
    engine.finish_flow(request.completion)
    return engine.state


def _build_chain(
    request: WebApiRunRequest,
    artifacts: _EngineArtifacts,
) -> _ChainArtifacts:
    admissions: list[PrimitiveAdmission] = []
    for spec in request.chain.capabilities:
        match spec.source:
            case WebApiSource.IDENTITY_WORKFLOW:
                admissions.append(
                    IdentityWorkflowPrimitive(
                        admission_id=spec.admission_id,
                        capability_id=spec.capability_id,
                        primitive=spec.primitive,
                        capability_kind=spec.capability_kind,
                        source_pack_id=spec.source_pack_id,
                        status=spec.status,
                        precondition_ids=spec.precondition_ids,
                        effect_ids=spec.effect_ids,
                        identity_graph=artifacts.identity.identity_graph,
                        workflow_graph=artifacts.identity.workflow_graph,
                    )
                )
            case WebApiSource.API_ASYNC:
                admissions.append(
                    ApiAsyncPrimitive(
                        admission_id=spec.admission_id,
                        capability_id=spec.capability_id,
                        primitive=spec.primitive,
                        capability_kind=spec.capability_kind,
                        source_pack_id=spec.source_pack_id,
                        status=spec.status,
                        precondition_ids=spec.precondition_ids,
                        effect_ids=spec.effect_ids,
                        surface_graph=artifacts.surface.graph,
                    )
                )
            case unreachable:
                assert_never(unreachable)
    registry = normalize_primitives(tuple(admissions))
    graph = request.chain.graph_template.model_copy(
        update={"capabilities": registry.capabilities}
    )
    engine = CrossSurfaceChainEngine.open(
        registry,
        graph,
        request.chain.authority,
    )
    search = engine.search(request.chain.settings)
    return _ChainArtifacts(
        registry=registry,
        graph=graph,
        search=search,
        checkpoint=engine.checkpoint(search, ()),
    )
