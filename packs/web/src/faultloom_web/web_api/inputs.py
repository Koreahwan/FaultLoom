from __future__ import annotations

from typing import Self

from pydantic import Field, model_validator

from faultloom.api_async import (
    FlowCompletion,
    FlowStart,
    SchemaSource,
    SurfaceBinding,
    UndocumentedObservation,
)
from faultloom.chain import (
    ChainAuthority,
    ChainSearchSettings,
    PrimitiveStatus,
)
from faultloom_protocol import (
    ActionIntent,
    ActionLease,
    ChainGraph,
    EgressPlane,
    ObservationRef,
    PrimitiveRecord,
    sha256_digest,
)
from faultloom_protocol.base import Identifier
from faultloom_web.identity_workflow import (
    IdentityGraphSeed,
    SessionRegistration,
    WorkflowTrace,
)

from ._base import (
    SchemaKind,
    WebApiIntegrationError,
    WebApiModel,
    WebApiSource,
)


class SurfaceSchemaInput(WebApiModel):
    kind: SchemaKind
    raw: bytes = Field(min_length=1)
    source: SchemaSource


class IdentityRunInput(WebApiModel):
    graph_seed: IdentityGraphSeed
    registrations: tuple[SessionRegistration, ...] = Field(min_length=1)
    workflow_trace: WorkflowTrace
    actor_context_id: Identifier

    @model_validator(mode="after")
    def _is_one_run(self) -> Self:
        context_ids = {
            registration.context.identity_context_id
            for registration in self.registrations
        }
        if self.graph_seed.run_id != self.workflow_trace.run_id:
            raise WebApiIntegrationError(
                "web_api.identity_run_mismatch",
                "identity graph and workflow trace must share one run",
            )
        if self.actor_context_id not in context_ids:
            raise WebApiIntegrationError(
                "web_api.actor_context_unknown",
                "the integration actor requires a registered identity context",
            )
        return self


class SurfaceRunInput(WebApiModel):
    binding: SurfaceBinding
    schemas: tuple[SurfaceSchemaInput, ...] = Field(min_length=1)
    undocumented: tuple[UndocumentedObservation, ...] = ()
    flow_start: FlowStart
    completion: FlowCompletion

    @model_validator(mode="after")
    def _sources_match_binding(self) -> Self:
        if any(item.source.target_id != self.binding.target_id for item in self.schemas):
            raise WebApiIntegrationError(
                "web_api.schema_target_mismatch",
                "schema sources must target the bound API surface",
            )
        if any(
            item.operation.target_id != self.binding.target_id
            for item in self.undocumented
        ):
            raise WebApiIntegrationError(
                "web_api.observed_target_mismatch",
                "observed operations must target the bound API surface",
            )
        if self.completion.async_flow_id != self.flow_start.flow.async_flow_id:
            raise WebApiIntegrationError(
                "web_api.flow_completion_mismatch",
                "the completion must identify the integrated async flow",
            )
        return self


class CapabilitySpec(WebApiModel):
    source: WebApiSource
    admission_id: Identifier
    capability_id: Identifier
    primitive: PrimitiveRecord
    capability_kind: Identifier
    source_pack_id: Identifier
    status: PrimitiveStatus
    precondition_ids: tuple[Identifier, ...] = ()
    effect_ids: tuple[Identifier, ...] = Field(min_length=1)


class ChainRunInput(WebApiModel):
    capabilities: tuple[CapabilitySpec, ...] = Field(min_length=2, max_length=2)
    graph_template: ChainGraph
    authority: ChainAuthority
    settings: ChainSearchSettings

    @model_validator(mode="after")
    def _has_exact_integrated_sources(self) -> Self:
        if {item.source for item in self.capabilities} != set(WebApiSource):
            raise WebApiIntegrationError(
                "web_api.capability_sources_incomplete",
                "the integrated chain requires identity/workflow and API/async sources",
            )
        if self.graph_template.capabilities:
            raise WebApiIntegrationError(
                "web_api.stale_capability_template",
                "the run facade owns normalized graph capabilities",
            )
        if any(
            item.primitive.run_id != self.graph_template.run_id
            for item in self.capabilities
        ):
            raise WebApiIntegrationError(
                "web_api.capability_run_mismatch",
                "chain capabilities must belong to the graph run",
            )
        return self


class ActionBoundaryRecord(WebApiModel):
    intent: ActionIntent
    lease: ActionLease
    observation: ObservationRef

    @model_validator(mode="after")
    def _is_gateway_bound(self) -> Self:
        intent = self.intent
        lease = self.lease
        if self.observation.run_id != intent.run_id:
            raise WebApiIntegrationError(
                "web_api.observation_run_mismatch",
                "normalized observations must belong to the action run",
            )
        expected = (
            intent.action_id,
            intent.target_id,
            intent.action_kind,
            intent.subject.identity_id,
            intent.subject.tenant_id,
            sha256_digest(intent),
        )
        actual = (
            lease.action_id,
            lease.target_id,
            lease.action_kind,
            lease.identity_id,
            lease.tenant_id,
            lease.intent_digest,
        )
        if expected != actual:
            raise WebApiIntegrationError(
                "web_api.action_lease_mismatch",
                "the action, identity, target, and intent digest require one exact lease",
            )
        if lease.egress_plane is not EgressPlane.TARGET_GATEWAY:
            raise WebApiIntegrationError(
                "web_api.direct_egress_denied",
                "Web/API actions require the Target Gateway egress plane",
            )
        return self


class WebApiRunRequest(WebApiModel):
    identity: IdentityRunInput
    surface: SurfaceRunInput
    chain: ChainRunInput
    actions: tuple[ActionBoundaryRecord, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _is_closed(self) -> Self:
        run_ids = {
            self.identity.graph_seed.run_id,
            self.surface.binding.run_id,
            self.chain.graph_template.run_id,
            *(item.intent.run_id for item in self.actions),
        }
        if len(run_ids) != 1:
            raise WebApiIntegrationError(
                "web_api.run_mismatch",
                "identity, surface, chain, and actions must share one run",
            )
        if self.surface.binding.grant_id != self.chain.authority.grant.grant_id:
            raise WebApiIntegrationError(
                "web_api.grant_mismatch",
                "surface and chain authority must share one grant",
            )
        api_spec = next(
            item
            for item in self.chain.capabilities
            if item.source is WebApiSource.API_ASYNC
        )
        if self.surface.completion.effect_id not in api_spec.effect_ids:
            raise WebApiIntegrationError(
                "web_api.async_effect_unbound",
                "the API capability must export the completed async effect",
            )
        return self
