from __future__ import annotations

import hashlib
from datetime import timedelta

from faultloom.api_async import (
    CorrelationKind,
    FlowCompletion,
    FlowStart,
    OpaqueCorrelation,
    SchemaSource,
    SurfaceBinding,
    UndocumentedObservation,
    correlation_ref,
    ingest_openapi,
)
from faultloom_protocol import AsyncFlow, OperationKind, OperationRef, SCHEMA_VERSION
from faultloom_web.identity_workflow import (
    IdentityGraphSeed,
    SessionChannel,
    SessionRegistration,
)
from faultloom_web.web_api import (
    IdentityRunInput,
    SchemaKind,
    SurfaceRunInput,
    SurfaceSchemaInput,
    WebApiRunRequest,
)
from labs.identity_workflow import IdentityWorkflowFixture, identity_workflow_fixture

from .chain_fixture import build_chain_fixture
from .contracts import WebApiFixture


def web_api_fixture() -> WebApiFixture:
    identity_fixture = identity_workflow_fixture()
    workflow = identity_fixture.workflows[0]
    now = workflow.steps[0].occurred_at
    source = SchemaSource(
        target_id=identity_fixture.target_id,
        schema_namespace="faultloom.lab.web.api.v1",
        observed_at=now,
    )
    openapi = b'{"openapi":"3.1.0","paths":{"/v1/start":{"post":{}}}}'
    start_operation = ingest_openapi(openapi, source).operations[0]
    job_operation = OperationRef(
        schema_version=SCHEMA_VERSION,
        operation_id="operation.web-api.job",
        target_id=identity_fixture.target_id,
        operation_kind=OperationKind.BACKGROUND_JOB,
        method="POST",
        path="/v1/jobs/canary",
        schema_namespace="faultloom.lab.web.api.v1",
        documented=False,
    )
    flow = AsyncFlow(
        schema_version=SCHEMA_VERSION,
        async_flow_id="async-flow.web-api.job",
        initiating_operation_id=start_operation.operation_id,
        operation_ids=(start_operation.operation_id, job_operation.operation_id),
        correlation_refs=(
            correlation_ref(
                OpaqueCorrelation(
                    kind=CorrelationKind.JOB_ID,
                    value=b"job.web-api.canary",
                )
            ),
        ),
        pending=True,
        initiated_at=now,
    )
    async_effect_id = "effect.web-api.async-complete"
    surface = SurfaceRunInput(
        binding=SurfaceBinding(
            engagement_id="engagement.web-api.lab",
            run_id=identity_fixture.run_id,
            target_id=identity_fixture.target_id,
            graph_id="surface-graph.web-api",
            grant_id="grant.web-api",
            scope_epoch=7,
            owned_callback_domains=("callbacks.loopback.test",),
        ),
        schemas=(
            SurfaceSchemaInput(kind=SchemaKind.OPENAPI, raw=openapi, source=source),
            SurfaceSchemaInput(
                kind=SchemaKind.GRAPHQL,
                raw=b"type Query { job(id: ID!): Job }",
                source=source,
            ),
        ),
        undocumented=(
            UndocumentedObservation(
                operation=job_operation,
                source_kind="traffic",
                source_digest=_digest("traffic.job"),
                observed_at=now,
            ),
        ),
        flow_start=FlowStart(flow=flow),
        completion=FlowCompletion(
            async_flow_id=flow.async_flow_id,
            terminal_operation_id=job_operation.operation_id,
            completed_at=now + timedelta(seconds=2),
            effect_id=async_effect_id,
        ),
    )
    identity = IdentityRunInput(
        graph_seed=IdentityGraphSeed(
            graph_id="identity-graph.web-api",
            run_id=identity_fixture.run_id,
            identities=identity_fixture.identities,
            tenants=identity_fixture.tenants,
            role_grants=identity_fixture.role_grants,
            relationships=identity_fixture.relationships,
            version=1,
        ),
        registrations=_registrations(identity_fixture),
        workflow_trace=workflow,
        actor_context_id=workflow.steps[0].identity_context_id,
    )
    positive_chain, negative_chain, action = build_chain_fixture(
        identity_fixture,
        async_effect_id,
    )
    positive = WebApiRunRequest(
        identity=identity,
        surface=surface,
        chain=positive_chain,
        actions=(action,),
    )
    negative = positive.model_copy(update={"chain": negative_chain})
    return WebApiFixture(
        schema_version=SCHEMA_VERSION,
        namespace="faultloom.lab.web.api.v1",
        fixture_id="fixture.web-api.integration",
        positive=positive,
        negative=negative,
        expected_async_effect_id=async_effect_id,
        expected_chain_edge_id="edge.web-api.identity-to-async",
    )


def _registrations(
    fixture: IdentityWorkflowFixture,
) -> tuple[SessionRegistration, ...]:
    profiles = {item.identity_id: item for item in fixture.identities}
    sessions = {item.auth_session_id: item for item in fixture.auth_sessions}
    values: list[SessionRegistration] = []
    for context in fixture.identity_contexts:
        channel = (
            SessionChannel.BROWSER
            if context.browser_context_ref is not None
            else SessionChannel.API
        )
        values.append(
            SessionRegistration(
                channel=channel,
                profile=profiles[context.identity_id],
                session=sessions[context.auth_session_id],
                context=context,
            )
        )
    return tuple(values)


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"
