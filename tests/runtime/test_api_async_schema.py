from __future__ import annotations

from faultloom.api_async import (
    CorrelationKind,
    SchemaSource,
    UndocumentedObservation,
    correlate_flow,
    ingest_graphql_sdl,
    ingest_openapi,
)
from faultloom_protocol import AsyncFlow, OperationKind, SCHEMA_VERSION
from tests.protocol.factories import D1, NOW
from tests.runtime.api_async_support import correlation, operation


def _source() -> SchemaSource:
    return SchemaSource(
        target_id="target.loopback.api_async",
        schema_namespace="faultloom.test.api_async.v1",
        observed_at=NOW,
    )


def test_openapi_and_graphql_ingest_produce_versioned_surface_operations() -> None:
    openapi = ingest_openapi(
        b'{"openapi":"3.1.0","paths":{"/v1/jobs":{"post":{}},"/v1/files/{id}":{"get":{}}}}',
        _source(),
    )
    graphql = ingest_graphql_sdl(
        b"type Query { invoice(id: ID!): Invoice }\n"
        b"type Mutation { approve(id: ID!): Job }\n"
        b"type Subscription { jobUpdated(id: ID!): Job }",
        _source(),
    )

    assert {item.operation_kind for item in openapi.operations} == {OperationKind.REST}
    assert {item.operation_kind for item in graphql.operations} == {
        OperationKind.GRAPHQL_QUERY,
        OperationKind.GRAPHQL_MUTATION,
        OperationKind.GRAPHQL_SUBSCRIPTION,
    }
    assert openapi.evidence.source_kind == "openapi"
    assert graphql.evidence.source_kind == "graphql"
    assert all(item.schema_version == SCHEMA_VERSION for item in graphql.operations)


def test_observed_undocumented_operation_creates_a_drift_hypothesis() -> None:
    from faultloom.api_async.schema import undocumented_batch

    item = operation("operation.hidden", OperationKind.REST, "/v1/hidden")
    batch = undocumented_batch(
        UndocumentedObservation(
            operation=item,
            source_kind="traffic",
            source_digest=D1,
            observed_at=NOW,
        )
    )

    assert batch.operations == (item,)
    assert batch.evidence.source_kind == "traffic"
    assert batch.evidence.drift_hypothesis_id is not None


def test_request_job_callback_object_message_and_time_correlations_are_complete() -> None:
    refs = tuple(
        correlation(kind, f"opaque-{kind.value}")
        for kind in CorrelationKind
    )
    flow = AsyncFlow(
        schema_version=SCHEMA_VERSION,
        async_flow_id="async-flow.correlation",
        initiating_operation_id="operation.start",
        operation_ids=("operation.start", "operation.finish"),
        correlation_refs=refs,
        pending=True,
        initiated_at=NOW,
    )

    match = correlate_flow(flow, tuple(reversed(refs)))

    assert match.complete is True
    assert {item.correlation_kind for item in match.matched} == {
        "request_id",
        "job_id",
        "callback_id",
        "object_id",
        "message_id",
        "timestamp",
    }
