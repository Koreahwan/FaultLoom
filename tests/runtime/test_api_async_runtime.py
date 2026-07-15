from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from faultloom.api_async import (
    ApiAsyncSurfaceEngine,
    CorrelationKind,
    FlowCompletion,
    FlowStart,
    FollowUpAction,
    FollowUpKind,
    InertFileCanary,
    JobAccessProbe,
    SchemaSource,
    SequenceMutation,
    SequencePlanRequest,
    SessionState,
    SurfaceDifferential,
)
from faultloom_protocol import (
    AsyncFlow,
    FilePipeline,
    FileStage,
    JobObservation,
    MessageEnvelope,
    OperationKind,
    SCHEMA_VERSION,
)
from tests.protocol.factories import D1, D2, D3, D4, NOW
from tests.runtime.api_async_support import (
    binding,
    callback_lease,
    correlation,
    observe_operation,
    operation,
)
from tests.runtime.resume_support import open_store


def _openapi_source() -> SchemaSource:
    return SchemaSource(
        target_id="target.loopback.api_async",
        schema_namespace="faultloom.test.api_async.v1",
        observed_at=NOW,
    )


def _add_async_operations(engine: ApiAsyncSurfaceEngine) -> tuple[str, str, str, str]:
    items = (
        operation("operation.ws", OperationKind.WEBSOCKET, "/v1/ws"),
        operation("operation.callback", OperationKind.WEBHOOK, "/v1/callback"),
        operation("operation.job", OperationKind.BACKGROUND_JOB, "/v1/jobs/{id}"),
        operation("operation.file", OperationKind.FILE_DOWNLOAD, "/v1/files/{id}"),
    )
    for item in items:
        observe_operation(engine, item)
    return tuple(item.operation_id for item in items)


def test_api_async_run_correlates_all_surfaces_and_is_idempotent(tmp_path: Path) -> None:
    with open_store(tmp_path) as store:
        engine = ApiAsyncSurfaceEngine.open(store, binding())
        rest = engine.ingest_openapi(
            b'{"openapi":"3.1.0","paths":{"/v1/start":{"post":{}}}}',
            _openapi_source(),
        ).operations[0]
        engine.ingest_graphql(
            b"type Query { job(id: ID!): Job }",
            _openapi_source(),
        )
        ws_id, callback_id, job_id, file_id = _add_async_operations(engine)
        lease = callback_lease()
        engine.issue_callback_lease(lease)
        request_ref = correlation(CorrelationKind.REQUEST_ID, "request-1")
        job_ref = correlation(CorrelationKind.JOB_ID, "job-1")
        flow = AsyncFlow(
            schema_version=SCHEMA_VERSION,
            async_flow_id="async-flow.api-async",
            initiating_operation_id=rest.operation_id,
            operation_ids=(rest.operation_id, job_id, callback_id),
            correlation_refs=(request_ref, job_ref),
            pending=True,
            initiated_at=NOW,
        )
        engine.begin_flow(
            FlowStart(
                flow=flow,
                follow_ups=(
                    FollowUpAction(
                        follow_up_id="follow-up.poll",
                        async_flow_id=flow.async_flow_id,
                        operation_id=job_id,
                        kind=FollowUpKind.POLL,
                    ),
                    FollowUpAction(
                        follow_up_id="follow-up.callback",
                        async_flow_id=flow.async_flow_id,
                        operation_id=callback_id,
                        kind=FollowUpKind.CALLBACK,
                        callback_lease_id=lease.callback_lease_id,
                    ),
                ),
            )
        )
        engine.observe_message(
            MessageEnvelope(
                schema_version=SCHEMA_VERSION,
                message_id="message.job-updated",
                channel_id=ws_id,
                direction="server_to_client",
                message_type="job.updated",
                payload_digest=D1,
                correlation_refs=(job_ref,),
                observed_at=NOW + timedelta(seconds=1),
            )
        )
        engine.observe_job(
            JobAccessProbe(
                observation=JobObservation(
                    schema_version=SCHEMA_VERSION,
                    job_observation_id="job-observation.1",
                    async_flow_id=flow.async_flow_id,
                    job_id_digest=D2,
                    identity_context_id="identity.owner",
                    status="complete",
                    evidence_refs=(),
                    observed_at=NOW + timedelta(seconds=2),
                ),
                owner_identity_context_id="identity.owner",
                owner_tenant_id="tenant.alpha",
                requester_identity_context_id="identity.owner",
                requester_tenant_id="tenant.alpha",
                session_state=SessionState.ACTIVE,
                server_allowed=True,
            )
        )
        engine.observe_file_pipeline(
            InertFileCanary(
                canary_id="canary.file.1",
                filename="canary.txt",
                media_type="text/plain",
                artifact_digest=D3,
                path_digest=D1,
                metadata_digest=D2,
                tenant_id="tenant.alpha",
            ),
            FilePipeline(
                schema_version=SCHEMA_VERSION,
                file_pipeline_id="file-pipeline.1",
                run_id="run.api-async",
                canary_id="canary.file.1",
                media_type="text/plain",
                stages=(
                    FileStage(
                        schema_version=SCHEMA_VERSION,
                        stage_id="file-stage.upload",
                        stage_kind="upload",
                        operation_id=file_id,
                        artifact_digest=D3,
                        tenant_id="tenant.alpha",
                        observed_at=NOW + timedelta(seconds=3),
                    ),
                ),
                correlation_refs=(request_ref,),
                evidence_refs=(),
            ),
        )
        engine.plan_sequence(
            SequencePlanRequest(
                plan_id="sequence-plan.1",
                operation_ids=(rest.operation_id, job_id),
                created_at=NOW + timedelta(seconds=4),
            )
        )
        engine.observe_differential(
            SurfaceDifferential(
                differential_id="differential.api-async.1",
                operation_id=job_id,
                baseline_identity_context_id="identity.owner",
                comparison_identity_context_id="identity.outsider",
                baseline_tenant_id="tenant.alpha",
                comparison_tenant_id="tenant.beta",
                baseline_effect_digest=D3,
                comparison_effect_digest=D4,
                comparison_authorized=False,
                observed_at=NOW + timedelta(seconds=5),
            )
        )
        completion = FlowCompletion(
            async_flow_id=flow.async_flow_id,
            terminal_operation_id=callback_id,
            completed_at=NOW + timedelta(seconds=6),
            effect_id="effect.callback.1",
        )
        engine.finish_flow(completion)
        assert store.ledger is not None
        event_count = len(store.ledger.events())
        engine.finish_flow(completion)

        state = engine.state
        assert {
            item.operation_kind for item in state.graph.operations
        }.issuperset(
            {
                OperationKind.REST,
                OperationKind.GRAPHQL_QUERY,
                OperationKind.WEBSOCKET,
                OperationKind.WEBHOOK,
                OperationKind.BACKGROUND_JOB,
                OperationKind.FILE_DOWNLOAD,
            }
        )
        assert len(store.ledger.events()) == event_count
        assert state.completed_effect_ids == ("effect.callback.1",)
        assert len(state.messages) == 1
        assert len(state.job_assessments) == 1
        assert len(state.file_pipelines) == 1
        assert len(state.sequence_plans[0].variants) == 4
        assert {item.mutation for item in state.sequence_plans[0].variants} == set(
            SequenceMutation
        )
        assert len(state.differentials) == 1
        floor = store.checkpoint()

    with open_store(tmp_path, minimum_anchor=floor) as reopened:
        replayed = ApiAsyncSurfaceEngine.open(reopened, binding()).state
        assert replayed.differentials == state.differentials
        assert replayed.completed_effect_ids == ("effect.callback.1",)


def test_pending_flow_survives_ten_resets_without_duplicate_effects(tmp_path: Path) -> None:
    with open_store(tmp_path) as store:
        engine = ApiAsyncSurfaceEngine.open(store, binding())
        first = operation("operation.start", OperationKind.REST, "/v1/start")
        second = operation("operation.job", OperationKind.BACKGROUND_JOB, "/v1/jobs/{id}")
        observe_operation(engine, first)
        observe_operation(engine, second)
        flow = AsyncFlow(
            schema_version=SCHEMA_VERSION,
            async_flow_id="async-flow.pending",
            initiating_operation_id=first.operation_id,
            operation_ids=(first.operation_id, second.operation_id),
            correlation_refs=(correlation(CorrelationKind.JOB_ID, "pending-job"),),
            pending=True,
            initiated_at=NOW,
        )
        engine.begin_flow(FlowStart(flow=flow))
        floor = store.checkpoint()
        expected_watermark = engine.state.watermark

    for _ in range(10):
        with open_store(tmp_path, minimum_anchor=floor) as reopened:
            restored = ApiAsyncSurfaceEngine.open(reopened, binding()).state
            assert restored.graph.async_flows == (flow,)
            assert restored.watermark == expected_watermark
            assert restored.completed_effect_ids == ()
            assert reopened.ledger is not None
            assert len(reopened.ledger.events()) == 4
