from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from faultloom.api_async import (
    ApiAsyncSurfaceEngine,
    FlowStart,
    FollowUpAction,
    FollowUpKind,
    InertFileCanary,
    JobAccessProbe,
    ScopeRevocation,
    SessionState,
    SurfacePolicyError,
)
from faultloom_protocol import (
    AsyncFlow,
    FilePipeline,
    FileStage,
    JobObservation,
    OperationKind,
    SCHEMA_VERSION,
)
from tests.protocol.factories import D1, D2, D3, NOW
from tests.runtime.api_async_support import (
    binding,
    callback_lease,
    observe_operation,
    operation,
)
from tests.runtime.resume_support import open_store


def test_callback_is_engagement_bound_and_scope_revoke_cancels_all_followups(
    tmp_path: Path,
) -> None:
    with open_store(tmp_path) as store:
        engine = ApiAsyncSurfaceEngine.open(store, binding())
        callback = operation("operation.callback", OperationKind.WEBHOOK, "/callback")
        job = operation("operation.job", OperationKind.BACKGROUND_JOB, "/jobs/{id}")
        websocket = operation("operation.ws", OperationKind.WEBSOCKET, "/ws")
        for item in (callback, job, websocket):
            observe_operation(engine, item)
        with pytest.raises(SurfacePolicyError):
            engine.issue_callback_lease(callback_lease(engagement_id="engagement.other"))
        lease = callback_lease()
        engine.issue_callback_lease(lease)
        with pytest.raises(SurfacePolicyError):
            engine.admit_callback(lease.callback_lease_id, lease.expires_at)
        flow = AsyncFlow(
            schema_version=SCHEMA_VERSION,
            async_flow_id="async-flow.followups",
            initiating_operation_id=job.operation_id,
            operation_ids=(job.operation_id, callback.operation_id, websocket.operation_id),
            correlation_refs=(),
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
                        operation_id=job.operation_id,
                        kind=FollowUpKind.POLL,
                    ),
                    FollowUpAction(
                        follow_up_id="follow-up.websocket",
                        async_flow_id=flow.async_flow_id,
                        operation_id=websocket.operation_id,
                        kind=FollowUpKind.WEBSOCKET,
                    ),
                    FollowUpAction(
                        follow_up_id="follow-up.callback",
                        async_flow_id=flow.async_flow_id,
                        operation_id=callback.operation_id,
                        kind=FollowUpKind.CALLBACK,
                        callback_lease_id=lease.callback_lease_id,
                    ),
                ),
            )
        )
        assert len(engine.eligible_follow_ups(NOW + timedelta(seconds=1))) == 3

        engine.revoke(ScopeRevocation(scope_epoch=7, revoked_at=NOW + timedelta(seconds=2)))

        assert engine.eligible_follow_ups(NOW + timedelta(seconds=3)) == ()
        with pytest.raises(SurfacePolicyError):
            engine.admit_callback(lease.callback_lease_id, NOW + timedelta(seconds=3))


def test_job_stale_authorization_is_detected_and_executable_files_are_rejected(
    tmp_path: Path,
) -> None:
    with open_store(tmp_path) as store:
        engine = ApiAsyncSurfaceEngine.open(store, binding())
        file_operation = operation(
            "operation.file-upload", OperationKind.FILE_UPLOAD, "/files"
        )
        observe_operation(engine, file_operation)
        engine.observe_job(
            JobAccessProbe(
                observation=JobObservation(
                    schema_version=SCHEMA_VERSION,
                    job_observation_id="job-observation.stale",
                    async_flow_id="async-flow.stale",
                    job_id_digest=D1,
                    identity_context_id="identity.outsider",
                    status="complete",
                    evidence_refs=(),
                    observed_at=NOW,
                ),
                owner_identity_context_id="identity.owner",
                owner_tenant_id="tenant.alpha",
                requester_identity_context_id="identity.outsider",
                requester_tenant_id="tenant.beta",
                session_state=SessionState.STALE,
                server_allowed=True,
            )
        )
        unsafe_canary = InertFileCanary(
            canary_id="canary.unsafe",
            filename="payload.exe",
            media_type="application/octet-stream",
            artifact_digest=D3,
            path_digest=D1,
            metadata_digest=D2,
            tenant_id="tenant.alpha",
        )
        pipeline = FilePipeline(
            schema_version=SCHEMA_VERSION,
            file_pipeline_id="file-pipeline.unsafe",
            run_id="run.api-async",
            canary_id="canary.unsafe",
            media_type="application/octet-stream",
            stages=(
                FileStage(
                    schema_version=SCHEMA_VERSION,
                    stage_id="file-stage.unsafe",
                    stage_kind="upload",
                    operation_id=file_operation.operation_id,
                    artifact_digest=D3,
                    tenant_id="tenant.alpha",
                    observed_at=NOW,
                ),
            ),
            correlation_refs=(),
            evidence_refs=(),
        )

        assert engine.state.job_assessments[0].authorization_mismatch is True
        with pytest.raises(SurfacePolicyError):
            engine.observe_file_pipeline(unsafe_canary, pipeline)
