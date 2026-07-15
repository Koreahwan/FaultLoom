from __future__ import annotations

import hashlib
from datetime import timedelta

from faultloom.api_async import (
    ApiAsyncSurfaceEngine,
    CorrelationKind,
    OpaqueCorrelation,
    SurfaceBinding,
    UndocumentedObservation,
    correlation_ref,
)
from faultloom_protocol import (
    CallbackLease,
    CorrelationRef,
    OperationKind,
    OperationRef,
    SCHEMA_VERSION,
    SecretRef,
)
from tests.protocol.factories import D1, NOW


def binding(*, engagement_id: str = "engagement.1") -> SurfaceBinding:
    return SurfaceBinding(
        engagement_id=engagement_id,
        run_id="run.api-async",
        target_id="target.loopback.api_async",
        graph_id="surface-graph.api-async",
        grant_id="grant.api-async",
        scope_epoch=7,
        owned_callback_domains=("callbacks.loopback.test",),
    )


def operation(
    operation_id: str,
    kind: OperationKind,
    path: str,
) -> OperationRef:
    return OperationRef(
        schema_version=SCHEMA_VERSION,
        operation_id=operation_id,
        target_id="target.loopback.api_async",
        operation_kind=kind,
        method="POST",
        path=path,
        schema_namespace="faultloom.test.api_async.v1",
        documented=False,
    )


def observe_operation(
    engine: ApiAsyncSurfaceEngine,
    item: OperationRef,
) -> None:
    source_digest = f"sha256:{hashlib.sha256(item.operation_id.encode()).hexdigest()}"
    engine.observe_undocumented(
        UndocumentedObservation(
            operation=item,
            source_kind="traffic",
            source_digest=source_digest,
            observed_at=NOW,
        )
    )


def correlation(kind: CorrelationKind, value: str) -> CorrelationRef:
    return correlation_ref(OpaqueCorrelation(kind=kind, value=value.encode()))


def callback_lease(*, engagement_id: str = "engagement.1") -> CallbackLease:
    return CallbackLease(
        schema_version=SCHEMA_VERSION,
        callback_lease_id="callback-lease.api-async",
        engagement_id=engagement_id,
        grant_id="grant.api-async",
        scope_epoch=7,
        owned_domain="callbacks.loopback.test",
        callback_path_digest=D1,
        callback_token_ref=SecretRef(
            schema_version=SCHEMA_VERSION,
            uri="secret://callback/api-async",
            purpose="owned callback token",
        ),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )
