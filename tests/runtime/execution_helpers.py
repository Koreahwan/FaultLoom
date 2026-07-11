from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import faultloom_protocol.models as m
from faultloom.execution import (
    EndpointScheme,
    ExecutionIdentity,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    GatewayResult,
    SemanticEndpoint,
    SemanticHttpObservation,
    SemanticHttpRequest,
    semantic_payload_digest,
)
from faultloom_protocol import SCHEMA_VERSION, sha256_digest

NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
D1 = "sha256:" + "11" * 32
D2 = "sha256:" + "22" * 32


def model(model_type: type[m.ProtocolModel], /, **values: object) -> m.ProtocolModel:
    return model_type(schema_version=SCHEMA_VERSION, **values)


def semantic_request(
    *,
    path: str = "/api/canary",
    hostname: str = "loopback.test",
) -> SemanticHttpRequest:
    endpoint = SemanticEndpoint(
        schema_version=SCHEMA_VERSION,
        scheme=EndpointScheme.HTTPS,
        hostname=hostname,
        port=443,
        path=path,
    )
    return SemanticHttpRequest(
        schema_version=SCHEMA_VERSION,
        endpoint=endpoint,
        method="GET",
    )


def execution_identity(
    *,
    context_id: str = "browser.owner",
    identity_id: str = "identity.owner",
    tenant_id: str = "tenant.alpha",
    session_uri: str = "secret://run/identity-owner",
) -> ExecutionIdentity:
    return ExecutionIdentity(
        schema_version=SCHEMA_VERSION,
        context_id=context_id,
        identity_id=identity_id,
        tenant_id=tenant_id,
        session_ref=m.SecretRef(
            schema_version=SCHEMA_VERSION,
            uri=session_uri,
            purpose="operator-provisioned browser session",
        ),
    )


def command(
    *,
    action_id: str = "action.nav",
    lease_id: str = "lease.nav",
    request: SemanticHttpRequest | None = None,
    identity: ExecutionIdentity | None = None,
    parent_action_ids: tuple[str, ...] = (),
    lease_issued_at: datetime = NOW,
    lease_expires_at: datetime | None = None,
) -> GatewayDispatchCommand:
    request = request or semantic_request()
    identity = identity or execution_identity()
    subject = model(
        m.SubjectRef,
        subject_id=f"subject.{action_id}",
        subject_kind="human",
        identity_id=identity.identity_id,
        tenant_id=identity.tenant_id,
    )
    resource = model(
        m.ResourceRef,
        resource_id=f"resource.{action_id}",
        resource_kind="http_endpoint",
        target_id="target.loopback",
        tenant_id=identity.tenant_id,
    )
    intent = model(
        m.ActionIntent,
        action_id=action_id,
        run_id="run.1",
        target_id="target.loopback",
        pack_id="pack.web",
        action_kind="http.semantic",
        action_class=m.ActionClass.SAFE_PROBE,
        subject=subject,
        resource=resource,
        protocol=request.endpoint.scheme.value,
        method=request.method,
        path=request.endpoint.path,
        payload_digest=semantic_payload_digest(request, identity),
        requested_at=NOW,
        parent_action_ids=parent_action_ids,
    )
    reservation = model(
        m.BudgetReservation,
        request_bytes=8192,
        response_bytes=8192,
        duration_seconds=10,
    )
    lease = model(
        m.ActionLease,
        lease_id=lease_id,
        intent_digest=sha256_digest(intent),
        grant_id="grant.1",
        grant_version=3,
        scope_epoch=7,
        issued_at=lease_issued_at,
        expires_at=lease_expires_at or NOW + timedelta(minutes=1),
        reservation=reservation,
    )
    decision = model(
        m.PolicyDecision,
        decision_id=f"decision.{action_id}",
        intent_digest=sha256_digest(intent),
        grant_id="grant.1",
        grant_version=3,
        scope_epoch=7,
        outcome=m.DecisionOutcome.ALLOW,
        reason_codes=("explicit.allow",),
        evaluated_at=NOW,
        lease_id=lease_id,
    )
    return GatewayDispatchCommand(
        schema_version=SCHEMA_VERSION,
        intent=intent,
        decision=decision,
        lease=lease,
        request=request,
        identity=identity,
    )


def completed_result(
    command: GatewayDispatchCommand,
    *,
    child_candidates: tuple[object, ...] = (),
    bytes_sent: int = 128,
    bytes_received: int = 256,
) -> GatewayDispatchResult:
    receipt = model(
        m.DispatchReceipt,
        receipt_id=f"receipt.{command.intent.action_id}",
        lease_id=command.lease.lease_id,
        intent_digest=command.intent_digest,
        decision_digest=command.decision_digest,
        scope_epoch=command.lease.scope_epoch,
        request_digest=D1,
        response_digest=D2,
        outcome=m.DispatchOutcome.COMPLETED,
        dispatched_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        response_status=200,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
    )
    response_ref = model(
        m.ObservationRef,
        observation_id=f"observation.{command.intent.action_id}",
        run_id=command.intent.run_id,
        cas_digest=D2,
        media_type="application/http",
        byte_length=bytes_received,
        created_at=NOW + timedelta(seconds=1),
    )
    observation = SemanticHttpObservation(
        schema_version=SCHEMA_VERSION,
        response_ref=response_ref,
        child_candidates=child_candidates,
    )
    return GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=receipt,
        observation=observation,
    )


class RecordingGateway:
    def __init__(self, handler: Callable[[GatewayDispatchCommand], GatewayResult]) -> None:
        self.calls: list[GatewayDispatchCommand] = []
        self._handler = handler

    def dispatch(self, dispatch_command: GatewayDispatchCommand) -> GatewayResult:
        self.calls.append(dispatch_command)
        return self._handler(dispatch_command)
