from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import faultloom_protocol.models as m
from faultloom.execution import (
    BrowserChildCandidate,
    EndpointScheme,
    ExecutionIdentity,
    GatewayCancellationReceipt,
    GatewayCancellationRequest,
    GatewayDeniedResult,
    GatewayDispatchCommand,
    GatewayDispatchFrame,
    GatewayDispatchResult,
    GatewayResponseEnvelope,
    GatewayResult,
    SemanticEndpoint,
    SemanticHttpObservation,
    SemanticHttpRequest,
    bind_gateway_cancellation,
    bind_gateway_response,
    canonical_dispatch_receipt_id,
    gateway_frame_digest,
    semantic_payload_digest,
)
from faultloom_protocol import SCHEMA_VERSION, sha256_digest

NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
D1 = "sha256:" + "11" * 32
D2 = "sha256:" + "22" * 32
CHANNEL_KEY = bytes.fromhex("ab" * 32)


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
    if request is None:
        request = semantic_request()
    if identity is None:
        identity = execution_identity()
    subject = m.SubjectRef(
        schema_version=SCHEMA_VERSION,
        subject_id=f"subject.{action_id}",
        subject_kind="human",
        identity_id=identity.identity_id,
        tenant_id=identity.tenant_id,
    )
    resource = m.ResourceRef(
        schema_version=SCHEMA_VERSION,
        resource_id=f"resource.{action_id}",
        resource_kind="http_endpoint",
        target_id="target.loopback",
        tenant_id=identity.tenant_id,
    )
    intent = m.ActionIntent(
        schema_version=SCHEMA_VERSION,
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
    reservation = m.BudgetReservation(
        schema_version=SCHEMA_VERSION,
        request_bytes=8192,
        response_bytes=8192,
        duration_seconds=10,
    )
    lease = m.ActionLease(
        schema_version=SCHEMA_VERSION,
        lease_id=lease_id,
        intent_digest=sha256_digest(intent),
        grant_id="grant.1",
        grant_version=3,
        scope_epoch=7,
        issued_at=lease_issued_at,
        expires_at=lease_expires_at or NOW + timedelta(minutes=1),
        reservation=reservation,
    )
    decision = m.PolicyDecision(
        schema_version=SCHEMA_VERSION,
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
    child_candidates: tuple[BrowserChildCandidate, ...] = (),
    bytes_sent: int = 128,
    bytes_received: int = 256,
) -> GatewayDispatchResult:
    provisional_receipt = m.DispatchReceipt(
        schema_version=SCHEMA_VERSION,
        receipt_id="receipt.pending",
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
    receipt_values = provisional_receipt.model_dump(mode="python")
    receipt_values["receipt_id"] = canonical_dispatch_receipt_id(provisional_receipt)
    receipt = m.DispatchReceipt.model_validate(receipt_values)
    response_ref = m.ObservationRef(
        schema_version=SCHEMA_VERSION,
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
    def __init__(
        self,
        handler: Callable[[GatewayDispatchCommand], GatewayResult],
        *,
        reconciler: Callable[[GatewayDispatchCommand], GatewayResult | None] | None = None,
    ) -> None:
        self.calls: list[GatewayDispatchFrame] = []
        self.cancel_calls: list[GatewayCancellationRequest] = []
        self.reconcile_calls: list[GatewayDispatchFrame] = []
        self._handler = handler
        self._reconciler = reconciler
        self._cancelled_generations: set[tuple[str, int]] = set()

    def dispatch(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope:
        owner = (frame.command.identity.context_id, frame.context_generation)
        if owner in self._cancelled_generations:
            denied = GatewayDeniedResult(
                schema_version=SCHEMA_VERSION,
                action_id=frame.command.intent.action_id,
                request_digest=gateway_frame_digest(frame),
                reason_code="scope.revoked",
            )
            return bind_gateway_response(frame, denied, CHANNEL_KEY)
        self.calls.append(frame)
        return bind_gateway_response(frame, self._handler(frame.command), CHANNEL_KEY)

    def cancel_context(
        self,
        request: GatewayCancellationRequest,
    ) -> GatewayCancellationReceipt:
        self.cancel_calls.append(request)
        self._cancelled_generations.add((request.context_id, request.context_generation))
        return bind_gateway_cancellation(request, (), CHANNEL_KEY)

    def reconcile(self, frame: GatewayDispatchFrame) -> GatewayResponseEnvelope | None:
        self.reconcile_calls.append(frame)
        if self._reconciler is None:
            return None
        result = self._reconciler(frame.command)
        if result is None:
            return None
        return bind_gateway_response(frame, result, CHANNEL_KEY)
