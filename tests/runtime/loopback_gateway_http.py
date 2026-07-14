from __future__ import annotations

import hashlib
import http.client
from datetime import timedelta
from typing import assert_never

import faultloom_protocol.models as m

from faultloom.execution import (
    EndpointScheme,
    GatewayDispatchFrame,
    GatewayDispatchResult,
    SemanticHttpObservation,
    canonical_dispatch_receipt_id,
)
from faultloom_protocol import SCHEMA_VERSION


def perform_http(frame: GatewayDispatchFrame) -> GatewayDispatchResult:
    command = frame.command
    endpoint = command.request.endpoint
    match endpoint.scheme:
        case EndpointScheme.HTTP:
            pass
        case EndpointScheme.HTTPS | EndpointScheme.WS | EndpointScheme.WSS:
            raise RuntimeError("loopback fixture supports only plain HTTP")
        case unreachable:
            assert_never(unreachable)
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=3)
    try:
        connection.request(command.request.method, endpoint.path)
        response = connection.getresponse()
        body = response.read(command.lease.reservation.response_bytes + 1)
        status = response.status
    finally:
        connection.close()
    if len(body) > command.lease.reservation.response_bytes:
        raise RuntimeError("loopback response exceeded its reservation")
    return _completed_result(frame, status, body)


def _completed_result(
    frame: GatewayDispatchFrame,
    status: int,
    body: bytes,
) -> GatewayDispatchResult:
    command = frame.command
    response_digest = _byte_digest(body)
    request_bytes = f"{command.request.method} {command.request.endpoint.path}".encode()
    completed_at = command.lease.issued_at + timedelta(milliseconds=1)
    provisional = m.DispatchReceipt(
        schema_version=SCHEMA_VERSION,
        receipt_id="receipt.pending",
        lease_id=command.lease.lease_id,
        intent_digest=command.intent_digest,
        decision_digest=command.decision_digest,
        scope_epoch=command.lease.scope_epoch,
        request_digest=_byte_digest(request_bytes),
        response_digest=response_digest,
        outcome=m.DispatchOutcome.COMPLETED,
        dispatched_at=command.lease.issued_at,
        completed_at=completed_at,
        response_status=status,
        bytes_sent=len(request_bytes),
        bytes_received=len(body),
    )
    receipt_values = provisional.model_dump(mode="python")
    receipt_values["receipt_id"] = canonical_dispatch_receipt_id(provisional)
    observation = SemanticHttpObservation(
        schema_version=SCHEMA_VERSION,
        response_ref=m.ObservationRef(
            schema_version=SCHEMA_VERSION,
            observation_id=f"observation.{command.intent.action_id}",
            run_id=command.intent.run_id,
            cas_digest=response_digest,
            media_type="application/octet-stream",
            byte_length=len(body),
            created_at=completed_at,
        ),
    )
    return GatewayDispatchResult(
        schema_version=SCHEMA_VERSION,
        receipt=m.DispatchReceipt.model_validate(receipt_values),
        observation=observation,
    )


def _byte_digest(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"
