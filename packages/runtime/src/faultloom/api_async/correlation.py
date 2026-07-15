from __future__ import annotations

import hashlib
from typing import Literal, assert_never

from pydantic import Field

from faultloom_protocol import AsyncFlow, CorrelationRef, SCHEMA_VERSION

from .contracts import (
    CorrelationKind,
    OpaqueCorrelation,
    SurfaceConflictError,
    _SurfaceModel,
)

type CorrelationWireKind = Literal[
    "request_id", "job_id", "callback_id", "object_id", "message_id", "timestamp"
]


class CorrelationMatch(_SurfaceModel):
    async_flow_id: str
    matched: tuple[CorrelationRef, ...] = Field(min_length=1)
    complete: bool


def correlation_ref(value: OpaqueCorrelation) -> CorrelationRef:
    digest = f"sha256:{hashlib.sha256(value.value).hexdigest()}"
    identity = hashlib.sha256(value.kind.value.encode() + b"\0" + value.value).hexdigest()
    return CorrelationRef(
        schema_version=SCHEMA_VERSION,
        correlation_id=f"correlation.{identity}",
        correlation_kind=_wire_kind(value.kind),
        opaque_value_digest=digest,
    )


def correlate_flow(
    flow: AsyncFlow,
    observed: tuple[CorrelationRef, ...],
) -> CorrelationMatch:
    expected = {
        (item.correlation_kind, item.opaque_value_digest): item
        for item in flow.correlation_refs
    }
    matched = tuple(
        expected[key]
        for key in sorted(
            {
                (item.correlation_kind, item.opaque_value_digest)
                for item in observed
            }.intersection(expected)
        )
    )
    if not matched:
        raise SurfaceConflictError("observation has no correlation with the async flow")
    return CorrelationMatch(
        async_flow_id=flow.async_flow_id,
        matched=matched,
        complete=len(matched) == len(expected),
    )


def _wire_kind(kind: CorrelationKind) -> CorrelationWireKind:
    match kind:
        case CorrelationKind.REQUEST_ID:
            return "request_id"
        case CorrelationKind.JOB_ID:
            return "job_id"
        case CorrelationKind.CALLBACK_ID:
            return "callback_id"
        case CorrelationKind.OBJECT_ID:
            return "object_id"
        case CorrelationKind.MESSAGE_ID:
            return "message_id"
        case CorrelationKind.TIMESTAMP:
            return "timestamp"
        case unreachable:
            assert_never(unreachable)
