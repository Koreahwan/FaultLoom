from __future__ import annotations

import base64

from .contracts import (
    ProviderInvocationResult,
    ProviderOutputIntegrityError,
)

MAX_CURSOR_BYTES = 4096
_INVOCATION_DUMP = ProviderInvocationResult.model_dump
_INVOCATION_VALIDATE = ProviderInvocationResult.model_validate


def b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64decode(value: str) -> bytes:
    if type(value) is not str or not value or "=" in value:
        raise ValueError("invalid cursor segment")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64encode(decoded) != value:
        raise ValueError("noncanonical cursor segment")
    return decoded


def validated_invocation(
    invocation: ProviderInvocationResult,
) -> ProviderInvocationResult:
    if type(invocation) is not ProviderInvocationResult:
        raise ProviderOutputIntegrityError(
            "provider output reader requires an exact invocation result"
        )
    try:
        validated = _INVOCATION_VALIDATE(
            _INVOCATION_DUMP(invocation, mode="python")
        )
    except Exception as exc:
        raise ProviderOutputIntegrityError(
            "provider invocation result integrity failed"
        ) from exc
    return validated


def cursor_document(
    invocation: ProviderInvocationResult,
    *,
    inner_cursor: str,
) -> dict[str, object]:
    output = invocation.output_ref
    observation = output.observation
    return {
        "byte_length": observation.byte_length,
        "cas_digest": observation.cas_digest,
        "engagement_id": output.engagement_id,
        "event_hash": output.event_hash,
        "event_seq": output.event_seq,
        "inner_cursor": inner_cursor,
        "media_type": observation.media_type,
        "observation_id": observation.observation_id,
        "receipt_digest": output.receipt_digest,
        "run_id": observation.run_id,
        "version": 1,
    }
