from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Annotated, Literal, Self

from faultloom.provider import (
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderProxyResult,
    ProxyOutcome,
)
from faultloom_protocol import ObservationRef, ProtocolModel
from faultloom_protocol.base import Identifier, MAX_INT64, Sha256Digest
from pydantic import Field, ValidationInfo, field_validator, model_validator

from ._errors import (
    ProviderOutputError,
    ProviderOutputIntegrityError,
    ProviderOutputScopeError,
)
from ._immutable import ProviderOutputCursorKey, ProviderOutputPage

SCHEMA_VERSION = "0.1.0"
PositiveSigned64 = Annotated[int, Field(strict=True, ge=1, le=MAX_INT64)]
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_MEDIA_TYPE = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}"
)


class _OutputModel(ProtocolModel):
    schema_version: Literal["0.1.0"] = SCHEMA_VERSION


def _digest_hex(value: str) -> str:
    if type(value) is not str:
        raise TypeError("provider output digest must be an exact string")
    match = _DIGEST.fullmatch(value)
    if match is None:
        raise ValueError("provider output digest is not canonical SHA-256")
    return match.group(1)


def provider_observation_id(receipt_digest: str) -> str:
    return f"provider-output-{_digest_hex(receipt_digest)}"


def provider_output_actor_stream(run_id: str, receipt_digest: str) -> str:
    if type(run_id) is not str or not run_id:
        raise ValueError("provider output run ID must be an exact non-empty string")
    receipt_hex = _digest_hex(receipt_digest)
    binding = hashlib.sha256(
        b"faultloom.provider-output.actor.v1\0"
        + run_id.encode("utf-8")
        + b"\0"
        + receipt_hex.encode("ascii")
    ).hexdigest()
    return f"provider-output:{binding}"


def require_media_type(value: str) -> str:
    if type(value) is not str or _MEDIA_TYPE.fullmatch(value) is None:
        raise ValueError("provider output media type is not canonical")
    return value


def _exact_raw_string(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"provider output {label} is not an exact canonical string")
    return value


def _strict_observation_input(value: object) -> object:
    if type(value) is ObservationRef:
        observation_values: dict[str, object] = {
            "observation_id": value.observation_id,
            "run_id": value.run_id,
            "cas_digest": value.cas_digest,
            "media_type": value.media_type,
        }
    elif type(value) is dict:
        observation_values = value
    else:
        raise ValueError("provider output observation must be an exact mapping")
    _exact_raw_string(observation_values.get("observation_id"), "observation ID")
    _exact_raw_string(observation_values.get("run_id"), "run ID")
    _digest_hex(_exact_raw_string(observation_values.get("cas_digest"), "CAS digest"))
    require_media_type(
        _exact_raw_string(observation_values.get("media_type"), "media type")
    )
    return value


class ProviderOutputRef(_OutputModel):
    engagement_id: Identifier
    receipt_digest: Sha256Digest
    event_seq: PositiveSigned64
    event_hash: Sha256Digest
    observation: ObservationRef

    @field_validator(
        "engagement_id",
        "receipt_digest",
        "event_hash",
        mode="before",
    )
    @classmethod
    def _raw_identity_is_exact(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> str:
        field_name = info.field_name
        if field_name is None:
            raise ValueError("provider output identity field is unavailable")
        label = {
            "engagement_id": "engagement ID",
            "receipt_digest": "receipt digest",
            "event_hash": "event hash",
        }.get(field_name, "identity")
        exact = _exact_raw_string(value, label)
        if field_name != "engagement_id":
            _digest_hex(exact)
        return exact

    @field_validator("observation", mode="before")
    @classmethod
    def _raw_observation_is_exact(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        exact = _strict_observation_input(value)
        if info.mode == "json" and type(exact) is dict:
            return ObservationRef.model_validate_json(
                json.dumps(exact, separators=(",", ":"))
            )
        return exact

    @model_validator(mode="after")
    def _canonical_identity(self) -> Self:
        if self.observation.observation_id != provider_observation_id(
            self.receipt_digest
        ):
            raise ValueError("provider output observation ID is not receipt-bound")
        if self.observation.cursor is not None:
            raise ValueError("provider output references cannot accept a transport cursor")
        require_media_type(self.observation.media_type)
        return self


class ProviderInvocationResult(_OutputModel):
    receipt: ProviderCallReceipt
    output_ref: ProviderOutputRef

    @model_validator(mode="after")
    def _receipt_output_chain(self) -> Self:
        receipt = self.receipt
        output = self.output_ref
        observation = output.observation
        result = receipt.proxy_result
        if type(receipt) is not ProviderCallReceipt:
            raise ValueError("provider invocation requires an exact receipt")
        if (
            receipt.outcome is not ProviderCallOutcome.COMPLETED
            or type(result) is not ProviderProxyResult
            or result.outcome is not ProxyOutcome.COMPLETED
            or receipt.response_digest is None
        ):
            raise ValueError("provider invocation requires a completed response")
        if (
            not hmac.compare_digest(output.receipt_digest, receipt.receipt_digest)
            or observation.run_id != receipt.run_id
            or not hmac.compare_digest(
                observation.cas_digest,
                receipt.response_digest,
            )
            or observation.byte_length != receipt.bytes_received
        ):
            raise ValueError("provider output is not bound to its receipt")
        return self


__all__ = [
    "ProviderInvocationResult",
    "ProviderOutputCursorKey",
    "ProviderOutputError",
    "ProviderOutputIntegrityError",
    "ProviderOutputPage",
    "ProviderOutputRef",
    "ProviderOutputScopeError",
]
