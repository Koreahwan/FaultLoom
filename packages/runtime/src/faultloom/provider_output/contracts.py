from __future__ import annotations

import hashlib
import hmac
import re
from typing import Annotated, Literal, NoReturn, Self, final

from faultloom.provider import (
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderProxyResult,
    ProxyOutcome,
)
from faultloom_protocol import ObservationRef, ProtocolModel
from faultloom_protocol.base import Identifier, MAX_INT64, Sha256Digest
from pydantic import Field, model_validator

SCHEMA_VERSION = "0.1.0"
PositiveSigned64 = Annotated[int, Field(strict=True, ge=1, le=MAX_INT64)]
_DIGEST = re.compile(r"sha256:([0-9a-f]{64})")
_MEDIA_TYPE = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}"
)


class ProviderOutputError(RuntimeError):
    pass


class ProviderOutputIntegrityError(ProviderOutputError):
    pass


class ProviderOutputScopeError(ProviderOutputError):
    pass


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


class ProviderOutputRef(_OutputModel):
    engagement_id: Identifier
    receipt_digest: Sha256Digest
    event_seq: PositiveSigned64
    event_hash: Sha256Digest
    observation: ObservationRef

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


@final
class ProviderOutputCursorKey:
    __slots__ = ("__material",)

    def __init__(self, material: bytes) -> None:
        if type(material) is not bytes or len(material) != 32:
            raise ValueError("provider output cursor key must be exactly 32 bytes")
        self.__material = material

    def _copy_for_hmac(self) -> bytes:
        return bytes(self.__material)

    def __repr__(self) -> str:
        return "ProviderOutputCursorKey(<redacted>)"

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderOutputCursorKey cannot be serialized")


@final
class ProviderOutputPage:
    __slots__ = ("__data", "offset", "total_bytes", "next_cursor")

    def __init__(
        self,
        data: bytes,
        *,
        offset: int,
        total_bytes: int,
        next_cursor: str | None,
    ) -> None:
        if type(data) is not bytes:
            raise TypeError("provider output page data must be exact bytes")
        if (
            type(offset) is not int
            or type(total_bytes) is not int
            or offset < 0
            or total_bytes < 0
            or offset + len(data) > total_bytes
        ):
            raise ValueError("provider output page bounds are invalid")
        if next_cursor is not None and (
            type(next_cursor) is not str or not next_cursor
        ):
            raise ValueError("provider output continuation cursor is invalid")
        self.__data = data
        self.offset = offset
        self.total_bytes = total_bytes
        self.next_cursor = next_cursor

    @property
    def data(self) -> bytes:
        return bytes(self.__data)

    def __repr__(self) -> str:
        return (
            "ProviderOutputPage(data=<redacted>, "
            f"offset={self.offset}, total_bytes={self.total_bytes}, "
            f"has_next={self.next_cursor is not None})"
        )

    def __reduce__(self) -> NoReturn:
        raise TypeError("ProviderOutputPage cannot be serialized")


__all__ = [
    "ProviderInvocationResult",
    "ProviderOutputCursorKey",
    "ProviderOutputError",
    "ProviderOutputIntegrityError",
    "ProviderOutputPage",
    "ProviderOutputRef",
    "ProviderOutputScopeError",
]
