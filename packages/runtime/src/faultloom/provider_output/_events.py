from __future__ import annotations

import datetime as dt
import hmac
import json
from typing import Protocol

from faultloom.provider import ProviderCallReceipt
from faultloom.state import ArtifactRef, EventRecord, RetrievalPage
from faultloom_protocol import ObservationRef, canonical_json

from .contracts import (
    ProviderInvocationResult,
    ProviderOutputIntegrityError,
    ProviderOutputRef,
    provider_observation_id,
    provider_output_actor_stream,
)

EVENT_TYPE = "provider-output-published"
METADATA_MEDIA_TYPE = "application/vnd.faultloom.observation-metadata+json"
METADATA_LIMIT = 4096


class _StoreBinding(Protocol):
    @property
    def engagement_id(self) -> str: ...

    def verify(self) -> None: ...

    def references(self) -> tuple[ArtifactRef, ...]: ...

    def read_page(
        self,
        reference: ArtifactRef,
        *,
        cursor: str | None,
        max_bytes: int,
    ) -> RetrievalPage: ...

    def verify_artifact(self, reference: ArtifactRef) -> None: ...


def _mapping(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ProviderOutputIntegrityError(f"provider output {label} is invalid")
    return value


def _artifact(value: object, *, label: str) -> ArtifactRef:
    document = _mapping(value, label=label)
    if set(document) != {
        "byte_length",
        "engagement_id",
        "media_type",
        "schema_version",
        "sha256",
    }:
        raise ProviderOutputIntegrityError(
            f"provider output {label} is invalid"
        )
    byte_length = document["byte_length"]
    engagement_id = document["engagement_id"]
    media_type = document["media_type"]
    schema_version = document["schema_version"]
    digest = document["sha256"]
    if (
        type(byte_length) is not int
        or type(engagement_id) is not str
        or type(media_type) is not str
        or type(schema_version) is not int
        or type(digest) is not str
    ):
        raise ProviderOutputIntegrityError(
            f"provider output {label} is invalid"
        )
    try:
        reference = ArtifactRef(
            engagement_id=engagement_id,
            sha256=digest,
            byte_length=byte_length,
            media_type=media_type,
            schema_version=schema_version,
        )
    except Exception as exc:
        raise ProviderOutputIntegrityError(
            f"provider output {label} is invalid"
        ) from exc
    if type(reference) is not ArtifactRef:
        raise ProviderOutputIntegrityError(f"provider output {label} is invalid")
    return reference


def expected_metadata(
    receipt: ProviderCallReceipt,
    *,
    engagement_id: str,
    media_type: str,
) -> dict[str, object]:
    return {
        "attempt_id": receipt.attempt_id,
        "byte_length": receipt.bytes_received,
        "call_id": receipt.call_id,
        "engagement_id": engagement_id,
        "media_type": media_type,
        "provider_id": receipt.provider_id,
        "proxy_receipt_digest": receipt.proxy_receipt_digest,
        "purpose": "faultloom.provider-output.v1",
        "receipt_digest": receipt.receipt_digest,
        "response_digest": receipt.response_digest,
        "run_id": receipt.run_id,
    }


def event_artifacts(event: EventRecord) -> tuple[ArtifactRef, ArtifactRef]:
    if type(event.payload) is not dict or set(event.payload) != {
        "artifact_ref",
        "metadata_ref",
        "metadata_schema_version",
    } or event.payload["metadata_schema_version"] != 1:
        raise ProviderOutputIntegrityError("provider output event payload is invalid")
    return (
        _artifact(event.payload["artifact_ref"], label="artifact reference"),
        _artifact(event.payload["metadata_ref"], label="metadata reference"),
    )


def read_metadata(
    binding: _StoreBinding,
    reference: ArtifactRef,
) -> dict[str, object]:
    if reference.media_type != METADATA_MEDIA_TYPE:
        raise ProviderOutputIntegrityError("provider output metadata type is invalid")
    page = binding.read_page(reference, cursor=None, max_bytes=METADATA_LIMIT)
    if (
        page.offset != 0
        or page.next_cursor is not None
        or page.total_bytes != len(page.data)
        or page.total_bytes > METADATA_LIMIT
    ):
        raise ProviderOutputIntegrityError("provider output metadata is oversized")
    try:
        document = json.loads(page.data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderOutputIntegrityError("provider output metadata is invalid") from exc
    values = _mapping(document, label="metadata")
    if set(values) != {"schema_version", "values"} or values["schema_version"] != 1:
        raise ProviderOutputIntegrityError("provider output metadata is invalid")
    if canonical_json(values).encode("utf-8") != page.data:
        raise ProviderOutputIntegrityError("provider output metadata is not canonical")
    return _mapping(values["values"], label="metadata values")


def event_created_at(event: EventRecord) -> dt.datetime:
    try:
        value = dt.datetime.fromisoformat(event.created_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProviderOutputIntegrityError(
            "provider output event timestamp is invalid"
        ) from exc
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProviderOutputIntegrityError("provider output event timestamp is invalid")
    return value


def invocation_from_event(
    binding: _StoreBinding,
    receipt: ProviderCallReceipt,
    event: EventRecord,
    *,
    media_type: str,
) -> ProviderInvocationResult:
    binding.verify()
    if (
        type(event) is not EventRecord
        or event.engagement_id != binding.engagement_id
        or event.event_type != EVENT_TYPE
        or event.actor_stream
        != provider_output_actor_stream(receipt.run_id, receipt.receipt_digest)
    ):
        raise ProviderOutputIntegrityError("provider output event identity is invalid")
    reference, metadata_reference = event_artifacts(event)
    registered = binding.references()
    if reference not in registered or metadata_reference not in registered:
        raise ProviderOutputIntegrityError(
            "provider output event artifacts are not registered"
        )
    expected = expected_metadata(
        receipt,
        engagement_id=binding.engagement_id,
        media_type=media_type,
    )
    if read_metadata(binding, metadata_reference) != expected:
        raise ProviderOutputIntegrityError(
            "provider output encrypted metadata does not match its receipt"
        )
    response_digest = receipt.response_digest
    if (
        type(response_digest) is not str
        or reference.engagement_id != binding.engagement_id
        or reference.media_type != media_type
        or reference.byte_length != receipt.bytes_received
        or not hmac.compare_digest(
            f"sha256:{reference.sha256}",
            response_digest,
        )
    ):
        raise ProviderOutputIntegrityError(
            "provider output artifact does not match its receipt"
        )
    binding.verify_artifact(reference)
    observation = ObservationRef(
        schema_version="0.1.0",
        observation_id=provider_observation_id(receipt.receipt_digest),
        run_id=receipt.run_id,
        cas_digest=f"sha256:{reference.sha256}",
        media_type=reference.media_type,
        byte_length=reference.byte_length,
        cursor=None,
        created_at=event_created_at(event),
    )
    output_ref = ProviderOutputRef(
        engagement_id=binding.engagement_id,
        receipt_digest=receipt.receipt_digest,
        event_seq=event.seq,
        event_hash=f"sha256:{event.event_hash}",
        observation=observation,
    )
    return ProviderInvocationResult(receipt=receipt, output_ref=output_ref)
