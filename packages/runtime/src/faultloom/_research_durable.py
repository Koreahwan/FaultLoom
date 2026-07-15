from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from pydantic import BaseModel

from faultloom.state import ArtifactRef, EventRecord, StateStore, StorageError
from faultloom_protocol import canonical_json_bytes


_PAYLOAD_KEYS = frozenset(
    {"artifact_ref", "metadata_ref", "metadata_schema_version"}
)


@dataclass(frozen=True, slots=True)
class EncryptedEventSpec:
    actor_stream: str
    event_type: str
    media_type: str
    run_id: str
    record_id: str


def canonical_model_bytes(model: BaseModel) -> bytes:
    return canonical_json_bytes(model.model_dump(mode="json", exclude_none=False))


def append_encrypted(
    store: StateStore,
    model: BaseModel,
    spec: EncryptedEventSpec,
) -> EventRecord:
    event, _ = store.append_observation(
        actor_stream=spec.actor_stream,
        event_type=spec.event_type,
        raw_output=canonical_model_bytes(model),
        metadata={"record_id": spec.record_id, "run_id": spec.run_id},
        media_type=spec.media_type,
    )
    return event


def load_encrypted(
    store: StateStore,
    event: EventRecord,
    spec: EncryptedEventSpec,
) -> bytes:
    if event.actor_stream != spec.actor_stream or event.event_type != spec.event_type:
        raise StorageError("durable research event identity is invalid")
    if frozenset(event.payload) != _PAYLOAD_KEYS:
        raise StorageError("durable research event payload shape is invalid")
    value = event.payload.get("artifact_ref")
    if type(value) is not dict:
        raise StorageError("durable research artifact reference is invalid")
    reference = ArtifactRef.from_dict(value)
    if reference.engagement_id != store.engagement_id:
        raise StorageError("durable research artifact belongs to another engagement")
    if reference.media_type != spec.media_type:
        raise StorageError("durable research artifact media type is invalid")
    cas = store.cas
    if cas is None:
        raise StorageError("state store is closed")
    return cas.get(reference)


def durable_events(store: StateStore) -> Iterator[EventRecord]:
    ledger = store.ledger
    if ledger is None:
        raise StorageError("state store is closed")
    after_sequence = 0
    while True:
        page = ledger.events(after_seq=after_sequence, limit=10_000)
        yield from page
        if len(page) < 10_000:
            return
        after_sequence = page[-1].seq
