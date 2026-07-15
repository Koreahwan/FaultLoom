from __future__ import annotations

import hashlib
from dataclasses import dataclass

from pydantic import ValidationError

from faultloom._research_durable import (
    EncryptedEventSpec,
    append_encrypted,
    canonical_model_bytes,
    durable_events,
    load_encrypted,
)
from faultloom.state import EventRecord, StateStore, StorageError
from faultloom_protocol import canonical_json_bytes
from faultloom_protocol.base import AwareDatetime

from .contracts import (
    SurfaceBinding,
    SurfaceConflictError,
    SurfaceIntegrityError,
)
from .state_models import SurfaceSnapshot, SurfaceState, empty_surface_state

BIND_EVENT_TYPE = "api_async.bound.v1"
SNAPSHOT_EVENT_TYPE = "api_async.snapshot.v1"
CONTROL_STREAM = "api_async.control"
STATE_STREAM = "api_async.state"
SNAPSHOT_MEDIA_TYPE = "application/vnd.faultloom.api-async-snapshot+json"


@dataclass(frozen=True, slots=True)
class SurfaceReplay:
    binding: SurfaceBinding | None
    state: SurfaceState | None
    snapshot_digest: str | None


def bind_surface(store: StateStore, binding: SurfaceBinding) -> SurfaceState:
    if binding.engagement_id != store.engagement_id:
        raise SurfaceConflictError("surface binding belongs to another engagement")
    with store.serialized():
        replay = replay_surface(store, binding.run_id)
        if replay.binding is not None:
            if replay.binding != binding:
                raise SurfaceConflictError("surface run is already bound differently")
            return replay.state or empty_surface_state(binding)
        ledger = store.ledger
        if ledger is None:
            raise StorageError("state store is closed")
        ledger.append(
            actor_stream=CONTROL_STREAM,
            event_type=BIND_EVENT_TYPE,
            payload=binding.model_dump(mode="json"),
        )
    return empty_surface_state(binding)


def append_state(
    store: StateStore,
    state: SurfaceState,
    recorded_at: AwareDatetime,
) -> SurfaceState:
    binding = state.binding
    with store.serialized():
        replay = replay_surface(store, binding.run_id)
        current = replay.state or empty_surface_state(binding)
        if replay.binding != binding or state.binding != binding:
            raise SurfaceConflictError("surface state differs from its durable binding")
        if state == current:
            return current
        if state.watermark != current.watermark + 1:
            raise SurfaceConflictError("surface state watermark is not contiguous")
        snapshot = SurfaceSnapshot(
            sequence=state.watermark,
            previous_snapshot_digest=replay.snapshot_digest,
            state=state,
            recorded_at=recorded_at,
        )
        append_encrypted(
            store,
            snapshot,
            _snapshot_spec(binding.run_id, f"snapshot.{state.watermark}"),
        )
    return state


def replay_surface(store: StateStore, run_id: str) -> SurfaceReplay:
    binding: SurfaceBinding | None = None
    state: SurfaceState | None = None
    previous_digest: str | None = None
    for event in durable_events(store):
        if event.event_type == BIND_EVENT_TYPE:
            candidate = _binding_from_event(event)
            if candidate.run_id != run_id:
                continue
            if binding is not None:
                raise SurfaceIntegrityError("surface run has multiple bindings")
            binding = candidate
            continue
        if event.event_type != SNAPSHOT_EVENT_TYPE:
            continue
        snapshot, digest = _snapshot_from_event(store, event)
        if snapshot.state.binding.run_id != run_id:
            continue
        if binding is None or snapshot.state.binding != binding:
            raise SurfaceIntegrityError("surface snapshot has no exact binding")
        expected_sequence = 1 if state is None else state.watermark + 1
        if snapshot.sequence != expected_sequence:
            raise SurfaceIntegrityError("surface snapshot sequence is not contiguous")
        if snapshot.previous_snapshot_digest != previous_digest:
            raise SurfaceIntegrityError("surface snapshot predecessor differs")
        if snapshot.state.watermark != snapshot.sequence:
            raise SurfaceIntegrityError("surface snapshot watermark differs")
        state = snapshot.state
        previous_digest = digest
    return SurfaceReplay(binding=binding, state=state, snapshot_digest=previous_digest)


def _binding_from_event(event: EventRecord) -> SurfaceBinding:
    if event.actor_stream != CONTROL_STREAM:
        raise SurfaceIntegrityError("surface binding actor stream is invalid")
    try:
        return SurfaceBinding.model_validate_json(canonical_json_bytes(event.payload))
    except ValidationError as exc:
        raise SurfaceIntegrityError("surface binding payload is invalid") from exc


def _snapshot_from_event(
    store: StateStore,
    event: EventRecord,
) -> tuple[SurfaceSnapshot, str]:
    raw = load_encrypted(store, event, _snapshot_spec("run", "snapshot"))
    try:
        snapshot = SurfaceSnapshot.model_validate_json(raw)
    except (ValidationError, ValueError, StorageError) as exc:
        raise SurfaceIntegrityError("durable surface snapshot is invalid") from exc
    canonical = canonical_model_bytes(snapshot)
    if canonical != raw:
        raise SurfaceIntegrityError("durable surface snapshot is not canonical")
    return snapshot, f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def _snapshot_spec(run_id: str, record_id: str) -> EncryptedEventSpec:
    return EncryptedEventSpec(
        actor_stream=STATE_STREAM,
        event_type=SNAPSHOT_EVENT_TYPE,
        media_type=SNAPSHOT_MEDIA_TYPE,
        run_id=run_id,
        record_id=record_id,
    )
