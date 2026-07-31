"""Atomic encrypted persistence for one validated automation turn."""

from __future__ import annotations

from typing import Self

from pydantic import BaseModel, ConfigDict, model_validator

from faultloom._research_durable import (
    EncryptedEventSpec,
    append_encrypted,
    durable_events,
    load_encrypted,
)
from faultloom.state import EventRecord, StateStore, StorageError
from faultloom_protocol import sha256_digest
from faultloom_protocol.base import Identifier, Sha256Digest

from .models import AuthorizedAutomationResult


AUTOMATION_TURN_ACTOR_STREAM = "automation.authoritative"
AUTOMATION_TURN_EVENT_TYPE = "automation.turn.v1"
AUTOMATION_TURN_MEDIA_TYPE = "application/vnd.faultloom.automation-turn+json"


class AutomationTurnEnvelope(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )

    turn_id: Identifier
    result_digest: Sha256Digest
    result: AuthorizedAutomationResult

    @model_validator(mode="after")
    def _digest_is_exact(self) -> Self:
        if self.result_digest != _result_digest(self.result):
            raise ValueError("automation turn result digest mismatch")
        if self.turn_id != _turn_id(self.result_digest):
            raise ValueError("automation turn ID is not digest-bound")
        return self


def persist_automation_turn(
    store: StateStore,
    result: AuthorizedAutomationResult,
) -> EventRecord:
    """Create or idempotently return one encrypted aggregate turn event."""

    if type(store) is not StateStore:
        raise TypeError("automation persistence requires an exact state store")
    if type(result) is not AuthorizedAutomationResult:
        raise TypeError("automation persistence requires an exact result")
    exact = AuthorizedAutomationResult.model_validate(result.model_dump(mode="python"))
    digest = _result_digest(exact)
    envelope = AutomationTurnEnvelope(
        turn_id=_turn_id(digest),
        result_digest=digest,
        result=exact,
    )
    spec = _spec(exact.run_id, envelope.turn_id)
    with store.serialized():
        for event in durable_events(store):
            if (
                event.actor_stream != AUTOMATION_TURN_ACTOR_STREAM
                or event.event_type != AUTOMATION_TURN_EVENT_TYPE
            ):
                continue
            prior = _load_envelope(store, event, spec)
            if prior.turn_id != envelope.turn_id:
                continue
            if prior != envelope:
                raise StorageError("automation turn ID is bound to different bytes")
            return event
        return append_encrypted(store, envelope, spec)


def load_automation_turn(
    store: StateStore,
    event: EventRecord,
) -> AutomationTurnEnvelope:
    """Load and revalidate one encrypted automation aggregate."""

    if type(store) is not StateStore or type(event) is not EventRecord:
        raise TypeError("automation load requires an exact store and event")
    return _load_envelope(
        store,
        event,
        _spec("placeholder.run", "placeholder.turn"),
    )


def _load_envelope(
    store: StateStore,
    event: EventRecord,
    spec: EncryptedEventSpec,
) -> AutomationTurnEnvelope:
    try:
        return AutomationTurnEnvelope.model_validate_json(
            load_encrypted(store, event, spec)
        )
    except Exception as exc:
        if isinstance(exc, StorageError):
            raise
        raise StorageError("automation turn artifact is invalid") from exc


def _result_digest(result: AuthorizedAutomationResult) -> str:
    return sha256_digest(result.model_dump(mode="json"))


def _turn_id(result_digest: str) -> str:
    return "automation-turn." + result_digest.removeprefix("sha256:")


def _spec(run_id: str, turn_id: str) -> EncryptedEventSpec:
    return EncryptedEventSpec(
        actor_stream=AUTOMATION_TURN_ACTOR_STREAM,
        event_type=AUTOMATION_TURN_EVENT_TYPE,
        media_type=AUTOMATION_TURN_MEDIA_TYPE,
        run_id=run_id,
        record_id=turn_id,
    )


__all__ = [
    "AUTOMATION_TURN_ACTOR_STREAM",
    "AUTOMATION_TURN_EVENT_TYPE",
    "AUTOMATION_TURN_MEDIA_TYPE",
    "AutomationTurnEnvelope",
    "load_automation_turn",
    "persist_automation_turn",
]
