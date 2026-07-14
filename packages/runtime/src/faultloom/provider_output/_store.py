from __future__ import annotations

from collections.abc import Mapping

from faultloom.provider import ProviderCallReceipt
from faultloom.state import (
    ArtifactRef,
    EncryptedCAS,
    EventLedger,
    EventRecord,
    RetrievalPage,
    StateStore,
)
from faultloom.state.anchor import EngagementLock
from .contracts import (
    ProviderOutputIntegrityError,
    provider_output_actor_stream,
)
from ._events import EVENT_TYPE, expected_metadata

_STATE_APPEND = StateStore.append_observation
_STATE_CHECKPOINT = StateStore.checkpoint
_LEDGER_EVENTS = EventLedger.events
_LEDGER_REFERENCES = EventLedger.referenced_artifacts
_LEDGER_VERIFY = EventLedger.verify_chain
_CAS_READ_PAGE = EncryptedCAS.read_page


def _method_is_original(owner: type[object], name: str, expected: object) -> bool:
    namespace = type.__getattribute__(owner, "__dict__")
    return namespace.get(name) is expected


def _instance_values(value: object) -> dict[str, object]:
    namespace = object.__getattribute__(value, "__dict__")
    if type(namespace) is not dict or any(type(key) is not str for key in namespace):
        raise ProviderOutputIntegrityError(
            "provider output capability namespace is invalid"
        )
    return namespace


class ProviderOutputStoreBinding:
    __slots__ = ("_state", "engagement_id", "max_artifact_bytes")

    def __init__(self, state: StateStore) -> None:
        if type(state) is not StateStore:
            raise ProviderOutputIntegrityError(
                "provider output requires the exact T20 StateStore"
            )
        self._state = state
        state_values = _instance_values(state)
        engagement_id = state_values.get("engagement_id")
        if type(engagement_id) is not str or not engagement_id:
            raise ProviderOutputIntegrityError(
                "provider output StateStore identity is invalid"
            )
        self.engagement_id = engagement_id
        cas = state_values.get("cas")
        maximum = (
            _instance_values(cas).get("max_artifact_bytes")
            if type(cas) is EncryptedCAS
            else None
        )
        if type(maximum) is not int or not 1 <= maximum <= 2**31:
            raise ProviderOutputIntegrityError(
                "provider output CAS byte ceiling is invalid"
            )
        self.max_artifact_bytes = maximum
        self.validate()

    def validate(self) -> None:
        state = self._state
        instance_values = _instance_values(state)
        state_engagement_id = instance_values.get("engagement_id")
        exact_methods = (
            (StateStore, "append_observation", _STATE_APPEND),
            (StateStore, "checkpoint", _STATE_CHECKPOINT),
            (EventLedger, "events", _LEDGER_EVENTS),
            (EventLedger, "referenced_artifacts", _LEDGER_REFERENCES),
            (EventLedger, "verify_chain", _LEDGER_VERIFY),
            (EncryptedCAS, "read_page", _CAS_READ_PAGE),
        )
        if any(
            not _method_is_original(owner, name, expected)
            for owner, name, expected in exact_methods
        ) or any(
            name in instance_values
            for name in ("append_observation", "checkpoint")
        ):
            raise ProviderOutputIntegrityError(
                "provider output StateStore capability changed"
            )
        if (
            type(self.engagement_id) is not str
            or type(state_engagement_id) is not str
            or state_engagement_id != self.engagement_id
        ):
            raise ProviderOutputIntegrityError(
                "provider output StateStore identity changed"
            )
        cas = instance_values.get("cas")
        ledger = instance_values.get("ledger")
        lock = instance_values.get("_lock")
        cas_values = (
            _instance_values(cas)
            if type(cas) is EncryptedCAS
            else {}
        )
        ledger_values = (
            _instance_values(ledger)
            if type(ledger) is EventLedger
            else {}
        )
        cas_engagement_id = cas_values.get("engagement_id")
        cas_maximum = cas_values.get("max_artifact_bytes")
        ledger_engagement_id = ledger_values.get("engagement_id")
        if (
            type(cas) is not EncryptedCAS
            or type(ledger) is not EventLedger
            or type(lock) is not EngagementLock
            or type(cas_engagement_id) is not str
            or cas_engagement_id != self.engagement_id
            or type(self.max_artifact_bytes) is not int
            or type(cas_maximum) is not int
            or cas_maximum != self.max_artifact_bytes
            or type(ledger_engagement_id) is not str
            or ledger_engagement_id != self.engagement_id
        ):
            raise ProviderOutputIntegrityError(
                "provider output StateStore components are invalid"
            )
        if "read_page" in cas_values or any(
            name in ledger_values
            for name in ("events", "referenced_artifacts", "verify_chain")
        ):
            raise ProviderOutputIntegrityError(
                "provider output StateStore component capability changed"
            )

    def lock(self) -> EngagementLock:
        self.validate()
        lock = _instance_values(self._state).get("_lock")
        if type(lock) is not EngagementLock:
            raise ProviderOutputIntegrityError("provider output lock is unavailable")
        return lock

    def verify(self) -> None:
        self.validate()
        ledger = self.ledger()
        _LEDGER_VERIFY(ledger)
        _STATE_CHECKPOINT(self._state)

    def ledger(self) -> EventLedger:
        self.validate()
        ledger = _instance_values(self._state).get("ledger")
        if type(ledger) is not EventLedger:
            raise ProviderOutputIntegrityError("provider output ledger is unavailable")
        return ledger

    def cas(self) -> EncryptedCAS:
        self.validate()
        cas = _instance_values(self._state).get("cas")
        if type(cas) is not EncryptedCAS:
            raise ProviderOutputIntegrityError("provider output CAS is unavailable")
        return cas

    def find(self, receipt: ProviderCallReceipt) -> EventRecord | None:
        actor_stream = provider_output_actor_stream(
            receipt.run_id,
            receipt.receipt_digest,
        )
        ledger = self.ledger()
        after_seq = 0
        found: EventRecord | None = None
        while True:
            records = _LEDGER_EVENTS(ledger, after_seq=after_seq, limit=1000)
            for record in records:
                if type(record) is not EventRecord:
                    raise ProviderOutputIntegrityError(
                        "provider output ledger returned an invalid event"
                    )
                if record.actor_stream == actor_stream:
                    if found is not None:
                        raise ProviderOutputIntegrityError(
                            "provider output receipt has duplicate events"
                        )
                    found = record
            if len(records) < 1000:
                return found
            after_seq = records[-1].seq

    def append(
        self,
        receipt: ProviderCallReceipt,
        raw_output: bytes,
        *,
        media_type: str,
    ) -> None:
        metadata: Mapping[str, object] = expected_metadata(
            receipt,
            engagement_id=self.engagement_id,
            media_type=media_type,
        )
        try:
            _STATE_APPEND(
                self._state,
                actor_stream=provider_output_actor_stream(
                    receipt.run_id,
                    receipt.receipt_digest,
                ),
                event_type=EVENT_TYPE,
                raw_output=raw_output,
                metadata=metadata,
                media_type=media_type,
            )
        except Exception as exc:
            raise ProviderOutputIntegrityError(
                "provider output persistence failed"
            ) from exc

    def references(self) -> tuple[ArtifactRef, ...]:
        return _LEDGER_REFERENCES(self.ledger())

    def read_page(
        self,
        reference: ArtifactRef,
        *,
        cursor: str | None,
        max_bytes: int,
    ) -> RetrievalPage:
        try:
            page = _CAS_READ_PAGE(
                self.cas(),
                reference,
                cursor=cursor,
                max_bytes=max_bytes,
            )
        except Exception as exc:
            raise ProviderOutputIntegrityError(
                "provider output storage read failed"
            ) from exc
        if type(page) is not RetrievalPage:
            raise ProviderOutputIntegrityError(
                "provider output storage returned an invalid page"
            )
        return page

    def verify_artifact(self, reference: ArtifactRef) -> None:
        page = self.read_page(reference, cursor=None, max_bytes=1)
        expected_page_bytes = min(reference.byte_length, 1)
        if (
            page.offset != 0
            or page.total_bytes != reference.byte_length
            or len(page.data) != expected_page_bytes
            or (
                reference.byte_length <= 1
                and page.next_cursor is not None
            )
            or (
                reference.byte_length > 1
                and (
                    type(page.next_cursor) is not str
                    or not page.next_cursor
                )
            )
        ):
            raise ProviderOutputIntegrityError(
                "provider output artifact verification failed"
            )
