from __future__ import annotations

from collections.abc import Mapping
from typing import NoReturn, final

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
from ._store_support import (
    CAS_READ_PAGE,
    LEDGER_EVENTS,
    LEDGER_REFERENCES,
    LEDGER_VERIFY,
    STATE_APPEND,
    STATE_CHECKPOINT,
    StoreAdmission,
    instance_values,
    method_is_original,
    trusted_store_admission,
)
from ._store_artifacts import (
    artifact_references,
    read_artifact_page,
    verify_artifact_reference,
)


@final
class ProviderOutputStoreBinding:
    __slots__ = ("__admission",)
    __admission: StoreAdmission

    def __init__(self, state: StateStore) -> None:
        if type(state) is not StateStore:
            raise ProviderOutputIntegrityError(
                "provider output requires the exact T20 StateStore"
            )
        state_values = instance_values(state)
        engagement_id = state_values.get("engagement_id")
        if type(engagement_id) is not str or not engagement_id:
            raise ProviderOutputIntegrityError(
                "provider output StateStore identity is invalid"
            )
        cas = state_values.get("cas")
        maximum = (
            instance_values(cas).get("max_artifact_bytes")
            if type(cas) is EncryptedCAS
            else None
        )
        if type(maximum) is not int or not 1 <= maximum <= 2**31:
            raise ProviderOutputIntegrityError(
                "provider output CAS byte ceiling is invalid"
            )
        self.__admission = StoreAdmission(state, engagement_id, maximum)
        self.validate()

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_ProviderOutputStoreBinding__admission":
            try:
                object.__getattribute__(self, name)
            except AttributeError:
                object.__setattr__(self, name, value)
                return
        raise AttributeError("ProviderOutputStoreBinding is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ProviderOutputStoreBinding is immutable")

    def _trusted_admission(self) -> StoreAdmission:
        return trusted_store_admission(
            object.__getattribute__(
                self,
                "_ProviderOutputStoreBinding__admission",
            )
        )

    @property
    def engagement_id(self) -> str:
        return self._trusted_admission().engagement_id

    @property
    def max_artifact_bytes(self) -> int:
        return self._trusted_admission().max_artifact_bytes

    def validate(self) -> None:
        admission = self._trusted_admission()
        state = admission.state
        state_namespace = instance_values(state)
        state_engagement_id = state_namespace.get("engagement_id")
        exact_methods = (
            (StateStore, "append_observation", STATE_APPEND),
            (StateStore, "checkpoint", STATE_CHECKPOINT),
            (EventLedger, "events", LEDGER_EVENTS),
            (EventLedger, "referenced_artifacts", LEDGER_REFERENCES),
            (EventLedger, "verify_chain", LEDGER_VERIFY),
            (EncryptedCAS, "read_page", CAS_READ_PAGE),
        )
        if any(
            not method_is_original(owner, name, expected)
            for owner, name, expected in exact_methods
        ) or any(
            name in state_namespace
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
        cas = state_namespace.get("cas")
        ledger = state_namespace.get("ledger")
        lock = state_namespace.get("_lock")
        cas_values = (
            instance_values(cas)
            if type(cas) is EncryptedCAS
            else {}
        )
        ledger_values = (
            instance_values(ledger)
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
        lock = instance_values(self._trusted_admission().state).get("_lock")
        if type(lock) is not EngagementLock:
            raise ProviderOutputIntegrityError("provider output lock is unavailable")
        return lock

    def verify(self) -> None:
        self.validate()
        ledger = self.ledger()
        LEDGER_VERIFY(ledger)
        STATE_CHECKPOINT(self._trusted_admission().state)

    def ledger(self) -> EventLedger:
        self.validate()
        ledger = instance_values(self._trusted_admission().state).get("ledger")
        if type(ledger) is not EventLedger:
            raise ProviderOutputIntegrityError("provider output ledger is unavailable")
        return ledger

    def cas(self) -> EncryptedCAS:
        self.validate()
        cas = instance_values(self._trusted_admission().state).get("cas")
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
            records = LEDGER_EVENTS(ledger, after_seq=after_seq, limit=1000)
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
            STATE_APPEND(
                self._trusted_admission().state,
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
        return artifact_references(self)

    def read_page(
        self,
        reference: ArtifactRef,
        *,
        cursor: str | None,
        max_bytes: int,
    ) -> RetrievalPage:
        return read_artifact_page(
            self,
            reference,
            cursor=cursor,
            max_bytes=max_bytes,
        )

    def verify_artifact(self, reference: ArtifactRef) -> None:
        verify_artifact_reference(self, reference)
