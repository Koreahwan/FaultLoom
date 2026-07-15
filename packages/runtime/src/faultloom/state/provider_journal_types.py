"""Public immutable records for anchored provider receipt state."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from .anchor import AnchorCheckpoint
from .provider_receipt import (
    ProviderCanonicalReceipt,
    ProviderReceiptMetadata,
)
from .provider_receipt_validation import _require_digest, _require_identifier
from .types import StorageError


_ENTRY_KEYS = frozenset(
    {
        "phase",
        "receipt_digest",
        "reservation_receipt_digest",
        "call_id",
        "attempt",
        "attempt_id",
        "binding_digest",
        "dispatch_reservation_digest",
        "proxy_request_digest",
        "canonical_receipt_json",
    }
)


@dataclass(frozen=True, slots=True)
class ProviderJournalEntry:
    """Opaque canonical provider receipt plus its immutable indexed binding."""

    phase: Literal["reserved", "finalized"]
    receipt_digest: str
    reservation_receipt_digest: str | None
    call_id: str
    attempt: int
    attempt_id: str
    binding_digest: str
    dispatch_reservation_digest: str
    proxy_request_digest: str
    canonical_receipt_json: str

    def __post_init__(self) -> None:
        if type(self.phase) is not str or self.phase not in {"reserved", "finalized"}:
            raise StorageError("provider journal phase is invalid")
        _require_digest(self.receipt_digest, field="receipt_digest")
        if self.reservation_receipt_digest is not None:
            _require_digest(
                self.reservation_receipt_digest,
                field="reservation_receipt_digest",
            )
        _require_identifier(self.call_id, field="call_id")
        if type(self.attempt) is not int or not 1 <= self.attempt <= 2**63 - 1:
            raise StorageError("attempt must be a positive signed 64-bit integer")
        _require_identifier(self.attempt_id, field="attempt_id")
        _require_digest(self.binding_digest, field="binding_digest")
        _require_digest(
            self.dispatch_reservation_digest,
            field="dispatch_reservation_digest",
        )
        _require_digest(self.proxy_request_digest, field="proxy_request_digest")
        receipt = ProviderCanonicalReceipt.parse(self.canonical_receipt_json)
        metadata = receipt.metadata
        if (
            receipt.phase != self.phase
            or receipt.receipt_digest != self.receipt_digest
            or receipt.reservation_receipt_digest != self.reservation_receipt_digest
            or metadata.call_id != self.call_id
            or metadata.attempt != self.attempt
            or metadata.attempt_id != self.attempt_id
            or metadata.binding_digest != self.binding_digest
            or metadata.dispatch_reservation_digest != self.dispatch_reservation_digest
            or metadata.proxy_request_digest != self.proxy_request_digest
        ):
            raise StorageError("canonical provider receipt differs from indexed identity")
        if self.phase == "reserved":
            if self.reservation_receipt_digest is not None:
                raise StorageError("reserved receipt cannot cite a reservation receipt")
        else:
            if self.reservation_receipt_digest is None:
                raise StorageError("finalized receipt must cite its reservation receipt")
            _require_digest(
                self.reservation_receipt_digest,
                field="reservation_receipt_digest",
            )
            if self.reservation_receipt_digest == self.receipt_digest:
                raise StorageError("finalized receipt cannot cite itself")

    @classmethod
    def from_receipt(cls, receipt: ProviderCanonicalReceipt) -> ProviderJournalEntry:
        if type(receipt) is not ProviderCanonicalReceipt:
            raise StorageError("provider journal requires a typed canonical receipt")
        metadata = receipt.metadata
        return cls(
            phase=receipt.phase,
            receipt_digest=receipt.receipt_digest,
            reservation_receipt_digest=receipt.reservation_receipt_digest,
            call_id=metadata.call_id,
            attempt=metadata.attempt,
            attempt_id=metadata.attempt_id,
            binding_digest=metadata.binding_digest,
            dispatch_reservation_digest=metadata.dispatch_reservation_digest,
            proxy_request_digest=metadata.proxy_request_digest,
            canonical_receipt_json=receipt.canonical_json_text(),
        )

    def validated_copy(self) -> ProviderJournalEntry:
        return ProviderJournalEntry(
            phase=self.phase,
            receipt_digest=self.receipt_digest,
            reservation_receipt_digest=self.reservation_receipt_digest,
            call_id=self.call_id,
            attempt=self.attempt,
            attempt_id=self.attempt_id,
            binding_digest=self.binding_digest,
            dispatch_reservation_digest=self.dispatch_reservation_digest,
            proxy_request_digest=self.proxy_request_digest,
            canonical_receipt_json=self.canonical_receipt_json,
        )

    def to_event_payload(self) -> dict[str, Any]:
        entry = self.validated_copy()
        return {
            "attempt": entry.attempt,
            "attempt_id": entry.attempt_id,
            "binding_digest": entry.binding_digest,
            "call_id": entry.call_id,
            "canonical_receipt_json": entry.canonical_receipt_json,
            "dispatch_reservation_digest": entry.dispatch_reservation_digest,
            "phase": entry.phase,
            "proxy_request_digest": entry.proxy_request_digest,
            "receipt_digest": entry.receipt_digest,
            "reservation_receipt_digest": entry.reservation_receipt_digest,
        }

    @classmethod
    def from_event_payload(cls, payload: Mapping[str, Any]) -> ProviderJournalEntry:
        if type(payload) is not dict or set(payload) != _ENTRY_KEYS:
            raise StorageError("provider journal event payload schema is invalid")
        return cls(
            phase=payload["phase"],
            receipt_digest=payload["receipt_digest"],
            reservation_receipt_digest=payload["reservation_receipt_digest"],
            call_id=payload["call_id"],
            attempt=payload["attempt"],
            attempt_id=payload["attempt_id"],
            binding_digest=payload["binding_digest"],
            dispatch_reservation_digest=payload["dispatch_reservation_digest"],
            proxy_request_digest=payload["proxy_request_digest"],
            canonical_receipt_json=payload["canonical_receipt_json"],
        )


@dataclass(frozen=True, slots=True)
class ProviderJournalRecord:
    """One journal entry proven by the event chain and external anchor."""

    entry: ProviderJournalEntry
    event_seq: int
    event_hash: str
    anchor: AnchorCheckpoint

    def __post_init__(self) -> None:
        if type(self.entry) is not ProviderJournalEntry:
            raise StorageError("provider journal record entry is invalid")
        if type(self.anchor) is not AnchorCheckpoint:
            raise StorageError("provider journal record anchor is invalid")
        if type(self.event_seq) is not int:
            raise StorageError("provider journal event sequence is invalid")
        if self.event_seq <= 0 or self.event_seq > self.anchor.seq:
            raise StorageError("provider journal event is not covered by its anchor")
        if type(self.event_hash) is not str or not re.fullmatch(
            r"[0-9a-f]{64}", self.event_hash
        ):
            raise StorageError("provider journal event hash is invalid")
        if self.event_seq == self.anchor.seq and self.event_hash != self.anchor.head:
            raise StorageError("provider journal event differs from its anchor head")
