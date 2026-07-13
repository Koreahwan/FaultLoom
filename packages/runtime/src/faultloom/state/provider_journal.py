"""Typed, provider-independent records for the anchored receipt journal."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from .anchor import AnchorCheckpoint
from .canonical import canonical_json
from .types import ChainIntegrityError, StorageError


PROVIDER_RESERVED_EVENT = "provider.receipt.reserved"
PROVIDER_FINALIZED_EVENT = "provider.receipt.finalized"
PROVIDER_JOURNAL_ACTOR = "state.provider_journal"

PROVIDER_SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS provider_journal_entries (
        receipt_digest TEXT PRIMARY KEY,
        phase TEXT NOT NULL CHECK (phase IN ('reserved', 'finalized')),
        reservation_receipt_digest TEXT
            REFERENCES provider_journal_entries(receipt_digest),
        call_id TEXT NOT NULL,
        attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 9223372036854775807),
        attempt_id TEXT NOT NULL,
        binding_digest TEXT NOT NULL,
        dispatch_reservation_digest TEXT NOT NULL,
        proxy_request_digest TEXT NOT NULL,
        receipt_json TEXT NOT NULL,
        anchor_event_seq INTEGER NOT NULL UNIQUE REFERENCES events(seq),
        CHECK (
            (phase = 'reserved' AND reservation_receipt_digest IS NULL) OR
            (phase = 'finalized' AND reservation_receipt_digest IS NOT NULL
                                 AND reservation_receipt_digest <> receipt_digest)
        )
    ) WITHOUT ROWID
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_reservation_call_attempt_uq
    ON provider_journal_entries(call_id, attempt) WHERE phase = 'reserved'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_reservation_attempt_id_uq
    ON provider_journal_entries(attempt_id) WHERE phase = 'reserved'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_reservation_dispatch_uq
    ON provider_journal_entries(dispatch_reservation_digest) WHERE phase = 'reserved'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_reservation_request_uq
    ON provider_journal_entries(proxy_request_digest) WHERE phase = 'reserved'
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS provider_finalization_once_uq
    ON provider_journal_entries(reservation_receipt_digest) WHERE phase = 'finalized'
    """,
    """
    CREATE TRIGGER IF NOT EXISTS provider_journal_entries_no_update
    BEFORE UPDATE ON provider_journal_entries
    BEGIN SELECT RAISE(ABORT, 'append-only provider journal'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS provider_journal_entries_no_delete
    BEFORE DELETE ON provider_journal_entries
    BEGIN SELECT RAISE(ABORT, 'append-only provider journal'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS provider_journal_finalization_binding
    BEFORE INSERT ON provider_journal_entries
    WHEN NEW.phase = 'finalized'
    BEGIN
        SELECT CASE WHEN NOT EXISTS (
            SELECT 1 FROM provider_journal_entries AS reserved
            WHERE reserved.phase = 'reserved'
              AND reserved.receipt_digest = NEW.reservation_receipt_digest
              AND reserved.call_id = NEW.call_id
              AND reserved.attempt = NEW.attempt
              AND reserved.attempt_id = NEW.attempt_id
              AND reserved.binding_digest = NEW.binding_digest
              AND reserved.dispatch_reservation_digest = NEW.dispatch_reservation_digest
              AND reserved.proxy_request_digest = NEW.proxy_request_digest
        ) THEN RAISE(ABORT, 'provider finalization binding mismatch') END;
    END
    """,
)

PROVIDER_SCHEMA = ";\n".join(
    statement.strip() for statement in PROVIDER_SCHEMA_STATEMENTS
) + ";\n"

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
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


def _require_identifier(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise StorageError(f"{field} is not a valid provider identifier")
    return value


def _require_digest(value: str, *, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise StorageError(f"{field} is not a prefixed SHA-256 digest")
    return value


def _require_canonical_receipt(value: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value:
        raise StorageError("canonical_receipt_json must be non-empty JSON")
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise StorageError("canonical_receipt_json is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise StorageError("canonical_receipt_json must encode an object")
    if canonical_json(parsed) != value:
        raise StorageError("canonical_receipt_json is not canonical")
    return parsed


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
        if self.phase not in {"reserved", "finalized"}:
            raise StorageError("provider journal phase is invalid")
        _require_digest(self.receipt_digest, field="receipt_digest")
        _require_identifier(self.call_id, field="call_id")
        if (
            not isinstance(self.attempt, int)
            or isinstance(self.attempt, bool)
            or not 1 <= self.attempt <= 2**63 - 1
        ):
            raise StorageError("attempt must be a positive signed 64-bit integer")
        _require_identifier(self.attempt_id, field="attempt_id")
        _require_digest(self.binding_digest, field="binding_digest")
        _require_digest(
            self.dispatch_reservation_digest,
            field="dispatch_reservation_digest",
        )
        _require_digest(self.proxy_request_digest, field="proxy_request_digest")
        receipt = _require_canonical_receipt(self.canonical_receipt_json)
        if receipt.get("receipt_digest") != self.receipt_digest:
            raise StorageError(
                "canonical receipt does not contain the indexed receipt_digest"
            )
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

    def to_event_payload(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "attempt_id": self.attempt_id,
            "binding_digest": self.binding_digest,
            "call_id": self.call_id,
            "canonical_receipt_json": self.canonical_receipt_json,
            "dispatch_reservation_digest": self.dispatch_reservation_digest,
            "phase": self.phase,
            "proxy_request_digest": self.proxy_request_digest,
            "receipt_digest": self.receipt_digest,
            "reservation_receipt_digest": self.reservation_receipt_digest,
        }

    @classmethod
    def from_event_payload(cls, payload: Mapping[str, Any]) -> ProviderJournalEntry:
        if not isinstance(payload, Mapping) or set(payload) != _ENTRY_KEYS:
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
        if not isinstance(self.event_seq, int) or isinstance(self.event_seq, bool):
            raise StorageError("provider journal event sequence is invalid")
        if self.event_seq <= 0 or self.event_seq > self.anchor.seq:
            raise StorageError("provider journal event is not covered by its anchor")
        if not isinstance(self.event_hash, str) or not re.fullmatch(
            r"[0-9a-f]{64}", self.event_hash
        ):
            raise StorageError("provider journal event hash is invalid")
        if self.event_seq == self.anchor.seq and self.event_hash != self.anchor.head:
            raise StorageError("provider journal event differs from its anchor head")


class _ProviderEvent(Protocol):
    @property
    def actor_stream(self) -> str: ...

    @property
    def event_type(self) -> str: ...

    @property
    def payload(self) -> dict[str, Any]: ...


def provider_entry_from_row(row: sqlite3.Row) -> ProviderJournalEntry:
    try:
        phase_value = str(row["phase"])
        if phase_value not in {"reserved", "finalized"}:
            raise StorageError("provider journal phase is invalid")
        return ProviderJournalEntry(
            phase=cast(Literal["reserved", "finalized"], phase_value),
            receipt_digest=str(row["receipt_digest"]),
            reservation_receipt_digest=row["reservation_receipt_digest"],
            call_id=str(row["call_id"]),
            attempt=int(row["attempt"]),
            attempt_id=str(row["attempt_id"]),
            binding_digest=str(row["binding_digest"]),
            dispatch_reservation_digest=str(row["dispatch_reservation_digest"]),
            proxy_request_digest=str(row["proxy_request_digest"]),
            canonical_receipt_json=str(row["receipt_json"]),
        )
    except (StorageError, TypeError, ValueError) as exc:
        raise ChainIntegrityError(
            "provider journal projection contains an invalid entry"
        ) from exc


def provider_row_by_digest(
    connection: sqlite3.Connection, receipt_digest: str
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT journal.*, event.event_hash
        FROM provider_journal_entries AS journal
        JOIN events AS event ON event.seq = journal.anchor_event_seq
        WHERE journal.receipt_digest = ?
        """,
        (receipt_digest,),
    ).fetchone()


def provider_terminal_for_reservation(
    connection: sqlite3.Connection, reservation_receipt_digest: str
) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT journal.*, event.event_hash
        FROM provider_journal_entries AS journal
        JOIN events AS event ON event.seq = journal.anchor_event_seq
        WHERE journal.phase = 'finalized'
          AND journal.reservation_receipt_digest = ?
        """,
        (reservation_receipt_digest,),
    ).fetchone()


def provider_terminal_or_reservation(
    connection: sqlite3.Connection, reservation: sqlite3.Row | None
) -> sqlite3.Row | None:
    if reservation is None or str(reservation["phase"]) == "finalized":
        return reservation
    terminal = provider_terminal_for_reservation(
        connection, str(reservation["receipt_digest"])
    )
    return reservation if terminal is None else terminal


def insert_provider_entry(
    connection: sqlite3.Connection,
    event_seq: int,
    entry: ProviderJournalEntry,
) -> None:
    connection.execute(
        """
        INSERT INTO provider_journal_entries(
            receipt_digest, phase, reservation_receipt_digest,
            call_id, attempt, attempt_id, binding_digest,
            dispatch_reservation_digest, proxy_request_digest,
            receipt_json, anchor_event_seq
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            entry.receipt_digest,
            entry.phase,
            entry.reservation_receipt_digest,
            entry.call_id,
            entry.attempt,
            entry.attempt_id,
            entry.binding_digest,
            entry.dispatch_reservation_digest,
            entry.proxy_request_digest,
            entry.canonical_receipt_json,
            event_seq,
        ),
    )


def verify_provider_projection(
    events: Mapping[int, _ProviderEvent],
    rows: Iterable[sqlite3.Row],
) -> None:
    expected: dict[int, dict[str, Any]] = {}
    entries: dict[str, tuple[int, ProviderJournalEntry]] = {}
    call_attempts: set[tuple[str, int]] = set()
    attempt_ids: set[str] = set()
    dispatch_reservations: set[str] = set()
    proxy_requests: set[str] = set()
    finalizations: set[str] = set()
    for event_seq, event in events.items():
        if event.event_type not in {
            PROVIDER_RESERVED_EVENT,
            PROVIDER_FINALIZED_EVENT,
        }:
            continue
        if event.actor_stream != PROVIDER_JOURNAL_ACTOR:
            raise ChainIntegrityError(
                "provider journal event has an unauthorized actor stream"
            )
        try:
            entry = ProviderJournalEntry.from_event_payload(event.payload)
        except StorageError as exc:
            raise ChainIntegrityError(
                "provider journal event payload is invalid"
            ) from exc
        expected_phase = (
            "reserved" if event.event_type == PROVIDER_RESERVED_EVENT else "finalized"
        )
        if entry.phase != expected_phase:
            raise ChainIntegrityError("provider journal event type and phase differ")
        if entry.receipt_digest in entries:
            raise ChainIntegrityError("provider journal receipt digest is not unique")
        entries[entry.receipt_digest] = (event_seq, entry)
        expected[event_seq] = {
            "attempt": entry.attempt,
            "attempt_id": entry.attempt_id,
            "binding_digest": entry.binding_digest,
            "call_id": entry.call_id,
            "dispatch_reservation_digest": entry.dispatch_reservation_digest,
            "phase": entry.phase,
            "proxy_request_digest": entry.proxy_request_digest,
            "receipt_digest": entry.receipt_digest,
            "receipt_json": entry.canonical_receipt_json,
            "reservation_receipt_digest": entry.reservation_receipt_digest,
        }
        if entry.phase == "reserved":
            call_attempt = (entry.call_id, entry.attempt)
            if (
                call_attempt in call_attempts
                or entry.attempt_id in attempt_ids
                or entry.dispatch_reservation_digest in dispatch_reservations
                or entry.proxy_request_digest in proxy_requests
            ):
                raise ChainIntegrityError(
                    "provider reservation identity is not unique"
                )
            call_attempts.add(call_attempt)
            attempt_ids.add(entry.attempt_id)
            dispatch_reservations.add(entry.dispatch_reservation_digest)
            proxy_requests.add(entry.proxy_request_digest)

    immutable_fields = (
        "call_id",
        "attempt",
        "attempt_id",
        "binding_digest",
        "dispatch_reservation_digest",
        "proxy_request_digest",
    )
    for event_seq, entry in entries.values():
        if entry.phase != "finalized":
            continue
        reservation_digest = entry.reservation_receipt_digest
        assert reservation_digest is not None
        reservation_pair = entries.get(reservation_digest)
        if reservation_pair is None:
            raise ChainIntegrityError(
                "provider finalization has no authenticated reservation"
            )
        reservation_seq, reservation = reservation_pair
        if reservation.phase != "reserved" or reservation_seq >= event_seq:
            raise ChainIntegrityError(
                "provider finalization reservation lineage is invalid"
            )
        if reservation_digest in finalizations:
            raise ChainIntegrityError(
                "provider reservation has more than one finalization"
            )
        finalizations.add(reservation_digest)
        if any(
            getattr(entry, field) != getattr(reservation, field)
            for field in immutable_fields
        ):
            raise ChainIntegrityError(
                "provider finalization binding differs from its reservation"
            )

    actual: dict[int, dict[str, Any]] = {}
    for row in rows:
        actual[int(row["anchor_event_seq"])] = {
            "attempt": int(row["attempt"]),
            "attempt_id": str(row["attempt_id"]),
            "binding_digest": str(row["binding_digest"]),
            "call_id": str(row["call_id"]),
            "dispatch_reservation_digest": str(
                row["dispatch_reservation_digest"]
            ),
            "phase": str(row["phase"]),
            "proxy_request_digest": str(row["proxy_request_digest"]),
            "receipt_digest": str(row["receipt_digest"]),
            "receipt_json": str(row["receipt_json"]),
            "reservation_receipt_digest": row["reservation_receipt_digest"],
        }
    if actual != expected:
        raise ChainIntegrityError(
            "provider journal projection is incomplete or differs from the event chain"
        )
