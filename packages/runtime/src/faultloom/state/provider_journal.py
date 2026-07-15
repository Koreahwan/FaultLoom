"""Typed, provider-independent records for the anchored receipt journal."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping
from typing import Any, Literal, Protocol, cast

from .provider_journal_rows import _provider_projection_row
from .provider_journal_schema import PROVIDER_SCHEMA, PROVIDER_SCHEMA_STATEMENTS
from .provider_journal_types import (
    ProviderJournalEntry,
    ProviderJournalRecord,
    _require_digest,
    _require_identifier,
)
from .types import ChainIntegrityError, StorageError


PROVIDER_RESERVED_EVENT = "provider.receipt.reserved"
PROVIDER_FINALIZED_EVENT = "provider.receipt.finalized"
PROVIDER_JOURNAL_ACTOR = "state.provider_journal"


class _ProviderEvent(Protocol):
    @property
    def actor_stream(self) -> str: ...

    @property
    def event_type(self) -> str: ...

    @property
    def payload(self) -> dict[str, Any]: ...


def provider_entry_from_row(row: sqlite3.Row) -> ProviderJournalEntry:
    try:
        values = _provider_projection_row(row, require_event_hash=True)
        phase_value = values.phase
        if phase_value not in {"reserved", "finalized"}:
            raise StorageError("provider journal phase is invalid")
        return ProviderJournalEntry(
            phase=cast(Literal["reserved", "finalized"], phase_value),
            receipt_digest=values.receipt_digest,
            reservation_receipt_digest=values.reservation_receipt_digest,
            call_id=values.call_id,
            attempt=values.attempt,
            attempt_id=values.attempt_id,
            binding_digest=values.binding_digest,
            dispatch_reservation_digest=values.dispatch_reservation_digest,
            proxy_request_digest=values.proxy_request_digest,
            canonical_receipt_json=values.receipt_json,
        )
    except StorageError as exc:
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
        try:
            values = _provider_projection_row(row)
        except StorageError as exc:
            raise ChainIntegrityError(
                "provider journal projection contains invalid storage values"
            ) from exc
        actual[values.anchor_event_seq] = {
            "attempt": values.attempt,
            "attempt_id": values.attempt_id,
            "binding_digest": values.binding_digest,
            "call_id": values.call_id,
            "dispatch_reservation_digest": values.dispatch_reservation_digest,
            "phase": values.phase,
            "proxy_request_digest": values.proxy_request_digest,
            "receipt_digest": values.receipt_digest,
            "receipt_json": values.receipt_json,
            "reservation_receipt_digest": values.reservation_receipt_digest,
        }
    if actual != expected:
        raise ChainIntegrityError(
            "provider journal projection is incomplete or differs from the event chain"
        )
