"""Exact SQLite decoding for provider journal projection rows."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from .types import StorageError


_TEXT_COLUMNS = (
    "receipt_digest",
    "phase",
    "call_id",
    "attempt_id",
    "binding_digest",
    "dispatch_reservation_digest",
    "proxy_request_digest",
    "receipt_json",
)


@dataclass(frozen=True, slots=True)
class _ProviderProjectionRow:
    receipt_digest: str
    phase: str
    reservation_receipt_digest: str | None
    call_id: str
    attempt: int
    attempt_id: str
    binding_digest: str
    dispatch_reservation_digest: str
    proxy_request_digest: str
    receipt_json: str
    anchor_event_seq: int
    event_hash: str | None


def _row_value(row: sqlite3.Row, field: str) -> Any:
    try:
        return row[field]
    except IndexError as exc:
        raise StorageError(f"provider journal row is missing {field}") from exc


def _exact_text(row: sqlite3.Row, field: str) -> str:
    value = _row_value(row, field)
    if type(value) is not str:
        raise StorageError(f"provider journal row has non-TEXT {field}")
    return value


def _exact_positive_integer(row: sqlite3.Row, field: str) -> int:
    value = _row_value(row, field)
    if type(value) is not int or not 1 <= value < 2**63:
        raise StorageError(f"provider journal row has non-INTEGER {field}")
    return value


def _provider_projection_row(
    row: sqlite3.Row,
    *,
    require_event_hash: bool = False,
) -> _ProviderProjectionRow:
    text = {field: _exact_text(row, field) for field in _TEXT_COLUMNS}
    reservation_digest = _row_value(row, "reservation_receipt_digest")
    if reservation_digest is not None and type(reservation_digest) is not str:
        raise StorageError(
            "provider journal row has non-TEXT reservation_receipt_digest"
        )
    has_event_hash = "event_hash" in row.keys()
    if require_event_hash and not has_event_hash:
        raise StorageError("provider journal row is missing event_hash")
    event_hash = _exact_text(row, "event_hash") if has_event_hash else None
    return _ProviderProjectionRow(
        receipt_digest=text["receipt_digest"],
        phase=text["phase"],
        reservation_receipt_digest=reservation_digest,
        call_id=text["call_id"],
        attempt=_exact_positive_integer(row, "attempt"),
        attempt_id=text["attempt_id"],
        binding_digest=text["binding_digest"],
        dispatch_reservation_digest=text["dispatch_reservation_digest"],
        proxy_request_digest=text["proxy_request_digest"],
        receipt_json=text["receipt_json"],
        anchor_event_seq=_exact_positive_integer(row, "anchor_event_seq"),
        event_hash=event_hash,
    )
