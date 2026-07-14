from __future__ import annotations

from pathlib import Path

import pytest

from faultloom.state import (
    AnchorCheckpoint,
    EngagementKey,
    ProviderJournalEntry,
    ProviderJournalRecord,
    StateStore,
    StorageError,
)
from tests.runtime.provider_journal_support import (
    KEY_BYTES,
    digest,
    reservation,
    store,
    terminal,
)


def test_reserve_is_one_winner_finalize_replays_and_lookups_are_exact(
    tmp_path: Path,
) -> None:
    reserved = reservation()
    finalized = terminal(reserved)
    with store(tmp_path) as state:
        first = state.reserve_provider_receipt(reserved)
        with pytest.raises(StorageError, match="already durably claimed"):
            state.reserve_provider_receipt(reserved)
        assert first.event_seq == first.anchor.seq == 1
        assert state.provider_receipt_by_digest(reserved.receipt_digest) == first
        assert state.provider_receipt_by_attempt(
            reserved.call_id, reserved.attempt
        ) == first
        assert state.provider_receipt_by_attempt_id(reserved.attempt_id) == first

        terminal_record = state.finalize_provider_receipt(
            reserved.receipt_digest, finalized
        )
        terminal_replay = state.finalize_provider_receipt(
            reserved.receipt_digest, finalized
        )
        assert terminal_replay == terminal_record
        assert terminal_record.event_seq == terminal_record.anchor.seq == 2

        # Digest lookup is exact-key bound; attempt lookup resolves terminal state.
        reserved_readback = state.provider_receipt_by_digest(reserved.receipt_digest)
        assert reserved_readback is not None
        assert reserved_readback.entry == first.entry
        assert reserved_readback.event_seq == first.event_seq
        assert reserved_readback.event_hash == first.event_hash
        assert reserved_readback.anchor == terminal_record.anchor
        assert (
            state.provider_receipt_by_digest(finalized.receipt_digest)
            == terminal_record
        )
        assert (
            state.provider_receipt_by_attempt(reserved.call_id, reserved.attempt)
            == terminal_record
        )
        assert (
            state.provider_receipt_by_attempt_id(reserved.attempt_id)
            == terminal_record
        )
        assert state.checkpoint().seq == 2


def test_conflicting_reservation_and_finalization_fail_without_new_event(
    tmp_path: Path,
) -> None:
    reserved = reservation()
    finalized = terminal(reserved)
    conflicting_reservation = reservation(
        label="conflict",
        call_id=reserved.call_id,
        attempt=reserved.attempt,
        attempt_id="attempt-conflict",
    )
    conflicting_terminal = terminal(reserved, label="different")
    with store(tmp_path) as state:
        state.reserve_provider_receipt(reserved)
        with pytest.raises(StorageError, match="already durably claimed"):
            state.reserve_provider_receipt(conflicting_reservation)
        state.finalize_provider_receipt(reserved.receipt_digest, finalized)
        with pytest.raises(StorageError, match="conflicting finalization"):
            state.finalize_provider_receipt(
                reserved.receipt_digest, conflicting_terminal
            )
        assert state.checkpoint().seq == 2


def test_entry_rejects_noncanonical_receipt_and_wrong_embedded_digest() -> None:
    entry = reservation(
        label="strict",
        call_id="call/strict",
        attempt_id="attempt-strict",
    )
    values = {
        "phase": entry.phase,
        "receipt_digest": entry.receipt_digest,
        "reservation_receipt_digest": entry.reservation_receipt_digest,
        "call_id": entry.call_id,
        "attempt": entry.attempt,
        "attempt_id": entry.attempt_id,
        "binding_digest": entry.binding_digest,
        "dispatch_reservation_digest": entry.dispatch_reservation_digest,
        "proxy_request_digest": entry.proxy_request_digest,
    }
    with pytest.raises(StorageError, match="canonical provider receipt"):
        ProviderJournalEntry(
            **values,
            canonical_receipt_json=entry.canonical_receipt_json.replace("{", "{ ", 1),
        )
    wrong_digest_receipt = entry.canonical_receipt_json.replace(
        f'"receipt_digest":"{entry.receipt_digest}"',
        f'"receipt_digest":"{digest("other")}"',
        1,
    )
    with pytest.raises(StorageError, match="canonical provider receipt"):
        ProviderJournalEntry(
            **values,
            canonical_receipt_json=wrong_digest_receipt,
        )


def test_provider_state_api_rejects_subclass_owner(tmp_path: Path) -> None:
    class DerivedStateStore(StateStore):
        pass

    with DerivedStateStore(
        tmp_path / "state",
        "eng.provider-subclass",
        EngagementKey(KEY_BYTES),
        anchor_root=tmp_path / "anchor",
    ) as state:
        with pytest.raises(StorageError, match="exact StateStore"):
            state.reserve_provider_receipt(reservation(label="subclass"))
        assert state.checkpoint().seq == 0


def test_provider_record_rejects_event_outside_anchor_head() -> None:
    with pytest.raises(StorageError, match="differs from its anchor head"):
        ProviderJournalRecord(
            entry=reservation(label="record"),
            event_seq=1,
            event_hash="1" * 64,
            anchor=AnchorCheckpoint(
                engagement_id="eng.provider-record",
                seq=1,
                head="2" * 64,
            ),
        )
