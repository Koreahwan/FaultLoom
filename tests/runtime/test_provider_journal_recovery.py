from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from faultloom.state import ChainIntegrityError, StorageError
from tests.runtime.provider_journal_support import (
    database_path,
    reservation,
    store,
    terminal,
)


def test_commit_before_anchor_failure_recovers_as_unknown_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reserved = reservation()
    state = store(tmp_path, "eng.provider-anchor-failure")
    original_write = state.anchor.write
    armed = True

    def fail_once(checkpoint) -> None:
        nonlocal armed
        if armed and checkpoint.seq == 1:
            armed = False
            raise StorageError("simulated anchor write interruption")
        original_write(checkpoint)

    monkeypatch.setattr(state.anchor, "write", fail_once)
    with pytest.raises(StorageError, match="simulated anchor"):
        state.reserve_provider_receipt(reserved)
    assert state.anchor.load_optional().seq == 0
    monkeypatch.setattr(state.anchor, "write", original_write)
    recovered = state.provider_receipt_by_attempt(reserved.call_id, reserved.attempt)
    assert recovered is not None
    assert recovered.entry == reserved
    assert recovered.anchor.seq == 1
    state.close()


def test_provider_projection_deletion_and_index_erasure_fail_closed(
    tmp_path: Path,
) -> None:
    reserved = reservation()
    path = database_path(tmp_path, "eng.provider-tamper")
    with store(tmp_path, "eng.provider-tamper") as state:
        state.reserve_provider_receipt(reserved)

    with sqlite3.connect(path) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' "
            "AND name='provider_journal_entries_no_delete'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER provider_journal_entries_no_delete")
        connection.execute("DELETE FROM provider_journal_entries")
        connection.execute(trigger)
        connection.commit()
    with pytest.raises(ChainIntegrityError, match="provider journal projection"):
        store(tmp_path, "eng.provider-tamper")

    index_root = tmp_path / "index"
    with store(index_root, "eng.provider-index") as state:
        state.reserve_provider_receipt(reservation(label="index"))
    with sqlite3.connect(database_path(index_root, "eng.provider-index")) as connection:
        connection.execute("DROP INDEX provider_reservation_call_attempt_uq")
        connection.commit()
    with pytest.raises(ChainIntegrityError, match="schema manifest"):
        store(index_root, "eng.provider-index")


def test_database_rollback_behind_provider_anchor_fails_closed(tmp_path: Path) -> None:
    reserved = reservation()
    with store(tmp_path, "eng.provider-rollback") as state:
        state.reserve_provider_receipt(reserved)
    snapshot = tmp_path / "state-snapshot"
    shutil.copytree(tmp_path / "state", snapshot)
    with store(tmp_path, "eng.provider-rollback") as state:
        state.finalize_provider_receipt(reserved.receipt_digest, terminal(reserved))
        assert state.checkpoint().seq == 2
    shutil.rmtree(tmp_path / "state")
    shutil.copytree(snapshot, tmp_path / "state")
    with pytest.raises(ChainIntegrityError, match="behind its authenticated anchor"):
        store(tmp_path, "eng.provider-rollback")


@pytest.mark.parametrize(
    ("column", "error"),
    [
        ("attempt", "provider journal projection"),
        ("anchor_event_seq", "SQLite foreign-key integrity"),
    ],
)
def test_real_valued_provider_projection_tamper_fails_closed(
    tmp_path: Path, column: str, error: str
) -> None:
    # Given a valid reservation whose integer projection column is rewritten as REAL.
    engagement_id = f"eng.provider-real-{column}"
    path = database_path(tmp_path, engagement_id)
    with store(tmp_path, engagement_id) as state:
        state.reserve_provider_receipt(reservation(label=column))
    with sqlite3.connect(path) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' "
            "AND name='provider_journal_entries_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER provider_journal_entries_no_update")
        connection.execute(
            f"UPDATE provider_journal_entries SET {column} = 1.5"
        )
        connection.execute(trigger)
        connection.commit()
        assert connection.execute(
            f"SELECT typeof({column}) FROM provider_journal_entries"
        ).fetchone()[0] == "real"

    # When startup verifies the event-backed provider projection.
    with pytest.raises(ChainIntegrityError, match=error):
        store(tmp_path, engagement_id)

    # Then no lossy integer coercion can normalize the tampered storage class.
