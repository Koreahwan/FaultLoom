from __future__ import annotations

import hashlib
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from faultloom.state import (
    AnchorCheckpoint,
    ChainIntegrityError,
    EngagementKey,
    ProviderJournalEntry,
    ProviderJournalRecord,
    StateStore,
    StorageError,
)
from faultloom.state.canonical import canonical_json
from faultloom.state.ledger import EventLedger, LEDGER_SCHEMA_VERSION


KEY_BYTES = bytes(range(32))


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def receipt_json(receipt_digest: str, *, kind: str) -> str:
    return canonical_json(
        {
            "kind": kind,
            "receipt_digest": receipt_digest,
            "schema_version": "test.v1",
        }
    )


def reservation(
    *,
    label: str = "one",
    call_id: str = "call/one",
    attempt: int = 1,
    attempt_id: str = "attempt-one",
) -> ProviderJournalEntry:
    receipt_digest = digest(f"reservation:{label}")
    return ProviderJournalEntry(
        phase="reserved",
        receipt_digest=receipt_digest,
        reservation_receipt_digest=None,
        call_id=call_id,
        attempt=attempt,
        attempt_id=attempt_id,
        binding_digest=digest(f"binding:{call_id}:{attempt}"),
        dispatch_reservation_digest=digest(f"dispatch:{call_id}:{attempt}"),
        proxy_request_digest=digest(f"proxy-request:{call_id}:{attempt}"),
        canonical_receipt_json=receipt_json(receipt_digest, kind="reservation"),
    )


def terminal(
    reserved: ProviderJournalEntry, *, label: str = "success"
) -> ProviderJournalEntry:
    receipt_digest = digest(f"terminal:{label}")
    return ProviderJournalEntry(
        phase="finalized",
        receipt_digest=receipt_digest,
        reservation_receipt_digest=reserved.receipt_digest,
        call_id=reserved.call_id,
        attempt=reserved.attempt,
        attempt_id=reserved.attempt_id,
        binding_digest=reserved.binding_digest,
        dispatch_reservation_digest=reserved.dispatch_reservation_digest,
        proxy_request_digest=reserved.proxy_request_digest,
        canonical_receipt_json=receipt_json(receipt_digest, kind="terminal"),
    )


def store(root: Path, engagement_id: str = "eng.provider") -> StateStore:
    return StateStore(
        root / "state",
        engagement_id,
        EngagementKey(KEY_BYTES),
        anchor_root=root / "anchor",
    )


def database_path(root: Path, engagement_id: str = "eng.provider") -> Path:
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    return root / "state" / "engagements" / namespace / "state.sqlite3"


def downgrade_empty_provider_projection_to_v2(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT count(*) FROM provider_journal_entries"
        ).fetchone()[0] == 0
        connection.execute("DROP TABLE provider_journal_entries")
        connection.execute("PRAGMA user_version=2")
        connection.commit()


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


def test_same_attempt_concurrency_has_one_durable_winner(tmp_path: Path) -> None:
    first = reservation(label="first", attempt_id="attempt-first")
    second = reservation(label="second", attempt_id="attempt-second")
    left = store(tmp_path, "eng.provider-concurrent")
    right = store(tmp_path, "eng.provider-concurrent")
    try:
        def reserve_one(
            state: StateStore, entry: ProviderJournalEntry
        ) -> tuple[str, str]:
            try:
                record = state.reserve_provider_receipt(entry)
                return "won", record.entry.receipt_digest
            except StorageError:
                return "lost", entry.receipt_digest

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = (
                pool.submit(reserve_one, left, first),
                pool.submit(reserve_one, right, second),
            )
            results = [future.result(timeout=10) for future in futures]
        assert sorted(result[0] for result in results) == ["lost", "won"]
        winner = next(result[1] for result in results if result[0] == "won")
        record = left.provider_receipt_by_attempt(first.call_id, first.attempt)
        assert record is not None
        assert record.entry.receipt_digest == winner
        assert left.checkpoint().seq == 1
    finally:
        left.close()
        right.close()


def test_same_attempt_across_processes_has_one_durable_winner(tmp_path: Path) -> None:
    script = r'''
import hashlib
import sys
import time
from pathlib import Path

source_root, base_value, label, ready_value, release_value, result_value = sys.argv[1:]
sys.path.insert(0, source_root)
from faultloom.state import EngagementKey, ProviderJournalEntry, StateStore, StorageError
from faultloom.state.canonical import canonical_json

def digest(value):
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()

base = Path(base_value)
receipt_digest = digest("reservation:process-shared")
entry = ProviderJournalEntry(
    phase="reserved",
    receipt_digest=receipt_digest,
    reservation_receipt_digest=None,
    call_id="call/process",
    attempt=1,
    attempt_id="attempt-process-shared",
    binding_digest=digest("binding:call/process:1"),
    dispatch_reservation_digest=digest("dispatch:call/process:1"),
    proxy_request_digest=digest("proxy-request:call/process:1"),
    canonical_receipt_json=canonical_json({
        "kind": "reservation",
        "receipt_digest": receipt_digest,
        "schema_version": "test.v1",
    }),
)
state = StateStore(
    base / "state",
    "eng.provider-process",
    EngagementKey(bytes(range(32))),
    anchor_root=base / "anchor",
)
Path(ready_value).write_text("ready")
release = Path(release_value)
deadline = time.monotonic() + 15
while not release.exists():
    if time.monotonic() > deadline:
        raise RuntimeError("process barrier timed out")
    time.sleep(0.01)
try:
    state.reserve_provider_receipt(entry)
except StorageError:
    outcome = "lost"
else:
    outcome = "won"
Path(result_value).write_text(outcome + ":" + receipt_digest)
state.close()
'''
    source_root = Path(__file__).parents[2] / "packages" / "runtime" / "src"
    release = tmp_path / "release"
    processes: list[subprocess.Popen[str]] = []
    ready_paths: list[Path] = []
    result_paths: list[Path] = []
    for label in ("left", "right"):
        ready = tmp_path / f"ready-{label}"
        result = tmp_path / f"result-{label}"
        ready_paths.append(ready)
        result_paths.append(result)
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    script,
                    str(source_root),
                    str(tmp_path),
                    label,
                    str(ready),
                    str(release),
                    str(result),
                ],
                env={},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )
    deadline = time.monotonic() + 15
    while not all(path.exists() for path in ready_paths):
        if time.monotonic() > deadline:
            for process in processes:
                process.kill()
            raise AssertionError("provider subprocesses did not reach the barrier")
        time.sleep(0.01)
    release.touch()
    for process in processes:
        _, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, stderr
    results = [path.read_text().split(":", 1) for path in result_paths]
    assert sorted(result[0] for result in results) == ["lost", "won"]
    winner = next(result[1] for result in results if result[0] == "won")
    with store(tmp_path, "eng.provider-process") as state:
        record = state.provider_receipt_by_attempt("call/process", 1)
        assert record is not None
        assert record.entry.receipt_digest == winner
        assert state.checkpoint().seq == 1


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


def test_provider_reservation_holds_engagement_lock_through_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engagement_id = "eng.provider-close-race"
    reserved = reservation(label="close-race")
    state = store(tmp_path, engagement_id)
    ledger_module = sys.modules[type(state.ledger).__module__]
    original_insert = ledger_module.insert_provider_entry
    insertion_started = threading.Event()
    allow_insert = threading.Event()
    close_finished = threading.Event()
    failures: list[BaseException] = []

    def insert_then_wait(connection, event_seq, entry) -> None:
        insertion_started.set()
        if not allow_insert.wait(timeout=10):
            raise AssertionError("close-race barrier timed out")
        original_insert(connection, event_seq, entry)

    monkeypatch.setattr(ledger_module, "insert_provider_entry", insert_then_wait)

    def reserve_in_thread() -> None:
        try:
            state.reserve_provider_receipt(reserved)
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)

    def close_in_thread() -> None:
        try:
            state.close()
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            close_finished.set()

    reserve_worker = threading.Thread(target=reserve_in_thread)
    reserve_worker.start()
    assert insertion_started.wait(timeout=10)
    close_worker = threading.Thread(target=close_in_thread)
    close_worker.start()
    assert not close_finished.wait(timeout=0.25)
    allow_insert.set()
    reserve_worker.join(timeout=15)
    close_worker.join(timeout=15)
    assert not reserve_worker.is_alive()
    assert not close_worker.is_alive()
    assert failures == []

    with store(tmp_path, engagement_id) as reopened:
        record = reopened.provider_receipt_by_attempt(
            reserved.call_id, reserved.attempt
        )
        assert record is not None
        assert record.entry == reserved
        assert record.anchor.seq == 1


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


def test_v2_migration_keeps_event_hashes_and_anchor_floor(tmp_path: Path) -> None:
    engagement_id = "eng.provider-migration"
    with store(tmp_path, engagement_id) as state:
        event = state.ledger.append(
            actor_stream="researcher",
            event_type="legacy.event",
            payload={"legacy": True},
        )
        floor = state.checkpoint()
    path = database_path(tmp_path, engagement_id)
    downgrade_empty_provider_projection_to_v2(path)

    migrated = StateStore(
        tmp_path / "state",
        engagement_id,
        EngagementKey(KEY_BYTES),
        anchor_root=tmp_path / "anchor",
        minimum_anchor=floor,
    )
    try:
        assert migrated.ledger.events()[0].event_hash == event.event_hash
        assert migrated.checkpoint() == floor
        reserved = reservation(label="migrated")
        assert migrated.reserve_provider_receipt(reserved).event_seq == 2
    finally:
        migrated.close()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == (
            LEDGER_SCHEMA_VERSION
        )
        assert connection.execute(
            "SELECT count(*) FROM provider_journal_entries"
        ).fetchone()[0] == 1


def test_failed_v2_migration_rolls_back_partial_provider_ddl(tmp_path: Path) -> None:
    engagement_id = "eng.provider-bad-migration"
    with store(tmp_path, engagement_id):
        pass
    path = database_path(tmp_path, engagement_id)
    downgrade_empty_provider_projection_to_v2(path)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER events_no_update")
        connection.execute(
            "CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT 1; END"
        )
        connection.commit()
    with pytest.raises(ChainIntegrityError, match="schema manifest"):
        store(tmp_path, engagement_id)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT count(*) FROM sqlite_schema "
            "WHERE name='provider_journal_entries'"
        ).fetchone()[0] == 0


def test_v2_migration_rejects_public_rehash_without_event_authentication(
    tmp_path: Path,
) -> None:
    engagement_id = "eng.provider-authenticated-migration"
    with store(tmp_path, engagement_id) as state:
        event = state.ledger.append(
            actor_stream="researcher",
            event_type="legacy.event",
            payload={"legacy": True},
        )
        floor = state.checkpoint()
    path = database_path(tmp_path, engagement_id)
    downgrade_empty_provider_projection_to_v2(path)
    changed_payload_json = canonical_json({"legacy": False})
    changed_payload_sha256 = hashlib.sha256(
        changed_payload_json.encode("utf-8")
    ).hexdigest()
    changed_event_hash = EventLedger._event_digest(
        seq=event.seq,
        engagement_id=event.engagement_id,
        actor_stream=event.actor_stream,
        event_type=event.event_type,
        payload_sha256=changed_payload_sha256,
        prev_hash=event.prev_hash,
        created_at=event.created_at,
    )
    with sqlite3.connect(path) as connection:
        update_trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' "
            "AND name='events_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER events_no_update")
        connection.execute(
            "UPDATE events SET payload_json=?, payload_sha256=?, event_hash=? "
            "WHERE seq=?",
            (
                changed_payload_json,
                changed_payload_sha256,
                changed_event_hash,
                event.seq,
            ),
        )
        connection.execute(update_trigger)
        connection.commit()
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    anchor_path = tmp_path / "anchor" / "anchors" / f"{namespace}.anchor"
    anchor_before = anchor_path.read_bytes()
    with pytest.raises(ChainIntegrityError, match="authentication tag"):
        StateStore(
            tmp_path / "state",
            engagement_id,
            EngagementKey(KEY_BYTES),
            anchor_root=tmp_path / "anchor",
            minimum_anchor=floor,
        )
    assert anchor_path.read_bytes() == anchor_before
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT count(*) FROM sqlite_schema "
            "WHERE name='provider_journal_entries'"
        ).fetchone()[0] == 0


def test_entry_rejects_noncanonical_receipt_and_wrong_embedded_digest() -> None:
    receipt_digest = digest("receipt")
    values = {
        "phase": "reserved",
        "receipt_digest": receipt_digest,
        "reservation_receipt_digest": None,
        "call_id": "call/strict",
        "attempt": 1,
        "attempt_id": "attempt-strict",
        "binding_digest": digest("binding"),
        "dispatch_reservation_digest": digest("dispatch"),
        "proxy_request_digest": digest("proxy"),
    }
    with pytest.raises(StorageError, match="not canonical"):
        ProviderJournalEntry(
            **values,
            canonical_receipt_json=(
                '{"receipt_digest": "' + receipt_digest + '", "kind": "reserved"}'
            ),
        )
    with pytest.raises(StorageError, match="indexed receipt_digest"):
        ProviderJournalEntry(
            **values,
            canonical_receipt_json=receipt_json(digest("other"), kind="reserved"),
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
