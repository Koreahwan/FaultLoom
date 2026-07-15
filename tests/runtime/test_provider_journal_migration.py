from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

from faultloom.state import ChainIntegrityError, EngagementKey, StateStore
from faultloom.state.canonical import canonical_json
from faultloom.state.ledger import EventLedger, LEDGER_SCHEMA_VERSION
from tests.runtime.provider_journal_support import (
    KEY_BYTES,
    database_path,
    downgrade_empty_provider_projection_to_v2,
    reservation,
    store,
)


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
