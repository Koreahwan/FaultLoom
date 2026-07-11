from __future__ import annotations

import hashlib
import json
import os
import pickle
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from faultloom.state import (
    AnchorCheckpoint,
    ArtifactRef,
    ChainIntegrityError,
    CrossEngagementError,
    EncryptedCAS,
    EngagementKey,
    EventLedger,
    StateStore,
    StorageError,
)
import faultloom.state.cas as cas_module
import faultloom.state.ledger as ledger_module


KEY_BYTES = bytes(range(32))


def key() -> EngagementKey:
    return EngagementKey(KEY_BYTES)


def state_root(root: Path) -> Path:
    return root / "state"


def anchor_root(root: Path) -> Path:
    return root / "anchor"


def state_store(
    root: Path,
    engagement_id: str,
    engagement_key: EngagementKey | None = None,
    *,
    minimum_anchor: AnchorCheckpoint | None = None,
) -> StateStore:
    return StateStore(
        state_root(root),
        engagement_id,
        engagement_key or key(),
        anchor_root=anchor_root(root),
        minimum_anchor=minimum_anchor,
    )


def database_path(root: Path, engagement_id: str) -> Path:
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    return state_root(root) / "engagements" / namespace / "state.sqlite3"


def tamper_live_ledger(path: Path, mutation: str) -> None:
    with sqlite3.connect(path, timeout=5.0) as connection:
        if mutation == "metadata":
            trigger = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' "
                "AND name='ledger_metadata_no_update'"
            ).fetchone()[0]
            connection.execute("DROP TRIGGER ledger_metadata_no_update")
            connection.execute(
                "UPDATE ledger_metadata SET value=? "
                "WHERE key='event_auth_key_commitment'",
                ("0" * 64,),
            )
            connection.execute(trigger)
        elif mutation == "schema":
            connection.execute("DROP TRIGGER events_no_update")
            connection.execute(
                "CREATE TRIGGER events_no_update BEFORE UPDATE ON events "
                "BEGIN SELECT 1; END"
            )
        elif mutation == "header":
            connection.execute("PRAGMA user_version=99")
        else:  # pragma: no cover - test helper contract
            raise AssertionError(f"unknown ledger mutation: {mutation}")


def mutate_ledger_with_exact_trigger_restore(
    path: Path,
    *,
    trigger: str,
    statement: str,
    parameters: tuple[object, ...] = (),
) -> None:
    """Commit a row mutation while restoring the exact append-only trigger."""

    with sqlite3.connect(path, isolation_level=None, timeout=5.0) as connection:
        row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
            (trigger,),
        ).fetchone()
        assert row is not None
        trigger_sql = row[0]
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(f"DROP TRIGGER {trigger}")
            connection.execute(statement, parameters)
            connection.execute(trigger_sql)
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        restored = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
            (trigger,),
        ).fetchone()
        assert restored == (trigger_sql,)


def blob_path(root: Path, reference: ArtifactRef) -> Path:
    namespace = hashlib.sha256(reference.engagement_id.encode()).hexdigest()
    return (
        state_root(root)
        / "cas"
        / namespace
        / reference.sha256[:2]
        / f"{reference.sha256}.flcas"
    )


def replace_private_directory(path: Path, displaced: Path) -> None:
    """Replace a live private root with an executable same-owner 0700 copy."""

    before = path.stat()
    path.rename(displaced)
    shutil.copytree(displaced, path)
    after = path.stat()
    assert (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
    assert stat.S_IMODE(after.st_mode) == 0o700
    getuid = getattr(os, "geteuid", None)
    if getuid is not None:
        assert after.st_uid == getuid()


def replace_private_file_with_identical_copy(path: Path, displaced_root: Path) -> None:
    """Displace a live private file and install an identical private new inode."""

    displaced_root.mkdir(mode=0o700)
    displaced = displaced_root / path.name
    before_bytes = path.read_bytes()
    before = path.stat()
    assert stat.S_IMODE(before.st_mode) == 0o600
    assert before.st_nlink == 1
    path.rename(displaced)
    shutil.copyfile(displaced, path)
    path.chmod(0o600)
    after = path.stat()
    assert path.read_bytes() == before_bytes == displaced.read_bytes()
    assert (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
    assert stat.S_IMODE(after.st_mode) == 0o600
    assert after.st_nlink == 1
    getuid = getattr(os, "geteuid", None)
    if getuid is not None:
        assert after.st_uid == getuid()


def install_stale_sidecar_stat_swap(
    monkeypatch: pytest.MonkeyPatch,
    ledger: EventLedger,
    path: Path,
    sidecar_suffix: str,
    displaced_root: Path,
    state: dict[str, bool],
) -> None:
    """Replace a sidecar after its old name metadata has been returned."""

    real_stat = ledger_module.os.stat
    target_name = f"{path.name}{sidecar_suffix}"

    def stat_then_replace(name, *args, **kwargs):
        metadata = real_stat(name, *args, **kwargs)
        if (
            state["armed"]
            and not state["replaced"]
            and name == target_name
            and kwargs.get("dir_fd") == ledger._parent_fd
            and kwargs.get("follow_symlinks") is False
        ):
            state["replaced"] = True
            replace_private_file_with_identical_copy(
                Path(f"{path}{sidecar_suffix}"), displaced_root
            )
        return metadata

    monkeypatch.setattr(ledger_module.os, "stat", stat_then_replace)


def assert_reopened_observation(
    root: Path, engagement_id: str, expected_raw: bytes
) -> None:
    with state_store(root, engagement_id) as reopened:
        events = reopened.ledger.events()
        assert len(events) == 1
        assert reopened.checkpoint().seq == 1
        reference = ArtifactRef.from_dict(events[0].payload["artifact_ref"])
        assert reopened.cas.get(reference) == expected_raw


def test_full_raw_output_is_encrypted_and_retrievable_without_truncation(tmp_path: Path) -> None:
    raw = (b"line with a unique raw marker\n" * 1200) + b"tail"
    with state_store(tmp_path, "eng.alpha") as store:
        event, reference = store.append_observation(
            actor_stream="researcher",
            event_type="tool.observation",
            raw_output=raw,
            metadata={"tool": "loopback"},
            media_type="text/plain",
        )
        assert event.payload["artifact_ref"] == reference.to_dict()
        assert store.cas.get(reference) == raw
        encrypted = blob_path(tmp_path, reference).read_bytes()
        assert raw[:64] not in encrypted
        assert b"unique raw marker" not in encrypted
        assert raw not in database_path(tmp_path, "eng.alpha").read_bytes()


def test_bounded_cursor_reads_all_bytes_and_rejects_tampering(tmp_path: Path) -> None:
    raw = bytes(range(256)) * 100
    with EncryptedCAS(tmp_path, "eng.cursor", key()) as cas:
        reference = cas.put(raw)
        first = cas.read_page(reference, max_bytes=997)
        assert first.offset == 0
        assert first.next_cursor is not None
        pieces = [first.data]
        cursor = first.next_cursor
        while cursor is not None:
            page = cas.read_page(reference, cursor=cursor, max_bytes=997)
            pieces.append(page.data)
            cursor = page.next_cursor
        assert b"".join(pieces) == raw
        assert first.next_cursor is not None
        tampered = first.next_cursor[:-1] + ("A" if first.next_cursor[-1] != "A" else "B")
        with pytest.raises(StorageError, match="cursor"):
            cas.read_page(reference, cursor=tampered)
        with pytest.raises(StorageError, match="bounded"):
            cas.read_page(reference, max_bytes=1024 * 1024 + 1)


def test_cas_rejects_wrong_key_cross_engagement_and_ciphertext_tamper(tmp_path: Path) -> None:
    with EncryptedCAS(tmp_path, "eng.one", key()) as first:
        reference = first.put(b"evidence")
    with EncryptedCAS(tmp_path, "eng.one", EngagementKey(b"x" * 32)) as wrong_key:
        with pytest.raises(ChainIntegrityError, match="authentication"):
            wrong_key.get(reference)
    with EncryptedCAS(tmp_path, "eng.two", key()) as second:
        with pytest.raises(CrossEngagementError):
            second.get(reference)
    namespace = hashlib.sha256(reference.engagement_id.encode()).hexdigest()
    path = tmp_path / namespace / reference.sha256[:2] / f"{reference.sha256}.flcas"
    envelope = bytearray(path.read_bytes())
    envelope[-1] ^= 1
    path.write_bytes(envelope)
    with EncryptedCAS(tmp_path, "eng.one", key()) as first:
        with pytest.raises(ChainIntegrityError, match="authentication"):
            first.get(reference)


def test_same_content_can_have_multiple_descriptive_media_types(tmp_path: Path) -> None:
    with EncryptedCAS(tmp_path, "eng.media", key()) as cas:
        text = cas.put(b"same", media_type="text/plain")
        binary = cas.put(b"same", media_type="application/octet-stream")
        assert text.sha256 == binary.sha256
        assert cas.get(text) == cas.get(binary) == b"same"
        assert len(cas.blob_digests()) == 1


@pytest.mark.parametrize("operation", ["get", "put"])
def test_cas_final_name_swap_after_descriptor_read_fails_closed_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    cas_root = tmp_path / "cas"
    engagement_id = f"eng.final-swap-{operation}"
    raw = b"descriptor-bound evidence"
    cas = EncryptedCAS(cas_root, engagement_id, key())
    reference = cas.put(raw)
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    final = (
        cas_root
        / namespace
        / reference.sha256[:2]
        / f"{reference.sha256}.flcas"
    )
    replacement = final.with_name(".executable-final-swap")
    replacement.write_bytes(final.read_bytes())
    replacement.chmod(0o600)
    original_decrypt = cas._decrypt
    swapped = False

    def decrypt_then_swap(candidate: ArtifactRef, envelope: bytes) -> bytes:
        nonlocal swapped
        plaintext = original_decrypt(candidate, envelope)
        if not swapped:
            os.replace(replacement, final)
            swapped = True
        return plaintext

    monkeypatch.setattr(cas, "_decrypt", decrypt_then_swap)
    with pytest.raises(ChainIntegrityError, match="final name changed"):
        if operation == "get":
            cas.get(reference)
        else:
            cas.put(raw)
    assert swapped
    cas.close()

    with EncryptedCAS(cas_root, engagement_id, key()) as reopened:
        assert reopened.get(reference) == raw


def test_content_id_is_deterministic_but_initial_encryption_is_randomized(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    with EncryptedCAS(first_root, "eng.random", key()) as first:
        one = first.put(b"same")
        first_path = (
            first_root
            / hashlib.sha256(b"eng.random").hexdigest()
            / one.sha256[:2]
            / f"{one.sha256}.flcas"
        )
        ciphertext = first_path.read_bytes()
        again = first.put(b"same")
        assert first_path.read_bytes() == ciphertext
    with EncryptedCAS(second_root, "eng.random", key()) as second:
        two = second.put(b"same")
        second_path = (
            second_root
            / hashlib.sha256(b"eng.random").hexdigest()
            / two.sha256[:2]
            / f"{two.sha256}.flcas"
        )
    assert one.sha256 == again.sha256 == two.sha256
    assert ciphertext != second_path.read_bytes()


def test_key_is_redacted_and_not_pickleable() -> None:
    engagement_key = key()
    assert repr(engagement_key) == "EngagementKey(<redacted>)"
    assert KEY_BYTES.hex() not in repr(engagement_key)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(engagement_key)


def test_event_chain_round_trip_and_append_only_sql_triggers(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with EventLedger(path, "eng.ledger", key()) as ledger:
        one = ledger.append(
            actor_stream="researcher", event_type="delta", payload={"value": 1}
        )
        two = ledger.append(
            actor_stream="verifier", event_type="proposal", payload={"value": 2}
        )
        assert two.prev_hash == one.event_hash
        assert ledger.verify_chain() == two.event_hash
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            ledger._connection.execute("UPDATE events SET event_type = 'changed' WHERE seq = 1")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            ledger._connection.execute("DELETE FROM events WHERE seq = 1")
        assert [event.seq for event in ledger.events()] == [1, 2]


def test_events_rejects_committed_payload_tamper_with_exact_trigger_restored(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    ledger = EventLedger(path, "eng.read-events-tamper", key())
    ledger.append(
        actor_stream="researcher",
        event_type="baseline",
        payload={"visible": "authentic"},
    )
    mutate_ledger_with_exact_trigger_restore(
        path,
        trigger="events_no_update",
        statement="UPDATE events SET payload_json=? WHERE seq=1",
        parameters=('{"visible":"forged"}',),
    )

    with pytest.raises(ChainIntegrityError, match="payload digest mismatch"):
        ledger.events()
    assert not ledger._connection.in_transaction
    with pytest.raises(ChainIntegrityError, match="payload digest mismatch"):
        ledger.close()
    assert ledger._closed


def test_event_hash_at_rejects_committed_hash_tamper_with_exact_trigger_restored(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    ledger = EventLedger(path, "eng.read-hash-tamper", key())
    ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 1}
    )
    mutate_ledger_with_exact_trigger_restore(
        path,
        trigger="events_no_update",
        statement="UPDATE events SET event_hash=? WHERE seq=1",
        parameters=("f" * 64,),
    )

    with pytest.raises(ChainIntegrityError, match="event hash mismatch"):
        ledger.event_hash_at(1)
    assert not ledger._connection.in_transaction
    with pytest.raises(ChainIntegrityError, match="event hash mismatch"):
        ledger.close()
    assert ledger._closed


def test_search_rejects_committed_title_tamper_with_exact_trigger_restored(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    ledger = EventLedger(path, "eng.read-search-tamper", key())
    source = ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 1}
    )
    ledger.add_search_document(
        doc_id="doc.one",
        event_seq=source.seq,
        title="authentic title",
        redacted_text="needle remains searchable",
    )
    mutate_ledger_with_exact_trigger_restore(
        path,
        trigger="search_documents_no_update",
        statement="UPDATE search_documents SET title=? WHERE doc_id='doc.one'",
        parameters=("forged title",),
    )

    with pytest.raises(ChainIntegrityError, match="FTS projection|search projection"):
        ledger.search("needle")
    assert not ledger._connection.in_transaction
    with pytest.raises(ChainIntegrityError, match="FTS projection|search projection"):
        ledger.close()
    assert ledger._closed


def test_neighbors_rejects_committed_edge_tamper_with_exact_trigger_restored(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    ledger = EventLedger(path, "eng.read-neighbors-tamper", key())
    source = ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 1}
    )
    ledger.add_graph_node(
        node_id="node.one", node_kind="subject", attributes={}, event_seq=source.seq
    )
    ledger.add_graph_node(
        node_id="node.two", node_kind="resource", attributes={}, event_seq=source.seq
    )
    ledger.add_graph_edge(
        edge_id="edge.one",
        source_node_id="node.one",
        target_node_id="node.two",
        edge_kind="authentic",
        attributes={},
        event_seq=source.seq,
    )
    mutate_ledger_with_exact_trigger_restore(
        path,
        trigger="graph_edges_no_update",
        statement="UPDATE graph_edges SET edge_kind=? WHERE edge_id='edge.one'",
        parameters=("forged",),
    )

    with pytest.raises(ChainIntegrityError, match="graph edge projection"):
        ledger.neighbors("node.one")
    assert not ledger._connection.in_transaction
    with pytest.raises(ChainIntegrityError, match="graph edge projection"):
        ledger.close()
    assert ledger._closed


def test_verified_public_ledger_reads_preserve_results_cursors_and_limits(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite3"
    with EventLedger(path, "eng.verified-reads", key()) as ledger:
        events = tuple(
            ledger.append(
                actor_stream="researcher",
                event_type="baseline",
                payload={"value": value},
            )
            for value in range(1, 4)
        )
        assert [record.payload["value"] for record in ledger.events(limit=2)] == [1, 2]
        assert [record.seq for record in ledger.events(after_seq=2, limit=1)] == [3]
        assert ledger.events(after_seq=events[-1].seq) == ()
        assert ledger.event_hash_at(2) == events[1].event_hash
        assert not ledger._connection.in_transaction
        with pytest.raises(ChainIntegrityError, match="sequence is missing"):
            ledger.event_hash_at(999)
        assert not ledger._connection.in_transaction

        for suffix in ("one", "two"):
            ledger.add_search_document(
                doc_id=f"doc.{suffix}",
                event_seq=events[0].seq,
                title=f"title {suffix}",
                redacted_text="common needle",
            )
        hits = ledger.search("needle", limit=1)
        assert len(hits) == 1
        assert hits[0]["doc_id"] == "doc.one"
        assert ledger.search("absent") == ()
        with pytest.raises(StorageError, match="search query failed closed"):
            ledger.search('"')
        assert not ledger._connection.in_transaction

        for suffix in ("one", "two", "three"):
            ledger.add_graph_node(
                node_id=f"node.{suffix}",
                node_kind="subject",
                attributes={"suffix": suffix},
                event_seq=events[0].seq,
            )
        for suffix, target in (("one", "two"), ("two", "three")):
            ledger.add_graph_edge(
                edge_id=f"edge.{suffix}",
                source_node_id="node.one",
                target_node_id=f"node.{target}",
                edge_kind="reads",
                attributes={"suffix": suffix},
                event_seq=events[0].seq,
            )
        adjacent = ledger.neighbors("node.one", limit=1)
        assert len(adjacent) == 1
        assert adjacent[0]["edge_id"] == "edge.one"
        assert ledger.neighbors("node.none") == ()
        assert not ledger._connection.in_transaction


def test_in_transaction_hash_lookup_supports_anchor_recovery_and_close_paths(
    tmp_path: Path,
) -> None:
    store = state_store(tmp_path, "eng.internal-hash-read")
    first = store.ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 1}
    )
    with pytest.raises(StorageError, match="active transaction"):
        store.ledger._event_hash_at_in_transaction(first.seq)
    assert store.checkpoint().seq == first.seq

    second = store.ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 2}
    )
    assert store.checkpoint().seq == second.seq
    third = store.ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 3}
    )
    assert store.recover().anchor.seq == third.seq
    store.ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 4}
    )
    store.close()
    assert store._closed


def test_chain_detects_offline_database_tampering(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with EventLedger(path, "eng.tamper", key()) as ledger:
        ledger.append(actor_stream="researcher", event_type="delta", payload={"safe": True})
    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER events_no_update")
    raw.execute("UPDATE events SET payload_json = '{\"safe\":false}' WHERE seq = 1")
    raw.commit()
    raw.close()
    with pytest.raises(ChainIntegrityError, match="schema manifest|payload digest"):
        EventLedger(path, "eng.tamper", key())


def test_derived_index_tampering_is_detected_against_chain_anchor(tmp_path: Path) -> None:
    path = database_path(tmp_path, "eng.index-tamper")
    with state_store(tmp_path, "eng.index-tamper") as store:
        event, reference = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"raw",
            metadata={},
        )
        store.index_observation(
            doc_id="doc.anchor",
            event=event,
            reference=reference,
            title="anchored",
            redacted_text="safe projection",
        )
    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER search_documents_no_update")
    raw.execute("UPDATE search_documents SET redacted_text='tampered'")
    raw.commit()
    raw.close()
    with pytest.raises(ChainIntegrityError, match="schema manifest|search projection"):
        EventLedger(path, "eng.index-tamper", key())


def test_artifact_registry_requires_reference_in_hashed_payload(tmp_path: Path) -> None:
    reference = ArtifactRef(
        engagement_id="eng.artifact-anchor",
        sha256=hashlib.sha256(b"raw").hexdigest(),
        byte_length=3,
    )
    with EventLedger(tmp_path / "state.sqlite3", "eng.artifact-anchor", key()) as ledger:
        with pytest.raises(StorageError, match="exactly match"):
            ledger.append(
                actor_stream="researcher",
                event_type="observation",
                payload={"missing": True},
                artifacts=(reference,),
            )


def test_unregistered_payload_artifact_is_rejected(tmp_path: Path) -> None:
    reference = ArtifactRef(
        engagement_id="eng.unregistered",
        sha256=hashlib.sha256(b"raw").hexdigest(),
        byte_length=3,
    )
    with EventLedger(tmp_path / "state.sqlite3", "eng.unregistered", key()) as ledger:
        with pytest.raises(StorageError, match="exactly match"):
            ledger.append(
                actor_stream="researcher",
                event_type="observation",
                payload={"artifact_ref": reference.to_dict()},
            )


def test_ledger_rejects_cross_engagement_open(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with EventLedger(path, "eng.original", key()):
        pass
    with pytest.raises(CrossEngagementError):
        EventLedger(path, "eng.other", key())


@pytest.mark.parametrize(
    "payload",
    [
        {"float": 0.1},
        {"too_large": 2**63},
        {"bytes": b"raw"},
        {1: "non-string-key"},
    ],
)
def test_event_canonical_profile_rejects_ambiguous_values(
    tmp_path: Path, payload: dict[object, object]
) -> None:
    with EventLedger(tmp_path / "state.sqlite3", "eng.canonical", key()) as ledger:
        with pytest.raises(StorageError):
            ledger.append(actor_stream="researcher", event_type="delta", payload=payload)


def test_search_projection_and_graph_are_append_only(tmp_path: Path) -> None:
    with state_store(tmp_path, "eng.index") as store:
        event, reference = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"secret raw bytes are not indexed",
            metadata={"redacted": True},
        )
        store.index_observation(
            doc_id="doc.one",
            event=event,
            reference=reference,
            title="authorization finding",
            redacted_text="tenant boundary negative control",
        )
        hits = store.ledger.search("tenant AND boundary")
        assert hits[0]["doc_id"] == "doc.one"
        store.ledger.add_graph_node(
            node_id="subject.owner",
            node_kind="subject",
            attributes={"role": "owner"},
            event_seq=event.seq,
        )
        store.ledger.add_graph_node(
            node_id="resource.one", node_kind="resource", attributes={}, event_seq=event.seq
        )
        store.ledger.add_graph_edge(
            edge_id="edge.reads",
            source_node_id="subject.owner",
            target_node_id="resource.one",
            edge_kind="reads",
            attributes={"verified": True},
            event_seq=event.seq,
        )
        assert store.ledger.neighbors("subject.owner")[0]["target_node_id"] == "resource.one"
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            store.ledger._connection.execute(
                "UPDATE graph_nodes SET node_kind='changed' WHERE node_id='subject.owner'"
            )


def test_recovery_quarantines_uncommitted_cas_write(tmp_path: Path) -> None:
    with state_store(tmp_path, "eng.recover") as store:
        committed_event, committed = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"committed",
            metadata={},
        )
        assert committed_event.seq == 1
        orphan = store.cas.put(b"crashed before ledger commit")
        report = store.recover()
        assert committed.sha256 in report.verified_artifacts
        assert len(report.verified_artifacts) == 2
        assert report.quarantined_orphans == (orphan.sha256,)
        assert report.recovery_id is not None
        assert store.cas.blob_digests() == report.verified_artifacts
        assert store.cas.get(committed) == b"committed"


def test_recovery_quarantines_interrupted_prepublication_write(tmp_path: Path) -> None:
    engagement_id = "eng.interrupted"
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    with state_store(tmp_path, engagement_id) as store:
        shard = state_root(tmp_path) / "cas" / namespace / "ab"
        shard.mkdir(mode=0o700)
        temporary = shard / (".tmp-" + "1" * 32)
        temporary.write_bytes(b"partial encrypted envelope")
        temporary.chmod(0o600)
        report = store.recover()
        assert report.quarantined_interrupted_writes == (
            "ab/.tmp-" + "1" * 32,
        )
        assert report.recovery_id is not None
        assert not temporary.exists()
        assert store.cas.temporary_entries() == ()


def test_recovery_fails_if_ledger_artifact_is_missing(tmp_path: Path) -> None:
    with state_store(tmp_path, "eng.missing") as store:
        _, reference = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"must remain",
            metadata={},
        )
        store.cas.quarantine_orphan(reference.sha256, recovery_id="manual-test")
        with pytest.raises(ChainIntegrityError, match="missing"):
            store.recover()


def test_concurrent_appends_have_one_contiguous_chain(tmp_path: Path) -> None:
    with EventLedger(tmp_path / "state.sqlite3", "eng.concurrent", key()) as ledger:
        def append(index: int) -> int:
            return ledger.append(
                actor_stream=f"actor.{index % 3}",
                event_type="delta",
                payload={"index": index},
            ).seq

        with ThreadPoolExecutor(max_workers=8) as pool:
            sequences = sorted(pool.map(append, range(40)))
        assert sequences == list(range(1, 41))
        assert len(ledger.events(limit=100)) == 40
        ledger.verify_chain()


def test_committed_wal_event_survives_abrupt_process_exit(tmp_path: Path) -> None:
    script = f"""
import os
from pathlib import Path
from faultloom.state import EngagementKey, StateStore
base = Path({str(tmp_path)!r})
store = StateStore(
    base / 'state',
    'eng.crash',
    EngagementKey(bytes(range(32))),
    anchor_root=base / 'anchor',
)
store.append_observation(
    actor_stream='researcher', event_type='observation', raw_output=b'durable', metadata={{}}
)
os._exit(0)
"""
    environment = os.environ.copy()
    source_root = Path(__file__).parents[2] / "packages" / "runtime" / "src"
    environment["PYTHONPATH"] = str(source_root)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        env=environment,
        check=False,
        timeout=20,
    )
    assert completed.returncode == 0
    with state_store(tmp_path, "eng.crash") as reopened:
        assert reopened.ledger.events()[0].seq == 1
        report = reopened.recover()
        assert len(report.verified_artifacts) == 2


def test_authenticated_committed_tail_is_recovered_and_anchored_once(
    tmp_path: Path,
) -> None:
    engagement_id = "eng.authenticated-tail"
    with state_store(tmp_path, engagement_id) as store:
        store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"anchored",
            metadata={},
        )
        trusted = store.checkpoint()

    anchor_path = (
        anchor_root(tmp_path)
        / "anchors"
        / f"{hashlib.sha256(engagement_id.encode()).hexdigest()}.anchor"
    )
    anchor_before = anchor_path.read_bytes()
    script = r'''
import os
import sys

source_root, database, engagement_id = sys.argv[1:]
sys.path.insert(0, source_root)
from faultloom.state import EngagementKey, EventLedger

ledger = EventLedger(database, engagement_id, EngagementKey(bytes(range(32))))
tail = ledger.append(
    actor_stream="researcher",
    event_type="crash.tail",
    payload={"committed": True},
)
assert tail.seq == 2
os._exit(0)
'''
    source_root = Path(__file__).parents[2] / "packages" / "runtime" / "src"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(source_root),
            str(database_path(tmp_path, engagement_id)),
            engagement_id,
        ],
        env={},
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert anchor_path.read_bytes() == anchor_before

    with state_store(tmp_path, engagement_id, minimum_anchor=trusted) as recovered:
        assert recovered.checkpoint().seq == trusted.seq + 1
        assert [event.seq for event in recovered.ledger.events()] == [1, 2]
    with state_store(tmp_path, engagement_id, minimum_anchor=trusted) as reopened:
        assert reopened.checkpoint().seq == trusted.seq + 1
        assert [event.seq for event in reopened.ledger.events()] == [1, 2]


def test_keyless_public_hash_tail_is_rejected_without_anchor_advancement(
    tmp_path: Path,
) -> None:
    engagement_id = "eng.keyless-forgery"
    with state_store(tmp_path, engagement_id) as store:
        store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"legitimate",
            metadata={},
        )
        trusted = store.checkpoint()

    anchor_path = (
        anchor_root(tmp_path)
        / "anchors"
        / f"{hashlib.sha256(engagement_id.encode()).hexdigest()}.anchor"
    )
    anchor_before = anchor_path.read_bytes()
    script = r'''
import datetime
import hashlib
import json
import sqlite3
import sys

path, engagement_id = sys.argv[1:]
connection = sqlite3.connect(path)
last = connection.execute(
    "SELECT seq, event_hash, event_auth_tag FROM events ORDER BY seq DESC LIMIT 1"
).fetchone()
seq = last[0] + 1
payload_json = json.dumps({"forged": True}, sort_keys=True, separators=(",", ":"))
payload_sha256 = hashlib.sha256(payload_json.encode()).hexdigest()
created_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="microseconds")
body = {
    "actor_stream": "attacker",
    "created_at": created_at,
    "engagement_id": engagement_id,
    "event_type": "forged.tail",
    "payload_sha256": payload_sha256,
    "prev_hash": last[1],
    "schema_version": 2,
    "seq": seq,
}
event_hash = hashlib.sha256(
    json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
connection.execute(
    """INSERT INTO events(
           seq, schema_version, engagement_id, actor_stream, event_type,
           payload_json, payload_sha256, prev_hash, event_hash,
           prev_auth_tag, event_auth_tag, created_at
       ) VALUES (?, 2, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
    (
        seq, engagement_id, "attacker", "forged.tail", payload_json,
        payload_sha256, last[1], event_hash, last[2], "0" * 64, created_at,
    ),
)
connection.commit()
connection.close()
'''
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(database_path(tmp_path, engagement_id)),
            engagement_id,
        ],
        env={},
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr

    with pytest.raises(ChainIntegrityError, match="authentication tag mismatch"):
        state_store(tmp_path, engagement_id, minimum_anchor=trusted)
    assert anchor_path.read_bytes() == anchor_before


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        ("metadata", "metadata authentication key or schema"),
        ("schema", "schema manifest"),
        ("header", "schema version"),
    ),
)
def test_live_ledger_integrity_is_rechecked_before_verify_checkpoint_and_append(
    tmp_path: Path, mutation: str, message: str
) -> None:
    path = tmp_path / "ledger" / "state.sqlite3"
    path.parent.mkdir(mode=0o700)
    ledger = EventLedger(path, f"eng.live-{mutation}", key())
    first = ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 1}
    )
    tamper_live_ledger(path, mutation)

    with pytest.raises(StorageError, match=message):
        ledger.verify_chain()
    with pytest.raises(StorageError, match=message):
        ledger.chain_checkpoint()
    with pytest.raises(StorageError, match=message):
        ledger.append(
            actor_stream="researcher", event_type="forbidden", payload={"value": 2}
        )

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT seq, event_hash FROM events ORDER BY seq"
        ).fetchall()
    assert rows == [(1, first.event_hash)]
    with pytest.raises(StorageError, match=message):
        ledger.close()
    with pytest.raises(StorageError, match=message):
        EventLedger(path, f"eng.live-{mutation}", key())


def test_live_metadata_tamper_blocks_state_surfaces_without_advancing_anchor(
    tmp_path: Path,
) -> None:
    engagement_id = "eng.live-metadata-surfaces"
    store = state_store(tmp_path, engagement_id)
    first = store.ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 1}
    )
    assert store.checkpoint().seq == first.seq
    orphan = store.cas.put(b"must-not-be-quarantined-after-integrity-failure")
    anchor_path = (
        anchor_root(tmp_path)
        / "anchors"
        / f"{hashlib.sha256(engagement_id.encode()).hexdigest()}.anchor"
    )
    anchor_before = anchor_path.read_bytes()
    path = database_path(tmp_path, engagement_id)
    tamper_live_ledger(path, "metadata")

    with pytest.raises(ChainIntegrityError, match="metadata authentication key"):
        store.checkpoint()
    assert anchor_path.read_bytes() == anchor_before
    with pytest.raises(ChainIntegrityError, match="metadata authentication key"):
        store.ledger.append(
            actor_stream="researcher", event_type="forbidden", payload={"value": 2}
        )
    assert anchor_path.read_bytes() == anchor_before
    with pytest.raises(ChainIntegrityError, match="metadata authentication key"):
        store.recover()
    assert orphan.sha256 in store.cas.blob_digests()
    assert anchor_path.read_bytes() == anchor_before
    with pytest.raises(ChainIntegrityError, match="metadata authentication key"):
        store.close()
    assert store._closed
    assert anchor_path.read_bytes() == anchor_before

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT seq, event_hash FROM events ORDER BY seq"
        ).fetchall()
    assert rows == [(1, first.event_hash)]
    with pytest.raises(ChainIntegrityError, match="metadata authentication key"):
        state_store(tmp_path, engagement_id)


def test_anchor_decision_holds_sqlite_writer_lock_until_persisted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engagement_id = "eng.anchor-transaction"
    store = state_store(tmp_path, engagement_id)
    first = store.ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 1}
    )
    assert store.checkpoint().seq == first.seq

    callback = store.ledger._commit_callback
    store.ledger._commit_callback = None
    try:
        tail = store.ledger.append(
            actor_stream="researcher", event_type="crash.tail", payload={"value": 2}
        )
    finally:
        store.ledger._commit_callback = callback
    assert store.anchor.load_optional().seq == first.seq

    path = database_path(tmp_path, engagement_id)
    with sqlite3.connect(path) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' "
            "AND name='ledger_metadata_no_update'"
        ).fetchone()[0]
    started = threading.Event()
    finished = threading.Event()
    failures: list[BaseException] = []

    def tamper_while_anchor_is_written() -> None:
        try:
            with sqlite3.connect(path, timeout=5.0) as connection:
                started.set()
                connection.execute("DROP TRIGGER ledger_metadata_no_update")
                connection.execute(
                    "UPDATE ledger_metadata SET value=? "
                    "WHERE key='event_auth_key_commitment'",
                    ("0" * 64,),
                )
                connection.execute(trigger)
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            finished.set()

    worker = threading.Thread(target=tamper_while_anchor_is_written)
    original_write = store.anchor.write

    def write_while_tamper_waits(checkpoint: AnchorCheckpoint) -> None:
        worker.start()
        assert started.wait(timeout=2.0)
        assert not finished.wait(timeout=0.25)
        original_write(checkpoint)

    monkeypatch.setattr(store.anchor, "write", write_while_tamper_waits)
    checkpoint = store.checkpoint()
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    assert failures == []
    assert checkpoint.seq == tail.seq
    anchor_path = (
        anchor_root(tmp_path)
        / "anchors"
        / f"{hashlib.sha256(engagement_id.encode()).hexdigest()}.anchor"
    )
    anchor_after = anchor_path.read_bytes()

    with pytest.raises(ChainIntegrityError, match="metadata authentication key"):
        store.checkpoint()
    assert anchor_path.read_bytes() == anchor_after
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == 2
    with pytest.raises(ChainIntegrityError, match="metadata authentication key"):
        store.close()


def test_recovery_holds_verified_writer_snapshot_through_cas_decisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engagement_id = "eng.recovery-transaction"
    store = state_store(tmp_path, engagement_id)
    event, raw_reference = store.append_observation(
        actor_stream="researcher",
        event_type="observation",
        raw_output=b"must-remain-retrievable",
        metadata={"source": "loopback"},
    )
    metadata_reference = ArtifactRef.from_dict(event.payload["metadata_ref"])
    orphan = store.cas.put(b"one-unreferenced-object")
    path = database_path(tmp_path, engagement_id)
    anchor_path = (
        anchor_root(tmp_path)
        / "anchors"
        / f"{hashlib.sha256(engagement_id.encode()).hexdigest()}.anchor"
    )
    anchor_before = anchor_path.read_bytes()
    with sqlite3.connect(path) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' "
            "AND name='artifacts_no_delete'"
        ).fetchone()[0]

    started = threading.Event()
    finished = threading.Event()
    failures: list[BaseException] = []

    def delete_projection_while_recovery_runs() -> None:
        try:
            with sqlite3.connect(path, timeout=5.0) as connection:
                started.set()
                connection.execute("DROP TRIGGER artifacts_no_delete")
                connection.execute("DELETE FROM artifacts")
                connection.execute(trigger)
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            finished.set()

    worker = threading.Thread(target=delete_projection_while_recovery_runs)
    original_temporary_entries = store.cas.temporary_entries
    writer_blocked: list[bool] = []

    def temporary_entries_while_writer_waits():
        worker.start()
        assert started.wait(timeout=2.0)
        writer_blocked.append(not finished.wait(timeout=0.25))
        return original_temporary_entries()

    monkeypatch.setattr(store.cas, "temporary_entries", temporary_entries_while_writer_waits)
    report = store.recover()
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    assert failures == []
    assert writer_blocked == [True]
    assert report.quarantined_orphans == (orphan.sha256,)
    assert raw_reference.sha256 in store.cas.blob_digests()
    assert metadata_reference.sha256 in store.cas.blob_digests()
    assert anchor_path.read_bytes() == anchor_before

    with pytest.raises(ChainIntegrityError, match="artifact registry is incomplete"):
        store.checkpoint()
    with pytest.raises(ChainIntegrityError, match="artifact registry is incomplete"):
        store.close()


def test_close_holds_verified_writer_snapshot_through_component_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engagement_id = "eng.close-transaction"
    store = state_store(tmp_path, engagement_id)
    first = store.ledger.append(
        actor_stream="researcher", event_type="baseline", payload={"value": 1}
    )
    assert store.checkpoint().seq == first.seq
    path = database_path(tmp_path, engagement_id)
    anchor_path = (
        anchor_root(tmp_path)
        / "anchors"
        / f"{hashlib.sha256(engagement_id.encode()).hexdigest()}.anchor"
    )
    anchor_before = anchor_path.read_bytes()
    with sqlite3.connect(path) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' "
            "AND name='ledger_metadata_no_update'"
        ).fetchone()[0]

    started = threading.Event()
    finished = threading.Event()
    failures: list[BaseException] = []

    def tamper_while_close_finishes_components() -> None:
        try:
            with sqlite3.connect(path, timeout=5.0) as connection:
                started.set()
                connection.execute("DROP TRIGGER ledger_metadata_no_update")
                connection.execute(
                    "UPDATE ledger_metadata SET value=? "
                    "WHERE key='event_auth_key_commitment'",
                    ("0" * 64,),
                )
                connection.execute(trigger)
        except BaseException as exc:  # pragma: no cover - surfaced below
            failures.append(exc)
        finally:
            finished.set()

    worker = threading.Thread(target=tamper_while_close_finishes_components)
    original_cas_close = store.cas.close
    writer_blocked: list[bool] = []
    invoked = False

    def close_cas_while_writer_waits() -> None:
        nonlocal invoked
        if not invoked:
            invoked = True
            worker.start()
            assert started.wait(timeout=2.0)
            writer_blocked.append(not finished.wait(timeout=0.25))
        original_cas_close()

    monkeypatch.setattr(store.cas, "close", close_cas_while_writer_waits)
    store.close()
    worker.join(timeout=5.0)
    assert not worker.is_alive()
    assert failures == []
    assert writer_blocked == [True]
    assert store._closed
    assert anchor_path.read_bytes() == anchor_before
    with pytest.raises(ChainIntegrityError, match="metadata authentication key"):
        state_store(tmp_path, engagement_id)


@pytest.mark.parametrize("sidecar_suffix", ["-wal", "-shm"])
def test_append_rejects_identical_sqlite_sidecar_replacement_before_return(
    tmp_path: Path, sidecar_suffix: str
) -> None:
    path = tmp_path / "ledger" / "state.sqlite3"
    path.parent.mkdir(mode=0o700)
    state = {"armed": False, "replaced": False}

    def replace_after_commit() -> None:
        if state["armed"] and not state["replaced"]:
            replace_private_file_with_identical_copy(
                Path(f"{path}{sidecar_suffix}"),
                tmp_path / "append-displaced",
            )
            state["replaced"] = True

    ledger = EventLedger(
        path, "eng.sidecar-append", key(), commit_callback=replace_after_commit
    )
    ledger.append(actor_stream="researcher", event_type="baseline", payload={"value": 1})
    state["armed"] = True
    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.append(actor_stream="researcher", event_type="delta", payload={"value": 2})
    assert state["replaced"]
    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.close()
    assert ledger._closed
    assert ledger._sidecar_descriptors == {}


@pytest.mark.parametrize("sidecar_suffix", ["-wal", "-shm"])
def test_append_rejects_sidecar_swap_after_stale_stat_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sidecar_suffix: str,
) -> None:
    path = tmp_path / "ledger" / "state.sqlite3"
    path.parent.mkdir(mode=0o700)
    state = {"armed": False, "replaced": False}

    def arm_after_commit() -> None:
        state["armed"] = True

    ledger = EventLedger(
        path,
        "eng.sidecar-stale-stat-append",
        key(),
        commit_callback=arm_after_commit,
    )
    ledger.append(actor_stream="researcher", event_type="baseline", payload={"value": 1})
    state["armed"] = False
    install_stale_sidecar_stat_swap(
        monkeypatch,
        ledger,
        path,
        sidecar_suffix,
        tmp_path / "stale-stat-append-displaced",
        state,
    )

    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.append(actor_stream="researcher", event_type="delta", payload={"value": 2})
    assert state["replaced"]
    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.close()
    assert ledger._closed
    assert ledger._sidecar_descriptors == {}


@pytest.mark.parametrize("sidecar_suffix", ["-wal", "-shm"])
def test_checkpoint_rejects_identical_sqlite_sidecar_replacement_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sidecar_suffix: str,
) -> None:
    path = tmp_path / "ledger" / "state.sqlite3"
    path.parent.mkdir(mode=0o700)
    ledger = EventLedger(path, "eng.sidecar-checkpoint", key())
    ledger.append(actor_stream="researcher", event_type="delta", payload={"value": 1})
    verify_snapshot = ledger._verify_snapshot

    def verify_then_replace(*, check_fts: bool) -> tuple[int, str]:
        checkpoint = verify_snapshot(check_fts=check_fts)
        replace_private_file_with_identical_copy(
            Path(f"{path}{sidecar_suffix}"),
            tmp_path / "checkpoint-displaced",
        )
        return checkpoint

    monkeypatch.setattr(ledger, "_verify_snapshot", verify_then_replace)
    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.chain_checkpoint()
    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.close()
    assert ledger._closed
    assert ledger._sidecar_descriptors == {}


@pytest.mark.parametrize("sidecar_suffix", ["-wal", "-shm"])
def test_checkpoint_rejects_sidecar_swap_after_stale_stat_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sidecar_suffix: str,
) -> None:
    path = tmp_path / "ledger" / "state.sqlite3"
    path.parent.mkdir(mode=0o700)
    state = {"armed": False, "replaced": False}
    ledger = EventLedger(path, "eng.sidecar-stale-stat-checkpoint", key())
    ledger.append(actor_stream="researcher", event_type="delta", payload={"value": 1})
    install_stale_sidecar_stat_swap(
        monkeypatch,
        ledger,
        path,
        sidecar_suffix,
        tmp_path / "stale-stat-checkpoint-displaced",
        state,
    )
    verify_snapshot = ledger._verify_snapshot

    def verify_then_arm(*, check_fts: bool) -> tuple[int, str]:
        checkpoint = verify_snapshot(check_fts=check_fts)
        state["armed"] = True
        return checkpoint

    monkeypatch.setattr(ledger, "_verify_snapshot", verify_then_arm)
    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.chain_checkpoint()
    assert state["replaced"]
    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.close()
    assert ledger._closed
    assert ledger._sidecar_descriptors == {}


@pytest.mark.parametrize("sidecar_suffix", ["-wal", "-shm"])
def test_close_rejects_identical_sqlite_sidecar_replacement_and_releases_resources(
    tmp_path: Path, sidecar_suffix: str
) -> None:
    path = tmp_path / "ledger" / "state.sqlite3"
    path.parent.mkdir(mode=0o700)
    state = {"armed": False, "validations": 0}

    def replace_after_final_preclose_validation() -> None:
        if not state["armed"]:
            return
        state["validations"] += 1
        if state["validations"] == 2:
            replace_private_file_with_identical_copy(
                Path(f"{path}{sidecar_suffix}"),
                tmp_path / "close-displaced",
            )

    ledger = EventLedger(
        path,
        "eng.sidecar-close",
        key(),
        path_validator=replace_after_final_preclose_validation,
    )
    ledger.append(actor_stream="researcher", event_type="delta", payload={"value": 1})
    state["armed"] = True
    with pytest.raises(StorageError, match="event ledger sidecar"):
        ledger.close()
    assert state["validations"] == 2
    assert ledger._closed
    assert ledger._sidecar_descriptors == {}


def test_sqlite_sidecar_create_remove_and_reopen_lifecycle_is_allowed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ledger" / "state.sqlite3"
    path.parent.mkdir(mode=0o700)
    sidecars = tuple(Path(f"{path}{suffix}") for suffix in ("-wal", "-shm"))
    assert not any(sidecar.exists() for sidecar in sidecars)

    for generation in (1, 2):
        ledger = EventLedger(path, "eng.sidecar-lifecycle", key())
        for sidecar in sidecars:
            metadata = sidecar.stat()
            assert stat.S_IMODE(metadata.st_mode) == 0o600
            assert metadata.st_nlink == 1
        ledger.append(
            actor_stream="researcher",
            event_type="delta",
            payload={"generation": generation},
        )
        assert ledger.chain_checkpoint()[0] == generation
        ledger.close()
        assert ledger._closed
        assert ledger._sidecar_descriptors == {}
        assert not any(sidecar.exists() for sidecar in sidecars)


def test_terminal_symlink_roots_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(StorageError, match="symlink"):
        EncryptedCAS(link, "eng.link", key())
    ledger_link = tmp_path / "ledger-link"
    ledger_link.symlink_to(real / "state.sqlite3")
    with pytest.raises(StorageError, match="symlink"):
        EventLedger(ledger_link, "eng.link", key())


@pytest.mark.parametrize("root_kind", ["state", "anchor"])
def test_append_rejects_live_private_root_replacement_at_transaction_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_kind: str
) -> None:
    engagement_id = f"eng.append-root-{root_kind}"
    raw = b"committed before root replacement detection"
    store = state_store(tmp_path, engagement_id)
    visible = state_root(tmp_path) if root_kind == "state" else anchor_root(tmp_path)
    displaced = tmp_path / f"{root_kind}-append-displaced"
    synchronize = store._synchronize_anchor
    calls = 0

    def synchronize_then_replace() -> AnchorCheckpoint:
        nonlocal calls
        checkpoint = synchronize()
        calls += 1
        if calls == 2:
            replace_private_directory(visible, displaced)
        return checkpoint

    monkeypatch.setattr(store, "_synchronize_anchor", synchronize_then_replace)
    with pytest.raises(StorageError, match="visible path identity changed"):
        store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=raw,
            metadata={},
        )
    assert calls == 2
    with pytest.raises(StorageError, match="visible path identity changed"):
        store.close()
    assert store._closed
    assert_reopened_observation(tmp_path, engagement_id, raw)


@pytest.mark.parametrize("root_kind", ["state", "anchor"])
def test_checkpoint_rejects_live_private_root_replacement_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_kind: str
) -> None:
    engagement_id = f"eng.checkpoint-root-{root_kind}"
    raw = b"checkpoint root binding"
    store = state_store(tmp_path, engagement_id)
    store.append_observation(
        actor_stream="researcher",
        event_type="observation",
        raw_output=raw,
        metadata={},
    )
    visible = state_root(tmp_path) if root_kind == "state" else anchor_root(tmp_path)
    displaced = tmp_path / f"{root_kind}-checkpoint-displaced"
    synchronize = store._synchronize_anchor

    def synchronize_then_replace() -> AnchorCheckpoint:
        checkpoint = synchronize()
        replace_private_directory(visible, displaced)
        return checkpoint

    monkeypatch.setattr(store, "_synchronize_anchor", synchronize_then_replace)
    with pytest.raises(StorageError, match="visible path identity changed"):
        store.checkpoint()
    with pytest.raises(StorageError, match="visible path identity changed"):
        store.close()
    assert store._closed
    assert_reopened_observation(tmp_path, engagement_id, raw)


@pytest.mark.parametrize("root_kind", ["state", "anchor"])
def test_close_rejects_live_private_root_replacement_and_releases_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root_kind: str
) -> None:
    engagement_id = f"eng.close-root-{root_kind}"
    raw = b"close root binding"
    store = state_store(tmp_path, engagement_id)
    store.append_observation(
        actor_stream="researcher",
        event_type="observation",
        raw_output=raw,
        metadata={},
    )
    visible = state_root(tmp_path) if root_kind == "state" else anchor_root(tmp_path)
    displaced = tmp_path / f"{root_kind}-close-displaced"
    synchronize = store._synchronize_anchor

    def synchronize_then_replace() -> AnchorCheckpoint:
        checkpoint = synchronize()
        replace_private_directory(visible, displaced)
        return checkpoint

    monkeypatch.setattr(store, "_synchronize_anchor", synchronize_then_replace)
    with pytest.raises(StorageError, match="visible path identity changed"):
        store.close()
    assert store._closed
    assert_reopened_observation(tmp_path, engagement_id, raw)


def test_artifact_reference_schema_is_strict() -> None:
    reference = ArtifactRef(
        engagement_id="eng.strict", sha256="a" * 64, byte_length=1, media_type="text/plain"
    )
    value = reference.to_dict()
    value["unexpected"] = True
    with pytest.raises(StorageError, match="keys"):
        ArtifactRef.from_dict(value)


def test_authenticated_anchor_rejects_database_snapshot_rollback(tmp_path: Path) -> None:
    with state_store(tmp_path, "eng.rollback") as store:
        store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"one",
            metadata={},
        )
    snapshot = tmp_path / "state-snapshot"
    shutil.copytree(state_root(tmp_path), snapshot)
    with state_store(tmp_path, "eng.rollback") as store:
        store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"two",
            metadata={},
        )
        assert store.checkpoint().seq == 2
    shutil.rmtree(state_root(tmp_path))
    shutil.copytree(snapshot, state_root(tmp_path))
    with pytest.raises(ChainIntegrityError, match="behind its authenticated anchor"):
        state_store(tmp_path, "eng.rollback")


def test_direct_ledger_mutation_advances_anchor_and_rejects_rollback(
    tmp_path: Path,
) -> None:
    engagement_id = "eng.direct-anchor"
    with state_store(tmp_path, engagement_id) as store:
        event, _ = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"one",
            metadata={},
        )
    snapshot = tmp_path / "state-before-direct-mutation"
    shutil.copytree(state_root(tmp_path), snapshot)
    with state_store(tmp_path, engagement_id) as store:
        node_event = store.ledger.add_graph_node(
            node_id="node.direct",
            node_kind="subject",
            attributes={},
            event_seq=event.seq,
        )
        checkpoint = store.anchor.load_optional()
        assert checkpoint is not None
        assert checkpoint.seq == node_event.seq == 2
        assert checkpoint.head == node_event.event_hash
    shutil.rmtree(state_root(tmp_path))
    shutil.copytree(snapshot, state_root(tmp_path))
    with pytest.raises(ChainIntegrityError, match="behind its authenticated anchor"):
        state_store(tmp_path, engagement_id)


def test_existing_state_without_authenticated_anchor_fails_closed(tmp_path: Path) -> None:
    engagement_id = "eng.missing-anchor"
    with state_store(tmp_path, engagement_id) as store:
        store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"anchored",
            metadata={},
        )
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    anchor = anchor_root(tmp_path) / "anchors" / f"{namespace}.anchor"
    anchor.unlink()
    with pytest.raises(ChainIntegrityError, match="missing for existing"):
        state_store(tmp_path, engagement_id)


def test_trusted_anchor_floor_detects_whole_store_rollback(tmp_path: Path) -> None:
    with state_store(tmp_path, "eng.floor") as store:
        store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"one",
            metadata={},
        )
        old_checkpoint = store.checkpoint()
    state_snapshot = tmp_path / "state-old"
    anchor_snapshot = tmp_path / "anchor-old"
    shutil.copytree(state_root(tmp_path), state_snapshot)
    shutil.copytree(anchor_root(tmp_path), anchor_snapshot)
    with state_store(tmp_path, "eng.floor") as store:
        store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"two",
            metadata={},
        )
        trusted = store.checkpoint()
    assert trusted.seq == old_checkpoint.seq + 1
    shutil.rmtree(state_root(tmp_path))
    shutil.rmtree(anchor_root(tmp_path))
    shutil.copytree(state_snapshot, state_root(tmp_path))
    shutil.copytree(anchor_snapshot, anchor_root(tmp_path))
    with state_store(tmp_path, "eng.floor") as restored:
        assert restored.checkpoint() == old_checkpoint
    with pytest.raises(ChainIntegrityError, match="older than the trusted floor"):
        state_store(tmp_path, "eng.floor", minimum_anchor=trusted)


def test_committed_wal_tail_truncation_is_detected_by_anchor(tmp_path: Path) -> None:
    script = f"""
import os
from pathlib import Path
from faultloom.state import EngagementKey, StateStore
base = Path({str(tmp_path)!r})
store = StateStore(
    base / 'state', 'eng.wal-anchor', EngagementKey(bytes(range(32))),
    anchor_root=base / 'anchor',
)
store.append_observation(
    actor_stream='researcher', event_type='observation', raw_output=b'one', metadata={{}}
)
store.append_observation(
    actor_stream='researcher', event_type='observation', raw_output=b'two', metadata={{}}
)
os._exit(0)
"""
    environment = os.environ.copy()
    source_root = Path(__file__).parents[2] / "packages" / "runtime" / "src"
    environment["PYTHONPATH"] = str(source_root)
    completed = subprocess.run(
        [sys.executable, "-c", script], env=environment, check=False, timeout=20
    )
    assert completed.returncode == 0
    database = database_path(tmp_path, "eng.wal-anchor")
    wal = Path(f"{database}-wal")
    data = wal.read_bytes()
    assert len(data) > 1
    wal.write_bytes(data[:-1])
    Path(f"{database}-shm").unlink(missing_ok=True)
    with pytest.raises(ChainIntegrityError, match="behind its authenticated anchor"):
        state_store(tmp_path, "eng.wal-anchor")


def test_wrong_key_cannot_replace_existing_content_address(tmp_path: Path) -> None:
    with state_store(tmp_path, "eng.key") as store:
        _, reference = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"same-content",
            metadata={},
        )
    path = blob_path(tmp_path, reference)
    before = path.read_bytes()
    with pytest.raises(ChainIntegrityError, match="anchor key|tag"):
        state_store(tmp_path, "eng.key", EngagementKey(b"x" * 32))
    assert path.read_bytes() == before
    with EncryptedCAS(
        state_root(tmp_path) / "cas", "eng.key", EngagementKey(b"x" * 32)
    ) as wrong:
        with pytest.raises(ChainIntegrityError, match="authentication"):
            wrong.put(b"same-content")
    assert path.read_bytes() == before


def test_recovery_waits_for_inflight_observation_transaction(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    recovery_done = threading.Event()
    result: dict[str, object] = {}
    with state_store(tmp_path, "eng.serialized") as store:
        original = store.ledger.append

        def delayed_append(*args: object, **kwargs: object) -> object:
            entered.set()
            assert release.wait(5)
            return original(*args, **kwargs)

        store.ledger.append = delayed_append  # type: ignore[method-assign]

        def writer() -> None:
            result["event"] = store.append_observation(
                actor_stream="researcher",
                event_type="observation",
                raw_output=b"in-flight",
                metadata={},
            )[0]

        def recoverer() -> None:
            result["recovery"] = store.recover()
            recovery_done.set()

        writer_thread = threading.Thread(target=writer)
        recovery_thread = threading.Thread(target=recoverer)
        writer_thread.start()
        assert entered.wait(5)
        recovery_thread.start()
        assert not recovery_done.wait(0.2)
        release.set()
        writer_thread.join(5)
        recovery_thread.join(5)
        store.ledger.append = original  # type: ignore[method-assign]
        assert not writer_thread.is_alive()
        assert not recovery_thread.is_alive()
        report = store.recover()
        assert report.quarantined_orphans == ()
        assert len(store.ledger.events()) == 1


def test_independent_processes_share_one_engagement_transaction_lock(
    tmp_path: Path,
) -> None:
    script = f"""
import sys
from pathlib import Path
from faultloom.state import EngagementKey, StateStore
base = Path({str(tmp_path)!r})
worker = int(sys.argv[1])
with StateStore(
    base / 'state', 'eng.processes', EngagementKey(bytes(range(32))),
    anchor_root=base / 'anchor',
) as store:
    for index in range(10):
        store.append_observation(
            actor_stream=f'worker.{{worker}}',
            event_type='observation',
            raw_output=f'{{worker}}:{{index}}'.encode(),
            metadata={{'worker': worker, 'index': index}},
        )
"""
    environment = os.environ.copy()
    source_root = Path(__file__).parents[2] / "packages" / "runtime" / "src"
    environment["PYTHONPATH"] = str(source_root)
    processes = [
        subprocess.Popen([sys.executable, "-c", script, str(worker)], env=environment)
        for worker in range(2)
    ]
    assert [process.wait(timeout=30) for process in processes] == [0, 0]
    with state_store(tmp_path, "eng.processes") as store:
        events = store.ledger.events(limit=100)
        assert [event.seq for event in events] == list(range(1, 21))
        assert store.checkpoint().seq == 20
        report = store.recover()
        assert report.quarantined_orphans == ()


def test_interrupted_cas_publication_link_is_reconciled(tmp_path: Path) -> None:
    with state_store(tmp_path, "eng.publish-crash") as store:
        _, reference = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"published",
            metadata={},
        )
        final = blob_path(tmp_path, reference)
        temporary = final.parent / (".tmp-" + "a" * 32)
        os.link(final, temporary)
        assert final.stat().st_nlink == 2
        report = store.recover()
        label = f"{reference.sha256[:2]}/{temporary.name}"
        assert report.reconciled_publications == (label,)
        assert not temporary.exists()
        assert final.stat().st_nlink == 1
        assert store.cas.get(reference) == b"published"


def test_quarantine_name_swap_is_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    engagement_id = "eng.swap"
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    with state_store(tmp_path, engagement_id) as store:
        shard = state_root(tmp_path) / "cas" / namespace / "ab"
        shard.mkdir(mode=0o700)
        source = shard / (".tmp-" + "1" * 32)
        source.write_bytes(b"checked")
        source.chmod(0o600)
        real_rename = os.rename

        def swap_then_rename(
            source_name: str,
            target_name: str,
            *,
            src_dir_fd: int,
            dst_dir_fd: int,
        ) -> None:
            os.unlink(source_name, dir_fd=src_dir_fd)
            descriptor = os.open(
                source_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=src_dir_fd,
            )
            try:
                os.write(descriptor, b"replacement")
            finally:
                os.close(descriptor)
            real_rename(
                source_name,
                target_name,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
            )

        monkeypatch.setattr(cas_module.os, "rename", swap_then_rename)
        with pytest.raises(ChainIntegrityError, match="changed during quarantine"):
            store.recover()


def test_quarantine_rename_is_recoverable_after_directory_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with state_store(tmp_path, "eng.quarantine-crash") as store:
        orphan = store.cas.put(b"orphan")
        real_fsync = os.fsync
        calls = 0

        def fail_first_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("simulated crash boundary")
            real_fsync(descriptor)

        monkeypatch.setattr(cas_module.os, "fsync", fail_first_fsync)
        with pytest.raises(StorageError, match="durably quarantine"):
            store.recover()
        monkeypatch.setattr(cas_module.os, "fsync", real_fsync)
        report = store.recover()
        assert orphan.sha256 not in store.cas.blob_digests()
        assert report.quarantined_orphans == ()


def test_unknown_schema_trigger_and_fts_drift_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with EventLedger(path, "eng.schema", key()) as ledger:
        event = ledger.append(
            actor_stream="researcher", event_type="delta", payload={"n": 1}
        )
        ledger.add_search_document(
            doc_id="doc.one",
            event_seq=event.seq,
            title="title",
            redacted_text="needle",
        )
    raw = sqlite3.connect(path)
    original_trigger = raw.execute(
        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='events_no_update'"
    ).fetchone()[0]
    raw.execute("PRAGMA user_version=99")
    raw.execute("CREATE TABLE future_v99(value TEXT)")
    raw.commit()
    raw.close()
    with pytest.raises(StorageError, match="schema version"):
        EventLedger(path, "eng.schema", key())
    raw = sqlite3.connect(path)
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 99
    raw.execute(f"PRAGMA user_version={ledger_module.SCHEMA_VERSION}")
    raw.execute("DROP TABLE future_v99")
    raw.execute("DROP TRIGGER events_no_update")
    raw.execute(
        "CREATE TRIGGER events_no_update BEFORE UPDATE ON events BEGIN SELECT 1; END"
    )
    raw.commit()
    raw.close()
    with pytest.raises(ChainIntegrityError, match="schema manifest"):
        EventLedger(path, "eng.schema", key())
    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER events_no_update")
    raw.execute(original_trigger)
    raw.execute("DELETE FROM search_fts WHERE rowid=1")
    raw.commit()
    raw.close()
    with pytest.raises(ChainIntegrityError, match="FTS projection"):
        EventLedger(path, "eng.schema", key())
    with EventLedger(path, "eng.schema", key(), rebuild_fts=True) as repaired:
        assert repaired.search("needle")[0]["doc_id"] == "doc.one"
    with EventLedger(path, "eng.schema", key()) as verified:
        verified.verify_chain()


@pytest.mark.parametrize(
    ("trigger", "statement", "message"),
    [
        (
            "artifacts_no_delete",
            "DELETE FROM artifacts",
            "artifact registry is incomplete",
        ),
        (
            "search_documents_no_delete",
            "DELETE FROM search_documents",
            "search projection is incomplete",
        ),
        (
            "graph_edges_no_delete",
            "DELETE FROM graph_edges",
            "graph edge projection is incomplete",
        ),
        (
            "graph_nodes_no_delete",
            "DELETE FROM graph_nodes",
            "graph node projection is incomplete",
        ),
    ],
)
def test_projection_row_deletion_is_detected_from_anchored_events(
    tmp_path: Path,
    trigger: str,
    statement: str,
    message: str,
) -> None:
    path = database_path(tmp_path, "eng.projection-completeness")
    with state_store(tmp_path, "eng.projection-completeness") as store:
        event, reference = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"raw",
            metadata={},
        )
        if statement == "DELETE FROM search_documents":
            store.index_observation(
                doc_id="doc.one",
                event=event,
                reference=reference,
                title="title",
                redacted_text="needle",
            )
        if statement in {"DELETE FROM graph_edges", "DELETE FROM graph_nodes"}:
            store.ledger.add_graph_node(
                node_id="node.one",
                node_kind="subject",
                attributes={},
                event_seq=event.seq,
            )
            store.ledger.add_graph_node(
                node_id="node.two",
                node_kind="resource",
                attributes={},
                event_seq=event.seq,
            )
            store.ledger.add_graph_edge(
                edge_id="edge.one",
                source_node_id="node.one",
                target_node_id="node.two",
                edge_kind="reads",
                attributes={},
                event_seq=event.seq,
            )
    raw = sqlite3.connect(path)
    trigger_sql = raw.execute(
        "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
        (trigger,),
    ).fetchone()[0]
    raw.execute(f"DROP TRIGGER {trigger}")
    if statement == "DELETE FROM search_documents":
        raw.execute("DELETE FROM search_fts")
    if statement == "DELETE FROM graph_nodes":
        raw.execute("PRAGMA foreign_keys=OFF")
        edge_trigger = raw.execute(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' "
            "AND name='graph_edges_no_delete'"
        ).fetchone()[0]
        raw.execute("DROP TRIGGER graph_edges_no_delete")
        raw.execute("DELETE FROM graph_edges")
        raw.execute(edge_trigger)
    raw.execute(statement)
    raw.execute(trigger_sql)
    raw.commit()
    raw.close()
    with pytest.raises(ChainIntegrityError, match=message):
        EventLedger(path, "eng.projection-completeness", key())


def test_unknown_cas_entries_insecure_modes_and_ancestor_symlinks_fail_closed(
    tmp_path: Path,
) -> None:
    with state_store(tmp_path, "eng.strict-fs") as store:
        namespace = hashlib.sha256(b"eng.strict-fs").hexdigest()
        unknown = state_root(tmp_path) / "cas" / namespace / "unexpected.txt"
        unknown.write_bytes(b"PLAINTEXT-SECRET")
        unknown.chmod(0o600)
        with pytest.raises(ChainIntegrityError, match="unknown entry"):
            store.recover()
        unknown.unlink()
        _, reference = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"private",
            metadata={},
        )
        blob = blob_path(tmp_path, reference)
        blob.chmod(0o644)
        with pytest.raises(ChainIntegrityError, match="private|0600"):
            store.cas.get(reference)
    outer = tmp_path / "outer"
    redirected = tmp_path / "redirected"
    outer.mkdir(mode=0o700)
    redirected.mkdir(mode=0o700)
    (outer / "link").symlink_to(redirected, target_is_directory=True)
    with pytest.raises(StorageError, match="symlink"):
        StateStore(
            outer / "link" / "state",
            "eng.linked",
            key(),
            anchor_root=tmp_path / "safe-anchor",
        )


def test_nonce_registry_rejects_repeated_rng_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cas_module.secrets, "token_bytes", lambda length: b"N" * length)
    with EncryptedCAS(tmp_path, "eng.nonce", key()) as cas:
        first = cas.put(b"first")
        with pytest.raises(StorageError, match="repeated a reserved nonce"):
            cas.put(b"second")
        assert cas.get(first) == b"first"


def test_same_base_key_derives_distinct_aead_keys_per_engagement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cas_module.secrets, "token_bytes", lambda length: b"N" * length)
    first_plaintext = b"A" * 32
    second_plaintext = b"B" * 32
    with EncryptedCAS(tmp_path / "one", "eng.derive-one", key()) as first:
        first_ref = first.put(first_plaintext)
    with EncryptedCAS(tmp_path / "two", "eng.derive-two", key()) as second:
        second_ref = second.put(second_plaintext)
    first_namespace = hashlib.sha256(b"eng.derive-one").hexdigest()
    second_namespace = hashlib.sha256(b"eng.derive-two").hexdigest()
    first_envelope = (
        tmp_path
        / "one"
        / first_namespace
        / first_ref.sha256[:2]
        / f"{first_ref.sha256}.flcas"
    ).read_bytes()
    second_envelope = (
        tmp_path
        / "two"
        / second_namespace
        / second_ref.sha256[:2]
        / f"{second_ref.sha256}.flcas"
    ).read_bytes()
    ciphertext_start = len(cas_module.MAGIC) + cas_module.NONCE_BYTES
    assert first_envelope[len(cas_module.MAGIC) : ciphertext_start] == b"N" * 12
    assert second_envelope[len(cas_module.MAGIC) : ciphertext_start] == b"N" * 12
    first_ciphertext = first_envelope[ciphertext_start:-16]
    second_ciphertext = second_envelope[ciphertext_start:-16]
    reused_keystream_signal = bytes(
        left ^ right for left, right in zip(first_ciphertext, second_ciphertext)
    )
    assert reused_keystream_signal != bytes(
        left ^ right for left, right in zip(first_plaintext, second_plaintext)
    )


def test_observation_metadata_is_typed_and_never_plaintext_in_sqlite(
    tmp_path: Path,
) -> None:
    marker = "SUPER-SECRET-METADATA-9f37"
    with state_store(tmp_path, "eng.metadata") as store:
        event, _ = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"raw",
            metadata={"token": marker},
        )
        metadata_reference = ArtifactRef.from_dict(event.payload["metadata_ref"])
        metadata = json.loads(store.cas.get(metadata_reference))
        assert metadata == {"schema_version": 1, "values": {"token": marker}}
    database = database_path(tmp_path, "eng.metadata")
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(f"{database}{suffix}")
        if candidate.exists():
            assert marker.encode() not in candidate.read_bytes()
