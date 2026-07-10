from __future__ import annotations

import hashlib
import os
import pickle
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from faultloom.state import (
    ArtifactRef,
    ChainIntegrityError,
    CrossEngagementError,
    EncryptedCAS,
    EngagementKey,
    EventLedger,
    StateStore,
    StorageError,
)


KEY_BYTES = bytes(range(32))


def key() -> EngagementKey:
    return EngagementKey(KEY_BYTES)


def database_path(root: Path, engagement_id: str) -> Path:
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    return root / "engagements" / namespace / "state.sqlite3"


def blob_path(root: Path, reference: ArtifactRef) -> Path:
    namespace = hashlib.sha256(reference.engagement_id.encode()).hexdigest()
    return root / "cas" / namespace / reference.sha256[:2] / f"{reference.sha256}.flcas"


def test_full_raw_output_is_encrypted_and_retrievable_without_truncation(tmp_path: Path) -> None:
    raw = (b"line with a unique raw marker\n" * 1200) + b"tail"
    with StateStore(tmp_path, "eng.alpha", key()) as store:
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


def test_key_is_redacted_and_not_pickleable() -> None:
    engagement_key = key()
    assert repr(engagement_key) == "EngagementKey(<redacted>)"
    assert KEY_BYTES.hex() not in repr(engagement_key)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(engagement_key)


def test_event_chain_round_trip_and_append_only_sql_triggers(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with EventLedger(path, "eng.ledger") as ledger:
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


def test_chain_detects_offline_database_tampering(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with EventLedger(path, "eng.tamper") as ledger:
        ledger.append(actor_stream="researcher", event_type="delta", payload={"safe": True})
    raw = sqlite3.connect(path)
    raw.execute("DROP TRIGGER events_no_update")
    raw.execute("UPDATE events SET payload_json = '{\"safe\":false}' WHERE seq = 1")
    raw.commit()
    raw.close()
    with pytest.raises(ChainIntegrityError, match="payload digest"):
        EventLedger(path, "eng.tamper")


def test_derived_index_tampering_is_detected_against_chain_anchor(tmp_path: Path) -> None:
    path = database_path(tmp_path, "eng.index-tamper")
    with StateStore(tmp_path, "eng.index-tamper", key()) as store:
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
    with pytest.raises(ChainIntegrityError, match="search projection"):
        EventLedger(path, "eng.index-tamper")


def test_artifact_registry_requires_reference_in_hashed_payload(tmp_path: Path) -> None:
    reference = ArtifactRef(
        engagement_id="eng.artifact-anchor",
        sha256=hashlib.sha256(b"raw").hexdigest(),
        byte_length=3,
    )
    with EventLedger(tmp_path / "state.sqlite3", "eng.artifact-anchor") as ledger:
        with pytest.raises(StorageError, match="present in the event payload"):
            ledger.append(
                actor_stream="researcher",
                event_type="observation",
                payload={"missing": True},
                artifacts=(reference,),
            )


def test_ledger_rejects_cross_engagement_open(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    with EventLedger(path, "eng.original"):
        pass
    with pytest.raises(CrossEngagementError):
        EventLedger(path, "eng.other")


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
    with EventLedger(tmp_path / "state.sqlite3", "eng.canonical") as ledger:
        with pytest.raises(StorageError):
            ledger.append(actor_stream="researcher", event_type="delta", payload=payload)


def test_search_projection_and_graph_are_append_only(tmp_path: Path) -> None:
    with StateStore(tmp_path, "eng.index", key()) as store:
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
    with StateStore(tmp_path, "eng.recover", key()) as store:
        committed_event, committed = store.append_observation(
            actor_stream="researcher",
            event_type="observation",
            raw_output=b"committed",
            metadata={},
        )
        assert committed_event.seq == 1
        orphan = store.cas.put(b"crashed before ledger commit")
        report = store.recover()
        assert report.verified_artifacts == (committed.sha256,)
        assert report.quarantined_orphans == (orphan.sha256,)
        assert report.recovery_id is not None
        assert store.cas.blob_digests() == (committed.sha256,)
        assert store.cas.get(committed) == b"committed"


def test_recovery_quarantines_interrupted_prepublication_write(tmp_path: Path) -> None:
    engagement_id = "eng.interrupted"
    namespace = hashlib.sha256(engagement_id.encode()).hexdigest()
    with StateStore(tmp_path, engagement_id, key()) as store:
        shard = tmp_path / "cas" / namespace / "ab"
        shard.mkdir()
        temporary = shard / (".tmp-" + "1" * 32)
        temporary.write_bytes(b"partial encrypted envelope")
        report = store.recover()
        assert report.quarantined_interrupted_writes == (
            "ab/.tmp-" + "1" * 32,
        )
        assert report.recovery_id is not None
        assert not temporary.exists()
        assert store.cas.temporary_entries() == ()


def test_recovery_fails_if_ledger_artifact_is_missing(tmp_path: Path) -> None:
    with StateStore(tmp_path, "eng.missing", key()) as store:
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
    with EventLedger(tmp_path / "state.sqlite3", "eng.concurrent") as ledger:
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
store = StateStore(Path({str(tmp_path)!r}), 'eng.crash', EngagementKey(bytes(range(32))))
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
    with StateStore(tmp_path, "eng.crash", key()) as reopened:
        assert reopened.ledger.events()[0].seq == 1
        report = reopened.recover()
        assert len(report.verified_artifacts) == 1


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
        EventLedger(ledger_link, "eng.link")


def test_artifact_reference_schema_is_strict() -> None:
    reference = ArtifactRef(
        engagement_id="eng.strict", sha256="a" * 64, byte_length=1, media_type="text/plain"
    )
    value = reference.to_dict()
    value["unexpected"] = True
    with pytest.raises(StorageError, match="keys"):
        ArtifactRef.from_dict(value)
