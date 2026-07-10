"""Append-only SQLite/WAL research event ledger and retrieval indexes."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .canonical import canonical_json
from .cas import ArtifactRef
from .types import (
    ChainIntegrityError,
    CrossEngagementError,
    StorageError,
    require_identifier,
    require_sha256,
)


ZERO_HASH = "0" * 64
SCHEMA_VERSION = 1


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _payload_contains_artifact(value: Any, reference: ArtifactRef) -> bool:
    expected = reference.to_dict()
    if isinstance(value, Mapping):
        if dict(value) == expected:
            return True
        return any(_payload_contains_artifact(child, reference) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_payload_contains_artifact(child, reference) for child in value)
    return False


@dataclass(frozen=True, slots=True)
class EventRecord:
    seq: int
    engagement_id: str
    actor_stream: str
    event_type: str
    payload: dict[str, Any]
    payload_sha256: str
    prev_hash: str
    event_hash: str
    created_at: str
    schema_version: int = SCHEMA_VERSION


SCHEMA = """
PRAGMA application_id = 0x464C4F4D;
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS ledger_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    engagement_id TEXT NOT NULL,
    actor_stream TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    prev_hash TEXT NOT NULL CHECK (length(prev_hash) = 64),
    event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    sha256 TEXT PRIMARY KEY CHECK (length(sha256) = 64),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    media_type TEXT NOT NULL,
    first_event_seq INTEGER NOT NULL REFERENCES events(seq)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS search_documents (
    rowid INTEGER PRIMARY KEY,
    doc_id TEXT NOT NULL UNIQUE,
    source_event_seq INTEGER NOT NULL REFERENCES events(seq),
    anchor_event_seq INTEGER NOT NULL UNIQUE REFERENCES events(seq),
    artifact_sha256 TEXT REFERENCES artifacts(sha256),
    title TEXT NOT NULL,
    redacted_text TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
    title,
    redacted_text,
    content='search_documents',
    content_rowid='rowid',
    tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS search_documents_ai
AFTER INSERT ON search_documents BEGIN
    INSERT INTO search_fts(rowid, title, redacted_text)
    VALUES (new.rowid, new.title, new.redacted_text);
END;

CREATE TABLE IF NOT EXISTS graph_nodes (
    node_id TEXT PRIMARY KEY,
    node_kind TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    source_event_seq INTEGER NOT NULL REFERENCES events(seq),
    anchor_event_seq INTEGER NOT NULL UNIQUE REFERENCES events(seq)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS graph_edges (
    edge_id TEXT PRIMARY KEY,
    source_node_id TEXT NOT NULL REFERENCES graph_nodes(node_id),
    target_node_id TEXT NOT NULL REFERENCES graph_nodes(node_id),
    edge_kind TEXT NOT NULL,
    attributes_json TEXT NOT NULL,
    source_event_seq INTEGER NOT NULL REFERENCES events(seq),
    anchor_event_seq INTEGER NOT NULL UNIQUE REFERENCES events(seq)
) WITHOUT ROWID;

CREATE TRIGGER IF NOT EXISTS ledger_metadata_no_update
BEFORE UPDATE ON ledger_metadata BEGIN SELECT RAISE(ABORT, 'append-only metadata'); END;
CREATE TRIGGER IF NOT EXISTS ledger_metadata_no_delete
BEFORE DELETE ON ledger_metadata BEGIN SELECT RAISE(ABORT, 'append-only metadata'); END;
CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'append-only events'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT, 'append-only events'); END;
CREATE TRIGGER IF NOT EXISTS artifacts_no_update
BEFORE UPDATE ON artifacts BEGIN SELECT RAISE(ABORT, 'append-only artifacts'); END;
CREATE TRIGGER IF NOT EXISTS artifacts_no_delete
BEFORE DELETE ON artifacts BEGIN SELECT RAISE(ABORT, 'append-only artifacts'); END;
CREATE TRIGGER IF NOT EXISTS search_documents_no_update
BEFORE UPDATE ON search_documents BEGIN SELECT RAISE(ABORT, 'append-only documents'); END;
CREATE TRIGGER IF NOT EXISTS search_documents_no_delete
BEFORE DELETE ON search_documents BEGIN SELECT RAISE(ABORT, 'append-only documents'); END;
CREATE TRIGGER IF NOT EXISTS graph_nodes_no_update
BEFORE UPDATE ON graph_nodes BEGIN SELECT RAISE(ABORT, 'append-only graph nodes'); END;
CREATE TRIGGER IF NOT EXISTS graph_nodes_no_delete
BEFORE DELETE ON graph_nodes BEGIN SELECT RAISE(ABORT, 'append-only graph nodes'); END;
CREATE TRIGGER IF NOT EXISTS graph_edges_no_update
BEFORE UPDATE ON graph_edges BEGIN SELECT RAISE(ABORT, 'append-only graph edges'); END;
CREATE TRIGGER IF NOT EXISTS graph_edges_no_delete
BEFORE DELETE ON graph_edges BEGIN SELECT RAISE(ABORT, 'append-only graph edges'); END;
"""


class EventLedger:
    """One append-only database per engagement."""

    def __init__(self, path: Path, engagement_id: str) -> None:
        self.engagement_id = require_identifier(engagement_id, field="engagement_id")
        path = Path(path)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.is_symlink():
            raise StorageError("ledger path must not contain a terminal symlink")
        parent_before = path.parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(parent_before.st_mode):
            raise StorageError("ledger parent is not a directory")
        if not path.exists():
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.close(descriptor)
        opened = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise StorageError("ledger must be a private regular file")
        os.chmod(path, 0o600)
        self.path = path
        self._connection = sqlite3.connect(
            path,
            isolation_level=None,
            check_same_thread=False,
            timeout=5.0,
        )
        after = path.stat(follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
            self._connection.close()
            raise StorageError("ledger file changed while opening")
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        try:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA trusted_schema=OFF")
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.executescript(SCHEMA)
            self._initialize_metadata()
            self.verify_chain()
        except (sqlite3.Error, StorageError) as exc:
            self._connection.close()
            if isinstance(exc, StorageError):
                raise
            raise StorageError(f"cannot initialize event ledger: {exc}") from exc
        self._closed = False

    def __enter__(self) -> EventLedger:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        with self._lock:
            self._connection.execute("PRAGMA wal_checkpoint(FULL)")
            self._connection.close()
            self._closed = True

    def _require_open(self) -> None:
        if self._closed:
            raise StorageError("event ledger is closed")

    def _initialize_metadata(self) -> None:
        rows = dict(self._connection.execute("SELECT key, value FROM ledger_metadata"))
        expected = {
            "engagement_id": self.engagement_id,
            "schema_version": str(SCHEMA_VERSION),
        }
        if not rows:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.executemany(
                    "INSERT INTO ledger_metadata(key, value) VALUES (?, ?)", expected.items()
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        elif rows != expected:
            raise CrossEngagementError("ledger metadata does not match this engagement")

    @staticmethod
    def _event_digest(
        *,
        seq: int,
        engagement_id: str,
        actor_stream: str,
        event_type: str,
        payload_sha256: str,
        prev_hash: str,
        created_at: str,
    ) -> str:
        body = {
            "actor_stream": actor_stream,
            "created_at": created_at,
            "engagement_id": engagement_id,
            "event_type": event_type,
            "payload_sha256": payload_sha256,
            "prev_hash": prev_hash,
            "schema_version": SCHEMA_VERSION,
            "seq": seq,
        }
        return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()

    def append(
        self,
        *,
        actor_stream: str,
        event_type: str,
        payload: Mapping[str, Any],
        artifacts: Iterable[ArtifactRef] = (),
        created_at: str | None = None,
        _side_effect: Callable[[sqlite3.Connection, int], None] | None = None,
    ) -> EventRecord:
        self._require_open()
        actor_stream = require_identifier(actor_stream, field="actor_stream")
        event_type = require_identifier(event_type, field="event_type")
        if not isinstance(payload, Mapping):
            raise StorageError("event payload must be an object")
        payload_value = dict(payload)
        payload_json = canonical_json(payload_value)
        payload_value = json.loads(payload_json)
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        timestamp = created_at or _now()
        try:
            parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise StorageError("created_at is not an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise StorageError("created_at must be timezone-aware")
        artifact_values = tuple(artifacts)
        for reference in artifact_values:
            if reference.engagement_id != self.engagement_id:
                raise CrossEngagementError("event artifact belongs to another engagement")
            if not _payload_contains_artifact(payload_value, reference):
                raise StorageError("registered artifact must be present in the event payload")
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                last = self._connection.execute(
                    "SELECT seq, event_hash FROM events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                seq = 1 if last is None else int(last["seq"]) + 1
                prev_hash = ZERO_HASH if last is None else str(last["event_hash"])
                event_hash = self._event_digest(
                    seq=seq,
                    engagement_id=self.engagement_id,
                    actor_stream=actor_stream,
                    event_type=event_type,
                    payload_sha256=payload_sha256,
                    prev_hash=prev_hash,
                    created_at=timestamp,
                )
                self._connection.execute(
                    """
                    INSERT INTO events(
                        seq, schema_version, engagement_id, actor_stream, event_type,
                        payload_json, payload_sha256, prev_hash, event_hash, created_at
                    ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        seq,
                        self.engagement_id,
                        actor_stream,
                        event_type,
                        payload_json,
                        payload_sha256,
                        prev_hash,
                        event_hash,
                        timestamp,
                    ),
                )
                for reference in artifact_values:
                    existing = self._connection.execute(
                        "SELECT byte_length FROM artifacts WHERE sha256 = ?", (reference.sha256,)
                    ).fetchone()
                    if existing is None:
                        self._connection.execute(
                            """
                            INSERT INTO artifacts(sha256, byte_length, media_type, first_event_seq)
                            VALUES (?, ?, ?, ?)
                            """,
                            (
                                reference.sha256,
                                reference.byte_length,
                                reference.media_type,
                                seq,
                            ),
                        )
                    elif int(existing["byte_length"]) != reference.byte_length:
                        raise ChainIntegrityError("artifact digest collision in ledger metadata")
                if _side_effect is not None:
                    _side_effect(self._connection, seq)
                self._connection.execute("COMMIT")
            except Exception as exc:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                if isinstance(exc, StorageError):
                    raise
                raise StorageError(f"cannot append event: {exc}") from exc
        return EventRecord(
            seq=seq,
            engagement_id=self.engagement_id,
            actor_stream=actor_stream,
            event_type=event_type,
            payload=payload_value,
            payload_sha256=payload_sha256,
            prev_hash=prev_hash,
            event_hash=event_hash,
            created_at=timestamp,
        )

    @staticmethod
    def _record(row: sqlite3.Row) -> EventRecord:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ChainIntegrityError("event payload is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ChainIntegrityError("event payload is not a JSON object")
        return EventRecord(
            seq=int(row["seq"]),
            schema_version=int(row["schema_version"]),
            engagement_id=str(row["engagement_id"]),
            actor_stream=str(row["actor_stream"]),
            event_type=str(row["event_type"]),
            payload=payload,
            payload_sha256=str(row["payload_sha256"]),
            prev_hash=str(row["prev_hash"]),
            event_hash=str(row["event_hash"]),
            created_at=str(row["created_at"]),
        )

    def events(self, *, after_seq: int = 0, limit: int = 1000) -> tuple[EventRecord, ...]:
        self._require_open()
        if not isinstance(after_seq, int) or isinstance(after_seq, bool) or after_seq < 0:
            raise StorageError("after_seq is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
            raise StorageError("event limit is invalid")
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?", (after_seq, limit)
            ).fetchall()
        return tuple(self._record(row) for row in rows)

    def verify_chain(self) -> str:
        self._require_open() if hasattr(self, "_closed") else None
        with self._lock:
            integrity = self._connection.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                raise ChainIntegrityError(f"SQLite integrity check failed: {integrity}")
            rows = self._connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
        previous = ZERO_HASH
        for expected_seq, row in enumerate(rows, 1):
            record = self._record(row)
            if record.seq != expected_seq or record.schema_version != SCHEMA_VERSION:
                raise ChainIntegrityError("event sequence or schema version is invalid")
            if record.engagement_id != self.engagement_id:
                raise CrossEngagementError("event row belongs to another engagement")
            payload_json = canonical_json(record.payload)
            payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(payload_sha256, record.payload_sha256):
                raise ChainIntegrityError(f"event payload digest mismatch at sequence {record.seq}")
            if not hmac.compare_digest(record.prev_hash, previous):
                raise ChainIntegrityError(f"event chain link mismatch at sequence {record.seq}")
            expected_hash = self._event_digest(
                seq=record.seq,
                engagement_id=record.engagement_id,
                actor_stream=record.actor_stream,
                event_type=record.event_type,
                payload_sha256=record.payload_sha256,
                prev_hash=record.prev_hash,
                created_at=record.created_at,
            )
            if not hmac.compare_digest(expected_hash, record.event_hash):
                raise ChainIntegrityError(f"event hash mismatch at sequence {record.seq}")
            previous = record.event_hash
        self._verify_auxiliary_state({record.seq: record for record in map(self._record, rows)})
        return previous

    def _verify_auxiliary_state(self, events: dict[int, EventRecord]) -> None:
        with self._lock:
            artifacts = self._connection.execute(
                "SELECT sha256, byte_length, media_type, first_event_seq FROM artifacts"
            ).fetchall()
            documents = self._connection.execute(
                """
                SELECT doc_id, source_event_seq, anchor_event_seq, artifact_sha256,
                       title, redacted_text FROM search_documents
                """
            ).fetchall()
            nodes = self._connection.execute(
                """
                SELECT node_id, node_kind, attributes_json, source_event_seq,
                       anchor_event_seq FROM graph_nodes
                """
            ).fetchall()
            edges = self._connection.execute(
                """
                SELECT edge_id, source_node_id, target_node_id, edge_kind,
                       attributes_json, source_event_seq, anchor_event_seq FROM graph_edges
                """
            ).fetchall()
        for row in artifacts:
            reference = ArtifactRef(
                engagement_id=self.engagement_id,
                sha256=str(row["sha256"]),
                byte_length=int(row["byte_length"]),
                media_type=str(row["media_type"]),
            )
            event = events.get(int(row["first_event_seq"]))
            if event is None or not _payload_contains_artifact(event.payload, reference):
                raise ChainIntegrityError("artifact registry is not anchored in its first event")
        for row in documents:
            event = events.get(int(row["anchor_event_seq"]))
            expected = {
                "artifact_sha256": row["artifact_sha256"],
                "doc_id": row["doc_id"],
                "redacted_text": row["redacted_text"],
                "source_event_seq": row["source_event_seq"],
                "title": row["title"],
            }
            if event is None or event.event_type != "index.search" or event.payload != expected:
                raise ChainIntegrityError("search projection is not anchored in the event chain")
        for row in nodes:
            try:
                attributes = json.loads(row["attributes_json"])
            except json.JSONDecodeError as exc:
                raise ChainIntegrityError("graph node attributes are invalid JSON") from exc
            event = events.get(int(row["anchor_event_seq"]))
            expected = {
                "attributes": attributes,
                "node_id": row["node_id"],
                "node_kind": row["node_kind"],
                "source_event_seq": row["source_event_seq"],
            }
            if event is None or event.event_type != "index.graph_node" or event.payload != expected:
                raise ChainIntegrityError("graph node is not anchored in the event chain")
        for row in edges:
            try:
                attributes = json.loads(row["attributes_json"])
            except json.JSONDecodeError as exc:
                raise ChainIntegrityError("graph edge attributes are invalid JSON") from exc
            event = events.get(int(row["anchor_event_seq"]))
            expected = {
                "attributes": attributes,
                "edge_id": row["edge_id"],
                "edge_kind": row["edge_kind"],
                "source_event_seq": row["source_event_seq"],
                "source_node_id": row["source_node_id"],
                "target_node_id": row["target_node_id"],
            }
            if event is None or event.event_type != "index.graph_edge" or event.payload != expected:
                raise ChainIntegrityError("graph edge is not anchored in the event chain")

    def referenced_artifacts(self) -> tuple[ArtifactRef, ...]:
        self._require_open()
        with self._lock:
            rows = self._connection.execute(
                "SELECT sha256, byte_length, media_type FROM artifacts ORDER BY sha256"
            ).fetchall()
        return tuple(
            ArtifactRef(
                engagement_id=self.engagement_id,
                sha256=str(row["sha256"]),
                byte_length=int(row["byte_length"]),
                media_type=str(row["media_type"]),
            )
            for row in rows
        )

    def add_search_document(
        self,
        *,
        doc_id: str,
        event_seq: int,
        title: str,
        redacted_text: str,
        artifact_sha256: str | None = None,
    ) -> EventRecord:
        self._require_open()
        require_identifier(doc_id, field="doc_id")
        if not isinstance(event_seq, int) or isinstance(event_seq, bool) or event_seq <= 0:
            raise StorageError("event_seq is invalid")
        if not isinstance(title, str) or not title or len(title) > 1024:
            raise StorageError("search title is invalid")
        if not isinstance(redacted_text, str) or len(redacted_text.encode("utf-8")) > 1024 * 1024:
            raise StorageError("redacted search text is invalid")
        if "\x00" in title or "\x00" in redacted_text:
            raise StorageError("search projection contains NUL")
        if artifact_sha256 is not None:
            require_sha256(artifact_sha256, field="artifact_sha256")
        payload = {
            "artifact_sha256": artifact_sha256,
            "doc_id": doc_id,
            "redacted_text": redacted_text,
            "source_event_seq": event_seq,
            "title": title,
        }

        def insert(connection: sqlite3.Connection, anchor_seq: int) -> None:
            connection.execute(
                """
                INSERT INTO search_documents(
                    doc_id, source_event_seq, anchor_event_seq, artifact_sha256,
                    title, redacted_text, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (doc_id, event_seq, anchor_seq, artifact_sha256, title, redacted_text, _now()),
            )

        return self.append(
            actor_stream="state.indexer",
            event_type="index.search",
            payload=payload,
            _side_effect=insert,
        )

    def search(self, query: str, *, limit: int = 20) -> tuple[dict[str, Any], ...]:
        self._require_open()
        if not isinstance(query, str) or not query.strip() or len(query) > 2048:
            raise StorageError("search query is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise StorageError("search limit is invalid")
        with self._lock:
            try:
                rows = self._connection.execute(
                    """
                    SELECT d.doc_id, d.source_event_seq AS event_seq,
                           d.anchor_event_seq, d.artifact_sha256, d.title,
                           snippet(search_fts, 1, '[', ']', '…', 24) AS snippet,
                           bm25(search_fts) AS rank
                    FROM search_fts
                    JOIN search_documents AS d ON d.rowid = search_fts.rowid
                    WHERE search_fts MATCH ?
                    ORDER BY rank, d.rowid
                    LIMIT ?
                    """,
                    (query, limit),
                ).fetchall()
            except sqlite3.Error as exc:
                raise StorageError(f"search query failed closed: {exc}") from exc
        return tuple(dict(row) for row in rows)

    def add_graph_node(
        self,
        *,
        node_id: str,
        node_kind: str,
        attributes: Mapping[str, Any],
        event_seq: int,
    ) -> EventRecord:
        self._require_open()
        require_identifier(node_id, field="node_id")
        require_identifier(node_kind, field="node_kind")
        if not isinstance(event_seq, int) or isinstance(event_seq, bool) or event_seq <= 0:
            raise StorageError("event_seq is invalid")
        attribute_value = dict(attributes)
        attributes_json = canonical_json(attribute_value)
        payload = {
            "attributes": attribute_value,
            "node_id": node_id,
            "node_kind": node_kind,
            "source_event_seq": event_seq,
        }

        def insert(connection: sqlite3.Connection, anchor_seq: int) -> None:
            connection.execute(
                """
                INSERT INTO graph_nodes(
                    node_id, node_kind, attributes_json, source_event_seq, anchor_event_seq
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (node_id, node_kind, attributes_json, event_seq, anchor_seq),
            )

        return self.append(
            actor_stream="state.indexer",
            event_type="index.graph_node",
            payload=payload,
            _side_effect=insert,
        )

    def add_graph_edge(
        self,
        *,
        edge_id: str,
        source_node_id: str,
        target_node_id: str,
        edge_kind: str,
        attributes: Mapping[str, Any],
        event_seq: int,
    ) -> EventRecord:
        self._require_open()
        for field, value in (
            ("edge_id", edge_id),
            ("source_node_id", source_node_id),
            ("target_node_id", target_node_id),
            ("edge_kind", edge_kind),
        ):
            require_identifier(value, field=field)
        if not isinstance(event_seq, int) or isinstance(event_seq, bool) or event_seq <= 0:
            raise StorageError("event_seq is invalid")
        attribute_value = dict(attributes)
        attributes_json = canonical_json(attribute_value)
        payload = {
            "attributes": attribute_value,
            "edge_id": edge_id,
            "edge_kind": edge_kind,
            "source_event_seq": event_seq,
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
        }

        def insert(connection: sqlite3.Connection, anchor_seq: int) -> None:
            connection.execute(
                """
                INSERT INTO graph_edges(
                    edge_id, source_node_id, target_node_id, edge_kind,
                    attributes_json, source_event_seq, anchor_event_seq
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    edge_id,
                    source_node_id,
                    target_node_id,
                    edge_kind,
                    attributes_json,
                    event_seq,
                    anchor_seq,
                ),
            )

        return self.append(
            actor_stream="state.indexer",
            event_type="index.graph_edge",
            payload=payload,
            _side_effect=insert,
        )

    def neighbors(self, node_id: str, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        self._require_open()
        require_identifier(node_id, field="node_id")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise StorageError("graph limit is invalid")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT edge_id, source_node_id, target_node_id, edge_kind,
                       attributes_json, source_event_seq, anchor_event_seq
                FROM graph_edges
                WHERE source_node_id = ? OR target_node_id = ?
                ORDER BY edge_id LIMIT ?
                """,
                (node_id, node_id, limit),
            ).fetchall()
        return tuple(
            {
                "edge_id": row["edge_id"],
                "source_node_id": row["source_node_id"],
                "target_node_id": row["target_node_id"],
                "edge_kind": row["edge_kind"],
                "attributes": json.loads(row["attributes_json"]),
                "event_seq": row["source_event_seq"],
                "anchor_event_seq": row["anchor_event_seq"],
            }
            for row in rows
        )
