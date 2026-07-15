"""Append-only SQLite/WAL research event ledger and retrieval indexes."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import sqlite3
import threading
from collections.abc import Iterable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .canonical import canonical_json
from .cas import ArtifactRef, EngagementKey
from .filesystem import (
    DirectoryBinding,
    NOFOLLOW,
    PRIVATE_FILE_MODE,
    inode_identity,
    require_private_file,
)
from .types import (
    ChainIntegrityError,
    CrossEngagementError,
    StorageError,
    require_identifier,
    require_sha256,
)


ZERO_HASH = "0" * 64
SCHEMA_VERSION = 2
APPLICATION_ID = 0x464C4F4D


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")


def _validate_ledger_directory(parent_fd: int, database_name: str) -> None:
    allowed = {database_name, f"{database_name}-wal", f"{database_name}-shm"}
    entries = set(os.listdir(parent_fd))
    unknown = entries - allowed
    if unknown:
        raise ChainIntegrityError(
            f"event ledger directory contains unknown entries: {sorted(unknown)}"
        )
    for filename in entries:
        try:
            metadata = os.stat(filename, dir_fd=parent_fd, follow_symlinks=False)
            require_private_file(metadata, context=f"event ledger file {filename!r}")
        except (OSError, StorageError) as exc:
            raise ChainIntegrityError(f"event ledger file {filename!r} is unsafe") from exc


def _payload_contains_artifact(value: Any, reference: ArtifactRef) -> bool:
    expected = reference.to_dict()
    if isinstance(value, Mapping):
        if dict(value) == expected:
            return True
        return any(_payload_contains_artifact(child, reference) for child in value.values())
    if isinstance(value, (list, tuple)):
        return any(_payload_contains_artifact(child, reference) for child in value)
    return False


def _payload_artifacts(value: Any) -> tuple[ArtifactRef, ...]:
    """Extract typed artifact references from a canonical event payload."""

    if isinstance(value, Mapping):
        candidate = dict(value)
        if set(candidate) == {
            "engagement_id",
            "sha256",
            "byte_length",
            "media_type",
            "schema_version",
        }:
            return (ArtifactRef.from_dict(candidate),)
        result: list[ArtifactRef] = []
        for child in value.values():
            result.extend(_payload_artifacts(child))
        return tuple(result)
    if isinstance(value, (list, tuple)):
        result = []
        for child in value:
            result.extend(_payload_artifacts(child))
        return tuple(result)
    return ()


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
    prev_auth_tag: str
    event_auth_tag: str
    created_at: str
    schema_version: int = SCHEMA_VERSION


SCHEMA = """
CREATE TABLE IF NOT EXISTS ledger_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    schema_version INTEGER NOT NULL CHECK (schema_version = 2),
    engagement_id TEXT NOT NULL,
    actor_stream TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64),
    prev_hash TEXT NOT NULL CHECK (length(prev_hash) = 64),
    event_hash TEXT NOT NULL UNIQUE CHECK (length(event_hash) = 64),
    prev_auth_tag TEXT NOT NULL CHECK (length(prev_auth_tag) = 64),
    event_auth_tag TEXT NOT NULL UNIQUE CHECK (length(event_auth_tag) = 64),
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

    def __init__(
        self,
        path: Path,
        engagement_id: str,
        key: EngagementKey,
        *,
        rebuild_fts: bool = False,
        transaction_lock: AbstractContextManager[Any] | None = None,
        commit_callback: Callable[[], None] | None = None,
        path_validator: Callable[[], None] | None = None,
    ) -> None:
        self.engagement_id = require_identifier(engagement_id, field="engagement_id")
        key_material = key._copy_for_cipher()
        self._event_auth_key = hmac.digest(
            key_material,
            b"faultloom-event-auth-key-v1\0" + self.engagement_id.encode("utf-8"),
            "sha256",
        )
        self._transaction_lock = transaction_lock or nullcontext()
        self._commit_callback = commit_callback
        self._path_validator = path_validator
        path = Path(path)
        if not path.is_absolute() or path.name in {"", ".", ".."} or "/" in path.name:
            raise StorageError("ledger path must be an absolute private file path")
        self._parent_binding = DirectoryBinding(
            path.parent, create=True, context="event ledger directory"
        )
        self._parent_fd = self._parent_binding.descriptor
        created = False
        try:
            descriptor = os.open(
                path.name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                PRIVATE_FILE_MODE,
                dir_fd=self._parent_fd,
            )
            created = True
        except FileExistsError:
            try:
                descriptor = os.open(
                    path.name,
                    os.O_RDWR | NOFOLLOW,
                    dir_fd=self._parent_fd,
                )
            except OSError as exc:
                self._parent_binding.close()
                raise StorageError(
                    "cannot safely open event ledger; symlinks are forbidden"
                ) from exc
        try:
            opened = os.fstat(descriptor)
            require_private_file(opened, context="event ledger")
            if not created and opened.st_size == 0:
                raise StorageError("existing event ledger is empty")
        except Exception:
            os.close(descriptor)
            self._parent_binding.close()
            raise
        os.close(descriptor)
        self.path = path
        self._sidecar_descriptors: dict[str, int] = {}
        try:
            _validate_ledger_directory(self._parent_fd, path.name)
            self._validate_sidecars()
        except Exception:
            self._close_sidecar_descriptors()
            self._parent_binding.close()
            raise
        stable_path = f"/proc/self/fd/{self._parent_fd}/{path.name}"
        try:
            self._connection = sqlite3.connect(
                stable_path,
                isolation_level=None,
                check_same_thread=False,
                timeout=5.0,
            )
        except sqlite3.Error as exc:
            self._close_sidecar_descriptors()
            self._parent_binding.close()
            raise StorageError("cannot connect to event ledger") from exc
        after = os.stat(path.name, dir_fd=self._parent_fd, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino):
            self._connection.close()
            self._close_sidecar_descriptors()
            self._parent_binding.close()
            raise StorageError("ledger file changed while opening")
        self._database_identity = inode_identity(after)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        try:
            if not created:
                self._verify_header()
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA trusted_schema=OFF")
            self._connection.execute("PRAGMA busy_timeout=5000")
            _validate_ledger_directory(self._parent_fd, path.name)
            self._validate_sidecars()
            if created:
                self._connection.executescript(SCHEMA)
                self._connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                self._connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self._verify_header()
            self._verify_schema()
            self._initialize_metadata(allow_create=created)
            self.verify_chain(check_fts=not rebuild_fts)
            if rebuild_fts:
                self.rebuild_fts()
            self._validate_paths()
        except Exception as exc:
            self._connection.close()
            self._close_sidecar_descriptors()
            self._parent_binding.close()
            if isinstance(exc, sqlite3.Error):
                raise StorageError(f"cannot initialize event ledger: {exc}") from exc
            raise
        self._closed = False

    def __enter__(self) -> EventLedger:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self.close_verified()

    def close_verified(
        self,
        finalizer: Callable[[tuple[int, str]], None] | None = None,
    ) -> None:
        """Authenticate the final snapshot and hold its writer lock through cleanup."""

        if self._closed:
            return
        failure: Exception | None = None

        def remember(exc: Exception) -> None:
            nonlocal failure
            if failure is not None:
                return
            if isinstance(exc, sqlite3.Error):
                failure = StorageError(f"cannot close event ledger: {exc}")
            else:
                failure = exc

        try:
            with self._transaction_lock:
                with self._lock:
                    try:
                        self._validate_paths()
                        self._connection.execute("PRAGMA wal_checkpoint(FULL)")
                        self._connection.execute("BEGIN IMMEDIATE")
                        checkpoint = self._verify_snapshot(check_fts=True)
                        if finalizer is not None:
                            finalizer(checkpoint)
                        if self._verify_snapshot(check_fts=True) != checkpoint:
                            raise ChainIntegrityError(
                                "event ledger changed while closing"
                            )
                        self._validate_paths()
                    except Exception as exc:
                        remember(exc)
                    try:
                        # Closing an active read-only writer transaction is the
                        # linearization point: competing writers cannot change
                        # the authenticated snapshot before finalizer returns.
                        self._connection.close()
                    except Exception as exc:
                        remember(exc)
        except Exception as exc:
            remember(exc)
            try:
                self._connection.close()
            except Exception as close_exc:
                remember(close_exc)
        try:
            self._validate_paths(allow_removed_sidecars=True)
        except Exception as exc:
            remember(exc)
        finally:
            self._close_sidecar_descriptors()
            self._parent_binding.close()
            self._closed = True
        if failure is not None:
            raise failure

    def _require_open(self) -> None:
        if self._closed:
            raise StorageError("event ledger is closed")
        self._validate_paths()

    def _close_sidecar_descriptors(self) -> None:
        for descriptor in self._sidecar_descriptors.values():
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._sidecar_descriptors.clear()

    def _current_sidecar_identity(self, filename: str) -> tuple[int, int]:
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY | NOFOLLOW,
                dir_fd=self._parent_fd,
            )
        except OSError as exc:
            raise StorageError(
                f"event ledger sidecar {filename!r} cannot be reopened safely"
            ) from exc
        try:
            metadata = os.fstat(descriptor)
            require_private_file(
                metadata, context=f"event ledger sidecar {filename!r} current path"
            )
            return inode_identity(metadata)
        finally:
            os.close(descriptor)

    def _validate_sidecars(self, *, allow_removed: bool = False) -> None:
        for suffix in ("-wal", "-shm"):
            filename = f"{self.path.name}{suffix}"
            descriptor = self._sidecar_descriptors.get(filename)
            if descriptor is None:
                try:
                    candidate = os.open(
                        filename,
                        os.O_RDONLY | NOFOLLOW,
                        dir_fd=self._parent_fd,
                    )
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise StorageError(
                        f"event ledger sidecar {filename!r} cannot be safely bound"
                    ) from exc
                try:
                    retained = os.fstat(candidate)
                    visible = os.stat(
                        filename,
                        dir_fd=self._parent_fd,
                        follow_symlinks=False,
                    )
                    require_private_file(
                        retained, context=f"event ledger sidecar {filename!r} descriptor"
                    )
                    require_private_file(
                        visible, context=f"event ledger sidecar {filename!r} path"
                    )
                    retained_identity = inode_identity(retained)
                    if (
                        retained_identity != inode_identity(visible)
                        or self._current_sidecar_identity(filename) != retained_identity
                    ):
                        raise StorageError(
                            f"event ledger sidecar {filename!r} changed while binding"
                        )
                except (OSError, StorageError) as exc:
                    os.close(candidate)
                    if isinstance(exc, StorageError):
                        raise
                    raise StorageError(
                        f"event ledger sidecar {filename!r} cannot be safely bound"
                    ) from exc
                self._sidecar_descriptors[filename] = candidate
                continue

            try:
                retained = os.fstat(descriptor)
            except OSError as exc:
                raise StorageError(
                    f"event ledger sidecar {filename!r} descriptor is unavailable"
                ) from exc
            try:
                visible = os.stat(
                    filename,
                    dir_fd=self._parent_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError as exc:
                if not allow_removed:
                    raise StorageError(
                        f"event ledger sidecar {filename!r} path disappeared"
                    ) from exc
                try:
                    require_private_file(
                        retained,
                        context=f"event ledger sidecar {filename!r} removed descriptor",
                        allowed_links=(0,),
                    )
                except StorageError as retained_error:
                    raise StorageError(
                        f"event ledger sidecar {filename!r} path changed instead of "
                        "being removed"
                    ) from retained_error
                continue
            except OSError as exc:
                raise StorageError(
                    f"event ledger sidecar {filename!r} path is unavailable"
                ) from exc
            require_private_file(
                retained, context=f"event ledger sidecar {filename!r} descriptor"
            )
            require_private_file(
                visible, context=f"event ledger sidecar {filename!r} path"
            )
            retained_identity = inode_identity(retained)
            if (
                retained_identity != inode_identity(visible)
                or self._current_sidecar_identity(filename) != retained_identity
            ):
                raise StorageError(
                    f"event ledger sidecar {filename!r} path identity changed"
                )

    def _validate_paths(self, *, allow_removed_sidecars: bool = False) -> None:
        self._parent_binding.revalidate()
        try:
            database = os.stat(
                self.path.name,
                dir_fd=self._parent_fd,
                follow_symlinks=False,
            )
            require_private_file(database, context="event ledger path")
        except (OSError, StorageError) as exc:
            raise StorageError("event ledger path is no longer safely bound") from exc
        if inode_identity(database) != self._database_identity:
            raise StorageError("event ledger file path identity changed")
        self._validate_sidecars(allow_removed=allow_removed_sidecars)
        if self._path_validator is not None:
            self._path_validator()

    def _verify_header(self) -> None:
        application_id = self._connection.execute("PRAGMA application_id").fetchone()[0]
        user_version = self._connection.execute("PRAGMA user_version").fetchone()[0]
        if application_id != APPLICATION_ID or user_version != SCHEMA_VERSION:
            raise StorageError("event ledger application or schema version is unsupported")

    @staticmethod
    def _schema_manifest(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
        rows = connection.execute(
            """
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name NOT LIKE 'sqlite_%'
            ORDER BY type, name
            """
        ).fetchall()
        return tuple(tuple(row) for row in rows)

    def _verify_schema(self) -> None:
        expected = sqlite3.connect(":memory:")
        try:
            expected.executescript(SCHEMA)
            manifest = self._schema_manifest(expected)
        finally:
            expected.close()
        if self._schema_manifest(self._connection) != manifest:
            raise ChainIntegrityError("event ledger schema manifest is not exact")

    def _expected_metadata(self) -> dict[str, str]:
        return {
            "engagement_id": self.engagement_id,
            "schema_version": str(SCHEMA_VERSION),
            "event_auth_key_commitment": hmac.digest(
                self._event_auth_key,
                b"faultloom-event-auth-key-commitment-v1\0"
                + self.engagement_id.encode("utf-8"),
                "sha256",
            ).hex(),
        }

    def _verify_metadata(self) -> None:
        rows = dict(self._connection.execute("SELECT key, value FROM ledger_metadata"))
        expected = self._expected_metadata()
        if rows.get("engagement_id") != self.engagement_id:
            if "engagement_id" in rows:
                raise CrossEngagementError(
                    "ledger metadata does not match this engagement"
                )
            raise ChainIntegrityError("existing event ledger metadata is missing")
        if rows != expected:
            raise ChainIntegrityError(
                "ledger metadata authentication key or schema does not match"
            )

    def _initialize_metadata(self, *, allow_create: bool) -> None:
        rows = dict(self._connection.execute("SELECT key, value FROM ledger_metadata"))
        if not rows:
            if not allow_create:
                raise ChainIntegrityError("existing event ledger metadata is missing")
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.executemany(
                    "INSERT INTO ledger_metadata(key, value) VALUES (?, ?)",
                    self._expected_metadata().items(),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        self._verify_metadata()

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

    def _event_auth_digest(
        self, *, prev_auth_tag: str, event_hash: str
    ) -> str:
        try:
            authenticated = bytes.fromhex(prev_auth_tag) + bytes.fromhex(event_hash)
        except ValueError as exc:
            raise ChainIntegrityError("event authentication input is malformed") from exc
        if len(authenticated) != 64:
            raise ChainIntegrityError("event authentication input is malformed")
        return hmac.digest(
            self._event_auth_key,
            b"faultloom-event-record-v1\0" + authenticated,
            "sha256",
        ).hex()

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
        payload_artifacts = _payload_artifacts(payload_value)
        registered = {canonical_json(reference.to_dict()) for reference in artifact_values}
        discovered = {canonical_json(reference.to_dict()) for reference in payload_artifacts}
        if len(registered) != len(artifact_values):
            raise StorageError("event contains duplicate registered artifacts")
        if registered != discovered:
            raise StorageError(
                "event payload artifact references must exactly match registered artifacts"
            )
        for reference in artifact_values:
            if reference.engagement_id != self.engagement_id:
                raise CrossEngagementError("event artifact belongs to another engagement")
        with self._transaction_lock:
            with self._lock:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                    previous_checkpoint = self._verify_snapshot(check_fts=True)
                    last = self._connection.execute(
                        """SELECT seq, event_hash, event_auth_tag
                           FROM events ORDER BY seq DESC LIMIT 1"""
                    ).fetchone()
                    seq = 1 if last is None else int(last["seq"]) + 1
                    prev_hash = ZERO_HASH if last is None else str(last["event_hash"])
                    prev_auth_tag = (
                        ZERO_HASH if last is None else str(last["event_auth_tag"])
                    )
                    if previous_checkpoint != (seq - 1, prev_hash):
                        raise ChainIntegrityError(
                            "event ledger changed inside the append transaction"
                        )
                    event_hash = self._event_digest(
                        seq=seq,
                        engagement_id=self.engagement_id,
                        actor_stream=actor_stream,
                        event_type=event_type,
                        payload_sha256=payload_sha256,
                        prev_hash=prev_hash,
                        created_at=timestamp,
                    )
                    event_auth_tag = self._event_auth_digest(
                        prev_auth_tag=prev_auth_tag,
                        event_hash=event_hash,
                    )
                    self._connection.execute(
                        """
                        INSERT INTO events(
                            seq, schema_version, engagement_id, actor_stream, event_type,
                            payload_json, payload_sha256, prev_hash, event_hash,
                            prev_auth_tag, event_auth_tag, created_at
                        ) VALUES (?, 2, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                            prev_auth_tag,
                            event_auth_tag,
                            timestamp,
                        ),
                    )
                    for reference in artifact_values:
                        existing = self._connection.execute(
                            "SELECT byte_length FROM artifacts WHERE sha256 = ?",
                            (reference.sha256,),
                        ).fetchone()
                        if existing is None:
                            self._connection.execute(
                                """
                                INSERT INTO artifacts(
                                    sha256, byte_length, media_type, first_event_seq
                                ) VALUES (?, ?, ?, ?)
                                """,
                                (
                                    reference.sha256,
                                    reference.byte_length,
                                    reference.media_type,
                                    seq,
                                ),
                            )
                        elif int(existing["byte_length"]) != reference.byte_length:
                            raise ChainIntegrityError(
                                "artifact digest collision in ledger metadata"
                            )
                    if _side_effect is not None:
                        _side_effect(self._connection, seq)
                    if self._verify_snapshot(check_fts=True) != (seq, event_hash):
                        raise ChainIntegrityError(
                            "appended event does not match the verified transaction head"
                        )
                    self._connection.execute("COMMIT")
                    if self._commit_callback is not None:
                        self._commit_callback()
                except Exception as exc:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                    if isinstance(exc, StorageError):
                        raise
                    raise StorageError(f"cannot append event: {exc}") from exc
        record = EventRecord(
            seq=seq,
            engagement_id=self.engagement_id,
            actor_stream=actor_stream,
            event_type=event_type,
            payload=payload_value,
            payload_sha256=payload_sha256,
            prev_hash=prev_hash,
            event_hash=event_hash,
            prev_auth_tag=prev_auth_tag,
            event_auth_tag=event_auth_tag,
            created_at=timestamp,
        )
        self._validate_paths()
        return record

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
            prev_auth_tag=str(row["prev_auth_tag"]),
            event_auth_tag=str(row["event_auth_tag"]),
            created_at=str(row["created_at"]),
        )

    def _events_in_transaction(
        self, *, after_seq: int, limit: int
    ) -> tuple[EventRecord, ...]:
        if not self._connection.in_transaction:
            raise StorageError("event reads require an active transaction")
        rows = self._connection.execute(
            "SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?", (after_seq, limit)
        ).fetchall()
        return tuple(self._record(row) for row in rows)

    def events(self, *, after_seq: int = 0, limit: int = 1000) -> tuple[EventRecord, ...]:
        self._require_open()
        if not isinstance(after_seq, int) or isinstance(after_seq, bool) or after_seq < 0:
            raise StorageError("after_seq is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
            raise StorageError("event limit is invalid")
        with self.verified_checkpoint():
            records = self._events_in_transaction(after_seq=after_seq, limit=limit)
        return records

    def _verify_snapshot(self, *, check_fts: bool) -> tuple[int, str]:
        if not self._connection.in_transaction:
            raise StorageError("ledger verification requires an active transaction")
        self._validate_paths()
        self._verify_header()
        self._verify_schema()
        self._verify_metadata()
        _validate_ledger_directory(self._parent_fd, self.path.name)
        integrity = self._connection.execute("PRAGMA quick_check").fetchone()[0]
        if integrity != "ok":
            raise ChainIntegrityError(f"SQLite integrity check failed: {integrity}")
        foreign_keys = self._connection.execute("PRAGMA foreign_key_check").fetchall()
        if foreign_keys:
            raise ChainIntegrityError("SQLite foreign-key integrity check failed")
        if check_fts:
            try:
                self._connection.execute(
                    "INSERT INTO search_fts(search_fts, rank) VALUES('integrity-check', 1)"
                )
            except sqlite3.Error as exc:
                raise ChainIntegrityError("FTS projection integrity check failed") from exc
        rows = self._connection.execute("SELECT * FROM events ORDER BY seq").fetchall()
        return len(rows), self._verify_rows(rows)

    @contextmanager
    def verified_checkpoint(
        self, *, check_fts: bool = True
    ) -> Iterator[tuple[int, str]]:
        """Hold a verified SQLite writer snapshot across an anchor decision."""

        self._require_open() if hasattr(self, "_closed") else None
        with self._transaction_lock:
            with self._lock:
                try:
                    self._connection.execute("BEGIN IMMEDIATE")
                    checkpoint = self._verify_snapshot(check_fts=check_fts)
                    yield checkpoint
                    self._connection.execute("COMMIT")
                except Exception as exc:
                    if self._connection.in_transaction:
                        self._connection.execute("ROLLBACK")
                    if isinstance(exc, sqlite3.Error):
                        raise StorageError(
                            f"cannot verify event ledger transaction: {exc}"
                        ) from exc
                    raise
        self._validate_paths()

    def verify_chain(self, *, check_fts: bool = True) -> str:
        with self.verified_checkpoint(check_fts=check_fts) as (_, head):
            return head

    def _verify_rows(self, rows: list[sqlite3.Row]) -> str:
        previous = ZERO_HASH
        previous_auth_tag = ZERO_HASH
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
            if not hmac.compare_digest(record.prev_auth_tag, previous_auth_tag):
                raise ChainIntegrityError(
                    f"event authentication link mismatch at sequence {record.seq}"
                )
            expected_auth_tag = self._event_auth_digest(
                prev_auth_tag=record.prev_auth_tag,
                event_hash=record.event_hash,
            )
            if not hmac.compare_digest(expected_auth_tag, record.event_auth_tag):
                raise ChainIntegrityError(
                    f"event authentication tag mismatch at sequence {record.seq}"
                )
            previous = record.event_hash
            previous_auth_tag = record.event_auth_tag
        self._verify_auxiliary_state({record.seq: record for record in map(self._record, rows)})
        return previous

    def rebuild_fts(self) -> None:
        """Explicitly rebuild the derived FTS index after primary-state verification."""

        with self.verified_checkpoint(check_fts=False):
            try:
                self._connection.execute(
                    "INSERT INTO search_fts(search_fts) VALUES('rebuild')"
                )
                self._verify_snapshot(check_fts=True)
            except sqlite3.Error as exc:
                raise StorageError(
                    "cannot deterministically rebuild FTS projection"
                ) from exc
        self.verify_chain(check_fts=True)

    def chain_checkpoint(self) -> tuple[int, str]:
        """Return the verified current sequence and head hash."""

        with self.verified_checkpoint() as checkpoint:
            return checkpoint

    def _event_hash_at_in_transaction(self, seq: int) -> str:
        if not self._connection.in_transaction:
            raise StorageError("event hash reads require an active transaction")
        row = self._connection.execute(
            "SELECT event_hash FROM events WHERE seq = ?", (seq,)
        ).fetchone()
        if row is None:
            raise ChainIntegrityError("anchored event sequence is missing")
        return str(row["event_hash"])

    def event_hash_at(self, seq: int) -> str:
        self._require_open()
        if not isinstance(seq, int) or isinstance(seq, bool) or seq <= 0:
            raise StorageError("event sequence is invalid")
        with self.verified_checkpoint():
            event_hash = self._event_hash_at_in_transaction(seq)
        return event_hash

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
        expected_artifacts: dict[str, tuple[int, str, int]] = {}
        expected_documents: dict[int, dict[str, Any]] = {}
        expected_nodes: dict[int, dict[str, Any]] = {}
        expected_edges: dict[int, dict[str, Any]] = {}
        for event_seq, event in events.items():
            for reference in _payload_artifacts(event.payload):
                if reference.engagement_id != self.engagement_id:
                    raise CrossEngagementError(
                        "event payload contains a foreign artifact reference"
                    )
                expected = expected_artifacts.setdefault(
                    reference.sha256,
                    (reference.byte_length, reference.media_type, event_seq),
                )
                if expected[0] != reference.byte_length:
                    raise ChainIntegrityError(
                        "one artifact digest has inconsistent byte lengths"
                    )
            if event.event_type == "index.search":
                expected_documents[event_seq] = event.payload
            elif event.event_type == "index.graph_node":
                expected_nodes[event_seq] = event.payload
            elif event.event_type == "index.graph_edge":
                expected_edges[event_seq] = event.payload

        actual_artifacts: dict[str, tuple[int, str, int]] = {}
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
            actual_artifacts[reference.sha256] = (
                reference.byte_length,
                reference.media_type,
                int(row["first_event_seq"]),
            )
        if actual_artifacts != expected_artifacts:
            raise ChainIntegrityError(
                "artifact registry is incomplete or differs from the event chain"
            )

        actual_documents: dict[int, dict[str, Any]] = {}
        for row in documents:
            actual_documents[int(row["anchor_event_seq"])] = {
                "artifact_sha256": row["artifact_sha256"],
                "doc_id": row["doc_id"],
                "redacted_text": row["redacted_text"],
                "source_event_seq": row["source_event_seq"],
                "title": row["title"],
            }
        if actual_documents != expected_documents:
            raise ChainIntegrityError(
                "search projection is incomplete or differs from the event chain"
            )

        actual_nodes: dict[int, dict[str, Any]] = {}
        for row in nodes:
            try:
                attributes = json.loads(row["attributes_json"])
            except json.JSONDecodeError as exc:
                raise ChainIntegrityError("graph node attributes are invalid JSON") from exc
            actual_nodes[int(row["anchor_event_seq"])] = {
                "attributes": attributes,
                "node_id": row["node_id"],
                "node_kind": row["node_kind"],
                "source_event_seq": row["source_event_seq"],
            }
        if actual_nodes != expected_nodes:
            raise ChainIntegrityError(
                "graph node projection is incomplete or differs from the event chain"
            )

        actual_edges: dict[int, dict[str, Any]] = {}
        for row in edges:
            try:
                attributes = json.loads(row["attributes_json"])
            except json.JSONDecodeError as exc:
                raise ChainIntegrityError("graph edge attributes are invalid JSON") from exc
            actual_edges[int(row["anchor_event_seq"])] = {
                "attributes": attributes,
                "edge_id": row["edge_id"],
                "edge_kind": row["edge_kind"],
                "source_event_seq": row["source_event_seq"],
                "source_node_id": row["source_node_id"],
                "target_node_id": row["target_node_id"],
            }
        if actual_edges != expected_edges:
            raise ChainIntegrityError(
                "graph edge projection is incomplete or differs from the event chain"
            )

    def _referenced_artifacts_in_transaction(self) -> tuple[ArtifactRef, ...]:
        if not self._connection.in_transaction:
            raise StorageError("artifact references require an active transaction")
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

    def referenced_artifacts(self) -> tuple[ArtifactRef, ...]:
        with self.verified_checkpoint():
            references = self._referenced_artifacts_in_transaction()
        return references

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

    def _search_in_transaction(
        self, query: str, *, limit: int
    ) -> tuple[dict[str, Any], ...]:
        if not self._connection.in_transaction:
            raise StorageError("search reads require an active transaction")
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

    def search(self, query: str, *, limit: int = 20) -> tuple[dict[str, Any], ...]:
        self._require_open()
        if not isinstance(query, str) or not query.strip() or len(query) > 2048:
            raise StorageError("search query is invalid")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise StorageError("search limit is invalid")
        with self.verified_checkpoint():
            results = self._search_in_transaction(query, limit=limit)
        return results

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

    def _neighbors_in_transaction(
        self, node_id: str, *, limit: int
    ) -> tuple[dict[str, Any], ...]:
        if not self._connection.in_transaction:
            raise StorageError("graph reads require an active transaction")
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

    def neighbors(self, node_id: str, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        self._require_open()
        require_identifier(node_id, field="node_id")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise StorageError("graph limit is invalid")
        with self.verified_checkpoint():
            results = self._neighbors_in_transaction(node_id, limit=limit)
        return results
