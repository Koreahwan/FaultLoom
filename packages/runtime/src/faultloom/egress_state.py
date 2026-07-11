"""Authenticated durable state for non-target egress decisions.

The SQLite file is mutable storage, not a trust anchor.  Every committed state
is authenticated with a caller-held key and mirrored to a separately rooted
anchor file.  Callers must retain the latest checkpoint as their freshness
floor across restarts.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import RLock
from typing import Any, Iterator


ZERO_DIGEST = "0" * 64
APPLICATION_ID = 0x464C4547
SCHEMA_VERSION = 1
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class EgressStateIntegrityError(RuntimeError):
    """Security-critical egress state is missing, stale, or unauthenticated."""


@dataclass(frozen=True, slots=True)
class EgressStateCheckpoint:
    """Externally retained freshness floor for one egress state store."""

    sequence: int
    state_digest: str
    store_id: str | None

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("egress checkpoint sequence must be non-negative")
        if not _is_digest(self.state_digest):
            raise ValueError("egress checkpoint state_digest is invalid")
        if self.sequence == 0 and self.store_id is None:
            if self.state_digest != ZERO_DIGEST:
                raise ValueError("empty egress checkpoint must use the zero digest")
        elif not _is_store_id(self.store_id):
            raise ValueError("egress checkpoint store_id is invalid")

    @classmethod
    def empty(cls) -> "EgressStateCheckpoint":
        return cls(sequence=0, state_digest=ZERO_DIGEST, store_id=None)


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _is_store_id(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and _is_digest(value)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require_private_directory(metadata: os.stat_result, *, name: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise EgressStateIntegrityError(f"{name} is not a directory")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and metadata.st_uid != geteuid():
        raise EgressStateIntegrityError(f"{name} is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE:
        raise EgressStateIntegrityError(f"{name} must have effective mode 0700")


def _require_private_file(metadata: os.stat_result, *, name: str) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise EgressStateIntegrityError(f"{name} is not a private regular file")
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and metadata.st_uid != geteuid():
        raise EgressStateIntegrityError(f"{name} is not owned by the current user")
    if stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE:
        raise EgressStateIntegrityError(f"{name} must have effective mode 0600")


def _absolute_file(path: str | Path, *, name: str) -> Path:
    value = Path(path)
    if not value.is_absolute() or value.name in {"", ".", ".."}:
        raise ValueError(f"{name} must be an absolute canonical file path")
    if any(part in {"", ".", ".."} for part in value.parts[1:]):
        raise ValueError(f"{name} must be an absolute canonical file path")
    return value


SCHEMA = """
CREATE TABLE metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    store_id TEXT NOT NULL,
    state_sequence INTEGER NOT NULL CHECK (state_sequence >= 0),
    state_digest TEXT NOT NULL,
    schema_digest TEXT NOT NULL,
    state_mac TEXT NOT NULL
);
CREATE TABLE authority_watermark (
    trust_domain TEXT PRIMARY KEY,
    trusted_key_digest TEXT NOT NULL,
    key_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    grant_version INTEGER NOT NULL CHECK (grant_version > 0),
    authority_digest TEXT NOT NULL,
    scope_epoch INTEGER NOT NULL CHECK (scope_epoch > 0),
    epoch_digest TEXT NOT NULL,
    revoked INTEGER NOT NULL CHECK (revoked IN (0, 1)),
    updated_at TEXT NOT NULL
);
CREATE TABLE dispatch_hold (
    plane TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    correlation_digest TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    dispatch_authorization_digest TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts > 0),
    reconciliation_sequence INTEGER NOT NULL CHECK (reconciliation_sequence >= 0),
    reconciliation_id TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (plane, action_digest),
    UNIQUE (plane, correlation_digest)
);
CREATE TABLE dispatch_correlation (
    plane TEXT NOT NULL,
    correlation_digest TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    first_request_digest TEXT NOT NULL,
    first_reserved_at TEXT NOT NULL,
    PRIMARY KEY (plane, correlation_digest)
);
CREATE TABLE reconciliation_watermark (
    trust_domain TEXT PRIMARY KEY,
    trusted_key_digest TEXT NOT NULL,
    key_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    capability_id TEXT NOT NULL UNIQUE,
    updated_at TEXT NOT NULL
);
"""


class SqliteEgressStateStore:
    """Authenticated state with a mandatory external checkpoint and key."""

    def __init__(
        self,
        path: str | Path,
        *,
        anchor_path: str | Path,
        authentication_key: bytes,
        minimum_anchor: EgressStateCheckpoint,
    ) -> None:
        if not isinstance(authentication_key, bytes) or len(authentication_key) != 32:
            raise ValueError("egress authentication_key must contain exactly 32 bytes")
        if not isinstance(minimum_anchor, EgressStateCheckpoint):
            raise TypeError("egress state requires an external minimum_anchor")
        self._path = _absolute_file(path, name="egress state path")
        self._anchor_path = _absolute_file(anchor_path, name="egress anchor path")
        if self._path.parent == self._anchor_path.parent:
            raise ValueError("egress anchor must use a separate directory root")
        common = Path(os.path.commonpath((self._path.parent, self._anchor_path.parent)))
        if common in {self._path.parent, self._anchor_path.parent}:
            raise ValueError("egress anchor and mutable state roots must be separate")
        self._key = bytes(authentication_key)
        self._minimum_anchor = minimum_anchor
        self._thread_lock = RLock()
        self._state_parent_fd, self._state_parent_identity = self._open_parent(
            self._path.parent, name="egress state parent"
        )
        try:
            self._anchor_parent_fd, self._anchor_parent_identity = self._open_parent(
                self._anchor_path.parent, name="egress anchor parent"
            )
        except Exception:
            os.close(self._state_parent_fd)
            raise
        if self._state_parent_identity == self._anchor_parent_identity:
            os.close(self._anchor_parent_fd)
            os.close(self._state_parent_fd)
            raise EgressStateIntegrityError(
                "egress anchor and mutable state roots share one physical directory"
            )
        lock_name = f".{self._anchor_path.name}.lock"
        try:
            self._lock_fd = os.open(
                lock_name,
                os.O_RDWR | os.O_CREAT | NOFOLLOW,
                PRIVATE_FILE_MODE,
                dir_fd=self._anchor_parent_fd,
            )
            _require_private_file(os.fstat(self._lock_fd), name="egress state lock")
        except Exception:
            if hasattr(self, "_lock_fd"):
                os.close(self._lock_fd)
            os.close(self._anchor_parent_fd)
            os.close(self._state_parent_fd)
            raise
        self._lock_name = lock_name
        lock_metadata = os.fstat(self._lock_fd)
        self._lock_identity = (lock_metadata.st_dev, lock_metadata.st_ino)
        self._database_identity: tuple[int, int] | None = None
        self._closed = False
        try:
            with self._guard():
                database_exists = self._entry_exists(
                    self._state_parent_fd, self._path.name
                )
                anchor_exists = self._entry_exists(
                    self._anchor_parent_fd, self._anchor_path.name
                )
                if database_exists != anchor_exists:
                    raise EgressStateIntegrityError(
                        "egress database and authenticated anchor presence disagree"
                    )
                if not database_exists:
                    if minimum_anchor != EgressStateCheckpoint.empty():
                        raise EgressStateIntegrityError(
                            "egress state is missing below the external minimum anchor"
                        )
                    self._create_database()
                    self._initialize_database()
                else:
                    if minimum_anchor.store_id is None:
                        raise EgressStateIntegrityError(
                            "existing egress state requires a non-empty external minimum anchor"
                        )
                    self._bind_existing_database()
                    with self._connect() as connection:
                        self._verify(connection, permit_anchor_catchup=True)
        except Exception:
            os.close(self._lock_fd)
            os.close(self._anchor_parent_fd)
            os.close(self._state_parent_fd)
            self._closed = True
            raise

    @property
    def path(self) -> Path:
        return self._path

    @property
    def anchor_path(self) -> Path:
        return self._anchor_path

    def close(self) -> None:
        if self._closed:
            return
        with self._guard():
            with self._connect() as connection:
                self._verify(connection, permit_anchor_catchup=False)
        os.close(self._lock_fd)
        os.close(self._anchor_parent_fd)
        os.close(self._state_parent_fd)
        self._closed = True

    @contextmanager
    def _guard(self) -> Iterator[None]:
        with self._thread_lock:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def _open_parent(self, path: Path, *, name: str) -> tuple[int, tuple[int, int]]:
        if not path.is_dir() or path.is_symlink():
            raise ValueError(f"{name} must be an existing non-symlink directory")
        descriptor = os.open(path, os.O_RDONLY | DIRECTORY | NOFOLLOW)
        metadata = os.fstat(descriptor)
        try:
            _require_private_directory(metadata, name=name)
        except Exception:
            os.close(descriptor)
            raise
        return descriptor, (metadata.st_dev, metadata.st_ino)

    @staticmethod
    def _entry_exists(parent_fd: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    def _validate_parent(
        self, path: Path, descriptor: int, identity: tuple[int, int], *, name: str
    ) -> None:
        retained = os.fstat(descriptor)
        _require_private_directory(retained, name=name)
        if (retained.st_dev, retained.st_ino) != identity:
            raise EgressStateIntegrityError(f"{name} descriptor identity changed")
        visible = os.open(path, os.O_RDONLY | DIRECTORY | NOFOLLOW)
        try:
            metadata = os.fstat(visible)
            _require_private_directory(metadata, name=name)
            if (metadata.st_dev, metadata.st_ino) != identity:
                raise EgressStateIntegrityError(f"{name} visible identity changed")
        finally:
            os.close(visible)

    def _validate_paths(self) -> None:
        if self._closed:
            raise EgressStateIntegrityError("egress state store is closed")
        self._validate_parent(
            self._path.parent,
            self._state_parent_fd,
            self._state_parent_identity,
            name="egress state parent",
        )
        self._validate_parent(
            self._anchor_path.parent,
            self._anchor_parent_fd,
            self._anchor_parent_identity,
            name="egress anchor parent",
        )
        database = os.stat(
            self._path.name, dir_fd=self._state_parent_fd, follow_symlinks=False
        )
        _require_private_file(database, name="egress database")
        if self._database_identity != (database.st_dev, database.st_ino):
            raise EgressStateIntegrityError("egress database identity changed")
        anchor = os.stat(
            self._anchor_path.name,
            dir_fd=self._anchor_parent_fd,
            follow_symlinks=False,
        )
        _require_private_file(anchor, name="egress authenticated anchor")
        lock_file = os.stat(
            self._lock_name, dir_fd=self._anchor_parent_fd, follow_symlinks=False
        )
        _require_private_file(lock_file, name="egress state lock")
        if (lock_file.st_dev, lock_file.st_ino) != self._lock_identity:
            raise EgressStateIntegrityError("egress state lock identity changed")

    def _create_database(self) -> None:
        descriptor = os.open(
            self._path.name,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | NOFOLLOW,
            PRIVATE_FILE_MODE,
            dir_fd=self._state_parent_fd,
        )
        metadata = os.fstat(descriptor)
        try:
            _require_private_file(metadata, name="egress database")
            os.fsync(descriptor)
            self._database_identity = (metadata.st_dev, metadata.st_ino)
        finally:
            os.close(descriptor)
        os.fsync(self._state_parent_fd)

    def _bind_existing_database(self) -> None:
        descriptor = os.open(
            self._path.name, os.O_RDWR | NOFOLLOW, dir_fd=self._state_parent_fd
        )
        try:
            metadata = os.fstat(descriptor)
            _require_private_file(metadata, name="egress database")
            self._database_identity = (metadata.st_dev, metadata.st_ino)
        finally:
            os.close(descriptor)

    def _connect_raw(self) -> sqlite3.Connection:
        stable_path = f"/proc/self/fd/{self._state_parent_fd}/{self._path.name}"
        connection = sqlite3.connect(stable_path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    def _connect(self) -> sqlite3.Connection:
        self._validate_paths()
        connection = self._connect_raw()
        visible = os.stat(
            self._path.name, dir_fd=self._state_parent_fd, follow_symlinks=False
        )
        if self._database_identity != (visible.st_dev, visible.st_ino):
            connection.close()
            raise EgressStateIntegrityError("egress database changed while opening")
        return connection

    def _initialize_database(self) -> None:
        connection = self._connect_raw()
        try:
            connection.executescript(SCHEMA)
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            store_id = secrets.token_hex(32)
            schema_digest = self._schema_digest(connection)
            state_digest = self._state_digest(connection)
            state_mac = self._state_mac(store_id, 0, state_digest, schema_digest)
            connection.execute(
                """
                INSERT INTO metadata
                (singleton, store_id, state_sequence, state_digest, schema_digest, state_mac)
                VALUES (1, ?, 0, ?, ?, ?)
                """,
                (store_id, state_digest, schema_digest, state_mac),
            )
            connection.commit()
            self._fsync_database()
            checkpoint = EgressStateCheckpoint(0, state_digest, store_id)
            self._write_anchor(checkpoint)
            self._validate_paths()
            self._validate_minimum(checkpoint)
        finally:
            connection.close()

    def _schema_digest(self, connection: sqlite3.Connection) -> str:
        rows = connection.execute(
            """
            SELECT type, name, tbl_name, sql FROM sqlite_master
            WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name
            """
        ).fetchall()
        return _digest([list(row) for row in rows])

    def _state_digest(self, connection: sqlite3.Connection) -> str:
        tables: dict[str, list[list[Any]]] = {}
        for table, order in (
            ("authority_watermark", "trust_domain"),
            ("dispatch_hold", "plane, action_digest"),
            ("dispatch_correlation", "plane, correlation_digest"),
            ("reconciliation_watermark", "trust_domain"),
        ):
            rows = connection.execute(f"SELECT * FROM {table} ORDER BY {order}").fetchall()
            tables[table] = [list(row) for row in rows]
        return _digest({"schema_version": SCHEMA_VERSION, "tables": tables})

    def _state_mac(
        self, store_id: str, sequence: int, state_digest: str, schema_digest: str
    ) -> str:
        body = {
            "schema_version": SCHEMA_VERSION,
            "store_id": store_id,
            "sequence": sequence,
            "state_digest": state_digest,
            "schema_digest": schema_digest,
        }
        return hmac.digest(
            self._key, b"faultloom-egress-state-v1\0" + _canonical(body), "sha256"
        ).hex()

    def _anchor_bytes(self, checkpoint: EgressStateCheckpoint) -> bytes:
        body = {
            "schema_version": SCHEMA_VERSION,
            "store_id": checkpoint.store_id,
            "sequence": checkpoint.sequence,
            "state_digest": checkpoint.state_digest,
        }
        tag = hmac.digest(
            self._key, b"faultloom-egress-anchor-v1\0" + _canonical(body), "sha256"
        ).hex()
        return _canonical({**body, "tag": tag}) + b"\n"

    def _load_anchor(self) -> EgressStateCheckpoint:
        descriptor = os.open(
            self._anchor_path.name,
            os.O_RDONLY | NOFOLLOW,
            dir_fd=self._anchor_parent_fd,
        )
        try:
            _require_private_file(os.fstat(descriptor), name="egress authenticated anchor")
            data = os.read(descriptor, 16 * 1024 + 1)
            if len(data) > 16 * 1024 or os.read(descriptor, 1):
                raise EgressStateIntegrityError("egress anchor is oversized")
        finally:
            os.close(descriptor)
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EgressStateIntegrityError("egress anchor is invalid JSON") from exc
        expected = {"schema_version", "store_id", "sequence", "state_digest", "tag"}
        if not isinstance(value, dict) or set(value) != expected:
            raise EgressStateIntegrityError("egress anchor schema is invalid")
        body = {key: value[key] for key in expected if key != "tag"}
        expected_tag = hmac.digest(
            self._key, b"faultloom-egress-anchor-v1\0" + _canonical(body), "sha256"
        ).hex()
        if value["schema_version"] != SCHEMA_VERSION or not isinstance(
            value["tag"], str
        ) or not hmac.compare_digest(value["tag"], expected_tag):
            raise EgressStateIntegrityError("egress anchor authentication failed")
        try:
            return EgressStateCheckpoint(
                sequence=value["sequence"],
                state_digest=value["state_digest"],
                store_id=value["store_id"],
            )
        except (TypeError, ValueError) as exc:
            raise EgressStateIntegrityError("egress anchor values are invalid") from exc

    def _write_anchor(self, checkpoint: EgressStateCheckpoint) -> None:
        temporary = f".{self._anchor_path.name}.{secrets.token_hex(8)}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                PRIVATE_FILE_MODE,
                dir_fd=self._anchor_parent_fd,
            )
            _require_private_file(os.fstat(descriptor), name="temporary egress anchor")
            data = self._anchor_bytes(checkpoint)
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(
                temporary,
                self._anchor_path.name,
                src_dir_fd=self._anchor_parent_fd,
                dst_dir_fd=self._anchor_parent_fd,
            )
            os.fsync(self._anchor_parent_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=self._anchor_parent_fd)
            except FileNotFoundError:
                pass

    def _metadata(
        self, connection: sqlite3.Connection
    ) -> tuple[str, int, str, str, str]:
        row = connection.execute(
            """
            SELECT store_id, state_sequence, state_digest, schema_digest, state_mac
            FROM metadata WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise EgressStateIntegrityError("egress metadata is missing")
        store_id, sequence, state_digest, schema_digest, state_mac = row
        if not _is_store_id(store_id) or type(sequence) is not int:
            raise EgressStateIntegrityError("egress metadata values are invalid")
        return store_id, sequence, state_digest, schema_digest, state_mac

    def _validate_minimum(self, checkpoint: EgressStateCheckpoint) -> None:
        floor = self._minimum_anchor
        if floor.store_id is None:
            return
        if checkpoint.store_id != floor.store_id or checkpoint.sequence < floor.sequence:
            raise EgressStateIntegrityError("egress state is below its external minimum anchor")
        if (
            checkpoint.sequence == floor.sequence
            and checkpoint.state_digest != floor.state_digest
        ):
            raise EgressStateIntegrityError("egress state diverges from its minimum anchor")

    def _verify(
        self, connection: sqlite3.Connection, *, permit_anchor_catchup: bool
    ) -> EgressStateCheckpoint:
        if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
            raise EgressStateIntegrityError("egress database application ID is invalid")
        if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
            raise EgressStateIntegrityError("egress database schema version is invalid")
        store_id, sequence, stored_digest, schema_digest, stored_mac = self._metadata(
            connection
        )
        actual_schema = self._schema_digest(connection)
        actual_digest = self._state_digest(connection)
        expected_mac = self._state_mac(store_id, sequence, stored_digest, schema_digest)
        if actual_schema != schema_digest or actual_digest != stored_digest:
            raise EgressStateIntegrityError("egress database content was modified")
        if not isinstance(stored_mac, str) or not hmac.compare_digest(
            stored_mac, expected_mac
        ):
            raise EgressStateIntegrityError("egress database authentication failed")
        database_checkpoint = EgressStateCheckpoint(sequence, stored_digest, store_id)
        anchor = self._load_anchor()
        if anchor.store_id != store_id:
            raise EgressStateIntegrityError("egress anchor belongs to another store")
        if anchor.sequence == sequence:
            if anchor.state_digest != stored_digest:
                raise EgressStateIntegrityError("egress anchor and database diverged")
        elif permit_anchor_catchup and anchor.sequence + 1 == sequence:
            self._write_anchor(database_checkpoint)
            anchor = self._load_anchor()
            if anchor != database_checkpoint:
                raise EgressStateIntegrityError("egress anchor catch-up was not durable")
        else:
            raise EgressStateIntegrityError("egress anchor and database sequence disagree")
        self._validate_minimum(database_checkpoint)
        return database_checkpoint

    def _fsync_database(self) -> None:
        descriptor = os.open(
            self._path.name, os.O_RDONLY | NOFOLLOW, dir_fd=self._state_parent_fd
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _commit(self, connection: sqlite3.Connection) -> EgressStateCheckpoint:
        store_id, sequence, _, schema_digest, _ = self._metadata(connection)
        actual_schema = self._schema_digest(connection)
        if actual_schema != schema_digest:
            connection.rollback()
            raise EgressStateIntegrityError("egress database schema changed")
        state_digest = self._state_digest(connection)
        next_sequence = sequence + 1
        state_mac = self._state_mac(
            store_id, next_sequence, state_digest, schema_digest
        )
        connection.execute(
            """
            UPDATE metadata
            SET state_sequence = ?, state_digest = ?, state_mac = ? WHERE singleton = 1
            """,
            (next_sequence, state_digest, state_mac),
        )
        connection.commit()
        self._fsync_database()
        checkpoint = EgressStateCheckpoint(next_sequence, state_digest, store_id)
        self._write_anchor(checkpoint)
        if self._load_anchor() != checkpoint:
            raise EgressStateIntegrityError("egress anchor update was not durable")
        return checkpoint

    def checkpoint(self) -> EgressStateCheckpoint:
        with self._guard(), self._connect() as connection:
            return self._verify(connection, permit_anchor_catchup=False)

    def observe_authority(
        self,
        *,
        trust_domain: str,
        trusted_key_digest: str,
        key_id: str,
        grant_id: str,
        grant_version: int,
        authority_digest: str,
        scope_epoch: int,
        epoch_digest: str,
        revoked: bool,
        observed_at: datetime,
    ) -> None:
        timestamp = observed_at.isoformat()
        with self._guard(), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._verify(connection, permit_anchor_catchup=False)
            row = connection.execute(
                """
                SELECT trusted_key_digest, key_id, grant_id, grant_version,
                       authority_digest, scope_epoch, epoch_digest, revoked
                FROM authority_watermark WHERE trust_domain = ?
                """,
                (trust_domain,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO authority_watermark
                    (trust_domain, trusted_key_digest, key_id, grant_id, grant_version,
                     authority_digest, scope_epoch, epoch_digest, revoked, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        trust_domain,
                        trusted_key_digest,
                        key_id,
                        grant_id,
                        grant_version,
                        authority_digest,
                        scope_epoch,
                        epoch_digest,
                        int(revoked),
                        timestamp,
                    ),
                )
                self._commit(connection)
                return
            (
                stored_key_digest,
                stored_key_id,
                stored_grant,
                stored_version,
                stored_authority_digest,
                stored_epoch,
                stored_epoch_digest,
                stored_revoked,
            ) = row
            if (
                stored_key_digest != trusted_key_digest
                or stored_key_id != key_id
                or stored_grant != grant_id
            ):
                connection.rollback()
                raise ValueError("authority trust binding changed")
            if grant_version < stored_version or scope_epoch < stored_epoch:
                connection.rollback()
                raise ValueError("authority or scope epoch rollback was rejected")
            if grant_version == stored_version and authority_digest != stored_authority_digest:
                connection.rollback()
                raise ValueError("same-version authority equivocation was rejected")
            if scope_epoch == stored_epoch and epoch_digest != stored_epoch_digest:
                connection.rollback()
                raise ValueError("same-number scope epoch equivocation was rejected")
            if stored_revoked and not revoked:
                connection.rollback()
                raise ValueError("authority was already revoked")
            connection.execute(
                """
                UPDATE authority_watermark
                SET grant_version = ?, authority_digest = ?, scope_epoch = ?,
                    epoch_digest = ?, revoked = ?, updated_at = ?
                WHERE trust_domain = ?
                """,
                (
                    grant_version,
                    authority_digest,
                    scope_epoch,
                    epoch_digest,
                    int(bool(stored_revoked) or revoked),
                    timestamp,
                    trust_domain,
                ),
            )
            self._commit(connection)

    def reserve_dispatch(
        self,
        *,
        plane: str,
        action_digest: str,
        correlation_digest: str,
        request_digest: str,
        dispatch_authorization_digest: str,
        reserved_at: datetime,
    ) -> str:
        timestamp = reserved_at.isoformat()
        with self._guard(), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._verify(connection, permit_anchor_catchup=False)
            row = connection.execute(
                """
                SELECT request_digest, state, attempts FROM dispatch_hold
                WHERE plane = ? AND action_digest = ?
                """,
                (plane, action_digest),
            ).fetchone()
            correlation = connection.execute(
                """
                SELECT action_digest FROM dispatch_correlation
                WHERE plane = ? AND correlation_digest = ?
                """,
                (plane, correlation_digest),
            ).fetchone()
            if correlation is not None and correlation[0] != action_digest:
                connection.rollback()
                return "conflict"
            if row is None:
                connection.execute(
                    """
                    INSERT INTO dispatch_hold
                    (plane, action_digest, correlation_digest, request_digest,
                     dispatch_authorization_digest, state, attempts,
                     reconciliation_sequence, reconciliation_id, updated_at)
                    VALUES (?, ?, ?, ?, ?, 'pending', 1, 0, NULL, ?)
                    """,
                    (
                        plane,
                        action_digest,
                        correlation_digest,
                        request_digest,
                        dispatch_authorization_digest,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO dispatch_correlation
                    (plane, correlation_digest, action_digest, first_request_digest,
                     first_reserved_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        plane,
                        correlation_digest,
                        action_digest,
                        request_digest,
                        timestamp,
                    ),
                )
                self._commit(connection)
                return "reserved"
            stored_request, state, attempts = row
            if state != "retry_authorized":
                connection.rollback()
                return "replay"
            if correlation is None:
                connection.execute(
                    """
                    INSERT INTO dispatch_correlation
                    (plane, correlation_digest, action_digest, first_request_digest,
                     first_reserved_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        plane,
                        correlation_digest,
                        action_digest,
                        request_digest,
                        timestamp,
                    ),
                )
            connection.execute(
                """
                UPDATE dispatch_hold
                SET correlation_digest = ?, request_digest = ?,
                    dispatch_authorization_digest = ?, state = 'pending',
                    attempts = ?, updated_at = ?
                WHERE plane = ? AND action_digest = ?
                """,
                (
                    correlation_digest,
                    request_digest,
                    dispatch_authorization_digest,
                    attempts + 1,
                    timestamp,
                    plane,
                    action_digest,
                ),
            )
            self._commit(connection)
            return "reserved"

    def finish_dispatch(
        self,
        *,
        plane: str,
        action_digest: str,
        request_digest: str,
        dispatch_authorization_digest: str,
        outcome: str,
        finished_at: datetime,
    ) -> None:
        if outcome not in {"completed", "failed", "unknown_outcome"}:
            raise ValueError("only dispatched outcomes can finish an egress hold")
        with self._guard(), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._verify(connection, permit_anchor_catchup=False)
            cursor = connection.execute(
                """
                UPDATE dispatch_hold SET state = ?, updated_at = ?
                WHERE plane = ? AND action_digest = ?
                  AND request_digest = ? AND dispatch_authorization_digest = ?
                  AND state = 'pending'
                """,
                (
                    outcome,
                    finished_at.isoformat(),
                    plane,
                    action_digest,
                    request_digest,
                    dispatch_authorization_digest,
                ),
            )
            if cursor.rowcount != 1:
                connection.rollback()
                raise EgressStateIntegrityError("egress hold was missing or not pending")
            self._commit(connection)

    def reconcile(
        self,
        *,
        trust_domain: str,
        trusted_key_digest: str,
        key_id: str,
        capability_id: str,
        sequence: int,
        plane: str,
        action_digest: str,
        request_digest: str,
        disposition: str,
        reconciled_at: datetime,
    ) -> bool:
        if disposition not in {"retry_authorized", "effect_confirmed"}:
            return False
        next_state = "retry_authorized" if disposition == "retry_authorized" else "completed"
        with self._guard(), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._verify(connection, permit_anchor_catchup=False)
            watermark = connection.execute(
                """
                SELECT trusted_key_digest, key_id, sequence, capability_id
                FROM reconciliation_watermark WHERE trust_domain = ?
                """,
                (trust_domain,),
            ).fetchone()
            if watermark is not None:
                stored_digest, stored_key, stored_sequence, stored_capability = watermark
                if stored_digest != trusted_key_digest or stored_key != key_id:
                    connection.rollback()
                    raise EgressStateIntegrityError("reconciliation trust binding changed")
                if sequence <= stored_sequence or capability_id == stored_capability:
                    connection.rollback()
                    return False
            row = connection.execute(
                """
                SELECT request_digest, state FROM dispatch_hold
                WHERE plane = ? AND action_digest = ?
                """,
                (plane, action_digest),
            ).fetchone()
            if row is None or row[0] != request_digest or row[1] not in {
                "pending",
                "unknown_outcome",
            }:
                connection.rollback()
                return False
            connection.execute(
                """
                UPDATE dispatch_hold SET state = ?, reconciliation_sequence = ?,
                    reconciliation_id = ?, updated_at = ?
                WHERE plane = ? AND action_digest = ?
                """,
                (
                    next_state,
                    sequence,
                    capability_id,
                    reconciled_at.isoformat(),
                    plane,
                    action_digest,
                ),
            )
            connection.execute(
                """
                INSERT INTO reconciliation_watermark
                (trust_domain, trusted_key_digest, key_id, sequence, capability_id, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(trust_domain) DO UPDATE SET
                    sequence = excluded.sequence,
                    capability_id = excluded.capability_id,
                    updated_at = excluded.updated_at
                """,
                (
                    trust_domain,
                    trusted_key_digest,
                    key_id,
                    sequence,
                    capability_id,
                    reconciled_at.isoformat(),
                ),
            )
            self._commit(connection)
            return True

    def dispatch_state(self, *, plane: str, action_digest: str) -> str | None:
        with self._guard(), self._connect() as connection:
            self._verify(connection, permit_anchor_catchup=False)
            row = connection.execute(
                """
                SELECT state FROM dispatch_hold WHERE plane = ? AND action_digest = ?
                """,
                (plane, action_digest),
            ).fetchone()
        return None if row is None else str(row[0])
