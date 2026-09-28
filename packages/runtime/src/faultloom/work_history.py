"""Private operator work records, separate from execution and verification ledgers."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import unicodedata
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import knowledge as files
from .history_files import validate_attachment, validate_check, validate_file_reference

SCHEMA = "faultloom.work-history.v1"
TRACKS = {"research": "공개 연구", "bug_bounty": "개인 버그바운티", "client": "고객 업무"}
DOMAINS = {"web_api": "Web/API", "web3": "Web3", "ai": "AI 보안", "other": "기타", "unknown": "미분류"}
STATES = {"planned": "예정", "active": "진행", "waiting": "대기", "closed": "종료", "historical": "과거 기록"}
NOTES = {"note": "작업 메모", "decision": "판단", "observation": "관찰", "negative_result": "부정 결과",
         "report": "보고서", "submission": "제보 기록", "delivery": "납품 기록", "outcome": "결과 기록",
         "correction": "정정"}
KINDS = {"case_created": "작업 등록", "case_updated": "작업 정보 수정", "reference": "자료 연결",
         "legacy_snapshot": "과거 제출표 연결", "file_reference": "파일 연결", "attachment": "첨부물 보관",
         "reference_check": "원본 다시 확인", **NOTES}
MAX_EVENTS = 5000
MAX_BYTES = 32 * 1024 * 1024
MAX_DATABASE_BYTES = 384 * 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
ZERO = "0" * 64


class HistoryError(ValueError):
    pass


def _canonical(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _text(value: object, label: str, maximum: int = 240, *, empty: bool = False, multiline: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise HistoryError(f"invalid {label}")
    for char in value:
        if unicodedata.category(char).startswith("C") and not (multiline and char in "\n\r\t"):
            raise HistoryError(f"control character in {label}")
    return value


def _exact(value: object, required: set[str], optional: set[str] | None = None) -> dict:
    try:
        return files._object(value, required, optional)
    except files.CatalogError as exc:
        raise HistoryError(str(exc)) from exc


def _choice(value: object, choices: dict, label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise HistoryError(f"invalid {label}")
    return value


def _date(value: object, *, optional: bool = False, day_allowed: bool = True) -> str | None:
    if optional and value is None:
        return None
    text = _text(value, "date", 40)
    try:
        if day_allowed and re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
            datetime.strptime(text, "%Y-%m-%d")
        elif datetime.fromisoformat(text).tzinfo is None:
            raise ValueError
    except ValueError as exc:
        raise HistoryError("date must be YYYY-MM-DD or an ISO timestamp with timezone") from exc
    return text


def _identifier(value: object, prefix: str, length: int) -> str:
    if not isinstance(value, str) or not re.fullmatch(prefix + r"_[0-9a-f]{" + str(length) + "}", value):
        raise HistoryError("invalid record identifier")
    return value


def _case(value: dict) -> None:
    _exact(value, {"title", "track", "domains", "state", "subject", "origin"})
    _text(value["title"], "title")
    _text(value["subject"], "subject", empty=True)
    _choice(value["track"], TRACKS, "track")
    _choice(value["state"], STATES, "work state")
    _choice(value["origin"], {"faultloom": "", "terminator": ""}, "origin")
    domains = value["domains"]
    if not isinstance(domains, list) or not 1 <= len(domains) <= len(DOMAINS):
        raise HistoryError("select at least one domain")
    for domain in domains:
        _choice(domain, DOMAINS, "domain")
    if len(domains) != len(set(domains)) or ("unknown" in domains and len(domains) != 1):
        raise HistoryError("duplicate or ambiguous domain selection")


def _reference(value: dict) -> None:
    _exact(value, {"origin", "path", "sha256", "bytes", "label"})
    _text(value["origin"], "reference origin", 64)
    files._relative(value["path"])
    files._sha(value["sha256"])
    _text(value["label"], "reference label")
    if type(value["bytes"]) is not int or not 0 <= value["bytes"] <= files.MAX_SOURCE_BYTES:
        raise HistoryError("invalid reference size")


def _event(value: dict) -> None:
    _exact(value, {"id", "case_id", "kind", "recorded_at", "occurred_at", "data"})
    _identifier(value["id"], "evt", 32)
    _identifier(value["case_id"], "case", 24)
    _date(value["recorded_at"], day_allowed=False)
    _date(value["occurred_at"], optional=True)
    kind = _choice(value["kind"], KINDS, "event kind")
    data = value["data"]
    if kind in {"case_created", "case_updated"}:
        _case(data)
    elif kind == "reference":
        _reference(data)
    elif kind == "file_reference":
        validate_file_reference(data)
    elif kind == "attachment":
        validate_attachment(data)
    elif kind == "reference_check":
        validate_check(data)
    elif kind == "legacy_snapshot":
        _exact(data, {"source", "line", "section", "platform", "status", "severity", "bounty_text", "submitted", "checked", "resolved"})
        _reference(data["source"])
        if type(data["line"]) is not int or not 1 <= data["line"] <= 100000:
            raise HistoryError("invalid source line")
        for name in ("section", "platform", "status", "severity", "bounty_text"):
            _text(data[name], name, 500, empty=True)
        for name in ("submitted", "checked", "resolved"):
            _date(data[name], optional=True)
    else:
        _exact(data, {"summary", "detail"}, {"corrects"})
        _text(data["summary"], "summary")
        _text(data["detail"], "detail", 12000, empty=True, multiline=True)
        if kind == "correction":
            _identifier(data.get("corrects"), "evt", 32)
        elif "corrects" in data:
            raise HistoryError("only corrections may refer to a corrected event")
    if len(_canonical(value)) > MAX_EVENT_BYTES:
        raise HistoryError("event exceeds the byte limit")


def summarize(events: list[dict]) -> list[dict]:
    cases = {}
    event_ids = set()
    for event in events:
        _event(event)
        case_id = event["case_id"]
        if event["id"] in event_ids:
            raise HistoryError("duplicate event id")
        event_ids.add(event["id"])
        if event["kind"] == "case_created":
            if case_id in cases:
                raise HistoryError("duplicate case id")
            cases[case_id] = {"id": case_id, **event["data"], "events": []}
        if case_id not in cases:
            raise HistoryError("event refers to a missing case")
        case = cases[case_id]
        if event["kind"] == "case_updated":
            if event["data"]["origin"] != case["origin"]:
                raise HistoryError("case origin cannot be rewritten")
            case.update(event["data"])
        if event["kind"] == "correction" and not any(
            prior["id"] == event["data"]["corrects"] for prior in case["events"]
        ):
            raise HistoryError("correction must refer to an earlier event in the same case")
        if event["kind"] == "reference_check":
            from .history_files import _source
            for result in event["data"]["results"]:
                prior = next((prior for prior in case["events"] if prior["id"] == result["event_id"]), None)
                if prior is None or _source(prior) != result["source"]:
                    raise HistoryError("source checks must refer to earlier sources in the same case")
        case["events"].append(event)
        case["updated_at"] = event["recorded_at"]
    return sorted(cases.values(), key=lambda case: (case["updated_at"], case["id"]), reverse=True)


def _safe_path(path: Path) -> Path:
    try:
        if not path.is_absolute():
            raise HistoryError("history directory must be absolute")
        path = files._absolute(path)
        files._ancestors(path)
        return path
    except (OSError, files.CatalogError) as exc:
        raise HistoryError("history path is unavailable or unsafe") from exc


def _private_create(path: Path, content: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _inside_git(path: Path) -> bool:
    for parent in (path, *path.parents):
        marker = parent / ".git"
        # An unrelated directory called .git is not itself a repository.
        # Worktree pointer files are conservatively treated as Git boundaries.
        if marker.is_file() or (marker.is_dir() and (marker / "HEAD").is_file()):
            return True
    return False


def initialize(directory: Path) -> dict:
    root = _safe_path(directory)
    if _inside_git(root):
        raise HistoryError("initialize private history outside Git worktrees")
    if root.exists():
        raise HistoryError("history destination already exists; use a new directory")
    root.mkdir(parents=True, mode=0o700)
    key = secrets.token_bytes(32)
    _private_create(root / "history.key", key)
    _private_create(root / "history.sqlite3", b"")
    vault_id = secrets.token_hex(16)
    marker = {"schema": SCHEMA, "vault_id": vault_id, "created_at": datetime.now(UTC).isoformat(timespec="seconds")}
    nonce = secrets.token_bytes(12)
    check = base64.b64encode(nonce + AESGCM(key).encrypt(nonce, SCHEMA.encode(), vault_id.encode())).decode()
    head_nonce = secrets.token_bytes(12)
    head = base64.b64encode(head_nonce + AESGCM(key).encrypt(
        head_nonce, _canonical({"count": 0, "head": ZERO}), (SCHEMA + ":head:" + vault_id).encode()
    )).decode()
    with sqlite3.connect(root / "history.sqlite3") as connection:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("CREATE TABLE events (sequence INTEGER PRIMARY KEY, envelope BLOB NOT NULL)")
        connection.executemany("INSERT INTO meta VALUES (?, ?)", [("vault_id", vault_id), ("key_check", check), ("head_check", head)])
    _private_create(root / "history.json", files.json_bytes(marker))
    return {"directory": str(root), "schema": SCHEMA, "vault_id": vault_id}


class WorkHistory:
    def __init__(self, directory: Path):
        self.root = _safe_path(directory)

    @contextmanager
    def _connection(self, *, write: bool = False):
        connection = None
        try:
            marker = files._read_json(self.root / "history.json")
            _exact(marker, {"schema", "vault_id", "created_at"})
            if marker["schema"] != SCHEMA or not re.fullmatch(r"[a-f0-9]{32}", str(marker["vault_id"])):
                raise HistoryError("invalid history marker")
            key = files._capture(self.root / "history.key", 32)
            if len(key) != 32:
                raise HistoryError("invalid history key")
            database = self.root / "history.sqlite3"
            for path in (database, *(Path(str(database) + suffix) for suffix in ("-journal", "-wal", "-shm"))):
                files._ancestors(path)
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    if path == database:
                        raise
                    # SQLite can remove a sidecar as another writer commits.
                    continue
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                        or getattr(metadata, "st_file_attributes", 0) & 0x400):
                    raise HistoryError("history storage must use ordinary unshared files")
            if database.stat().st_size > MAX_DATABASE_BYTES:
                raise HistoryError("history database exceeds its size limit")
            connection = sqlite3.connect(database.as_uri() + ("?mode=rw" if write else "?mode=ro"),
                                         uri=True, timeout=5, isolation_level=None)
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA synchronous=FULL")
            if not write:
                connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            metadata = dict(connection.execute("SELECT name, value FROM meta"))
            if metadata.get("vault_id") != marker["vault_id"]:
                raise HistoryError("history identity mismatch")
            encoded = base64.b64decode(metadata["key_check"], validate=True)
            cipher = AESGCM(key)
            if cipher.decrypt(encoded[:12], encoded[12:], marker["vault_id"].encode()) != SCHEMA.encode():
                raise HistoryError("history key check failed")
            yield connection, cipher, marker["vault_id"]
            connection.commit()
        except (OSError, sqlite3.Error, InvalidTag, files.CatalogError, KeyError, TypeError, ValueError, RecursionError) as exc:
            if connection is not None:
                connection.rollback()
            if isinstance(exc, HistoryError):
                raise
            raise HistoryError("history could not be read or committed; check its files and key") from exc
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _aad(vault_id: str, sequence: int, previous: str) -> bytes:
        return _canonical({"schema": SCHEMA, "vault_id": vault_id, "sequence": sequence, "previous": previous})

    def _read(self, connection, cipher, vault_id) -> tuple[list[dict], str, int]:
        count, total = connection.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(envelope)), 0) FROM events").fetchone()
        if count > MAX_EVENTS or total > MAX_BYTES:
            raise HistoryError("history event limits exceeded")
        events, previous = [], ZERO
        for expected, (sequence, raw) in enumerate(connection.execute("SELECT sequence, envelope FROM events ORDER BY sequence"), 1):
            if sequence != expected or not isinstance(raw, bytes) or len(raw) > MAX_EVENT_BYTES * 2:
                raise HistoryError("history sequence or envelope is invalid")
            outer = json.loads(raw, object_pairs_hook=files._pairs)
            files._depth(outer)
            _exact(outer, {"previous", "nonce", "ciphertext"})
            if outer["previous"] != previous:
                raise HistoryError("history digest chain mismatch")
            nonce = base64.b64decode(outer["nonce"], validate=True)
            ciphertext = base64.b64decode(outer["ciphertext"], validate=True)
            if len(nonce) != 12:
                raise HistoryError("invalid event nonce")
            plain = cipher.decrypt(nonce, ciphertext, self._aad(vault_id, sequence, previous))
            event = json.loads(plain, object_pairs_hook=files._pairs)
            files._depth(event)
            _event(event)
            events.append(event)
            previous = hashlib.sha256(raw).hexdigest()
        summarize(events)
        seal = connection.execute("SELECT value FROM meta WHERE name='head_check'").fetchone()
        if seal is None:
            raise HistoryError("history head seal is missing")
        encoded = base64.b64decode(seal[0], validate=True)
        head = json.loads(cipher.decrypt(encoded[:12], encoded[12:], (SCHEMA + ":head:" + vault_id).encode()))
        if head != {"count": len(events), "head": previous}:
            raise HistoryError("history head seal does not match the records")
        return events, previous, total

    def snapshot(self) -> dict:
        with self._connection() as (connection, cipher, vault_id):
            events, head, _ = self._read(connection, cipher, vault_id)
            return {"schema": SCHEMA, "vault_id": vault_id, "head": head,
                    "event_count": len(events), "cases": summarize(events),
                    "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                    "attestation": "operator_records_not_independent_verification"}

    def backup(self, destination: Path) -> dict:
        target = _safe_path(destination)
        if _inside_git(target) or target.exists() or target.is_relative_to(self.root):
            raise HistoryError("backup requires a new private directory outside the history and Git worktrees")
        with self._connection() as (connection, cipher, vault_id):
            events, head, _ = self._read(connection, cipher, vault_id)
            target.mkdir(parents=True, mode=0o700)
            _private_create(target / "history.key", files._capture(self.root / "history.key", 32))
            _private_create(target / "history.json", files._capture(self.root / "history.json", files.MAX_JSON_BYTES))
            _private_create(target / "history.sqlite3", b"")
            with sqlite3.connect(target / "history.sqlite3") as copy:
                connection.backup(copy)
        restored = WorkHistory(target).snapshot()
        if restored["head"] != head or restored["event_count"] != len(events):
            raise HistoryError("backup verification failed; retain both directories for review")
        from .history_files import verify_archives
        archives = verify_archives(WorkHistory(target))
        return {"backup": str(target), "events": len(events), "head": head, "includes_local_key": True, **archives}

    def append_batch(self, additions: list[dict], *, expected_head: str | None = None) -> dict:
        for event in additions:
            _event(event)
        with self._connection(write=True) as (connection, cipher, vault_id):
            return self._append_locked(connection, cipher, vault_id, additions, expected_head=expected_head)

    def _append_locked(self, connection, cipher, vault_id, additions, *, expected_head=None):
        from .history_files import _read_blob
        for event in additions:
            _event(event)
        events, previous, total = self._read(connection, cipher, vault_id)
        known = {event["id"]: event for event in events}
        pending = []
        for event in additions:
            if event["id"] in known:
                prior = {key: value for key, value in known[event["id"]].items() if key != "recorded_at"}
                current = {key: value for key, value in event.items() if key != "recorded_at"}
                if prior != current:
                    raise HistoryError("event id conflicts with an existing record")
                continue
            pending.append(event)
            known[event["id"]] = event
        if pending and expected_head is not None and previous != expected_head:
            raise HistoryError("history changed concurrently; read the current state and retry the edit")
        if len(events) + len(pending) > MAX_EVENTS:
            raise HistoryError("history event limit exceeded")
        summarize(events + pending)
        for sequence, event in enumerate(pending, len(events) + 1):
            if event["kind"] == "attachment":
                _read_blob(connection, cipher, vault_id, event["case_id"], event["data"])
            nonce = secrets.token_bytes(12)
            encrypted = cipher.encrypt(nonce, _canonical(event), self._aad(vault_id, sequence, previous))
            raw = _canonical({"previous": previous, "nonce": base64.b64encode(nonce).decode(),
                              "ciphertext": base64.b64encode(encrypted).decode()})
            total += len(raw)
            if total > MAX_BYTES:
                raise HistoryError("history byte limit exceeded")
            connection.execute("INSERT INTO events VALUES (?, ?)", (sequence, raw))
            previous = hashlib.sha256(raw).hexdigest()
        if pending:
            nonce = secrets.token_bytes(12)
            encoded = base64.b64encode(nonce + cipher.encrypt(
                nonce, _canonical({"count": len(events) + len(pending), "head": previous}),
                (SCHEMA + ":head:" + vault_id).encode()
            )).decode()
            connection.execute("UPDATE meta SET value=? WHERE name='head_check'", (encoded,))
        return {"appended": len(pending), "unchanged": len(additions) - len(pending), "head": previous}

    def create(self, data: dict, *, occurred_at: str | None = None) -> str:
        case_id = "case_" + secrets.token_hex(12)
        event = new_event(case_id, "case_created", data, occurred_at=occurred_at)
        self.append_batch([event])
        return case_id

    def record(self, case_id: str, kind: str, summary: str, detail: str = "", *, occurred_at=None, corrects=None) -> str:
        _choice(kind, NOTES, "note kind")
        data = {"summary": summary, "detail": detail}
        if corrects is not None:
            data["corrects"] = corrects
        event = new_event(case_id, kind, data, occurred_at=occurred_at)
        self.append_batch([event])
        return event["id"]

    def update(self, case_id: str, changes: dict) -> str:
        allowed = {"title", "track", "domains", "state", "subject"}
        if not changes or changes.keys() - allowed:
            raise HistoryError("invalid case update fields")
        # append_batch checks the journal again under the writer transaction. The
        # expected-head check below prevents overwriting a concurrent edit.
        snapshot = self.snapshot()
        case = next((case for case in snapshot["cases"] if case["id"] == case_id), None)
        if case is None:
            raise HistoryError("unknown case")
        data = {key: case[key] for key in (*allowed, "origin")}
        data.update(changes)
        event = new_event(case_id, "case_updated", data)
        self.append_batch([event], expected_head=snapshot["head"])
        return event["id"]


def new_event(case_id: str, kind: str, data: dict, *, occurred_at=None, event_id=None) -> dict:
    event = {"id": event_id or "evt_" + secrets.token_hex(16), "case_id": case_id, "kind": kind,
             "recorded_at": datetime.now(UTC).isoformat(timespec="microseconds"),
             "occurred_at": occurred_at, "data": data}
    _event(event)
    return event


def source_reference(root: Path, relative: str, *, origin: str, label: str) -> dict:
    source = files._root(root)
    path = files._relative(relative)
    raw = files._capture(source / path, files.MAX_SOURCE_BYTES)
    return {"origin": origin, "path": path, "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw), "label": label}


def write_export(path: Path, content: bytes, *, history_root: Path) -> None:
    destination = files._absolute(path)
    if _inside_git(destination.parent):
        raise HistoryError("export private records outside Git worktrees")
    files.write_new(destination, content, source_root=history_root)
