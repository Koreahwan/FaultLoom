"""Opaque local file archival and source checks for private work records."""
from __future__ import annotations

import hashlib
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from . import knowledge as files

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_BLOBS = 1024
MAX_CHECK_BYTES = 64 * 1024 * 1024
FILE_SUFFIXES = files.TEXT_SUFFIXES | {".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".tsv", ".log", ".pdf",
                 ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".html", ".zip", ".gz",
                 ".docx", ".xlsx", ".pptx", ".py", ".js", ".ts", ".rs", ".go", ".sol", ".sql",
                 ".c", ".cpp", ".h", ".java", ".diff", ".patch", ".har", ".mp4", ".webm"}
CHECK_STATUSES = {"unchanged", "changed", "missing", "unmapped", "unsafe_or_unavailable", "budget_exhausted"}


def relative_file(value: str) -> str:
    text = files._text(value, "file path", 700)
    path = PurePosixPath(text)
    if path.is_absolute() or path.as_posix() != text or not path.parts:
        raise files.CatalogError("file path must be canonical and relative")
    for part in path.parts:
        if part in {".", ".."} or part[-1:] in {".", " "} or any(char in part for char in '\\:<>"|?*'):
            raise files.CatalogError("unsafe file path component")
        if part.split(".", 1)[0].upper() in files._RESERVED:
            raise files.CatalogError("reserved file path component")
    if path.name.lower() in files._SECRET_NAMES | {"history.json", "history.sqlite3"} or path.name.lower().startswith(".env"):
        raise files.CatalogError("credential and history-storage files cannot be selected")
    if path.suffix.lower() not in FILE_SUFFIXES:
        raise files.CatalogError("unsupported attachment file type")
    return text


def validate_file_reference(value: dict) -> None:
    files._object(value, {"origin", "path", "sha256", "bytes", "label"})
    files._text(value["origin"], "origin", 64)
    relative_file(value["path"])
    files._sha(value["sha256"])
    files._text(value["label"], "label")
    if type(value["bytes"]) is not int or not 0 <= value["bytes"] <= MAX_FILE_BYTES:
        raise files.CatalogError("invalid file byte count")


def validate_attachment(value: dict) -> None:
    files._object(value, {"name", "label", "sha256", "bytes", "blob_id", "source"})
    if PurePosixPath(relative_file(value["name"])).name != value["name"]:
        raise files.CatalogError("attachment name must be a basename")
    files._text(value["label"], "label")
    files._sha(value["sha256"])
    files._sha(value["blob_id"])
    if type(value["bytes"]) is not int or not 0 <= value["bytes"] <= MAX_FILE_BYTES:
        raise files.CatalogError("invalid attachment byte count")
    validate_file_reference(value["source"])
    if value["source"]["sha256"] != value["sha256"] or value["source"]["bytes"] != value["bytes"]:
        raise files.CatalogError("attachment and captured source differ")


def validate_check(value: dict) -> None:
    files._object(value, {"checked_at", "results"})
    stamp = datetime.fromisoformat(files._text(value["checked_at"], "check time", 40))
    if stamp.tzinfo is None:
        raise files.CatalogError("source check time requires a timezone")
    if not isinstance(value["results"], list) or len(value["results"]) > 200:
        raise files.CatalogError("source check result limit exceeded")
    seen = set()
    for result in value["results"]:
        files._object(result, {"event_id", "source", "status", "observed_sha256"})
        if not isinstance(result["event_id"], str) or not re.fullmatch(r"evt_[a-f0-9]{32}", result["event_id"]):
            raise files.CatalogError("invalid source event")
        if result["event_id"] in seen:
            raise files.CatalogError("duplicate source result")
        seen.add(result["event_id"])
        validate_file_reference(result["source"])
        if not isinstance(result["status"], str) or result["status"] not in CHECK_STATUSES:
            raise files.CatalogError("invalid source status")
        if result["observed_sha256"] is not None:
            files._sha(result["observed_sha256"])
        if result["status"] in {"unchanged", "changed"} and result["observed_sha256"] is None:
            raise files.CatalogError("a checked source needs an observed digest")
        if result["status"] == "unchanged" and result["observed_sha256"] != result["source"]["sha256"]:
            raise files.CatalogError("unchanged source digest differs")


def capture_reference(root: Path, relative: str, *, origin: str, label: str, maximum: int = MAX_FILE_BYTES) -> tuple[dict, bytes]:
    root = files._root(root)
    relative = relative_file(relative)
    raw = files._capture(root / relative, min(maximum, MAX_FILE_BYTES))
    reference = {"origin": origin, "path": relative, "label": label,
                 "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    validate_file_reference(reference)
    return reference, raw


def _source(event: dict) -> dict | None:
    if event["kind"] in {"reference", "file_reference"}:
        return event["data"]
    if event["kind"] == "legacy_snapshot":
        return event["data"]["source"]
    if event["kind"] == "attachment":
        return event["data"]["source"]
    return None


def check_sources(store, case_id: str, roots: dict[str, Path], *, event_id: str | None = None, expected_head: str | None = None) -> dict:
    from .work_history import HistoryError, new_event
    snapshot = store.snapshot()
    case = next((case for case in snapshot["cases"] if case["id"] == case_id), None)
    if case is None:
        raise HistoryError("unknown case")
    if event_id is not None:
        known = next((event for event in case["events"] if event["id"] == event_id), None)
        if known:
            if known["kind"] != "reference_check":
                raise HistoryError("event id conflicts with an existing record")
            return {"appended": 0, "event_id": event_id, "case_id": case_id, "checks": known["data"]}
    selected = [(event, _source(event)) for event in case["events"] if _source(event) is not None]
    if len(selected) > 200:
        raise HistoryError("case has too many source references for one check")
    results, cache, consumed = [], {}, 0
    for event, reference in selected:
        identity = (reference["origin"], reference["path"], reference["sha256"], reference["bytes"])
        if identity not in cache:
            status, observed = "unmapped", None
            root = roots.get(reference["origin"])
            if root is not None:
                remaining = MAX_CHECK_BYTES - consumed
                try:
                    if remaining < reference["bytes"]:
                        status = "budget_exhausted"
                    else:
                        current, raw = capture_reference(root, reference["path"], origin=reference["origin"], label=reference["label"], maximum=remaining)
                        consumed += len(raw)
                        observed = current["sha256"]
                        status = "unchanged" if observed == reference["sha256"] and current["bytes"] == reference["bytes"] else "changed"
                except FileNotFoundError:
                    status = "missing"
                except (OSError, files.CatalogError):
                    consumed += min(MAX_FILE_BYTES, remaining)
                    status = "unsafe_or_unavailable"
            cache[identity] = status, observed
        status, observed = cache[identity]
        results.append({"event_id": event["id"], "source": reference, "status": status, "observed_sha256": observed})
    checks = {"checked_at": datetime.now(UTC).isoformat(timespec="seconds"), "results": results}
    validate_check(checks)
    if event_id is None:
        return {"case_id": case_id, "checks": checks}
    event = new_event(case_id, "reference_check", checks, event_id=event_id)
    result = store.append_batch([event], expected_head=expected_head or snapshot["head"])
    return {**result, "event_id": event_id, "case_id": case_id, "checks": checks}


def _aad(vault_id: str, case_id: str, data: dict) -> bytes:
    from .work_history import _canonical
    return _canonical({"schema": "faultloom.history-attachment.v1", "vault_id": vault_id,
                       "case_id": case_id, "blob_id": data["blob_id"], "sha256": data["sha256"], "bytes": data["bytes"]})


def _read_blob(connection, cipher, vault_id: str, case_id: str, data: dict) -> bytes:
    from .work_history import HistoryError
    validate_attachment(data)
    exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='attachments'").fetchone()
    if not exists:
        raise HistoryError("attachment storage is missing")
    length = connection.execute("SELECT LENGTH(envelope) FROM attachments WHERE blob_id=?", (data["blob_id"],)).fetchone()
    if length is None or type(length[0]) is not int or length[0] != data["bytes"] + 28:
        raise HistoryError("attachment is missing or exceeds its size limit")
    row = connection.execute("SELECT envelope FROM attachments WHERE blob_id=?", (data["blob_id"],)).fetchone()
    if not isinstance(row[0], bytes):
        raise HistoryError("attachment storage has an invalid type")
    raw = cipher.decrypt(row[0][:12], row[0][12:], _aad(vault_id, case_id, data))
    if len(raw) != data["bytes"] or hashlib.sha256(raw).hexdigest() != data["sha256"]:
        raise HistoryError("attachment content digest mismatch")
    return raw


def archive_source(store, case_id: str, root: Path, relative: str, *, origin: str, label: str,
                   expected_sha256: str, event_id: str | None = None, expected_head: str | None = None) -> dict:
    from .work_history import HistoryError, new_event
    files._sha(expected_sha256)
    if event_id is not None:
        with store._connection() as (connection, cipher, vault_id):
            events, head, _ = store._read(connection, cipher, vault_id)
            known = next((event for event in events if event["id"] == event_id), None)
            if known:
                if (known["case_id"] != case_id or known["kind"] != "attachment"
                        or known["data"]["source"]["origin"] != origin or known["data"]["source"]["path"] != relative
                        or known["data"]["label"] != label or known["data"]["sha256"] != expected_sha256):
                    raise HistoryError("event id conflicts with an existing record")
                _read_blob(connection, cipher, vault_id, case_id, known["data"])
                return {"appended": 0, "event_id": event_id, "case_id": case_id, "attachment": known["data"], "head": head}
    source_path = files._root(root) / relative_file(relative)
    if files._absolute(source_path).is_relative_to(store.root):
        raise HistoryError("history storage cannot archive itself")
    reference, raw = capture_reference(root, relative, origin=origin, label=label)
    if reference["sha256"] != expected_sha256:
        raise HistoryError("source changed since review; link the current source before archiving")
    event_id = event_id or "evt_" + secrets.token_hex(16)
    with store._connection(write=True) as (connection, cipher, vault_id):
        events, head, _ = store._read(connection, cipher, vault_id)
        known = next((event for event in events if event["id"] == event_id), None)
        content = {"name": PurePosixPath(relative).name, "label": label, "sha256": reference["sha256"],
                   "bytes": len(raw), "source": reference}
        if known:
            if known["kind"] != "attachment" or known["case_id"] != case_id or any(known["data"].get(key) != value for key, value in content.items()):
                raise HistoryError("event id conflicts with an existing record")
            _read_blob(connection, cipher, vault_id, case_id, known["data"])
            return {"appended": 0, "event_id": event_id, "case_id": case_id, "attachment": known["data"], "head": head}
        if not any(event["case_id"] == case_id for event in events):
            raise HistoryError("unknown case")
        if expected_head is not None and head != expected_head:
            raise HistoryError("history changed concurrently; refresh before archiving")
        previous = next((event for event in events if event["case_id"] == case_id and event["kind"] == "attachment"
                         and event["data"]["sha256"] == reference["sha256"]), None)
        connection.execute("CREATE TABLE IF NOT EXISTS attachments (blob_id TEXT PRIMARY KEY, envelope BLOB NOT NULL)")
        if previous:
            _read_blob(connection, cipher, vault_id, case_id, previous["data"])
            blob_id = previous["data"]["blob_id"]
        else:
            count, size = connection.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(envelope)),0) FROM attachments").fetchone()
            if count >= MAX_BLOBS or size + len(raw) + 28 > MAX_ARCHIVE_BYTES:
                raise HistoryError("attachment archive limit exceeded")
            blob_id = secrets.token_hex(32)
            nonce = secrets.token_bytes(12)
            content["blob_id"] = blob_id
            envelope = nonce + cipher.encrypt(nonce, raw, _aad(vault_id, case_id, content))
            connection.execute("INSERT INTO attachments VALUES (?, ?)", (blob_id, envelope))
        content["blob_id"] = blob_id
        event = new_event(case_id, "attachment", content, event_id=event_id)
        result = store._append_locked(connection, cipher, vault_id, [event], expected_head=head)
        return {**result, "event_id": event_id, "case_id": case_id, "attachment": content}


def read_attachment(store, case_id: str, event_id: str) -> tuple[dict, bytes]:
    from .work_history import HistoryError
    with store._connection() as (connection, cipher, vault_id):
        events, _, _ = store._read(connection, cipher, vault_id)
        event = next((event for event in events if event["id"] == event_id and event["case_id"] == case_id and event["kind"] == "attachment"), None)
        if event is None:
            raise HistoryError("attachment does not belong to this case")
        return event["data"], _read_blob(connection, cipher, vault_id, case_id, event["data"])


def verify_archives(store) -> dict:
    from .work_history import HistoryError
    with store._connection() as (connection, cipher, vault_id):
        events, head, _ = store._read(connection, cipher, vault_id)
        exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='attachments'").fetchone()
        stored_ids = set()
        if exists:
            count, size = connection.execute("SELECT COUNT(*), COALESCE(SUM(LENGTH(envelope)),0) FROM attachments").fetchone()
            if count > MAX_BLOBS or size > MAX_ARCHIVE_BYTES:
                raise HistoryError("attachment archive limits exceeded")
            stored_ids = {row[0] for row in connection.execute("SELECT blob_id FROM attachments")}
        seen, total = {}, 0
        for event in events:
            if event["kind"] != "attachment":
                continue
            identity = (event["case_id"], event["data"]["blob_id"])
            expected = (event["data"]["sha256"], event["data"]["bytes"])
            if identity in seen:
                if seen[identity] != expected:
                    raise HistoryError("attachment metadata has conflicting content bindings")
                continue
            raw = _read_blob(connection, cipher, vault_id, event["case_id"], event["data"])
            seen[identity] = expected
            total += len(raw)
        if stored_ids != {blob_id for _, blob_id in seen}:
            raise HistoryError("attachment storage has unreferenced content; preserve it for review")
        return {"verified_attachments": len(seen), "verified_plaintext_bytes": total,
                "head": head, "events": len(events), "cases": len({event["case_id"] for event in events})}
