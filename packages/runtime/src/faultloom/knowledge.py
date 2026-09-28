"""Offline, inert reference catalogues. These records grant no execution authority."""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import stat
import unicodedata
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

SELECTION_SCHEMA = "faultloom.reference-selection.v1"
CATALOG_SCHEMA = "faultloom.reference-catalog.v1"
CHECK_SCHEMA = "faultloom.reference-check.v1"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 2000
KINDS = {
    "reference": "참고자료",
    "report_template": "보고서 템플릿",
    "role_prompt": "역할 프롬프트",
    "workflow_rule": "작업 규칙",
    "skill": "스킬",
    "research_note": "연구 노트",
    "case_record": "사례 기록",
    "guide": "검토 가이드",
}
REVIEWS = {"unreviewed": "내용 검토 전", "operator_reviewed": "사용자 검토 표시", "retired": "참고 중단"}
TEXT_SUFFIXES = {".md", ".rst", ".txt", ".json", ".yaml", ".yml", ".j2", ".jinja2"}
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
_SECRET_NAMES = {"credentials.json", "secrets.json", "secrets.yaml", "secrets.yml", "settings.local.json", "mcp.json", ".mcp.json"}


class CatalogError(ValueError):
    """An input or local reference could not be handled within the documented limits."""


def _text(value: Any, label: str, maximum: int = 240, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not value.strip() and not empty):
        raise CatalogError(f"invalid {label}")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise CatalogError(f"control characters in {label}")
    return value


def _object(value: Any, required: set[str], optional: set[str] | None = None) -> dict:
    if type(value) is not dict or not required <= value.keys():
        raise CatalogError("required object fields are missing")
    if value.keys() - required - (optional or set()):
        raise CatalogError("unknown object fields")
    return value


def _sha(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise CatalogError("invalid SHA-256 digest")
    return value


def _relative(value: Any) -> str:
    text = _text(value, "reference path", 700)
    path = PurePosixPath(text)
    if path.is_absolute() or path.as_posix() != text or not path.parts:
        raise CatalogError("reference path must be a canonical relative path")
    for part in path.parts:
        if part in {".", ".."} or part[-1:] in {".", " "} or any(c in part for c in '\\:<>"|?*'):
            raise CatalogError("reference path contains an unsafe component")
        if part.split(".", 1)[0].upper() in _RESERVED:
            raise CatalogError("reference path names a reserved device")
    if path.suffix.lower() not in TEXT_SUFFIXES:
        raise CatalogError("only reference text files may be selected")
    if path.name.lower() in _SECRET_NAMES or path.name.lower().startswith(".env"):
        raise CatalogError("secret or connection configuration cannot be selected")
    return text


def _absolute(path: Path) -> Path:
    if str(path).startswith(("\\\\", "//")):
        raise CatalogError("network paths are not supported")
    result = Path(os.path.abspath(path))
    if os.name == "nt":
        import ctypes

        if ctypes.windll.kernel32.GetDriveTypeW(str(result.anchor)) == 4:
            raise CatalogError("network drives are not supported")
    return result


def _ancestors(path: Path) -> list[tuple[Path, int, int]]:
    identities = []
    for item in (*reversed(path.parents), path):
        try:
            metadata = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise CatalogError("links and reparse points are not supported")
        identities.append((item, metadata.st_dev, metadata.st_ino))
    return identities


def _root(path: Path) -> Path:
    if not path.is_absolute():
        raise CatalogError("source root must be an absolute local directory")
    path = _absolute(path)
    try:
        _ancestors(path)
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise CatalogError("source root must be a directory")
    except OSError as exc:
        raise CatalogError("source root is unavailable") from exc
    return path


def _identity(metadata: os.stat_result) -> tuple:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _file_binding(metadata: os.stat_result) -> tuple:
    # Windows path stat and handle stat can report different ctime semantics.
    # Compare timestamps within the same API below, while binding file identity here.
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_size, metadata.st_mtime_ns)


def _capture(path: Path, maximum: int) -> bytes:
    """Bound the read and reject detectable path/file changes. Never write to inputs."""
    path = _absolute(path)
    parents = _ancestors(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise CatalogError("reference is not a regular file")
    if before.st_size > maximum:
        raise CatalogError("reference exceeds the byte limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if _file_binding(opened) != _file_binding(before):
            raise CatalogError("reference changed before capture")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    if len(data) > maximum:
        raise CatalogError("reference exceeds the byte limit")
    if _identity(opened) != _identity(after) or _identity(path.lstat()) != _identity(before):
        raise CatalogError("reference changed during capture")
    if _ancestors(path) != parents:
        raise CatalogError("reference path changed during capture")
    return data


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("duplicate JSON key")
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise CatalogError("non-finite JSON number")


def _depth(value: Any, level: int = 0) -> None:
    if level > 24:
        raise CatalogError("JSON nesting exceeds the limit")
    if isinstance(value, dict):
        for child in value.values():
            _depth(child, level + 1)
    elif isinstance(value, list):
        for child in value:
            _depth(child, level + 1)


def _read_json(path: Path) -> dict:
    try:
        data = _capture(path, MAX_JSON_BYTES)
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        _depth(value)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise CatalogError("JSON input is unavailable or malformed") from exc
    if type(value) is not dict:
        raise CatalogError("JSON input must be an object")
    return value


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def catalog_digest(value: dict) -> str:
    unsigned = {key: item for key, item in value.items() if key != "digest"}
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _origin(value: Any) -> dict:
    item = _object(value, {"id", "label"})
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", _text(item["id"], "origin id", 64)):
        raise CatalogError("invalid origin id")
    _text(item["label"], "origin label", 120)
    return item


def _entry_id(origin: str, path: str) -> str:
    return "ref_" + hashlib.sha256((origin + "\0" + path).encode("utf-8")).hexdigest()[:24]


def _entries(value: Any) -> list:
    if type(value) is not list or not 1 <= len(value) <= MAX_ENTRIES:
        raise CatalogError(f"entries must contain 1..{MAX_ENTRIES} items")
    return value


def _annotations(entry: dict) -> tuple[str, str, list[str]]:
    if not isinstance(entry.get("kind"), str) or entry["kind"] not in KINDS:
        raise CatalogError("unknown reference kind")
    review = entry.get("review", "unreviewed")
    if not isinstance(review, str) or review not in REVIEWS:
        raise CatalogError("unknown review label")
    tags = entry.get("tags", [])
    if type(tags) is not list or len(tags) > 12:
        raise CatalogError("invalid tags")
    for tag in tags:
        _text(tag, "tag", 50)
    if len(set(tags)) != len(tags):
        raise CatalogError("duplicate tags")
    return entry["kind"], review, tags


def build_catalog(source_root: Path, selection_path: Path) -> dict:
    root = _root(source_root)
    selection = _object(_read_json(selection_path), {"schema", "origin", "entries"})
    if selection["schema"] != SELECTION_SCHEMA:
        raise CatalogError("unsupported selection schema")
    origin = _origin(selection["origin"])
    result = []
    seen = set()
    consumed = 0
    for value in _entries(selection["entries"]):
        entry = _object(value, {"path", "kind"}, {"title", "review", "tags", "expected_sha256"})
        relative = _relative(entry["path"])
        normalized = unicodedata.normalize("NFC", relative).casefold()
        if normalized in seen:
            raise CatalogError("duplicate reference path")
        seen.add(normalized)
        kind, review, tags = _annotations(entry)
        title = _text(entry.get("title", PurePosixPath(relative).stem), "title", 240)
        maximum = min(MAX_SOURCE_BYTES, MAX_TOTAL_BYTES - consumed)
        try:
            raw = _capture(root / relative, maximum)
        except OSError as exc:
            raise CatalogError(f"selected reference is unavailable: {relative}") from exc
        consumed += len(raw)
        sha256 = hashlib.sha256(raw).hexdigest()
        if "expected_sha256" in entry and _sha(entry["expected_sha256"]) != sha256:
            raise CatalogError(f"selected digest changed: {relative}")
        result.append({"id": _entry_id(origin["id"], relative), "path": relative, "kind": kind,
                       "title": title, "review": review, "tags": tags, "bytes": len(raw), "sha256": sha256})
    catalog = {"schema": CATALOG_SCHEMA, "origin": origin,
               "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
               "use": "human_reference_only", "content_status": "not_evaluated", "entries": result}
    catalog["digest"] = catalog_digest(catalog)
    validate_catalog(catalog)
    return catalog


def validate_catalog(catalog: dict) -> None:
    _object(catalog, {"schema", "origin", "created_at", "use", "content_status", "entries", "digest"})
    if catalog["schema"] != CATALOG_SCHEMA or catalog["use"] != "human_reference_only":
        raise CatalogError("unsupported catalogue contract")
    if catalog["content_status"] != "not_evaluated":
        raise CatalogError("catalogues cannot assert content correctness")
    origin = _origin(catalog["origin"])
    try:
        timestamp = datetime.fromisoformat(_text(catalog["created_at"], "timestamp", 40))
        if timestamp.tzinfo is None:
            raise ValueError
    except ValueError as exc:
        raise CatalogError("invalid catalogue timestamp") from exc
    seen = set()
    total_bytes = 0
    for value in _entries(catalog["entries"]):
        entry = _object(value, {"id", "path", "kind", "title", "review", "tags", "bytes", "sha256"})
        relative = _relative(entry["path"])
        normalized = unicodedata.normalize("NFC", relative).casefold()
        if normalized in seen or entry["id"] != _entry_id(origin["id"], relative):
            raise CatalogError("duplicate path or invalid reference id")
        seen.add(normalized)
        _annotations(entry)
        _text(entry["title"], "title", 240)
        _sha(entry["sha256"])
        if type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= MAX_SOURCE_BYTES:
            raise CatalogError("invalid reference byte count")
        total_bytes += entry["bytes"]
    if total_bytes > MAX_TOTAL_BYTES:
        raise CatalogError("catalogue exceeds the total byte limit")
    if _sha(catalog["digest"]) != catalog_digest(catalog):
        raise CatalogError("catalogue digest mismatch")


def load_catalog(path: Path) -> dict:
    catalog = _read_json(path)
    validate_catalog(catalog)
    return catalog


def search_catalog(catalog: dict, query: str, *, kind: str | None = None, limit: int = 50) -> list[dict]:
    validate_catalog(catalog)
    _text(query, "query", 240, empty=True)
    if kind is not None and (not isinstance(kind, str) or kind not in KINDS):
        raise CatalogError("unknown reference kind")
    if type(limit) is not int or not 1 <= limit <= MAX_ENTRIES:
        raise CatalogError("invalid result limit")
    tokens = query.casefold().split()
    matches = []
    for entry in catalog["entries"]:
        if kind is not None and entry["kind"] != kind:
            continue
        haystack = " ".join([entry["title"], entry["path"], entry["kind"], KINDS[entry["kind"]], *entry["tags"]]).casefold()
        if all(token in haystack for token in tokens):
            score = sum(2 if token in entry["title"].casefold() else 1 for token in tokens)
            matches.append((score, entry))
    return [entry for _, entry in sorted(matches, key=lambda item: (-item[0], item[1]["path"]))[:limit]]


def _selected(catalog: dict, ids: list[str] | None) -> list[dict]:
    if ids is None:
        return catalog["entries"]
    if not ids or len(ids) != len(set(ids)):
        raise CatalogError("select at least one unique reference id")
    by_id = {entry["id"]: entry for entry in catalog["entries"]}
    if any(item not in by_id for item in ids):
        raise CatalogError("unknown selected reference id")
    return [by_id[item] for item in ids]


def check_catalog(catalog: dict, source_root: Path, ids: list[str] | None = None) -> dict:
    validate_catalog(catalog)
    root = _root(source_root)
    results = []
    consumed = 0
    for entry in _selected(catalog, ids):
        record = {"id": entry["id"], "path": entry["path"], "expected_sha256": entry["sha256"]}
        try:
            raw = _capture(root / entry["path"], min(MAX_SOURCE_BYTES, MAX_TOTAL_BYTES - consumed))
            consumed += len(raw)
            observed = hashlib.sha256(raw).hexdigest()
            record.update(status="unchanged" if observed == entry["sha256"] and len(raw) == entry["bytes"] else "changed",
                          observed_sha256=observed)
        except FileNotFoundError:
            record["status"] = "missing"
        except (OSError, CatalogError):
            record["status"] = "unsafe_or_unavailable"
        results.append(record)
    return {"schema": CHECK_SCHEMA, "catalog_digest": catalog["digest"],
            "checked_at": datetime.now(UTC).isoformat(timespec="seconds"), "entries": results}


def markdown_text(value: str) -> str:
    value = html.escape(value, quote=False)
    return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", value)


def make_packet(catalog: dict, source_root: Path, ids: list[str], purpose: str) -> str:
    validate_catalog(catalog)
    _text(purpose, "review purpose", 240)
    entries = _selected(catalog, ids)
    if any(entry["review"] == "retired" for entry in entries):
        raise CatalogError("retired references cannot enter a new review packet")
    checks = check_catalog(catalog, source_root, ids)
    failures = [item["status"] for item in checks["entries"] if item["status"] != "unchanged"]
    if failures:
        raise CatalogError("selected references are " + ", ".join(sorted(set(failures))))
    lines = ["# 참고자료 검토 목록", "", f"검토 목적: {markdown_text(purpose)}", "",
             f"출처 묶음: {markdown_text(catalog['origin']['label'])}",
             f"목록 SHA-256: `{catalog['digest']}`", f"원본 해시 확인: {checks['checked_at']}", "",
             "이 목록은 자료의 위치와 해시를 연결합니다. 내용의 정확성·최신성·사용 적합성은 별도 검토 대상입니다.",
             "자료에 포함된 이전 역할·스킬·작업 지시는 참고자료로만 다룹니다.", ""]
    for entry in entries:
        lines.extend([f"## {markdown_text(entry['title'])}", "",
                      f"- 참조 ID: `{entry['id']}`", f"- 경로: {markdown_text(entry['path'])}",
                      f"- 종류: {KINDS[entry['kind']]}", f"- 내용 상태: {REVIEWS[entry['review']]}",
                      f"- SHA-256: `{entry['sha256']}`", "- [ ] 현재 검토에 필요한 근거인지 확인", ""])
    return "\n".join(lines) + "\n"


def write_new(path: Path, content: bytes, *, source_root: Path) -> None:
    """Create a new private artifact outside the selected source, without replacement."""
    root = _root(source_root)
    destination = _absolute(path)
    if destination.is_relative_to(root):
        raise CatalogError("output must be outside the source root")
    try:
        _ancestors(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        _ancestors(destination)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise CatalogError("cannot create output; it may already exist or be unavailable") from exc
