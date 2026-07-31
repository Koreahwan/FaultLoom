"""Fail-closed FaultLoom v0.1 command-line surface."""

from __future__ import annotations

import argparse
from fnmatch import fnmatchcase
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import sqlite3
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypeVar

from faultloom_protocol import (
    PROTOCOL_VERSION,
    SCHEMA_VERSION,
    ActionBudget,
    ActionClass,
    ActionPolicy,
    AuthorityGrant,
    AuthoritySigner,
    CallbackPolicy,
    Ed25519PublicKeyRecord,
    ExplicitDeny,
    ProviderPolicy,
    ProtocolModel,
    RetentionPolicy,
    ScopeContractDraft,
    SignedAuthorityGrant,
    StateChangePolicy,
    TargetAsset,
    TimeWindow,
    sha256_digest,
    sign_authority_grant,
    verify_authority_grant,
)
from faultloom_protocol.signing import SignatureVerificationError

from . import __version__
from .adapter_cli import configure_adapter_parser
from .automation_cli import (
    AutomationCompileDependencies,
    AutomationCompileError,
    AutomationExportHandoffDependencies,
    compile_automation,
    export_automation_handoff,
)
from .verification_cli import (
    VerificationCliDependencies,
    VerificationCliError,
    configure_verification_parsers,
)

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3
EXIT_AUTHORITY = 4
MAX_PROTOCOL_FILE_BYTES = 1024 * 1024
MAX_PROTOCOL_JSON_DEPTH = 128
PROTOCOL_READ_CHUNK_BYTES = 64 * 1024
EVIDENCE_COPY_CHUNK_BYTES = 1024 * 1024
TRUSTED_KEY_ENV = "FAULTLOOM_TRUSTED_AUTHORITY_KEY"
PACK_IDS = {
    "web": "pack.web",
    "llm": "pack.llm.agent",
    "advanced-web": "pack.advanced_web",
    "cloud": "pack.cloud.iam_oauth",
    "mobile": "pack.mobile",
    "web3": "pack.web3.future-fixture",
}
LIVE_PACK_IDS = frozenset({"pack.web"})
OFFLINE_REQUEST_ACTION_FAMILY = "http.semantic"
OFFLINE_REQUEST_ACTION_CLASS = ActionClass.SAFE_PROBE
REQUEST_ACCOUNTING_FILENAME = "request-accounting.sqlite3"
REQUEST_ACCOUNTING_STATE_KEY = "request_accounting_state_id"

ModelT = TypeVar("ModelT", bound=ProtocolModel)

_FILE_STAT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
_WINDOWS_FILE_STAT_FIELDS = tuple(
    field for field in _FILE_STAT_FIELDS if field != "st_ctime_ns"
)
_DIRECTORY_STAT_FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")


class CliError(RuntimeError):
    """A concise expected CLI failure with a stable exit code."""

    def __init__(self, message: str, *, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class _BoundProtocolFile:
    path: Path
    descriptor: int
    directory_descriptors: tuple[int, ...]
    directory_names: tuple[str, ...]
    directory_stats: tuple[os.stat_result, ...]
    leaf_name: str
    initial_stat: os.stat_result


@dataclass(frozen=True)
class _ProtocolFilePathSnapshot:
    path: Path
    root: str
    directory_names: tuple[str, ...]
    directory_stats: tuple[os.stat_result, ...]
    leaf_name: str
    leaf_stat: os.stat_result


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _port(value: str) -> int:
    parsed = _positive_int(value)
    if parsed > 65535:
        raise argparse.ArgumentTypeError("must be a TCP port between 1 and 65535")
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _stat_matches(
    left: os.stat_result,
    right: os.stat_result,
    fields: tuple[str, ...],
) -> bool:
    return all(getattr(left, field) == getattr(right, field) for field in fields)


def _close_descriptors(descriptors: list[int] | tuple[int, ...]) -> None:
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _protocol_file_error(path: Path, reason: str) -> CliError:
    return CliError(
        f"unsafe or unreadable protocol file {path}: {reason}",
        exit_code=EXIT_AUTHORITY,
    )


def _secure_open_flags_available() -> bool:
    return all(
        hasattr(os, name)
        for name in (
            "O_CLOEXEC",
            "O_DIRECTORY",
            "O_NOCTTY",
            "O_NOFOLLOW",
            "O_NONBLOCK",
        )
    )


def _path_parts(path: Path) -> tuple[str, tuple[str, ...]]:
    if path.is_absolute() and path.anchor != "/":
        raise _protocol_file_error(path, "path has a noncanonical absolute anchor")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise _protocol_file_error(path, "path must name a file without traversal")
    return ("/" if path.is_absolute() else "."), tuple(parts)


def _require_regular_single_link(
    path: Path,
    metadata: os.stat_result,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise _protocol_file_error(path, "input is not a regular file")
    if metadata.st_nlink != 1:
        raise _protocol_file_error(path, "input must have exactly one hard link")


def _snapshot_protocol_file_path(path: Path) -> _ProtocolFilePathSnapshot:
    root, parts = _path_parts(path)
    directory_names: list[str] = []
    directory_stats: list[os.stat_result] = []
    current_path = Path(root)

    try:
        root_stat = os.stat(root, follow_symlinks=False)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise _protocol_file_error(path, "path root is not a real directory")
        directory_stats.append(root_stat)

        for component in parts[:-1]:
            current_path /= component
            component_stat = os.stat(current_path, follow_symlinks=False)
            if not stat.S_ISDIR(component_stat.st_mode):
                raise _protocol_file_error(path, "path component is not a real directory")
            directory_names.append(component)
            directory_stats.append(component_stat)

        leaf_name = parts[-1]
        leaf_stat = os.stat(current_path / leaf_name, follow_symlinks=False)
        _require_regular_single_link(path, leaf_stat)
        if leaf_stat.st_size > MAX_PROTOCOL_FILE_BYTES:
            raise _protocol_file_error(
                path,
                f"input exceeds {MAX_PROTOCOL_FILE_BYTES} bytes",
            )
        return _ProtocolFilePathSnapshot(
            path=path,
            root=root,
            directory_names=tuple(directory_names),
            directory_stats=tuple(directory_stats),
            leaf_name=leaf_name,
            leaf_stat=leaf_stat,
        )
    except CliError:
        raise
    except (OSError, ValueError) as exc:
        raise _protocol_file_error(path, str(exc)) from exc


def _open_bound_protocol_file(
    snapshot: _ProtocolFilePathSnapshot,
) -> _BoundProtocolFile:
    path = snapshot.path
    if not _secure_open_flags_available():
        raise _protocol_file_error(path, "secure descriptor flags are unavailable")

    directory_descriptors: list[int] = []
    file_descriptor: int | None = None
    directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | os.O_NOCTTY
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )

    try:
        root_descriptor = os.open(snapshot.root, directory_flags)
        directory_descriptors.append(root_descriptor)
        root_stat = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_stat.st_mode) or not _stat_matches(
            snapshot.directory_stats[0],
            root_stat,
            _DIRECTORY_STAT_FIELDS,
        ):
            raise _protocol_file_error(path, "path root changed before opening")

        for index, component in enumerate(snapshot.directory_names, start=1):
            parent_descriptor = directory_descriptors[-1]
            before = os.stat(
                component,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if not stat.S_ISDIR(before.st_mode):
                raise _protocol_file_error(path, "path component is not a real directory")
            expected = snapshot.directory_stats[index]
            if not _stat_matches(expected, before, _DIRECTORY_STAT_FIELDS):
                raise _protocol_file_error(path, "path component changed before opening")
            child_descriptor = os.open(component, directory_flags, dir_fd=parent_descriptor)
            try:
                child_stat = os.fstat(child_descriptor)
            except OSError:
                os.close(child_descriptor)
                raise
            if not _stat_matches(expected, child_stat, _DIRECTORY_STAT_FIELDS):
                os.close(child_descriptor)
                raise _protocol_file_error(path, "path component changed while opening")
            directory_descriptors.append(child_descriptor)

        parent_descriptor = directory_descriptors[-1]
        before = os.stat(
            snapshot.leaf_name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        _require_regular_single_link(path, before)
        if not _stat_matches(snapshot.leaf_stat, before, _FILE_STAT_FIELDS):
            raise _protocol_file_error(path, "input changed before opening")
        file_descriptor = os.open(
            snapshot.leaf_name,
            file_flags,
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(file_descriptor)
        _require_regular_single_link(path, opened)
        if not _stat_matches(snapshot.leaf_stat, opened, _FILE_STAT_FIELDS):
            raise _protocol_file_error(path, "input changed while opening")
        if opened.st_size > MAX_PROTOCOL_FILE_BYTES:
            raise _protocol_file_error(
                path,
                f"input exceeds {MAX_PROTOCOL_FILE_BYTES} bytes",
            )
        return _BoundProtocolFile(
            path=path,
            descriptor=file_descriptor,
            directory_descriptors=tuple(directory_descriptors),
            directory_names=snapshot.directory_names,
            directory_stats=snapshot.directory_stats,
            leaf_name=snapshot.leaf_name,
            initial_stat=snapshot.leaf_stat,
        )
    except CliError:
        if file_descriptor is not None:
            _close_descriptors([file_descriptor])
        _close_descriptors(directory_descriptors)
        raise
    except (OSError, ValueError) as exc:
        if file_descriptor is not None:
            _close_descriptors([file_descriptor])
        _close_descriptors(directory_descriptors)
        raise _protocol_file_error(path, str(exc)) from exc


def _close_bound_protocol_file(bound: _BoundProtocolFile) -> None:
    _close_descriptors([bound.descriptor])
    _close_descriptors(bound.directory_descriptors)


def _read_bound_protocol_file(bound: _BoundProtocolFile) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        while total <= MAX_PROTOCOL_FILE_BYTES:
            requested = min(
                PROTOCOL_READ_CHUNK_BYTES,
                MAX_PROTOCOL_FILE_BYTES + 1 - total,
            )
            chunk = os.read(bound.descriptor, requested)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError as exc:
        raise _protocol_file_error(bound.path, str(exc)) from exc

    if total > MAX_PROTOCOL_FILE_BYTES:
        raise _protocol_file_error(
            bound.path,
            f"input exceeds {MAX_PROTOCOL_FILE_BYTES} bytes",
        )
    try:
        current = os.fstat(bound.descriptor)
    except OSError as exc:
        raise _protocol_file_error(bound.path, str(exc)) from exc
    if total != bound.initial_stat.st_size or not _stat_matches(
        bound.initial_stat,
        current,
        _FILE_STAT_FIELDS,
    ):
        raise _protocol_file_error(bound.path, "input changed while reading")
    return b"".join(chunks)


def _reconcile_bound_protocol_file(bound: _BoundProtocolFile) -> None:
    try:
        for index, descriptor in enumerate(bound.directory_descriptors):
            current = os.fstat(descriptor)
            initial = bound.directory_stats[index]
            if not _stat_matches(initial, current, _DIRECTORY_STAT_FIELDS):
                raise _protocol_file_error(bound.path, "bound directory changed")
            if index > 0:
                path_stat = os.stat(
                    bound.directory_names[index - 1],
                    dir_fd=bound.directory_descriptors[index - 1],
                    follow_symlinks=False,
                )
                if not _stat_matches(initial, path_stat, _DIRECTORY_STAT_FIELDS):
                    raise _protocol_file_error(bound.path, "path component changed")

        current_file = os.fstat(bound.descriptor)
        path_file = os.stat(
            bound.leaf_name,
            dir_fd=bound.directory_descriptors[-1],
            follow_symlinks=False,
        )
        _require_regular_single_link(bound.path, path_file)
        if not _stat_matches(bound.initial_stat, current_file, _FILE_STAT_FIELDS):
            raise _protocol_file_error(bound.path, "bound input metadata changed")
        if not _stat_matches(bound.initial_stat, path_file, _FILE_STAT_FIELDS):
            raise _protocol_file_error(bound.path, "input path changed during capture")
    except CliError:
        raise
    except (OSError, ValueError) as exc:
        raise _protocol_file_error(bound.path, str(exc)) from exc


def _capture_protocol_file_pair(
    authority_path: Path,
    key_path: Path,
    *,
    private_second: bool = False,
) -> tuple[bytes, bytes]:
    if os.name == "nt":
        key_snapshot = _snapshot_windows_protocol_file(key_path)
        authority_snapshot = _snapshot_windows_protocol_file(authority_path)
        authority_content = _read_windows_protocol_file(
            authority_path,
            authority_snapshot,
        )
        key_content = _read_windows_protocol_file(key_path, key_snapshot)
        return authority_content, key_content

    key_snapshot = _snapshot_protocol_file_path(key_path)
    if private_second:
        mode = stat.S_IMODE(key_snapshot.leaf_stat.st_mode)
        owner_id = (
            os.geteuid()
            if hasattr(os, "geteuid")
            else key_snapshot.leaf_stat.st_uid
        )
        if mode != 0o600 or key_snapshot.leaf_stat.st_uid != owner_id:
            raise _protocol_file_error(
                key_path,
                "secret input must be owned by the current user with mode 0600",
            )
    authority_snapshot = _snapshot_protocol_file_path(authority_path)
    key = _open_bound_protocol_file(key_snapshot)
    try:
        authority = _open_bound_protocol_file(authority_snapshot)
        try:
            authority_content = _read_bound_protocol_file(authority)
            key_content = _read_bound_protocol_file(key)
            _reconcile_bound_protocol_file(authority)
            _reconcile_bound_protocol_file(key)
            return authority_content, key_content
        finally:
            _close_bound_protocol_file(authority)
    finally:
        _close_bound_protocol_file(key)


def _snapshot_windows_protocol_file(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
        _require_regular_single_link(path, metadata)
        if metadata.st_size > MAX_PROTOCOL_FILE_BYTES:
            raise _protocol_file_error(
                path,
                f"input exceeds {MAX_PROTOCOL_FILE_BYTES} bytes",
            )
        return metadata
    except CliError:
        raise
    except OSError as exc:
        raise _protocol_file_error(path, str(exc)) from exc


def _read_windows_protocol_file(
    path: Path,
    expected: os.stat_result,
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not _stat_matches(expected, opened, _WINDOWS_FILE_STAT_FIELDS):
                raise _protocol_file_error(path, "input changed before opening")
            while total <= MAX_PROTOCOL_FILE_BYTES:
                requested = min(
                    PROTOCOL_READ_CHUNK_BYTES,
                    MAX_PROTOCOL_FILE_BYTES + 1 - total,
                )
                chunk = stream.read(requested)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            current = os.fstat(stream.fileno())
        final = path.lstat()
    except CliError:
        raise
    except OSError as exc:
        raise _protocol_file_error(path, str(exc)) from exc
    if total > MAX_PROTOCOL_FILE_BYTES:
        raise _protocol_file_error(
            path,
            f"input exceeds {MAX_PROTOCOL_FILE_BYTES} bytes",
        )
    if (
        total != expected.st_size
        or not _stat_matches(expected, current, _WINDOWS_FILE_STAT_FIELDS)
        or not _stat_matches(expected, final, _WINDOWS_FILE_STAT_FIELDS)
    ):
        raise _protocol_file_error(path, "input changed while reading")
    return b"".join(chunks)


def _capture_public_protocol_file_pair(
    first_path: Path,
    second_path: Path,
) -> tuple[bytes, bytes]:
    return _capture_protocol_file_pair(first_path, second_path)


def _validate_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_PROTOCOL_JSON_DEPTH:
                raise ValueError(
                    f"JSON nesting exceeds {MAX_PROTOCOL_JSON_DEPTH} levels"
                )
        elif character in "]}":
            depth -= 1


def _parse_protocol_file(
    path: Path,
    content: bytes,
    model_type: type[ModelT],
) -> ModelT:
    try:
        text = content.decode("utf-8")
        _validate_json_depth(text)
        raw_value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        if model_type is SignedAuthorityGrant:
            _validate_signed_authority_cidr_wire_values(raw_value)
        return model_type.model_validate_json(text)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CliError(
            f"invalid {model_type.__name__} file {path}: {exc}",
            exit_code=EXIT_AUTHORITY,
        ) from exc


def _parse_workspace_run_file(path: Path, content: bytes) -> dict[str, object]:
    try:
        text = content.decode("utf-8")
        _validate_json_depth(text)
        manifest = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CliError(
            f"invalid manual run workspace file {path}: {exc}",
            exit_code=EXIT_AUTHORITY,
        ) from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != "faultloom.manual-run.v1"
        or not isinstance(manifest.get("run_id"), str)
    ):
        raise CliError(
            f"invalid manual run workspace {path.parent}: unsupported run.json",
            exit_code=EXIT_AUTHORITY,
        )
    return manifest


def _trusted_key_path(arguments: argparse.Namespace) -> Path:
    value = arguments.trusted_key or os.environ.get(TRUSTED_KEY_ENV)
    if not value:
        raise CliError(
            f"a trusted public-key record is required via --trusted-key or {TRUSTED_KEY_ENV}",
            exit_code=EXIT_AUTHORITY,
        )
    return Path(value)


def _canonical_network(
    value: object,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if (
        not isinstance(value, str)
        or not value
        or not value.isascii()
        or "%" in value
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        return None
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return None
    return network if str(network) == value else None


def _validate_signed_authority_cidr_wire_values(value: object) -> None:
    if not isinstance(value, dict):
        return
    payload = value.get("payload")
    if not isinstance(payload, dict):
        return
    targets = payload.get("targets")
    if not isinstance(targets, list):
        return
    for target in targets:
        if not isinstance(target, dict):
            continue
        cidrs = target.get("cidrs")
        if not isinstance(cidrs, list):
            continue
        for cidr in cidrs:
            if isinstance(cidr, str) and _canonical_network(cidr) is None:
                raise ValueError(
                    "CIDR must use canonical ASCII network-prefix notation"
                )


def _network_is_loopback(value: str) -> bool:
    network = _canonical_network(value)
    return bool(
        network is not None
        and network.network_address.is_loopback
        and network.broadcast_address.is_loopback
    )


def _hostname_is_loopback(value: str) -> bool:
    if (
        not value
        or not value.isascii()
        or value != value.lower()
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
        or "%" in value
    ):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return address.is_loopback and str(address) == value

    if len(value) > 253 or value.endswith("."):
        return False
    labels = value.split(".")
    for label in labels:
        if not 1 <= len(label) <= 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in label):
            return False
    return labels[-1] == "localhost"


def _target_is_loopback(target: object) -> bool:
    hostnames = tuple(getattr(target, "hostnames", ()))
    cidrs = tuple(getattr(target, "cidrs", ()))
    return bool(hostnames or cidrs) and all(
        _hostname_is_loopback(hostname) for hostname in hostnames
    ) and all(_network_is_loopback(cidr) for cidr in cidrs)


def _emit_json(value: object) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _write_new_file(path: Path, content: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as exc:
        raise CliError(f"cannot create {path}: {exc}", exit_code=EXIT_USAGE) from exc
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    except OSError as exc:
        try:
            path.unlink()
        except OSError:
            pass
        raise CliError(f"cannot write {path}: {exc}", exit_code=EXIT_USAGE) from exc
    finally:
        os.close(descriptor)
    try:
        os.chmod(path, mode)
    except OSError as exc:
        try:
            path.unlink()
        except OSError:
            pass
        raise CliError(f"cannot set permissions on {path}: {exc}", exit_code=EXIT_USAGE) from exc


def _write_protocol_model(path: Path, model: ProtocolModel, *, mode: int = 0o600) -> None:
    _write_new_file(
        path,
        (model.model_dump_json(indent=2) + "\n").encode("utf-8"),
        mode=mode,
    )


def _key_init(arguments: argparse.Namespace) -> int:
    root: Path = arguments.out_dir
    try:
        root.mkdir(parents=True, exist_ok=False, mode=0o700)
    except OSError as exc:
        raise CliError(
            f"cannot create new authority directory {root}: {exc}",
            exit_code=EXIT_USAGE,
        ) from exc
    seed = secrets.token_bytes(32)
    signer = AuthoritySigner.from_private_bytes(seed)
    private_path = root / "authority-private.key"
    public_path = root / "authority-public-key.json"
    _write_new_file(private_path, seed.hex().encode("ascii") + b"\n", mode=0o600)
    _write_protocol_model(public_path, signer.public_key_record, mode=0o644)
    _emit_json(
        {
            "key_id": signer.key_id,
            "private_key": str(private_path),
            "public_key": str(public_path),
        }
    )
    return EXIT_OK


def _scope_draft(arguments: argparse.Namespace) -> int:
    now = _utc_now()
    ends_at = now + timedelta(hours=arguments.duration_hours)
    methods = tuple(arguments.method or ("GET", "HEAD", "OPTIONS"))
    paths = tuple(arguments.path or ("/*",))
    hostnames = tuple(arguments.hostname or ())
    cidrs = tuple(arguments.cidr or ())
    pack_id = PACK_IDS[arguments.pack]
    try:
        target = TargetAsset(
            schema_version=SCHEMA_VERSION,
            target_id=arguments.target_id,
            hostnames=hostnames,
            cidrs=cidrs,
            ports=tuple(arguments.port or (443,)),
            protocols=("https",),
            paths=paths,
            methods=methods,
        )
        policy = ActionPolicy(
            schema_version=SCHEMA_VERSION,
            allowed_classes=(ActionClass.OBSERVE, ActionClass.SAFE_PROBE),
            allowed_families=("http.semantic", "browser.observe"),
            allowed_methods=methods,
            allowed_path_patterns=paths,
            denied=(
                ExplicitDeny(
                    schema_version=SCHEMA_VERSION,
                    deny_id="deny.external-message",
                    target_id=arguments.target_id,
                    action_families=("external_message",),
                    reason="External messages are not approved by the default template.",
                ),
            ),
        )
        draft = ScopeContractDraft(
            schema_version=SCHEMA_VERSION,
            draft_id=f"draft.{arguments.target_id}",
            revision=1,
            title=arguments.title,
            created_at=now,
            created_by=arguments.operator,
            targets=(target,),
            adapter_ids=("adapter.http",),
            action_policy=policy,
            identities=("identity.operator",),
            execution_windows=(
                TimeWindow(schema_version=SCHEMA_VERSION, starts_at=now, ends_at=ends_at),
            ),
            budget=ActionBudget(
                schema_version=SCHEMA_VERSION,
                total_actions=500,
                rate_per_minute=30,
                max_concurrency=2,
                max_request_bytes=1024 * 1024,
                max_response_bytes=10 * 1024 * 1024,
                max_duration_seconds=120,
            ),
            callback_policy=CallbackPolicy(
                schema_version=SCHEMA_VERSION,
                maximum_ttl_seconds=300,
            ),
            provider_policy=ProviderPolicy(
                schema_version=SCHEMA_VERSION,
                allowed_providers=("provider.manual",),
                allowed_model_snapshots=("operator-selected",),
                data_policy_id="policy.operator-controlled",
            ),
            retention_policy=RetentionPolicy(
                schema_version=SCHEMA_VERSION,
                policy_id="retention.30-days",
                retain_until=now + timedelta(days=30),
                delete_after_seconds=30 * 24 * 60 * 60,
            ),
            state_change_policy=StateChangePolicy(schema_version=SCHEMA_VERSION),
            emergency_contact_ref="contact.operator-stop",
            notes=(f"faultloom.pack:{pack_id}", f"faultloom.template:{arguments.template}"),
        )
    except ValueError as exc:
        raise CliError(f"invalid scope draft: {exc}", exit_code=EXIT_USAGE) from exc
    _write_protocol_model(arguments.out, draft)
    _emit_json({"draft": str(arguments.out), "pack_id": pack_id, "target_id": target.target_id})
    return EXIT_OK


def _private_signer(path: Path, content: bytes) -> AuthoritySigner:
    try:
        text = content.decode("ascii")
        if text.endswith("\r\n"):
            text = text[:-2]
        elif text.endswith("\n"):
            text = text[:-1]
        if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
            raise ValueError("expected one lowercase 64-character hex seed")
        return AuthoritySigner.from_private_bytes(bytes.fromhex(text))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CliError(f"invalid private key file {path}: {exc}", exit_code=EXIT_AUTHORITY) from exc


def _scope_approve(arguments: argparse.Namespace) -> int:
    draft_content, private_content = _capture_protocol_file_pair(
        arguments.draft,
        arguments.private_key,
        private_second=True,
    )
    draft = _parse_protocol_file(arguments.draft, draft_content, ScopeContractDraft)
    signer = _private_signer(arguments.private_key, private_content)
    now = _utc_now()
    pack_notes = tuple(
        note.removeprefix("faultloom.pack:")
        for note in draft.notes
        if note.startswith("faultloom.pack:")
    )
    pack_ids = pack_notes or ("pack.web",)
    grant_id = arguments.grant_id or f"grant.{draft.draft_id.removeprefix('draft.')}"
    try:
        grant = AuthorityGrant(
            schema_version=SCHEMA_VERSION,
            grant_id=grant_id,
            grant_version=1,
            draft_digest=sha256_digest(draft),
            issued_at=now,
            not_before=now,
            expires_at=max(window.ends_at for window in draft.execution_windows),
            issued_to=arguments.issued_to,
            approved_by=arguments.approved_by,
            targets=draft.targets,
            pack_ids=pack_ids,
            adapter_ids=draft.adapter_ids,
            action_policy=draft.action_policy,
            identities=draft.identities,
            roles=("role.operator",),
            tenants=draft.tenants,
            execution_windows=draft.execution_windows,
            budget=draft.budget,
            callback_policy=draft.callback_policy,
            provider_policy=draft.provider_policy,
            retention_policy=draft.retention_policy,
            state_change_policy=draft.state_change_policy,
            emergency_contact_ref=draft.emergency_contact_ref,
        )
        envelope = sign_authority_grant(grant, signer, signed_at=now)
    except ValueError as exc:
        raise CliError(f"cannot approve scope draft: {exc}", exit_code=EXIT_USAGE) from exc
    _write_protocol_model(arguments.out, envelope)
    _emit_json(
        {
            "authority": str(arguments.out),
            "grant_id": grant.grant_id,
            "key_id": signer.key_id,
        }
    )
    return EXIT_OK


def _pack_manifest(pack_id: str) -> ProtocolModel:
    normalized = PACK_IDS.get(pack_id, pack_id)
    if normalized == "pack.web":
        from faultloom_web.web_api.manifest import web_api_manifest

        return web_api_manifest()
    if normalized == "pack.llm.agent":
        from faultloom_llm.manifest import llm_agent_manifest

        return llm_agent_manifest()
    if normalized == "pack.advanced_web":
        from faultloom_advanced_web.manifest import advanced_web_manifest

        return advanced_web_manifest()
    if normalized == "pack.cloud.iam_oauth":
        from faultloom_cloud.manifest import cloud_iam_oauth_manifest

        return cloud_iam_oauth_manifest()
    if normalized == "pack.mobile":
        from faultloom_mobile.manifest import mobile_manifest

        return mobile_manifest()
    if normalized == "pack.web3.future-fixture":
        from faultloom_web3.manifest import web3_pack_manifest

        return web3_pack_manifest()
    raise CliError(f"unknown pack {pack_id!r}", exit_code=EXIT_USAGE)


def _pack_list(_: argparse.Namespace) -> int:
    manifests = [_pack_manifest(pack_id) for pack_id in sorted(PACK_IDS.values())]
    _emit_json(
        {
            "packs": [
                {
                    "live_dispatch_supported": manifest.pack_id in LIVE_PACK_IDS,
                    "pack_id": manifest.pack_id,
                    "pack_version": manifest.pack_version,
                }
                for manifest in manifests
            ]
        }
    )
    return EXIT_OK


def _pack_check(arguments: argparse.Namespace) -> int:
    manifest = _pack_manifest(arguments.pack_id)
    _emit_json(
        {
            "capability_count": len(manifest.capability_descriptors),
            "live_dispatch_supported": manifest.pack_id in LIVE_PACK_IDS,
            "ok": True,
            "pack_id": manifest.pack_id,
            "pack_version": manifest.pack_version,
            "protocol_range": manifest.protocol_range,
        }
    )
    return EXIT_OK


def _doctor(arguments: argparse.Namespace) -> int:
    live_supported = os.name == "posix"
    live_mode = "controller_provisioned_single_dispatch" if live_supported else "manual_only"
    network_access = "gateway_only" if live_supported else "none"
    result = {
        "component": "faultloom",
        "live_dispatch_enabled": live_supported,
        "live_dispatch_mode": live_mode,
        "network_access": network_access,
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "runtime_version": __version__,
    }
    if arguments.json:
        _emit_json(result)
    else:
        print("FaultLoom doctor: ok")
        print(f"runtime={__version__} protocol={PROTOCOL_VERSION}")
        state = "enabled" if live_supported else "disabled"
        print(f"live_dispatch={state} mode={live_mode} network_access={network_access}")
    return EXIT_OK


def _create_manual_workspace(
    workspace: Path,
    *,
    authority_content: bytes,
    key_content: bytes,
    grant: AuthorityGrant,
    target: TargetAsset,
    pack_id: str,
    now: datetime,
) -> dict[str, object]:
    try:
        workspace.mkdir(parents=True, exist_ok=False, mode=0o700)
    except OSError as exc:
        raise CliError(
            f"cannot create new run workspace {workspace}: {exc}",
            exit_code=EXIT_USAGE,
        ) from exc
    try:
        return _initialize_manual_workspace(
            workspace,
            authority_content=authority_content,
            key_content=key_content,
            grant=grant,
            target=target,
            pack_id=pack_id,
            now=now,
        )
    except Exception as exc:
        try:
            shutil.rmtree(workspace)
        except OSError as cleanup_exc:
            raise CliError(
                f"cannot clean failed new run workspace {workspace}: {cleanup_exc}",
                exit_code=EXIT_USAGE,
            ) from exc
        if isinstance(exc, CliError):
            raise
        raise CliError(
            f"cannot initialize new run workspace {workspace}: {exc}",
            exit_code=EXIT_USAGE,
        ) from exc


def _initialize_manual_workspace(
    workspace: Path,
    *,
    authority_content: bytes,
    key_content: bytes,
    grant: AuthorityGrant,
    target: TargetAsset,
    pack_id: str,
    now: datetime,
) -> dict[str, object]:
    os.chmod(workspace, 0o700)
    for relative in (
        "evidence/raw",
        "evidence/normalized",
        "findings",
        "reports",
    ):
        (workspace / relative).mkdir(parents=True, mode=0o700)

    run_id = f"run.{now:%Y%m%dT%H%M%SZ}.{secrets.token_hex(4)}"
    manifest: dict[str, object] = {
        "schema": "faultloom.manual-run.v1",
        "run_id": run_id,
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "mode": "manual_authorized",
        "dispatch_performed": False,
        "network_access": "none",
        "grant_id": grant.grant_id,
        "grant_version": grant.grant_version,
        "authority_sha256": hashlib.sha256(authority_content).hexdigest(),
        "trusted_key_sha256": hashlib.sha256(key_content).hexdigest(),
        REQUEST_ACCOUNTING_STATE_KEY: secrets.token_hex(32),
        "target": target.model_dump(mode="json"),
        "pack_id": pack_id,
        "action_policy": grant.action_policy.model_dump(mode="json"),
        "budget": grant.budget.model_dump(mode="json"),
        "execution_windows": [
            window.model_dump(mode="json") for window in grant.execution_windows
        ],
    }
    target_summary = json.dumps(
        target.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
    )
    methods = ", ".join(grant.action_policy.allowed_methods)
    paths = ", ".join(grant.action_policy.allowed_path_patterns)
    readme = f"""# FaultLoom authorized manual run

- Run: `{run_id}`
- Grant: `{grant.grant_id}`
- Pack: `{pack_id}`

This workspace authorizes manual research only within the signed scope below.
FaultLoom did not open a network socket or dispatch an action when creating it.

## Working rules

- Use only the listed target, ports, methods, and paths.
- Allowed HTTP methods: {methods}
- Allowed path patterns: {paths}
- Keep request/response exports and screenshots in `evidence/raw/`.
- Put cleaned evidence in `evidence/normalized/` and draft findings in `findings/`.
- Do not perform destructive changes, high-load testing, payments, or external messages.
- Do not store passwords, session cookies, API keys, or private signing keys here.
- Stop when the signed execution window or program authorization expires.

## Signed target

```json
{target_summary}
```
"""
    _write_new_file(workspace / "authority.json", authority_content, mode=0o600)
    _write_new_file(workspace / "trusted-key.json", key_content, mode=0o600)
    _write_new_file(
        workspace / "README.md",
        readme.encode("utf-8"),
        mode=0o600,
    )
    _write_new_file(
        workspace / "run.json",
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )
    _initialize_request_accounting(workspace, manifest)
    return manifest


def _load_manual_workspace(workspace: Path) -> dict[str, object]:
    manifest_path = workspace / "run.json"
    try:
        metadata = manifest_path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("run.json is not a regular file")
        if metadata.st_size > MAX_PROTOCOL_FILE_BYTES:
            raise ValueError("run.json is too large")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CliError(
            f"invalid manual run workspace {workspace}: {exc}",
            exit_code=EXIT_USAGE,
        ) from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != "faultloom.manual-run.v1"
        or not isinstance(manifest.get("run_id"), str)
    ):
        raise CliError(
            f"invalid manual run workspace {workspace}: unsupported run.json",
            exit_code=EXIT_USAGE,
        )
    return manifest


def _evidence_add(arguments: argparse.Namespace) -> int:
    manifest = _load_manual_workspace(arguments.workspace)
    source: Path = arguments.file
    try:
        source_metadata = source.stat()
    except OSError as exc:
        raise CliError(f"cannot read evidence file {source}: {exc}", exit_code=EXIT_USAGE) from exc
    if not stat.S_ISREG(source_metadata.st_mode):
        raise CliError(
            f"evidence source is not a regular file: {source}",
            exit_code=EXIT_USAGE,
        )

    now = _utc_now()
    evidence_id = f"evidence.{now:%Y%m%dT%H%M%SZ}.{secrets.token_hex(4)}"
    suffix = source.suffix.lower()
    if not (
        1 < len(suffix) <= 10
        and suffix.startswith(".")
        and suffix[1:].isalnum()
        and suffix.isascii()
    ):
        suffix = ".bin"
    destination = (
        arguments.workspace / "evidence" / "raw" / f"{evidence_id}.data{suffix}"
    )
    record_path = arguments.workspace / "evidence" / "raw" / f"{evidence_id}.json"
    digest = hashlib.sha256()
    size_bytes = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(destination, flags, 0o600)
        try:
            with source.open("rb") as stream:
                while chunk := stream.read(EVIDENCE_COPY_CHUNK_BYTES):
                    digest.update(chunk)
                    size_bytes += len(chunk)
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(descriptor, chunk[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        try:
            destination.unlink()
        except OSError:
            pass
        raise CliError(f"cannot store evidence file {source}: {exc}", exit_code=EXIT_USAGE) from exc

    record = {
        "schema": "faultloom.manual-evidence.v1",
        "evidence_id": evidence_id,
        "run_id": manifest["run_id"],
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "kind": arguments.kind,
        "title": arguments.title or source.name,
        "original_name": source.name,
        "stored_file": destination.name,
        "size_bytes": size_bytes,
        "sha256": digest.hexdigest(),
    }
    _write_new_file(
        record_path,
        (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )
    _emit_json(
        {
            "evidence_id": evidence_id,
            "record": str(record_path),
            "sha256": record["sha256"],
            "stored_file": str(destination),
        }
    )
    return EXIT_OK


def _evidence_file_suffix(source: Path) -> str:
    suffix = source.suffix.lower()
    if (
        1 < len(suffix) <= 10
        and suffix.startswith(".")
        and suffix[1:].isalnum()
        and suffix.isascii()
    ):
        return suffix
    return ".bin"


def _evidence_add_exchange(arguments: argparse.Namespace) -> int:
    """Archive one completed, digest-bound manual request/response exchange."""
    manifest, _, _, _ = _verified_request_workspace(
        arguments.workspace, _trusted_key_path(arguments), require_active=False
    )
    connection = _request_accounting_connection(arguments.workspace)
    try:
        _prepare_request_accounting(connection, manifest)
        row = connection.execute(
            """SELECT request_bytes, request_sha256, observed_response_bytes,
                      response_sha256, completed_at
               FROM reservations WHERE reservation_id = ?""",
            (arguments.reservation_id,),
        ).fetchone()
    except CliError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise CliError(
            f"cannot read request reservation: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc
    finally:
        connection.close()

    if row is None:
        raise CliError("unknown request reservation", exit_code=EXIT_AUTHORITY)
    request_bytes, request_sha256, response_bytes, response_sha256, completed_at = row
    if completed_at is None:
        raise CliError("request reservation is not complete", exit_code=EXIT_AUTHORITY)
    if not isinstance(response_sha256, str):
        raise CliError(
            "request reservation was completed without an exact response file",
            exit_code=EXIT_AUTHORITY,
        )
    if (
        not isinstance(request_sha256, str)
        or len(request_sha256) != 64
        or any(character not in "0123456789abcdef" for character in request_sha256)
        or not isinstance(request_bytes, int)
        or request_bytes < 0
    ):
        raise CliError("request reservation is invalid", exit_code=EXIT_AUTHORITY)
    if (
        len(response_sha256) != 64
        or any(character not in "0123456789abcdef" for character in response_sha256)
        or not isinstance(response_bytes, int)
        or response_bytes < 0
    ):
        raise CliError("request reservation response is invalid", exit_code=EXIT_AUTHORITY)

    request_content = _capture_bounded_local_file(
        arguments.request_file, maximum_bytes=request_bytes, label="request"
    )
    response_content = _capture_bounded_local_file(
        arguments.response_file, maximum_bytes=response_bytes, label="response"
    )
    if len(request_content) != request_bytes:
        raise CliError(
            "request file size does not match the reservation", exit_code=EXIT_AUTHORITY
        )
    if len(response_content) != response_bytes:
        raise CliError(
            "response file size does not match the reservation", exit_code=EXIT_AUTHORITY
        )
    if hashlib.sha256(request_content).hexdigest() != request_sha256:
        raise CliError(
            "request file digest does not match the reservation", exit_code=EXIT_AUTHORITY
        )
    if hashlib.sha256(response_content).hexdigest() != response_sha256:
        raise CliError(
            "response file digest does not match the reservation", exit_code=EXIT_AUTHORITY
        )

    now = _utc_now()
    evidence_id = f"evidence.{now:%Y%m%dT%H%M%SZ}.{secrets.token_hex(4)}"
    raw_directory = arguments.workspace / "evidence" / "raw"
    request_destination = raw_directory / (
        f"{evidence_id}.request.data{_evidence_file_suffix(arguments.request_file)}"
    )
    response_destination = raw_directory / (
        f"{evidence_id}.response.data{_evidence_file_suffix(arguments.response_file)}"
    )
    record_path = raw_directory / f"{evidence_id}.json"
    record = {
        "schema": "faultloom.manual-evidence.v1",
        "evidence_id": evidence_id,
        "run_id": manifest["run_id"],
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "kind": "http",
        "title": arguments.title or "Completed reserved request/response exchange",
        "reservation_id": arguments.reservation_id,
        # Keep these summary fields so existing finding new output remains useful.
        "original_name": arguments.request_file.name,
        "stored_file": request_destination.name,
        "size_bytes": len(request_content),
        "sha256": request_sha256,
        "request": {
            "original_name": arguments.request_file.name,
            "stored_file": request_destination.name,
            "size_bytes": len(request_content),
            "sha256": request_sha256,
        },
        "response": {
            "original_name": arguments.response_file.name,
            "stored_file": response_destination.name,
            "size_bytes": len(response_content),
            "sha256": response_sha256,
        },
    }
    created_paths: list[Path] = []
    try:
        _write_new_file(request_destination, request_content, mode=0o600)
        created_paths.append(request_destination)
        _write_new_file(response_destination, response_content, mode=0o600)
        created_paths.append(response_destination)
        _write_new_file(
            record_path,
            (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            mode=0o600,
        )
        created_paths.append(record_path)
    except CliError:
        for path in reversed(created_paths):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    _emit_json(
        {
            "evidence_id": evidence_id,
            "record": str(record_path),
            "request_stored_file": str(request_destination),
            "response_stored_file": str(response_destination),
        }
    )
    return EXIT_OK


def _read_small_text(path: Path, *, label: str) -> str:
    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("not a regular file")
        if metadata.st_size > MAX_PROTOCOL_FILE_BYTES:
            raise ValueError(f"exceeds {MAX_PROTOCOL_FILE_BYTES} bytes")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise CliError(f"invalid {label} file {path}: {exc}", exit_code=EXIT_USAGE) from exc


def _workspace_evidence(
    workspace: Path,
    *,
    run_id: str,
    selected_ids: tuple[str, ...],
) -> list[dict[str, object]]:
    records: dict[str, dict[str, object]] = {}
    raw_directory = workspace / "evidence" / "raw"
    try:
        record_paths = sorted(raw_directory.glob("evidence.*.json"))
    except OSError as exc:
        raise CliError(f"cannot list workspace evidence: {exc}", exit_code=EXIT_USAGE) from exc
    for record_path in record_paths:
        try:
            metadata = record_path.stat()
            if metadata.st_size > MAX_PROTOCOL_FILE_BYTES:
                continue
            value = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if (
            isinstance(value, dict)
            and value.get("schema") == "faultloom.manual-evidence.v1"
            and value.get("run_id") == run_id
            and isinstance(value.get("evidence_id"), str)
        ):
            records[str(value["evidence_id"])] = value
    wanted = selected_ids or tuple(sorted(records))
    missing = [evidence_id for evidence_id in wanted if evidence_id not in records]
    if missing:
        raise CliError(
            "unknown evidence id(s) for this workspace: " + ", ".join(missing),
            exit_code=EXIT_USAGE,
        )
    return [records[evidence_id] for evidence_id in wanted]


def _is_lower_hex(value: str, *, length: int) -> bool:
    return len(value) == length and all(
        character in "0123456789abcdef" for character in value
    )


def _is_exchange_stored_filename(value: object, *, component_name: str) -> bool:
    if not isinstance(value, str) or not value.isascii():
        return False
    parts = value.split(".")
    if len(parts) != 6:
        return False
    _, timestamp, token, component, data, extension = parts
    return (
        parts[0] == "evidence"
        and len(timestamp) == 16
        and timestamp[:8].isdigit()
        and timestamp[8] == "T"
        and timestamp[9:15].isdigit()
        and timestamp[15] == "Z"
        and _is_lower_hex(token, length=8)
        and component == component_name
        and data == "data"
        and 1 <= len(extension) <= 9
        and all(character in "abcdefghijklmnopqrstuvwxyz0123456789" for character in extension)
    )


def _is_reservation_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("reservation.")
        and _is_lower_hex(value.removeprefix("reservation."), length=32)
    )


def _exchange_evidence_component_line(
    component: object, *, component_name: str
) -> str:
    if not isinstance(component, dict):
        raise CliError("invalid archived exchange evidence summary", exit_code=EXIT_USAGE)
    stored_file = component.get("stored_file")
    size_bytes = component.get("size_bytes")
    sha256 = component.get("sha256")
    if (
        not _is_exchange_stored_filename(stored_file, component_name=component_name)
        or type(size_bytes) is not int
        or size_bytes < 0
        or not isinstance(sha256, str)
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
    ):
        raise CliError("invalid archived exchange evidence summary", exit_code=EXIT_USAGE)
    return (
        f"  - {component_name.title()}: `{stored_file}` — {size_bytes} bytes "
        f"— SHA-256 `{sha256}`"
    )


def _finding_evidence_lines(item: dict[str, object]) -> list[str]:
    exchange_fields = {"reservation_id", "request", "response"}
    if not any(field in item for field in exchange_fields):
        return [
            "- `{evidence_id}` — {kind} — SHA-256 `{sha256}` — `{stored_file}`".format(
                evidence_id=item.get("evidence_id", "unknown"),
                kind=item.get("kind", "other"),
                sha256=item.get("sha256", "unknown"),
                stored_file=item.get("stored_file", "unknown"),
            )
        ]
    if not _is_reservation_id(item.get("reservation_id")):
        raise CliError("invalid archived exchange evidence summary", exit_code=EXIT_USAGE)
    return [
        "- `{evidence_id}` — {kind} exchange — reservation `{reservation_id}`".format(
            evidence_id=item.get("evidence_id", "unknown"),
            kind=item.get("kind", "other"),
            reservation_id=item["reservation_id"],
        ),
        _exchange_evidence_component_line(item.get("request"), component_name="request"),
        _exchange_evidence_component_line(item.get("response"), component_name="response"),
    ]


def _finding_new(arguments: argparse.Namespace) -> int:
    manifest = _load_manual_workspace(arguments.workspace)
    run_id = str(manifest["run_id"])
    evidence = _workspace_evidence(
        arguments.workspace,
        run_id=run_id,
        selected_ids=tuple(arguments.evidence or ()),
    )
    now = _utc_now()
    finding_id = f"finding.{now:%Y%m%dT%H%M%SZ}.{secrets.token_hex(4)}"
    steps = (
        _read_small_text(arguments.steps_file, label="reproduction steps").strip()
        if arguments.steps_file is not None
        else "[Add exact, repeatable steps here.]"
    )
    target = manifest.get("target")
    target_text = json.dumps(target, indent=2, sort_keys=True)
    evidence_lines = [
        line for item in evidence for line in _finding_evidence_lines(item)
    ]
    if not evidence_lines:
        evidence_lines.append("- [Add evidence with `faultloom evidence add`.]")
    summary = arguments.summary or "[Describe the vulnerability and affected component.]"
    impact = arguments.impact or "[Describe realistic security and business impact.]"
    remediation = arguments.remediation or "[Describe the smallest effective fix.]"
    markdown = f"""# {arguments.title}

> DRAFT — NOT INDEPENDENTLY VERIFIED

- Severity: **{arguments.severity.title()}**
- Finding ID: `{finding_id}`
- Run ID: `{run_id}`
- Signed grant: `{manifest.get('grant_id', 'unknown')}`

## Summary

{summary}

## Impact

{impact}

## Steps to reproduce

{steps}

## Evidence

{chr(10).join(evidence_lines)}

## Remediation

{remediation}

## Authorized target

```json
{target_text}
```

## Scope statement

Testing was performed manually under the signed FaultLoom grant stored with this run.
This draft does not claim independent verification or automatic exploit execution.
"""
    record = {
        "schema": "faultloom.manual-finding.v1",
        "finding_id": finding_id,
        "run_id": run_id,
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "status": "draft_unverified",
        "title": arguments.title,
        "severity": arguments.severity,
        "summary": summary,
        "impact": impact,
        "steps_to_reproduce": steps,
        "remediation": remediation,
        "evidence_ids": [item["evidence_id"] for item in evidence],
    }
    markdown_path = arguments.workspace / "findings" / f"{finding_id}.md"
    record_path = arguments.workspace / "findings" / f"{finding_id}.json"
    _write_new_file(markdown_path, markdown.encode("utf-8"), mode=0o600)
    _write_new_file(
        record_path,
        (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )
    _emit_json(
        {
            "finding": str(markdown_path),
            "finding_id": finding_id,
            "record": str(record_path),
            "status": "draft_unverified",
        }
    )
    return EXIT_OK


def _capture_single_protocol_file(path: Path) -> bytes:
    if os.name == "nt":
        snapshot = _snapshot_windows_protocol_file(path)
        return _read_windows_protocol_file(path, snapshot)
    snapshot = _snapshot_protocol_file_path(path)
    bound = _open_bound_protocol_file(snapshot)
    try:
        content = _read_bound_protocol_file(bound)
        _reconcile_bound_protocol_file(bound)
        return content
    finally:
        _close_bound_protocol_file(bound)


def _path_matches(pattern: str, path: str) -> bool:
    return path.startswith(pattern[:-1]) if pattern.endswith("*") else path == pattern


def _request_hostname_matches_target(hostname: str, target: TargetAsset) -> bool:
    if hostname in target.hostnames:
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    if str(address) != hostname:
        return False
    return any(address in ipaddress.ip_network(cidr) for cidr in target.cidrs)


def _request_matches_explicit_deny(
    deny: ExplicitDeny,
    *,
    target_id: str,
    hostname: str,
    method: str,
    path: str,
) -> bool:
    return (
        (
            not deny.action_families
            or OFFLINE_REQUEST_ACTION_FAMILY in deny.action_families
        )
        and (deny.target_id is None or deny.target_id == target_id)
        and (not deny.methods or method in deny.methods)
        and (deny.path_pattern is None or _path_matches(deny.path_pattern, path))
        and (deny.host_pattern is None or fnmatchcase(hostname, deny.host_pattern))
    )


def _request_byte_count(value: str, *, label: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise CliError(f"{label} must be a non-negative integer", exit_code=EXIT_AUTHORITY) from exc
    if count < 0:
        raise CliError(f"{label} must be a non-negative integer", exit_code=EXIT_AUTHORITY)
    return count


def _capture_bounded_local_file(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    """Capture one immutable local file without reading beyond its signed budget."""
    if maximum_bytes < 0:
        raise CliError(f"{label} byte limit is invalid", exit_code=EXIT_AUTHORITY)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CliError(
            f"cannot inspect {label} file {path}: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CliError(
            f"{label} file is not a regular non-symlink file", exit_code=EXIT_AUTHORITY
        )
    if metadata.st_size > maximum_bytes:
        raise CliError(
            f"{label} file exceeds the signed byte limit", exit_code=EXIT_AUTHORITY
        )
    # The protocol-file capture pins every path component and the opened inode.  Its
    # global cap is a second, stricter ceiling; the size check above makes its read
    # bound no larger than this request/response's signed budget.
    return _capture_single_protocol_file(path)


def _parse_raw_http11_request(
    content: bytes,
    *,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
    path: str,
) -> None:
    """Fail closed unless a raw file is one unambiguous HTTP/1.1 request."""
    if not content or b"\r\n\r\n" not in content:
        raise CliError("raw request is missing a CRLF header terminator", exit_code=EXIT_AUTHORITY)
    header_block, body = content.split(b"\r\n\r\n", 1)
    if b"\n" in header_block.replace(b"\r\n", b"") or b"\r" in header_block.replace(
        b"\r\n", b""
    ):
        raise CliError("raw request uses malformed CRLF framing", exit_code=EXIT_AUTHORITY)
    lines = header_block.split(b"\r\n")
    if not lines or not lines[0]:
        raise CliError("raw request has no request line", exit_code=EXIT_AUTHORITY)
    try:
        request_line = lines[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise CliError("raw request line is not ASCII", exit_code=EXIT_AUTHORITY) from exc
    expected_line = f"{method} {path} HTTP/1.1"
    if request_line != expected_line:
        raise CliError(
            "raw request line does not match the signed method and path",
            exit_code=EXIT_AUTHORITY,
        )

    host_values: list[str] = []
    content_lengths: list[str] = []
    for line in lines[1:]:
        if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
            raise CliError("raw request has malformed header framing", exit_code=EXIT_AUTHORITY)
        name, value = line.split(b":", 1)
        if not name or any(
            character not in b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            for character in name
        ):
            raise CliError("raw request has an invalid header name", exit_code=EXIT_AUTHORITY)
        if any(character < 32 and character not in {9} or character == 127 for character in value):
            raise CliError("raw request has an invalid header value", exit_code=EXIT_AUTHORITY)
        lowered = name.lower()
        try:
            normalized_value = value.strip(b" \t").decode("ascii")
        except UnicodeDecodeError as exc:
            raise CliError("raw request header is not ASCII", exit_code=EXIT_AUTHORITY) from exc
        if lowered == b"host":
            host_values.append(normalized_value)
        elif lowered == b"content-length":
            content_lengths.append(normalized_value)
        elif lowered == b"transfer-encoding":
            raise CliError("raw request transfer-encoding is not permitted", exit_code=EXIT_AUTHORITY)

    if len(host_values) != 1:
        raise CliError("raw request must contain exactly one Host header", exit_code=EXIT_AUTHORITY)
    default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        host_authority = hostname
    else:
        # URI authorities require brackets around IPv6 literals. Keep the
        # signed hostname unbracketed for target matching and fingerprinting,
        # and serialize it separately for the HTTP Host field.
        host_authority = f"[{address.compressed}]" if address.version == 6 else address.compressed
    expected_host = host_authority if default_port else f"{host_authority}:{port}"
    if host_values[0].lower() != expected_host.lower():
        raise CliError("raw request Host header does not match the signed endpoint", exit_code=EXIT_AUTHORITY)
    if len(content_lengths) > 1:
        raise CliError("raw request has duplicate Content-Length headers", exit_code=EXIT_AUTHORITY)
    if content_lengths:
        value = content_lengths[0]
        if not value.isascii() or not value.isdecimal() or str(int(value)) != value:
            raise CliError("raw request has an invalid Content-Length header", exit_code=EXIT_AUTHORITY)
        if int(value) != len(body):
            raise CliError("raw request body does not match Content-Length", exit_code=EXIT_AUTHORITY)
    elif body:
        raise CliError("raw request body requires exactly one Content-Length header", exit_code=EXIT_AUTHORITY)


def _capture_verified_raw_request(
    path: Path,
    *,
    maximum_bytes: int,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
    request_path: str,
) -> tuple[bytes, str]:
    content = _capture_bounded_local_file(path, maximum_bytes=maximum_bytes, label="request")
    _parse_raw_http11_request(
        content,
        hostname=hostname,
        port=port,
        scheme=scheme,
        method=method,
        path=request_path,
    )
    return content, hashlib.sha256(content).hexdigest()


def _verified_request_workspace(
    workspace: Path,
    trusted_key_path: Path,
    *,
    require_active: bool = True,
) -> tuple[dict[str, object], AuthorityGrant, TargetAsset, datetime]:
    authority_path = workspace / "authority.json"
    workspace_key_path = workspace / "trusted-key.json"
    run_path = workspace / "run.json"
    try:
        trusted_key_path.resolve(strict=True).relative_to(workspace.resolve(strict=True))
    except ValueError:
        pass
    except OSError as exc:
        raise CliError(
            f"cannot resolve trusted public-key record: {exc}",
            exit_code=EXIT_AUTHORITY,
        ) from exc
    else:
        raise CliError(
            "trusted public-key record must be outside the workspace",
            exit_code=EXIT_AUTHORITY,
        )
    authority_content, workspace_key_content = _capture_protocol_file_pair(
        authority_path,
        workspace_key_path,
    )
    trusted_key_content = _capture_single_protocol_file(trusted_key_path)
    run_content = _capture_single_protocol_file(run_path)
    envelope = _parse_protocol_file(authority_path, authority_content, SignedAuthorityGrant)
    public_key = _parse_protocol_file(
        trusted_key_path, trusted_key_content, Ed25519PublicKeyRecord
    )
    manifest = _parse_workspace_run_file(run_path, run_content)
    now = _utc_now()
    verification_now = (
        now
        if require_active
        else max(
            envelope.payload.issued_at,
            envelope.payload.not_before,
            envelope.signature.signed_at,
        )
    )
    try:
        grant = verify_authority_grant(envelope, public_key, now=verification_now)
    except (SignatureVerificationError, ValueError) as exc:
        raise CliError(
            f"authority verification failed: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc

    manifest_target = manifest.get("target")
    target_id = manifest_target.get("target_id") if isinstance(manifest_target, dict) else None
    targets = [target for target in grant.targets if target.target_id == target_id]
    if len(targets) != 1:
        raise CliError(
            "run.json target is absent from, or ambiguous in, the signed authority grant",
            exit_code=EXIT_AUTHORITY,
        )
    target = targets[0]
    state_id = manifest.get(REQUEST_ACCOUNTING_STATE_KEY)
    if state_id is None:
        raise CliError(
            "workspace predates request accounting; create a new run workspace",
            exit_code=EXIT_AUTHORITY,
        )
    if (
        not isinstance(state_id, str)
        or len(state_id) != 64
        or any(character not in "0123456789abcdef" for character in state_id)
        or manifest.get("grant_id") != grant.grant_id
        or manifest.get("grant_version") != grant.grant_version
        or manifest.get("pack_id") not in grant.pack_ids
        or manifest_target != target.model_dump(mode="json")
        or manifest.get("action_policy") != grant.action_policy.model_dump(mode="json")
        or manifest.get("budget") != grant.budget.model_dump(mode="json")
        or manifest.get("execution_windows")
        != [window.model_dump(mode="json") for window in grant.execution_windows]
        or manifest.get("authority_sha256") != hashlib.sha256(authority_content).hexdigest()
        or workspace_key_content != trusted_key_content
        or manifest.get("trusted_key_sha256")
        != hashlib.sha256(workspace_key_content).hexdigest()
        or manifest.get("trusted_key_sha256")
        != hashlib.sha256(trusted_key_content).hexdigest()
    ):
        raise CliError(
            "run.json is not bound to the verified authority grant",
            exit_code=EXIT_AUTHORITY,
        )
    if require_active and not any(
        window.starts_at <= now < window.ends_at for window in grant.execution_windows
    ):
        raise CliError(
            "current time is outside every signed execution window",
            exit_code=EXIT_AUTHORITY,
        )
    return manifest, grant, target, now


def _automation_compile(arguments: argparse.Namespace) -> int:
    try:
        return compile_automation(
            arguments,
            dependencies=AutomationCompileDependencies(
                verify_workspace=_verified_request_workspace,
                capture_file=_capture_single_protocol_file,
                emit_json=_emit_json,
            ),
        )
    except AutomationCompileError as exc:
        raise CliError(
            str(exc),
            exit_code=EXIT_AUTHORITY if exc.authority else EXIT_USAGE,
        ) from exc


def _automation_export_handoff(arguments: argparse.Namespace) -> int:
    try:
        return export_automation_handoff(
            arguments,
            dependencies=AutomationExportHandoffDependencies(
                verify_workspace=_verified_request_workspace,
                capture_file=_capture_single_protocol_file,
                parse_disclosure_key=lambda path, content: _parse_protocol_file(
                    path, content, Ed25519PublicKeyRecord
                ),
                write_new_file=lambda path, content: _write_new_file(
                    path, content, mode=0o600
                ),
                emit_json=_emit_json,
            ),
        )
    except AutomationCompileError as exc:
        raise CliError(
            str(exc),
            exit_code=EXIT_AUTHORITY if exc.authority else EXIT_USAGE,
        ) from exc


def _request_accounting_connection(workspace: Path) -> sqlite3.Connection:
    path = workspace / REQUEST_ACCOUNTING_FILENAME
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise CliError("request accounting state is missing", exit_code=EXIT_AUTHORITY)
    except OSError as exc:
        raise CliError(
            f"cannot inspect request accounting state: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CliError(
            "request accounting state is not a regular private file",
            exit_code=EXIT_AUTHORITY,
        )
    if os.name != "nt" and metadata.st_mode & 0o077:
        raise CliError(
            "request accounting state is not private", exit_code=EXIT_AUTHORITY
        )
    try:
        return sqlite3.connect(path, timeout=10, isolation_level=None)
    except sqlite3.Error as exc:
        raise CliError(
            f"cannot open request accounting state: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc


def _accounting_metadata(manifest: dict[str, object]) -> dict[str, str]:
    required = (
        "run_id",
        "grant_id",
        "grant_version",
        "authority_sha256",
        "trusted_key_sha256",
        REQUEST_ACCOUNTING_STATE_KEY,
    )
    metadata = {key: str(manifest[key]) for key in required}
    if any(not metadata[key] for key in required):
        raise CliError(
            "manual workspace has invalid accounting bindings", exit_code=EXIT_AUTHORITY
        )
    return metadata


def _prepare_request_accounting(
    connection: sqlite3.Connection,
    manifest: dict[str, object],
    *,
    initialize: bool = False,
) -> None:
    expected = _accounting_metadata(manifest)
    try:
        connection.execute("BEGIN IMMEDIATE")
        if initialize:
            connection.execute(
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                """CREATE TABLE reservations (
                    reservation_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    request_fingerprint TEXT NOT NULL,
                    request_bytes INTEGER NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    response_limit INTEGER NOT NULL,
                    completed_at REAL,
                    observed_response_bytes INTEGER,
                    response_sha256 TEXT
                )"""
            )
        objects = dict(
            connection.execute(
                "SELECT name, type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        )
        expected_objects = {"metadata": "table", "reservations": "table"}
        columns = tuple(
            (row[1], row[2], row[3], row[5])
            for row in connection.execute("PRAGMA table_info(reservations)")
        )
        metadata_columns = tuple(
            (row[1], row[2], row[3], row[5])
            for row in connection.execute("PRAGMA table_info(metadata)")
        )
        expected_columns = (
            ("reservation_id", "TEXT", 0, 1),
            ("created_at", "REAL", 1, 0),
            ("expires_at", "REAL", 1, 0),
            ("request_fingerprint", "TEXT", 1, 0),
            ("request_bytes", "INTEGER", 1, 0),
            ("request_sha256", "TEXT", 1, 0),
            ("response_limit", "INTEGER", 1, 0),
            ("completed_at", "REAL", 0, 0),
            ("observed_response_bytes", "INTEGER", 0, 0),
            ("response_sha256", "TEXT", 0, 0),
        )
        if (
            objects != expected_objects
            or metadata_columns != (("key", "TEXT", 0, 1), ("value", "TEXT", 1, 0))
            or columns != expected_columns
        ):
            raise CliError(
                "request accounting state uses an unsupported schema; create a new run workspace",
                exit_code=EXIT_AUTHORITY,
            )
        rows = dict(connection.execute("SELECT key, value FROM metadata"))
        if initialize:
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES(?, ?)", expected.items()
            )
        elif rows != expected:
            raise CliError(
                "request accounting state is not bound to the verified workspace",
                exit_code=EXIT_AUTHORITY,
            )
    except CliError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise CliError(
            f"invalid request accounting state: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc


def _initialize_request_accounting(
    workspace: Path, manifest: dict[str, object]
) -> None:
    try:
        _write_new_file(workspace / REQUEST_ACCOUNTING_FILENAME, b"", mode=0o600)
    except CliError as exc:
        raise CliError(
            f"cannot initialize request accounting state: {exc}", exit_code=EXIT_USAGE
        ) from exc
    connection = _request_accounting_connection(workspace)
    try:
        _prepare_request_accounting(connection, manifest, initialize=True)
        connection.commit()
    except CliError:
        connection.rollback()
        raise
    finally:
        connection.close()


def _request_fingerprint(
    *,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
    path: str,
    request_bytes: int,
    request_sha256: str,
    response_bytes: int,
) -> str:
    metadata = {
        "hostname": hostname,
        "method": method,
        "path": path,
        "port": port,
        "request_bytes": request_bytes,
        "request_sha256": request_sha256,
        "response_bytes": response_bytes,
        "scheme": scheme,
    }
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _active_reservation_count(connection: sqlite3.Connection, now: float) -> int:
    return connection.execute(
        "SELECT COUNT(*) FROM reservations WHERE completed_at IS NULL AND expires_at > ?", (now,)
    ).fetchone()[0]


def _response_file_size(path: Path) -> int:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CliError(
            f"cannot inspect response file {path}: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CliError(
            "response file is not a regular non-symlink file", exit_code=EXIT_AUTHORITY
        )
    return metadata.st_size


def _reserve_request(
    *,
    workspace: Path,
    manifest: dict[str, object],
    grant: AuthorityGrant,
    now: datetime,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
    path: str,
    request_bytes: int,
    request_sha256: str,
    response_bytes: int,
) -> dict[str, object]:
    now_seconds = now.timestamp()
    expires_at = min(
        now_seconds + grant.budget.max_duration_seconds,
        max(
            window.ends_at.timestamp()
            for window in grant.execution_windows
            if window.starts_at <= now < window.ends_at
        ),
    )
    connection = _request_accounting_connection(workspace)
    try:
        _prepare_request_accounting(connection, manifest)
        total = connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
        rate = connection.execute(
            "SELECT COUNT(*) FROM reservations WHERE created_at > ?", (now_seconds - 60,)
        ).fetchone()[0]
        active = _active_reservation_count(connection, now_seconds)
        if total >= grant.budget.total_actions:
            raise CliError("signed total action budget is exhausted", exit_code=EXIT_AUTHORITY)
        if rate >= grant.budget.rate_per_minute:
            raise CliError("signed rate budget is exhausted", exit_code=EXIT_AUTHORITY)
        if active >= grant.budget.max_concurrency:
            raise CliError("signed concurrency budget is exhausted", exit_code=EXIT_AUTHORITY)
        reservation_id = f"reservation.{secrets.token_hex(16)}"
        connection.execute(
            """INSERT INTO reservations(
                reservation_id, created_at, expires_at, request_fingerprint,
                request_bytes, request_sha256, response_limit
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                reservation_id,
                now_seconds,
                expires_at,
                _request_fingerprint(
                    hostname=hostname,
                    port=port,
                    scheme=scheme,
                    method=method,
                    path=path,
                    request_bytes=request_bytes,
                    request_sha256=request_sha256,
                    response_bytes=response_bytes,
                ),
                request_bytes,
                request_sha256,
                response_bytes,
            ),
        )
        connection.commit()
    except CliError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise CliError(f"cannot reserve request budget: {exc}", exit_code=EXIT_AUTHORITY) from exc
    finally:
        connection.close()
    return {
        "reservation_id": reservation_id,
        "reservation_expires_at": datetime.fromtimestamp(expires_at, UTC).isoformat().replace(
            "+00:00", "Z"
        ),
        "remaining_budget": {
            "total_actions": grant.budget.total_actions - total - 1,
            "rate_per_minute": grant.budget.rate_per_minute - rate - 1,
            "max_concurrency": grant.budget.max_concurrency - active - 1,
        },
    }


def _complete_request(
    *,
    workspace: Path,
    manifest: dict[str, object],
    reservation_id: str,
    request_file: Path,
    observed_response_bytes: int,
    response_file: Path | None,
) -> dict[str, object]:
    connection = _request_accounting_connection(workspace)
    try:
        _prepare_request_accounting(connection, manifest)
        row = connection.execute(
            """SELECT expires_at, request_bytes, request_sha256, response_limit, completed_at
               FROM reservations WHERE reservation_id = ?""",
            (reservation_id,),
        ).fetchone()
        if row is None:
            raise CliError("unknown request reservation", exit_code=EXIT_AUTHORITY)
        if row[4] is not None:
            raise CliError("request reservation is already complete", exit_code=EXIT_AUTHORITY)
        if _utc_now().timestamp() >= row[0]:
            raise CliError("request reservation has expired", exit_code=EXIT_AUTHORITY)
        request_content = _capture_bounded_local_file(
            request_file,
            maximum_bytes=row[1],
            label="request",
        )
        request_sha256 = hashlib.sha256(request_content).hexdigest()
        if request_sha256 != row[2]:
            raise CliError(
                "request file digest does not match the reservation",
                exit_code=EXIT_AUTHORITY,
            )
        response_sha256: str | None = None
        if response_file is not None:
            response_size = _response_file_size(response_file)
            if response_size != observed_response_bytes:
                raise CliError(
                    "response file length changed while being inspected",
                    exit_code=EXIT_AUTHORITY,
                )
            if response_size > row[3]:
                raise CliError(
                    "response file exceeds the reserved response limit",
                    exit_code=EXIT_AUTHORITY,
                )
            response_content = _capture_bounded_local_file(
                response_file,
                maximum_bytes=row[3],
                label="response",
            )
            if len(response_content) != observed_response_bytes:
                raise CliError(
                    "response file length changed while being read",
                    exit_code=EXIT_AUTHORITY,
                )
            response_sha256 = hashlib.sha256(response_content).hexdigest()
        within_reserved_response_budget = observed_response_bytes <= row[3]
        connection.execute(
            "UPDATE reservations SET completed_at = ?, observed_response_bytes = ?, response_sha256 = ? "
            "WHERE reservation_id = ?",
            (_utc_now().timestamp(), observed_response_bytes, response_sha256, reservation_id),
        )
        connection.commit()
    except CliError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise CliError(
            f"cannot complete request reservation: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc
    finally:
        connection.close()
    return {
        "observed_response_bytes": observed_response_bytes,
        "completed": True,
        "dispatch_performed": False,
        "network_access": "none",
        "request_sha256": request_sha256,
        "reservation_id": reservation_id,
        "response_sha256": response_sha256,
        "within_reserved_response_budget": within_reserved_response_budget,
    }


def _scope_verify_request(arguments: argparse.Namespace) -> int:
    workspace: Path = arguments.workspace
    trusted_key_path = _trusted_key_path(arguments)
    manifest, grant, target, now = _verified_request_workspace(workspace, trusted_key_path)

    method = arguments.method.upper()
    path = arguments.path
    if not path.startswith("/"):
        raise CliError("request path must start with '/'", exit_code=EXIT_AUTHORITY)
    response_bytes = _request_byte_count(arguments.response_bytes, label="response bytes")
    request_content, request_sha256 = _capture_verified_raw_request(
        arguments.request_file,
        maximum_bytes=grant.budget.max_request_bytes,
        hostname=arguments.hostname,
        port=arguments.port,
        scheme=arguments.scheme,
        method=method,
        request_path=path,
    )
    request_bytes = len(request_content)
    if (
        not _request_hostname_matches_target(arguments.hostname, target)
        or (target.ports and arguments.port not in target.ports)
        or (target.protocols and arguments.scheme not in target.protocols)
        or (target.methods and method not in target.methods)
        or (target.paths and not any(_path_matches(pattern, path) for pattern in target.paths))
    ):
        raise CliError(
            "request is outside the selected signed target", exit_code=EXIT_AUTHORITY
        )
    policy = grant.action_policy
    if (
        OFFLINE_REQUEST_ACTION_FAMILY not in policy.allowed_families
        or OFFLINE_REQUEST_ACTION_CLASS not in policy.allowed_classes
        or (policy.allowed_methods and method not in policy.allowed_methods)
        or (
            policy.allowed_path_patterns
            and not any(_path_matches(pattern, path) for pattern in policy.allowed_path_patterns)
        )
    ):
        raise CliError(
            "request is outside the signed action policy", exit_code=EXIT_AUTHORITY
        )
    if any(
        _request_matches_explicit_deny(
            deny,
            target_id=target.target_id,
            hostname=arguments.hostname,
            method=method,
            path=path,
        )
        for deny in policy.denied
    ):
        raise CliError("request matches an explicit signed deny", exit_code=EXIT_AUTHORITY)
    if (
        request_bytes > grant.budget.max_request_bytes
        or response_bytes > grant.budget.max_response_bytes
    ):
        raise CliError(
            "request exceeds the signed byte budget", exit_code=EXIT_AUTHORITY
        )
    reservation = _reserve_request(
        workspace=workspace,
        manifest=manifest,
        grant=grant,
        now=now,
        hostname=arguments.hostname,
        port=arguments.port,
        scheme=arguments.scheme,
        method=method,
        path=path,
        request_bytes=request_bytes,
        request_sha256=request_sha256,
        response_bytes=response_bytes,
    )
    _emit_json(
        {
            "authorized": True,
            "action_class": OFFLINE_REQUEST_ACTION_CLASS.value,
            "budget": grant.budget.model_dump(mode="json"),
            "budget_accounting": "operator_local_reservation",
            "dispatch_performed": False,
            "grant_id": grant.grant_id,
            "grant_version": grant.grant_version,
            "method": method,
            "network_access": "none",
            "pack_id": manifest["pack_id"],
            "path": path,
            "port": arguments.port,
            "request_bytes": request_bytes,
            "request_sha256": request_sha256,
            "response_bytes": response_bytes,
            "scheme": arguments.scheme,
            "target_id": target.target_id,
            "hostname": arguments.hostname,
            **reservation,
        }
    )
    return EXIT_OK


def _scope_complete_request(arguments: argparse.Namespace) -> int:
    manifest, _, _, _ = _verified_request_workspace(
        arguments.workspace, _trusted_key_path(arguments), require_active=False
    )
    completion = _complete_request(
        workspace=arguments.workspace,
        manifest=manifest,
        reservation_id=arguments.reservation_id,
        request_file=arguments.request_file,
        observed_response_bytes=(
            _request_byte_count(arguments.observed_response_bytes, label="observed response bytes")
            if arguments.response_file is None
            else _response_file_size(arguments.response_file)
        ),
        response_file=arguments.response_file,
    )
    _emit_json(completion)
    return EXIT_OK if completion["within_reserved_response_budget"] else EXIT_AUTHORITY


def _validate_live_command(
    command: object,
    *,
    grant: AuthorityGrant,
    target: TargetAsset,
    pack_id: str,
    authority_key_id: str,
    now: datetime,
) -> None:
    from .execution import GatewayDispatchCommand

    if type(command) is not GatewayDispatchCommand:
        raise CliError("live dispatch command has an invalid exact type", exit_code=EXIT_AUTHORITY)
    intent = command.intent
    request = command.request
    lease = command.lease
    policy = grant.action_policy
    endpoint = request.endpoint
    if (
        command.decision.grant_id != grant.grant_id
        or command.decision.grant_version != grant.grant_version
        or lease.grant_id != grant.grant_id
        or lease.grant_version != grant.grant_version
        or lease.authority_key_id != authority_key_id
    ):
        raise CliError(
            "live command is not bound to the verified authority grant",
            exit_code=EXIT_AUTHORITY,
        )
    if intent.target_id != target.target_id or lease.target_id != target.target_id:
        raise CliError(
            "live command is not bound to the selected signed target",
            exit_code=EXIT_AUTHORITY,
        )
    if intent.pack_id != pack_id:
        raise CliError(
            "live command pack differs from the selected signed pack",
            exit_code=EXIT_AUTHORITY,
        )
    if (
        intent.action_class not in policy.allowed_classes
        or intent.action_kind not in policy.allowed_families
        or (policy.allowed_methods and request.method not in policy.allowed_methods)
        or (
            policy.allowed_path_patterns
            and not any(
                _path_matches(pattern, endpoint.path)
                for pattern in policy.allowed_path_patterns
            )
        )
    ):
        raise CliError(
            "live command action is outside the signed action policy",
            exit_code=EXIT_AUTHORITY,
        )
    if any(
        (deny.target_id is None or deny.target_id == target.target_id)
        and (not deny.action_families or intent.action_kind in deny.action_families)
        and (not deny.methods or request.method in deny.methods)
        and (deny.path_pattern is None or _path_matches(deny.path_pattern, endpoint.path))
        and (
            deny.host_pattern is None
            or any(fnmatchcase(host, deny.host_pattern) for host in target.hostnames)
        )
        for deny in policy.denied
    ):
        raise CliError("live command matches an explicit signed deny", exit_code=EXIT_AUTHORITY)
    host_allowed = endpoint.hostname in target.hostnames
    if not host_allowed:
        try:
            address = ipaddress.ip_address(endpoint.hostname)
            host_allowed = any(address in ipaddress.ip_network(cidr) for cidr in target.cidrs)
        except ValueError:
            host_allowed = False
    if (
        not host_allowed
        or (target.ports and endpoint.port not in target.ports)
        or (target.protocols and endpoint.scheme.value not in target.protocols)
        or (target.methods and request.method not in target.methods)
        or (
            target.paths
            and not any(_path_matches(pattern, endpoint.path) for pattern in target.paths)
        )
    ):
        raise CliError(
            "live command endpoint is outside the selected signed target",
            exit_code=EXIT_AUTHORITY,
        )
    if command.identity.identity_id not in grant.identities:
        raise CliError(
            "live command identity is outside the signed grant",
            exit_code=EXIT_AUTHORITY,
        )
    if grant.tenants and command.identity.tenant_id not in grant.tenants:
        raise CliError("live command tenant is outside the signed grant", exit_code=EXIT_AUTHORITY)
    reservation = lease.reservation
    budget = grant.budget
    if (
        reservation.request_bytes > budget.max_request_bytes
        or reservation.response_bytes > budget.max_response_bytes
        or reservation.duration_seconds > budget.max_duration_seconds
    ):
        raise CliError(
            "live command reservation exceeds the signed budget",
            exit_code=EXIT_AUTHORITY,
        )
    active_window_ends = [
        window.ends_at
        for window in grant.execution_windows
        if window.starts_at <= now < window.ends_at
    ]
    if (
        lease.issued_at > now
        or now >= lease.expires_at
        or lease.expires_at > grant.expires_at
        or not active_window_ends
        or lease.expires_at > max(active_window_ends)
    ):
        raise CliError(
            "live command lease is outside the signed execution window",
            exit_code=EXIT_AUTHORITY,
        )


def _validate_external_live_workspace(
    workspace: Path | None,
    bundle: Path,
    command: Path,
) -> None:
    if workspace is None:
        raise CliError("external live dispatch requires --workspace", exit_code=EXIT_AUTHORITY)
    try:
        metadata = workspace.stat()
        root = workspace.resolve(strict=True)
        bundle.resolve(strict=True).relative_to(root)
        command.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise CliError(
            "external live bundle and command must be inside an existing workspace",
            exit_code=EXIT_AUTHORITY,
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CliError("external live workspace is not a directory", exit_code=EXIT_AUTHORITY)


def _run(arguments: argparse.Namespace) -> int:
    key_path = _trusted_key_path(arguments)
    authority_content, key_content = _capture_protocol_file_pair(
        arguments.authority,
        key_path,
    )
    envelope = _parse_protocol_file(
        arguments.authority,
        authority_content,
        SignedAuthorityGrant,
    )
    public_key = _parse_protocol_file(
        key_path,
        key_content,
        Ed25519PublicKeyRecord,
    )
    now = _utc_now()
    try:
        grant = verify_authority_grant(
            envelope,
            public_key,
            now=now,
            minimum_version=arguments.minimum_grant_version,
        )
    except (SignatureVerificationError, ValueError) as exc:
        raise CliError(
            f"authority verification failed: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc

    targets = [target for target in grant.targets if target.target_id == arguments.target]
    if len(targets) != 1:
        raise CliError(
            "target-id is absent from, or ambiguous in, the signed authority grant",
            exit_code=EXIT_AUTHORITY,
        )
    pack_id = PACK_IDS[arguments.pack]
    if pack_id not in grant.pack_ids:
        raise CliError(
            f"pack {arguments.pack!r} is not allowed by the signed authority grant",
            exit_code=EXIT_AUTHORITY,
        )
    if not any(window.starts_at <= now < window.ends_at for window in grant.execution_windows):
        raise CliError(
            "current time is outside every signed execution window",
            exit_code=EXIT_AUTHORITY,
        )
    target = targets[0]
    if not _target_is_loopback(target) and arguments.workspace is None:
        raise CliError(
            "external targets require --workspace for an authorized run",
            exit_code=EXIT_AUTHORITY,
        )
    if not arguments.live and (
        arguments.gateway_bundle is not None or arguments.dispatch_command is not None
    ):
        raise CliError(
            "--gateway-bundle and --dispatch-command require --live",
            exit_code=EXIT_USAGE,
        )

    if arguments.live:
        if pack_id not in LIVE_PACK_IDS:
            raise CliError(
                f"live Gateway dispatch is unavailable for manual-only pack {pack_id!r}",
                exit_code=EXIT_UNAVAILABLE,
            )
        if arguments.gateway_bundle is None or arguments.dispatch_command is None:
            raise CliError(
                "live dispatch requires a controller-provisioned --gateway-bundle "
                "and --dispatch-command",
                exit_code=EXIT_UNAVAILABLE,
            )
        from .execution import (
            GatewayDeniedResult,
            GatewayDispatchCommand,
            GatewayLaunchBundle,
            GatewayLaunchError,
            GatewayLauncher,
        )
        from .execution.http_validation import ExecutionContractError

        command_content = _capture_single_protocol_file(arguments.dispatch_command)
        command = _parse_protocol_file(
            arguments.dispatch_command,
            command_content,
            GatewayDispatchCommand,
        )
        _validate_live_command(
            command,
            grant=grant,
            target=target,
            pack_id=pack_id,
            authority_key_id=public_key.key_id,
            now=now,
        )
        if not _target_is_loopback(target):
            _validate_external_live_workspace(
                arguments.workspace,
                arguments.gateway_bundle,
                arguments.dispatch_command,
            )
        try:
            bundle = GatewayLaunchBundle.load(arguments.gateway_bundle)
            with GatewayLauncher(bundle) as launcher:
                result = launcher.dispatch(command)
        except (GatewayLaunchError, ExecutionContractError, OSError, ValueError) as exc:
            raise CliError(f"live Gateway dispatch failed: {exc}", exit_code=EXIT_UNAVAILABLE) from exc
        if isinstance(result, GatewayDeniedResult):
            raise CliError(
                f"Gateway denied live action {result.action_id}: {result.reason_code}",
                exit_code=EXIT_AUTHORITY,
            )
        _emit_json(
            {
                "authority_verified": True,
                "dispatch_performed": True,
                "grant_id": grant.grant_id,
                "mode": "live_gateway",
                "network_access": "gateway_only",
                "outcome": result.receipt.outcome.value,
                "pack_id": pack_id,
                "receipt_id": result.receipt.receipt_id,
                "target_id": target.target_id,
                "workspace": str(arguments.workspace) if arguments.workspace is not None else None,
            }
        )
        return EXIT_OK

    if arguments.workspace is not None:
        manifest = _create_manual_workspace(
            arguments.workspace,
            authority_content=authority_content,
            key_content=key_content,
            grant=grant,
            target=target,
            pack_id=pack_id,
            now=now,
        )
        _emit_json(
            {
                "authority_verified": True,
                "dispatch_performed": False,
                "grant_id": grant.grant_id,
                "mode": "manual_authorized",
                "network_access": "none",
                "pack_id": pack_id,
                "run_id": manifest["run_id"],
                "target_id": target.target_id,
                "workspace": str(arguments.workspace),
            }
        )
        return EXIT_OK

    _emit_json(
        {
            "authority_verified": True,
            "dispatch_performed": False,
            "grant_id": grant.grant_id,
            "mode": "loopback_smoke",
            "network_access": "none",
            "pack_id": pack_id,
            "target_id": target.target_id,
        }
    )
    return EXIT_OK


def _unavailable(arguments: argparse.Namespace) -> int:
    path = getattr(arguments, "command_path", arguments.command)
    raise CliError(
        f"{path} is declared but unavailable until its v0.1 engine is integrated",
        exit_code=EXIT_UNAVAILABLE,
    )


def _set_unavailable(parser: argparse.ArgumentParser, command_path: str) -> None:
    parser.set_defaults(handler=_unavailable, command_path=command_path)


def _configure_resume_command(
    parser: argparse.ArgumentParser,
    *,
    operation_name: str,
) -> None:
    if os.name == "nt":
        _set_unavailable(parser, operation_name)
        return

    from .resume_cli import ResumeCliError, ResumeOperation, configure_resume_parser

    operation = ResumeOperation(operation_name)
    configure_resume_parser(
        parser,
        operation=operation,
        capture_protocol_pair=_capture_protocol_file_pair,
        validate_json_depth=_validate_json_depth,
        reject_duplicate_keys=_reject_duplicate_keys,
    )
    configured_handler = parser.get_default("handler")

    def handle(arguments: argparse.Namespace) -> int:
        try:
            return int(configured_handler(arguments))
        except ResumeCliError as exc:
            raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc

    parser.set_defaults(handler=handle)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="faultloom")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    doctor = commands.add_parser("doctor", help="check local runtime readiness")
    doctor.add_argument("--json", action="store_true", help="emit compact JSON")
    doctor.set_defaults(handler=_doctor)

    key = commands.add_parser("key", help="manage local signing keys")
    key_commands = key.add_subparsers(dest="key_command", required=True)
    key_init = key_commands.add_parser("init", help="initialize a local authority key")
    key_init.add_argument("--out-dir", type=Path, default=Path(".faultloom/authority"))
    key_init.set_defaults(handler=_key_init)

    scope = commands.add_parser("scope", help="manage signed scope contracts")
    scope_commands = scope.add_subparsers(dest="scope_command", required=True)
    scope_draft = scope_commands.add_parser("draft", help="create a scope draft")
    scope_draft.add_argument("--template", choices=("lab", "bounty", "consulting"), required=True)
    scope_draft.add_argument("--target-id", required=True)
    target_location = scope_draft.add_mutually_exclusive_group(required=True)
    target_location.add_argument("--hostname", action="append")
    target_location.add_argument("--cidr", action="append")
    scope_draft.add_argument("--port", action="append", type=_port)
    scope_draft.add_argument("--method", action="append")
    scope_draft.add_argument("--path", action="append")
    scope_draft.add_argument("--pack", choices=tuple(PACK_IDS), default="web")
    scope_draft.add_argument("--duration-hours", type=_positive_int, default=8)
    scope_draft.add_argument("--title", default="FaultLoom authorized engagement")
    scope_draft.add_argument("--operator", default="operator.local")
    scope_draft.add_argument("--out", type=Path, required=True)
    scope_draft.set_defaults(handler=_scope_draft)
    scope_approve = scope_commands.add_parser("approve", help="approve a scope draft")
    scope_approve.add_argument("draft", type=Path)
    scope_approve.add_argument("--private-key", type=Path, required=True)
    scope_approve.add_argument("--out", type=Path, required=True)
    scope_approve.add_argument("--grant-id")
    scope_approve.add_argument("--issued-to", default="researcher.local")
    scope_approve.add_argument("--approved-by", default="operator.local")
    scope_approve.set_defaults(handler=_scope_approve)
    scope_revoke = scope_commands.add_parser("revoke", help="revoke an authority grant")
    scope_revoke.add_argument("grant_id")
    _set_unavailable(scope_revoke, "scope revoke")
    def configure_verify_request(command: argparse.ArgumentParser) -> None:
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--trusted-key", type=Path)
        command.add_argument("--hostname", required=True)
        command.add_argument("--port", type=_port, required=True)
        command.add_argument("--scheme", choices=("http", "https"), required=True)
        command.add_argument("--method", required=True)
        command.add_argument("--path", required=True)
        command.add_argument("--request-file", type=Path, required=True)
        command.add_argument("--response-bytes", required=True)
        command.set_defaults(handler=_scope_verify_request)

    scope_verify_request = scope_commands.add_parser(
        "verify-request",
        help="bind one exact local raw HTTP/1.1 request to a signed manual workspace",
    )
    configure_verify_request(scope_verify_request)
    scope_check_request = scope_commands.add_parser(
        "check-request",
        help="deprecated alias for verify-request; exact raw request file required",
    )
    configure_verify_request(scope_check_request)
    scope_complete_request = scope_commands.add_parser(
        "complete-request",
        help="record an offline Burp request reservation completion",
    )
    scope_complete_request.add_argument("--workspace", type=Path, required=True)
    scope_complete_request.add_argument("--trusted-key", type=Path)
    scope_complete_request.add_argument("--reservation-id", required=True)
    scope_complete_request.add_argument("--request-file", type=Path, required=True)
    response_source = scope_complete_request.add_mutually_exclusive_group(required=True)
    response_source.add_argument("--observed-response-bytes")
    response_source.add_argument("--response-file", type=Path)
    scope_complete_request.set_defaults(handler=_scope_complete_request)

    run = commands.add_parser("run", help="start an authorized research run")
    run.add_argument("--authority", type=Path, required=True)
    run.add_argument("--trusted-key", type=Path)
    run.add_argument("--minimum-grant-version", type=_positive_int, default=1)
    run.add_argument("--target", required=True, help="signed target-id; URLs are not accepted")
    run.add_argument("--pack", choices=tuple(PACK_IDS), required=True)
    run.add_argument(
        "--workspace",
        type=Path,
        help="create a new offline workspace for an authorized manual run",
    )
    run.add_argument("--live", action="store_true")
    run.add_argument("--gateway-bundle", type=Path)
    run.add_argument("--dispatch-command", type=Path)
    run.set_defaults(handler=_run)

    evidence = commands.add_parser("evidence", help="manage manual run evidence")
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_add = evidence_commands.add_parser("add", help="add a file to a run workspace")
    evidence_add.add_argument("--workspace", type=Path, required=True)
    evidence_add.add_argument("--file", type=Path, required=True)
    evidence_add.add_argument(
        "--kind",
        choices=("burp", "http", "screenshot", "note", "other"),
        required=True,
    )
    evidence_add.add_argument("--title")
    evidence_add.set_defaults(handler=_evidence_add)
    evidence_add_exchange = evidence_commands.add_parser(
        "add-exchange",
        help="archive one completed request/response reservation as evidence",
    )
    evidence_add_exchange.add_argument("--workspace", type=Path, required=True)
    evidence_add_exchange.add_argument("--trusted-key", type=Path)
    evidence_add_exchange.add_argument("--reservation-id", required=True)
    evidence_add_exchange.add_argument("--request-file", type=Path, required=True)
    evidence_add_exchange.add_argument("--response-file", type=Path, required=True)
    evidence_add_exchange.add_argument("--title")
    evidence_add_exchange.set_defaults(handler=_evidence_add_exchange)

    finding = commands.add_parser("finding", help="prepare manual finding drafts")
    finding_commands = finding.add_subparsers(dest="finding_command", required=True)
    finding_new = finding_commands.add_parser("new", help="create a report-ready draft")
    finding_new.add_argument("--workspace", type=Path, required=True)
    finding_new.add_argument("--title", required=True)
    finding_new.add_argument(
        "--severity",
        choices=("informational", "low", "medium", "high", "critical"),
        required=True,
    )
    finding_new.add_argument("--summary")
    finding_new.add_argument("--impact")
    finding_new.add_argument("--steps-file", type=Path)
    finding_new.add_argument("--remediation")
    finding_new.add_argument("--evidence", action="append")
    finding_new.set_defaults(handler=_finding_new)

    automation = commands.add_parser(
        "automation", help="compile offline automation candidates"
    )
    automation_commands = automation.add_subparsers(
        dest="automation_command", required=True
    )
    automation_compile = automation_commands.add_parser(
        "compile", help="compile one local model turn without provider or target access"
    )
    automation_compile.add_argument("--workspace", type=Path, required=True)
    automation_compile.add_argument("--trusted-key", type=Path, required=True)
    automation_compile.add_argument(
        "--minimum-grant-version", type=_positive_int, default=1
    )
    automation_compile.add_argument("--request", type=Path, required=True)
    automation_compile.add_argument("--model-turn", type=Path, required=True)
    automation_compile.set_defaults(handler=_automation_compile)
    automation_export_handoff = automation_commands.add_parser(
        "export-handoff",
        help="export an offline provider-neutral model-turn handoff",
    )
    automation_export_handoff.add_argument("--workspace", type=Path, required=True)
    automation_export_handoff.add_argument("--trusted-key", type=Path, required=True)
    automation_export_handoff.add_argument(
        "--minimum-grant-version", type=_positive_int, default=1
    )
    automation_export_handoff.add_argument("--request", type=Path, required=True)
    automation_export_handoff.add_argument("--provider-id", required=True)
    automation_export_handoff.add_argument(
        "--trusted-disclosure-key", type=Path, action="append", required=True
    )
    automation_export_handoff.add_argument("--out", type=Path, required=True)
    automation_export_handoff.set_defaults(handler=_automation_export_handoff)

    resume = commands.add_parser("resume", help="resume a durable run")
    _configure_resume_command(resume, operation_name="resume")
    inspect = commands.add_parser("inspect", help="inspect durable run state")
    _configure_resume_command(inspect, operation_name="inspect")
    verify = commands.add_parser("verify", help="verify a finding candidate")
    report = commands.add_parser("report", help="render a verified finding")
    configure_verification_parsers(
        verify,
        report,
        VerificationCliDependencies(
            capture_protocol_pair=_capture_public_protocol_file_pair,
            parse_protocol_file=_parse_protocol_file,
            now=_utc_now,
        ),
    )

    adapter = commands.add_parser("adapter", help="inspect adapter registry")
    configure_adapter_parser(adapter)
    pack = commands.add_parser("pack", help="inspect pack registry")
    pack_commands = pack.add_subparsers(dest="pack_command", required=True)
    pack_list = pack_commands.add_parser("list")
    pack_list.set_defaults(handler=_pack_list)
    for operation in ("doctor", "test"):
        child = pack_commands.add_parser(operation)
        child.add_argument("pack_id")
        child.set_defaults(handler=_pack_check)

    evaluation = commands.add_parser("eval", help="run a sealed evaluation manifest")
    evaluation_commands = evaluation.add_subparsers(dest="eval_command", required=True)
    evaluation_run = evaluation_commands.add_parser("run")
    evaluation_run.add_argument("manifest", type=Path)
    _set_unavailable(evaluation_run, "eval run")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        return int(arguments.handler(arguments))
    except CliError as exc:
        print(f"faultloom: error: {exc}", file=sys.stderr)
        return exc.exit_code
    except VerificationCliError as exc:
        print(f"faultloom: error: {exc}", file=sys.stderr)
        return EXIT_AUTHORITY


if __name__ == "__main__":
    raise SystemExit(main())
