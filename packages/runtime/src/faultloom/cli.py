"""Fail-closed FaultLoom v0.1 command-line surface."""

from __future__ import annotations

import argparse
import contextlib
import contextvars
import hashlib
import io
import ipaddress
import json
import os
import queue
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from typing import TypeVar, cast

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
    EvidenceRef,
    ExplicitDeny,
    FindingCandidate,
    FindingClass,
    PoCStep,
    ProtocolModel,
    ProviderPolicy,
    ReplayPlan,
    RetentionPolicy,
    ScopeContractDraft,
    SignedAuthorityGrant,
    StateChangePolicy,
    StateRef,
    TargetAsset,
    TimeWindow,
    sha256_digest,
    sign_authority_grant,
    verify_authority_grant,
)
from faultloom_protocol.signing import SignatureVerificationError
from pydantic import ValidationError

from . import __version__
from .adapter_cli import configure_adapter_parser
from .automation.candidate_outbox import (
    CandidateOutboxError,
    automation_result_candidate_digest,
)
from .automation.models import AuthorizedAutomationResult
from .automation_cli import (
    ArchivedHttpExchange,
    AutomationCompileDependencies,
    AutomationCompileError,
    AutomationExportHandoffDependencies,
    AutomationPrepareHttp1RequestArguments,
    AutomationPrepareHttp1RequestDependencies,
    compile_automation,
    export_automation_handoff,
    prepare_automation_http1_request,
)
from .personal_campaign import (
    EXACT_BODY_DIGEST_CLASSIFIER,
    PERSONAL_HTTP1_TRIAD_AUTOMATION_BINDING_SCHEMA,
    PERSONAL_HTTP1_TRIAD_BOUND_SCHEMA,
    PERSONAL_HTTP1_TRIAD_SCHEMA,
    PersonalCampaignError,
    PersonalHttp1TriadSpec,
    classify_exact_body_digest_triad,
    parse_personal_http1_triad_spec,
    sha256_hex,
    validate_campaign_id,
)
from .tool_planner import ToolCandidate
from .verification import (
    ArtifactVerificationError,
    ClaimAssemblyError,
    ClaimDraft,
    ResultArtifactContext,
    ResultArtifactDraft,
    VerificationCase,
    VerificationInputError,
    VerifierAuthorizationError,
    VerifierAuthorizationRequest,
    assemble_claim_packet,
    authorize_verifier,
    sign_verification_result,
    verify_candidate,
)
from .verification.http1_triad import (
    FinalizedTriadReplayExecutor,
    Http1TriadVerificationError,
    parse_strict_http1_request,
    require_independent_identity,
    require_separate_workspaces,
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
PERSONAL_HTTP1_MAX_REQUEST_BYTES = 65_536
PERSONAL_HTTP1_MAX_RESPONSE_BYTES = 1_048_576
PERSONAL_HTTP1_PREVIEW_CHARS = 3_072
_HANDOFF_VALIDATION_SNAPSHOTS: contextvars.ContextVar[dict[Path, bytes] | None] = contextvars.ContextVar(
    "handoff_validation_snapshots", default=None
)

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


class _PersonalPreDispatchError(RuntimeError):
    """A direct connection/TLS failure before any request byte was attempted."""


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


@dataclass(frozen=True)
class _AdmittedRawRequest:
    manifest: dict[str, object]
    grant: AuthorityGrant
    target: TargetAsset
    method: str
    path: str
    content: bytes
    request_sha256: str
    response_limit: int
    reservation: dict[str, object]


@dataclass(frozen=True)
class _CampaignRecordsDirectory:
    workspace: Path
    campaigns: Path
    workspace_stat: os.stat_result
    campaigns_stat: os.stat_result


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


def _personal_timeout_seconds(value: str) -> int:
    parsed = _positive_int(value)
    if parsed > 30:
        raise argparse.ArgumentTypeError("must be between 1 and 30 seconds")
    return parsed


def _campaign_id(value: str) -> str:
    try:
        return validate_campaign_id(value)
    except PersonalCampaignError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _body_preview_chars(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer between 0 and 3072") from exc
    if not 0 <= parsed <= PERSONAL_HTTP1_PREVIEW_CHARS:
        raise argparse.ArgumentTypeError("must be an integer between 0 and 3072")
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


def _capture_private_protocol_file(path: Path) -> bytes:
    """Capture one private seed with the same POSIX ownership/mode gate as scope signing."""

    if os.name == "nt":
        snapshot = _snapshot_windows_protocol_file(path)
        return _read_windows_protocol_file(path, snapshot)

    snapshot = _snapshot_protocol_file_path(path)
    mode = stat.S_IMODE(snapshot.leaf_stat.st_mode)
    owner_id = os.geteuid() if hasattr(os, "geteuid") else snapshot.leaf_stat.st_uid
    if mode != 0o600 or snapshot.leaf_stat.st_uid != owner_id:
        raise _protocol_file_error(
            path,
            "secret input must be owned by the current user with mode 0600",
        )
    bound = _open_bound_protocol_file(snapshot)
    try:
        content = _read_bound_protocol_file(bound)
        _reconcile_bound_protocol_file(bound)
        return content
    finally:
        _close_bound_protocol_file(bound)


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
            protocols=tuple(arguments.scheme or ("https",)),
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
        "personal_direct_send_enabled": True,
        "personal_direct_send_mode": "scope_gated_direct_http1",
        "personal_direct_send_network_access": "scope_gated_direct_http1",
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


def _evidence_add_exchange_result(arguments: argparse.Namespace) -> dict[str, object]:
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
    return {
        "evidence_id": evidence_id,
        "record": str(record_path),
        "request_stored_file": str(request_destination),
        "response_stored_file": str(response_destination),
    }


def _evidence_add_exchange(arguments: argparse.Namespace) -> int:
    """Archive one completed, digest-bound manual request/response exchange."""
    _emit_json(_evidence_add_exchange_result(arguments))
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


def _is_exchange_stored_filename(
    value: object,
    *,
    component_name: str,
    evidence_id: str | None = None,
) -> bool:
    if not isinstance(value, str) or not value.isascii():
        return False
    parts = value.split(".")
    if len(parts) != 6:
        return False
    _, timestamp, token, component, data, extension = parts
    return (
        parts[0] == "evidence"
        and (evidence_id is None or ".".join(parts[:3]) == evidence_id)
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


def _finding_new_result(arguments: argparse.Namespace) -> dict[str, object]:
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
    return {
        "finding": str(markdown_path),
        "finding_id": finding_id,
        "record": str(record_path),
        "status": "draft_unverified",
    }


def _finding_new(arguments: argparse.Namespace) -> int:
    _emit_json(_finding_new_result(arguments))
    return EXIT_OK


def _capture_single_protocol_file(path: Path) -> bytes:
    if os.name == "nt":
        snapshot = _snapshot_windows_protocol_file(path)
        content = _read_windows_protocol_file(path, snapshot)
    else:
        snapshot = _snapshot_protocol_file_path(path)
        bound = _open_bound_protocol_file(snapshot)
        try:
            content = _read_bound_protocol_file(bound)
            _reconcile_bound_protocol_file(bound)
        finally:
            _close_bound_protocol_file(bound)
    snapshots = _HANDOFF_VALIDATION_SNAPSHOTS.get()
    if snapshots is not None:
        try:
            snapshots[path.resolve(strict=True)] = content
        except OSError as exc:
            raise CliError("handoff source changed while being captured", exit_code=EXIT_AUTHORITY) from exc
    return content


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
    require_connection_close: bool = False,
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
    connection_values: list[str] = []
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
        elif lowered == b"connection":
            connection_values.append(normalized_value)
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
    if require_connection_close and (
        len(connection_values) != 1 or connection_values[0].lower() != "close"
    ):
        raise CliError(
            "direct personal requests require exactly 'Connection: close'",
            exit_code=EXIT_AUTHORITY,
        )


def _capture_verified_raw_request(
    path: Path,
    *,
    maximum_bytes: int,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
    request_path: str,
    require_connection_close: bool = False,
) -> tuple[bytes, str]:
    content = _capture_bounded_local_file(path, maximum_bytes=maximum_bytes, label="request")
    _parse_raw_http11_request(
        content,
        hostname=hostname,
        port=port,
        scheme=scheme,
        method=method,
        path=request_path,
        require_connection_close=require_connection_close,
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


def _load_archived_http_exchange(
    workspace: Path,
    manifest: dict[str, object],
    grant: AuthorityGrant,
    target: TargetAsset,
    evidence_id: str,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
    path: str,
) -> ArchivedHttpExchange:
    """Strictly bind one archived exchange back to its completed reservation."""

    if re.fullmatch(r"^evidence\.[0-9]{8}T[0-9]{6}Z\.[0-9a-f]{8}$", evidence_id) is None:
        raise CliError("evidence ID is invalid", exit_code=EXIT_AUTHORITY)
    record_path = workspace / "evidence" / "raw" / f"{evidence_id}.json"
    record_content = _capture_single_protocol_file(record_path)
    try:
        record = json.loads(
            record_content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CliError("invalid archived exchange record", exit_code=EXIT_AUTHORITY) from exc
    expected_record_fields = {
        "schema",
        "evidence_id",
        "run_id",
        "created_at",
        "kind",
        "title",
        "reservation_id",
        "original_name",
        "stored_file",
        "size_bytes",
        "sha256",
        "request",
        "response",
    }
    if type(record) is not dict or set(record) != expected_record_fields:
        raise CliError("invalid archived exchange record", exit_code=EXIT_AUTHORITY)
    reservation_id = record.get("reservation_id")
    if (
        record.get("schema") != "faultloom.manual-evidence.v1"
        or record.get("evidence_id") != evidence_id
        or record.get("run_id") != manifest.get("run_id")
        or record.get("kind") != "http"
        or not _is_reservation_id(reservation_id)
    ):
        raise CliError("archived exchange is not bound to this run", exit_code=EXIT_AUTHORITY)

    components: dict[str, tuple[Path, bytes, int, str]] = {}
    for component_name in ("request", "response"):
        component = record.get(component_name)
        if type(component) is not dict or set(component) != {
            "original_name",
            "stored_file",
            "size_bytes",
            "sha256",
        }:
            raise CliError("invalid archived exchange component", exit_code=EXIT_AUTHORITY)
        stored_file = component.get("stored_file")
        size_bytes = component.get("size_bytes")
        digest = component.get("sha256")
        if (
            not _is_exchange_stored_filename(
                stored_file,
                component_name=component_name,
                evidence_id=evidence_id,
            )
            or type(size_bytes) is not int
            or size_bytes < 0
            or type(digest) is not str
            or re.fullmatch(r"^[0-9a-f]{64}$", digest) is None
        ):
            raise CliError("invalid archived exchange component", exit_code=EXIT_AUTHORITY)
        stored_filename = cast(str, stored_file)
        component_path = record_path.parent / stored_filename
        content = _capture_bounded_local_file(
            component_path, maximum_bytes=size_bytes, label=f"archived {component_name}"
        )
        if len(content) != size_bytes or hashlib.sha256(content).hexdigest() != digest:
            raise CliError("archived exchange component digest differs", exit_code=EXIT_AUTHORITY)
        components[component_name] = (component_path, content, size_bytes, digest)
    if (
        record.get("stored_file") != record["request"]["stored_file"]
        or record.get("size_bytes") != record["request"]["size_bytes"]
        or record.get("sha256") != record["request"]["sha256"]
    ):
        raise CliError("archived exchange request summary differs", exit_code=EXIT_AUTHORITY)

    connection = _request_accounting_connection(workspace)
    try:
        _prepare_request_accounting(connection, manifest)
        row = connection.execute(
            """SELECT request_fingerprint, request_bytes, request_sha256,
                      response_limit, completed_at, observed_response_bytes,
                      response_sha256
                 FROM reservations WHERE reservation_id = ?""",
            (reservation_id,),
        ).fetchone()
    except CliError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise CliError("cannot read archived exchange reservation", exit_code=EXIT_AUTHORITY) from exc
    finally:
        connection.close()
    if row is None:
        raise CliError("archived exchange reservation is absent", exit_code=EXIT_AUTHORITY)
    (
        request_fingerprint,
        request_bytes,
        request_sha256,
        response_limit,
        completed_at,
        observed_response_bytes,
        response_sha256,
    ) = row
    request_content = components["request"][1]
    if (
        type(request_fingerprint) is not str
        or type(request_bytes) is not int
        or type(request_sha256) is not str
        or type(response_limit) is not int
        or type(completed_at) not in (int, float)
        or type(observed_response_bytes) is not int
        or type(response_sha256) is not str
        or request_bytes != components["request"][2]
        or request_sha256 != components["request"][3]
        or observed_response_bytes != components["response"][2]
        or response_sha256 != components["response"][3]
        or response_limit < observed_response_bytes
        or request_fingerprint
        != _request_fingerprint(
            hostname=hostname,
            port=port,
            scheme=scheme,
            method=method,
            path=path,
            request_bytes=request_bytes,
            request_sha256=request_sha256,
            response_bytes=response_limit,
        )
    ):
        raise CliError(
            "archived exchange differs from its completed reservation",
            exit_code=EXIT_AUTHORITY,
        )
    _parse_raw_http11_request(
        request_content,
        hostname=hostname,
        port=port,
        scheme=scheme,
        method=method,
        path=path,
    )
    policy = grant.action_policy
    if (
        method != method.upper()
        or not path.startswith("/")
        or not _request_hostname_matches_target(hostname, target)
        or (target.ports and port not in target.ports)
        or (target.protocols and scheme not in target.protocols)
        or (target.methods and method not in target.methods)
        or (target.paths and not any(_path_matches(pattern, path) for pattern in target.paths))
        or OFFLINE_REQUEST_ACTION_FAMILY not in policy.allowed_families
        or OFFLINE_REQUEST_ACTION_CLASS not in policy.allowed_classes
        or (policy.allowed_methods and method not in policy.allowed_methods)
        or (
            policy.allowed_path_patterns
            and not any(_path_matches(pattern, path) for pattern in policy.allowed_path_patterns)
        )
        or request_bytes > grant.budget.max_request_bytes
        or response_limit > grant.budget.max_response_bytes
    ):
        raise CliError("archived exchange is outside signed authority", exit_code=EXIT_AUTHORITY)
    if any(
        _request_matches_explicit_deny(
            deny,
            target_id=target.target_id,
            hostname=hostname,
            method=method,
            path=path,
        )
        for deny in policy.denied
    ):
        raise CliError("archived exchange matches an explicit signed deny", exit_code=EXIT_AUTHORITY)
    created_at_value = record.get("created_at")
    try:
        if type(created_at_value) is not str or not created_at_value.endswith("Z"):
            raise ValueError("created_at is not canonical UTC")
        _ = datetime.fromisoformat(created_at_value.removesuffix("Z") + "+00:00")
        created_at = datetime.fromtimestamp(completed_at, UTC)
    except (OSError, OverflowError, ValueError) as exc:
        raise CliError("archived exchange timestamp is invalid", exit_code=EXIT_AUTHORITY) from exc
    return ArchivedHttpExchange(
        evidence_id=evidence_id,
        created_at=created_at,
        request_content=request_content,
        request_sha256=request_sha256,
        response_sha256=response_sha256,
        response_limit=response_limit,
    )


def _automation_prepare_http1_request(arguments: argparse.Namespace) -> int:
    try:
        return prepare_automation_http1_request(
            AutomationPrepareHttp1RequestArguments(
                workspace=arguments.workspace,
                trusted_key=arguments.trusted_key,
                evidence_id=arguments.evidence_id,
                excerpt_file=arguments.excerpt_file,
                provider_id=arguments.provider_id,
                disclosure_private_key=arguments.disclosure_private_key,
                hostname=arguments.hostname,
                port=arguments.port,
                scheme=arguments.scheme,
                method=arguments.method,
                path=arguments.path,
                out=arguments.out,
                confirm_redacted_non_sensitive=arguments.confirm_redacted_non_sensitive,
            ),
            dependencies=AutomationPrepareHttp1RequestDependencies(
                verify_workspace=_verified_request_workspace,
                load_exchange=_load_archived_http_exchange,
                capture_file=_capture_single_protocol_file,
                load_signer=lambda path: _private_signer(
                    path, _capture_private_protocol_file(path)
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
    except (TypeError, ValueError, ValidationError) as exc:
        raise CliError(
            f"cannot build automation request: {exc}", exit_code=EXIT_AUTHORITY
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


def _automation_provider_turn(arguments: argparse.Namespace) -> int:
    from .live_provider_cli import (
        LiveProviderTurnDependencies,
        LiveProviderTurnError,
        run_live_provider_turn,
    )

    try:
        return run_live_provider_turn(
            arguments,
            dependencies=LiveProviderTurnDependencies(
                verify_workspace=_verified_request_workspace,
                capture_file=_capture_single_protocol_file,
                emit_json=_emit_json,
                environment=os.environ,
            ),
        )
    except LiveProviderTurnError as exc:
        raise CliError(
            str(exc),
            exit_code=EXIT_AUTHORITY if exc.authority else EXIT_USAGE,
        ) from exc


def _automation_sign_provider_config(arguments: argparse.Namespace) -> int:
    from .live_provider_cli import (
        LiveProviderTurnError,
        sign_provider_runtime_config_file,
    )

    try:
        return sign_provider_runtime_config_file(
            arguments,
            capture_file=_capture_single_protocol_file,
            write_new_file=lambda path, content: _write_new_file(
                path,
                content,
                mode=0o600,
            ),
            emit_json=_emit_json,
        )
    except LiveProviderTurnError as exc:
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
    campaign_bindings: bool = False,
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
        if campaign_bindings:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS campaign_bindings (
                    campaign_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    reservation_id TEXT NOT NULL UNIQUE,
                    request_sha256 TEXT NOT NULL,
                    response_sha256 TEXT NOT NULL,
                    body_sha256 TEXT NOT NULL,
                    response_file TEXT NOT NULL,
                    PRIMARY KEY(campaign_id, role)
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
        binding_columns = tuple(
            (row[1], row[2], row[3], row[5])
            for row in connection.execute("PRAGMA table_info(campaign_bindings)")
        )
        expected_binding_columns = (
            ("campaign_id", "TEXT", 1, 1),
            ("role", "TEXT", 1, 2),
            ("reservation_id", "TEXT", 1, 0),
            ("request_sha256", "TEXT", 1, 0),
            ("response_sha256", "TEXT", 1, 0),
            ("body_sha256", "TEXT", 1, 0),
            ("response_file", "TEXT", 1, 0),
        )
        objects_with_bindings = {**expected_objects, "campaign_bindings": "table"}
        if (
            objects not in (expected_objects, objects_with_bindings)
            or metadata_columns != (("key", "TEXT", 0, 1), ("value", "TEXT", 1, 0))
            or columns != expected_columns
            or ("campaign_bindings" in objects and binding_columns != expected_binding_columns)
            or (campaign_bindings and "campaign_bindings" not in objects)
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


def _validate_campaign_accounting_capacity(
    *,
    workspace: Path,
    manifest: dict[str, object],
    grant: AuthorityGrant,
    now: datetime,
    required_actions: int,
) -> None:
    """Reject a campaign before start unless all sequential reservations fit now."""

    now_seconds = now.timestamp()
    connection = _request_accounting_connection(workspace)
    try:
        _prepare_request_accounting(connection, manifest)
        total = connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
        rate = connection.execute(
            "SELECT COUNT(*) FROM reservations WHERE created_at > ?",
            (now_seconds - 60,),
        ).fetchone()[0]
        active = _active_reservation_count(connection, now_seconds)
        if total + required_actions > grant.budget.total_actions:
            raise CliError(
                "signed total action budget cannot fit the complete campaign",
                exit_code=EXIT_AUTHORITY,
            )
        if rate + required_actions > grant.budget.rate_per_minute:
            raise CliError(
                "signed rate budget cannot fit the complete campaign",
                exit_code=EXIT_AUTHORITY,
            )
        if active >= grant.budget.max_concurrency:
            raise CliError(
                "signed concurrency budget cannot start the campaign",
                exit_code=EXIT_AUTHORITY,
            )
        connection.commit()
    except CliError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise CliError(
            f"cannot preflight campaign request budget: {exc}",
            exit_code=EXIT_AUTHORITY,
        ) from exc
    finally:
        connection.close()


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
    response_content: bytes | None = None,
) -> dict[str, object]:
    if response_file is not None and response_content is not None:
        raise CliError("response source is ambiguous", exit_code=EXIT_AUTHORITY)
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
        if response_content is not None:
            if len(response_content) != observed_response_bytes:
                raise CliError(
                    "response content length does not match the observed response",
                    exit_code=EXIT_AUTHORITY,
                )
            if observed_response_bytes > row[3]:
                raise CliError(
                    "response content exceeds the reserved response limit",
                    exit_code=EXIT_AUTHORITY,
                )
            response_sha256 = hashlib.sha256(response_content).hexdigest()
        elif response_file is not None:
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


def _recheck_reserved_request_before_send(
    *,
    workspace: Path,
    manifest: dict[str, object],
    reservation_id: str,
    request_file: Path,
) -> None:
    """Bind the bytes handed to sendall to the still-live local reservation."""
    connection = _request_accounting_connection(workspace)
    try:
        _prepare_request_accounting(connection, manifest)
        row = connection.execute(
            "SELECT expires_at, request_bytes, request_sha256, completed_at "
            "FROM reservations WHERE reservation_id = ?",
            (reservation_id,),
        ).fetchone()
        if row is None or row[3] is not None:
            raise CliError("request reservation is unavailable for direct send", exit_code=EXIT_AUTHORITY)
        if _utc_now().timestamp() >= row[0]:
            raise CliError("request reservation has expired", exit_code=EXIT_AUTHORITY)
        request_content = _capture_bounded_local_file(
            request_file, maximum_bytes=row[1], label="request"
        )
        if len(request_content) != row[1] or hashlib.sha256(request_content).hexdigest() != row[2]:
            raise CliError(
                "request file digest does not match the reservation", exit_code=EXIT_AUTHORITY
            )
    finally:
        connection.close()


def _validate_request_authority(
    *,
    grant: AuthorityGrant,
    target: TargetAsset,
    hostname: str,
    port: int,
    scheme: str,
    method: str,
    path: str,
    request_bytes: int,
    response_bytes: int,
    maximum_request_bytes: int,
    maximum_response_bytes: int,
) -> None:
    """Apply pure signed target, policy, deny, and byte checks before mutation."""

    if (
        not _request_hostname_matches_target(hostname, target)
        or (target.ports and port not in target.ports)
        or (target.protocols and scheme not in target.protocols)
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
            hostname=hostname,
            method=method,
            path=path,
        )
        for deny in policy.denied
    ):
        raise CliError("request matches an explicit signed deny", exit_code=EXIT_AUTHORITY)
    if request_bytes > maximum_request_bytes or response_bytes > maximum_response_bytes:
        raise CliError(
            "request exceeds the signed byte budget", exit_code=EXIT_AUTHORITY
        )


def _admit_raw_request(
    arguments: argparse.Namespace,
    *,
    response_bytes: int | None = None,
    request_cap: int | None = None,
    response_cap: int | None = None,
    require_connection_close: bool = False,
    expected_request_sha256: str | None = None,
) -> _AdmittedRawRequest:
    workspace: Path = arguments.workspace
    trusted_key_path = _trusted_key_path(arguments)
    manifest, grant, target, now = _verified_request_workspace(workspace, trusted_key_path)

    method = arguments.method.upper()
    path = arguments.path
    if not path.startswith("/"):
        raise CliError("request path must start with '/'", exit_code=EXIT_AUTHORITY)
    if response_bytes is None:
        response_bytes = _request_byte_count(arguments.response_bytes, label="response bytes")
    maximum_request_bytes = min(
        grant.budget.max_request_bytes,
        request_cap if request_cap is not None else grant.budget.max_request_bytes,
    )
    maximum_response_bytes = min(
        grant.budget.max_response_bytes,
        response_cap if response_cap is not None else grant.budget.max_response_bytes,
    )
    request_content, request_sha256 = _capture_verified_raw_request(
        arguments.request_file,
        maximum_bytes=maximum_request_bytes,
        hostname=arguments.hostname,
        port=arguments.port,
        scheme=arguments.scheme,
        method=method,
        request_path=path,
        require_connection_close=require_connection_close,
    )
    if expected_request_sha256 is not None and request_sha256 != expected_request_sha256:
        raise CliError(
            "request file digest differs from the campaign start binding",
            exit_code=EXIT_AUTHORITY,
        )
    request_bytes = len(request_content)
    _validate_request_authority(
        grant=grant,
        target=target,
        hostname=arguments.hostname,
        port=arguments.port,
        scheme=arguments.scheme,
        method=method,
        path=path,
        request_bytes=request_bytes,
        response_bytes=response_bytes,
        maximum_request_bytes=maximum_request_bytes,
        maximum_response_bytes=maximum_response_bytes,
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
    return _AdmittedRawRequest(
        manifest=manifest,
        grant=grant,
        target=target,
        method=method,
        path=path,
        content=request_content,
        request_sha256=request_sha256,
        response_limit=response_bytes,
        reservation=reservation,
    )


def _scope_verify_request(arguments: argparse.Namespace) -> int:
    admitted = _admit_raw_request(arguments)
    _emit_json(
        {
            "authorized": True,
            "action_class": OFFLINE_REQUEST_ACTION_CLASS.value,
            "budget": admitted.grant.budget.model_dump(mode="json"),
            "budget_accounting": "operator_local_reservation",
            "dispatch_performed": False,
            "grant_id": admitted.grant.grant_id,
            "grant_version": admitted.grant.grant_version,
            "method": admitted.method,
            "network_access": "none",
            "pack_id": admitted.manifest["pack_id"],
            "path": admitted.path,
            "port": arguments.port,
            "request_bytes": len(admitted.content),
            "request_sha256": admitted.request_sha256,
            "response_bytes": admitted.response_limit,
            "scheme": arguments.scheme,
            "target_id": admitted.target.target_id,
            "hostname": arguments.hostname,
            **admitted.reservation,
        }
    )
    return EXIT_OK


def _resolved_address_is_explicitly_signed(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, target: TargetAsset
) -> bool:
    if str(address) in target.hostnames:
        return True
    return any(address in ipaddress.ip_network(cidr) for cidr in target.cidrs)


def _resolve_direct_address(
    hostname: str, port: int, target: TargetAsset, *, scheme: str, deadline: float
) -> tuple[int, tuple[object, ...]]:
    results: queue.Queue[tuple[object, object]] = queue.Queue(maxsize=1)
    finished = threading.Event()

    def resolve() -> None:
        try:
            results.put(("candidates", socket.getaddrinfo(
                hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )))
        except OSError as exc:
            results.put(("error", exc))
        finally:
            finished.set()

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _PersonalPreDispatchError("direct HTTP/1.1 deadline elapsed")
    threading.Thread(target=resolve, daemon=True).start()
    if not finished.wait(remaining) or time.monotonic() >= deadline:
        raise _PersonalPreDispatchError("resolution timed out")
    try:
        kind, value = results.get_nowait()
    except queue.Empty as exc:
        raise _PersonalPreDispatchError("resolution failed") from exc
    if kind == "error":
        if isinstance(value, BaseException):
            raise _PersonalPreDispatchError("resolution failed") from value
        raise _PersonalPreDispatchError("resolution failed")
    if not isinstance(value, list):
        raise _PersonalPreDispatchError("resolution returned invalid data")
    for candidate in value:
        if not isinstance(candidate, tuple) or len(candidate) != 5:
            continue
        family, socktype, _, _, sockaddr = candidate
        if family not in {socket.AF_INET, socket.AF_INET6} or socktype != socket.SOCK_STREAM:
            continue
        try:
            address = ipaddress.ip_address(str(sockaddr[0]))
        except (ValueError, IndexError, TypeError):
            continue
        explicitly_signed = _resolved_address_is_explicitly_signed(address, target)
        if scheme == "http" and not explicitly_signed:
            raise _PersonalPreDispatchError("plaintext resolution selected an unsigned address")
        if not address.is_global and not explicitly_signed:
            raise _PersonalPreDispatchError("resolution selected a non-global address")
        return family, tuple(sockaddr)
    raise _PersonalPreDispatchError("resolution returned no TCP address")


def _send_direct_http11_once(
    *,
    hostname: str,
    port: int,
    scheme: str,
    target: TargetAsset,
    request_content: bytes,
    response_limit: int,
    deadline: float,
) -> bytes:
    raw: socket.socket | None = None
    stream: socket.socket | ssl.SSLSocket | None = None

    def set_remaining_timeout(value: socket.socket | ssl.SSLSocket) -> None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("direct HTTP/1.1 deadline elapsed")
        value.settimeout(remaining)

    try:
        family, sockaddr = _resolve_direct_address(
            hostname, port, target, scheme=scheme, deadline=deadline
        )
        try:
            if time.monotonic() >= deadline:
                raise _PersonalPreDispatchError("direct HTTP/1.1 deadline elapsed")
            raw = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            set_remaining_timeout(raw)
            raw.connect(sockaddr)
            stream = raw
            if scheme == "https":
                context = ssl.create_default_context()
                context.set_alpn_protocols(["http/1.1"])
                set_remaining_timeout(raw)
                stream = context.wrap_socket(raw, server_hostname=hostname)
                selected_protocol = stream.selected_alpn_protocol()
                if selected_protocol not in {None, "http/1.1"}:
                    raise _PersonalPreDispatchError("TLS selected an unsupported protocol")
        except _PersonalPreDispatchError:
            raise
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise _PersonalPreDispatchError("connection or TLS setup failed") from exc

        # From this point forward the server may have received some or all bytes.
        assert stream is not None
        set_remaining_timeout(stream)
        if time.monotonic() >= deadline:
            raise _PersonalPreDispatchError("direct HTTP/1.1 deadline elapsed")
        stream.sendall(request_content)
        if time.monotonic() >= deadline:
            raise TimeoutError("direct HTTP/1.1 deadline elapsed")
        response = bytearray()
        while True:
            set_remaining_timeout(stream)
            chunk = stream.recv(min(65_536, response_limit - len(response) + 1))
            if not chunk:
                break
            response.extend(chunk)
            if len(response) > response_limit:
                raise CliError("direct response exceeds the fixed response limit", exit_code=EXIT_UNAVAILABLE)
            if time.monotonic() >= deadline:
                raise TimeoutError("direct HTTP/1.1 deadline elapsed")
        return bytes(response)
    finally:
        if stream is not None:
            stream.close()
        elif raw is not None:
            raw.close()


def _parse_personal_http11_response(content: bytes, *, method: str) -> tuple[int, list[str], bytes]:
    if b"\r\n\r\n" not in content:
        raise CliError("direct response is incomplete or malformed", exit_code=EXIT_UNAVAILABLE)
    header_block, body = content.split(b"\r\n\r\n", 1)
    lines = header_block.split(b"\r\n")
    try:
        status_parts = lines[0].decode("ascii").split(" ", 2)
    except UnicodeDecodeError as exc:
        raise CliError("direct response is incomplete or malformed", exit_code=EXIT_UNAVAILABLE) from exc
    if (
        len(status_parts) < 2
        or status_parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
        or not 200 <= int(status_parts[1]) <= 599
    ):
        raise CliError("direct response is incomplete or malformed", exit_code=EXIT_UNAVAILABLE)
    header_names: list[str] = []
    content_lengths: list[bytes] = []
    transfer_encodings: list[bytes] = []
    for line in lines[1:]:
        if not line or b":" not in line:
            raise CliError("direct response is incomplete or malformed", exit_code=EXIT_UNAVAILABLE)
        name, value = line.split(b":", 1)
        if not name or any(
            character not in b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            for character in name
        ):
            raise CliError("direct response is incomplete or malformed", exit_code=EXIT_UNAVAILABLE)
        if any(character < 32 and character not in {9} or character == 127 for character in value):
            raise CliError("direct response is incomplete or malformed", exit_code=EXIT_UNAVAILABLE)
        if len(header_names) < 64:
            header_names.append(name.decode("ascii"))
        if name.lower() == b"content-length":
            content_lengths.append(value.strip(b" \t"))
        elif name.lower() == b"transfer-encoding":
            transfer_encodings.append(value.strip(b" \t"))
    status_code = int(status_parts[1])
    if (
        100 <= status_code < 200
        or transfer_encodings
        or len(content_lengths) > 1
    ):
        raise CliError("direct response is incomplete or malformed", exit_code=EXIT_UNAVAILABLE)
    no_body = method == "HEAD" or status_code in {204, 205, 304}
    if (
        (
            content_lengths
            and (
                not content_lengths[0].isdigit()
                or (not no_body and int(content_lengths[0]) != len(body))
            )
        )
        or (no_body and body)
    ):
        raise CliError("direct response is incomplete or malformed", exit_code=EXIT_UNAVAILABLE)
    return status_code, header_names, body


def _open_windows_response_directory_guard(responses: Path) -> int:
    import ctypes
    from ctypes import wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("file_attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
    )
    get_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        str(responses), 0x80, 0x1 | 0x2, None, 3, 0x02000000 | 0x00200000, None,
    )
    if handle is None or handle == ctypes.c_void_p(-1).value:
        raise CliError("direct response directory is unsafe", exit_code=EXIT_AUTHORITY)
    handle_value = int(handle)
    info = FileAttributeTagInfo()
    if not get_information(handle_value, 9, ctypes.byref(info), ctypes.sizeof(info)):
        close_handle(handle_value)
        raise CliError("direct response directory is unsafe", exit_code=EXIT_AUTHORITY)
    if info.file_attributes & 0x400:
        close_handle(handle_value)
        raise CliError("direct response directory is unsafe", exit_code=EXIT_AUTHORITY)
    return handle_value


def _close_windows_response_directory_guard(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle(wintypes.HANDLE(handle))


def _is_safe_handoff_filename(name: str) -> bool:
    if (
        not 1 <= len(name) <= 128
        or not name[0].isascii()
        or not name[0].isalnum()
        or name.endswith(".")
        or any(not character.isascii() or not (character.isalnum() or character in {".", "_", "-"}) for character in name)
    ):
        return False
    stem = name.split(".", 1)[0].upper()
    return stem not in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }


def _windows_open_handoff_child(directory_handle: int, name: str, *, create: bool) -> int:
    """Open one direct child through an already guarded Windows directory handle."""
    import ctypes
    from ctypes import wintypes

    if not _is_safe_handoff_filename(name):
        raise CliError("verification handoff output path is unsafe", exit_code=EXIT_AUTHORITY)

    class UnicodeString(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT), ("Buffer", wintypes.LPWSTR)]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UnicodeString)), ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", ctypes.c_void_p), ("SecurityQualityOfService", ctypes.c_void_p),
        ]

    class IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_long), ("Information", ctypes.c_size_t)]

    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    nt_create_file = ntdll.NtCreateFile
    nt_create_file.argtypes = (
        ctypes.POINTER(wintypes.HANDLE), wintypes.ULONG, ctypes.POINTER(ObjectAttributes),
        ctypes.POINTER(IoStatusBlock), ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG,
        wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG,
    )
    nt_create_file.restype = ctypes.c_long
    buffer = ctypes.create_unicode_buffer(name)
    length = len(name.encode("utf-16-le"))
    unicode_name = UnicodeString(length, length + 2, ctypes.cast(buffer, wintypes.LPWSTR))
    attributes = ObjectAttributes(
        ctypes.sizeof(ObjectAttributes), directory_handle, ctypes.pointer(unicode_name), 0x40, None, None
    )
    io_status = IoStatusBlock()
    handle = wintypes.HANDLE()
    status = nt_create_file(
        ctypes.byref(handle), 0x0012019F, ctypes.byref(attributes), ctypes.byref(io_status), None,
        0x80, 0x3, 2 if create else 1, 0x20 | 0x40 | 0x00200000, None, 0,
    )
    if status != 0:
        if ctypes.c_ulong(status).value == 0xC0000035:
            raise FileExistsError(name)
        raise CliError("cannot open verification handoff output", exit_code=EXIT_AUTHORITY)
    if handle.value is None:
        raise CliError("cannot open verification handoff output", exit_code=EXIT_AUTHORITY)
    return int(handle.value)


def _write_personal_response_file(workspace: Path, reservation_id: str, content: bytes) -> Path:
    responses = workspace / "responses"
    filename = f"{reservation_id}.personal-http1.raw"
    try:
        if responses.exists():
            metadata = responses.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or responses.is_junction()
            ):
                raise CliError("direct response directory is unsafe", exit_code=EXIT_AUTHORITY)
        else:
            responses.mkdir(mode=0o700)
            metadata = responses.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or responses.is_junction()
            ):
                raise CliError("direct response directory is unsafe", exit_code=EXIT_AUTHORITY)
    except CliError:
        raise
    except OSError as exc:
        raise CliError("cannot create direct response file", exit_code=EXIT_USAGE) from exc
    path = responses / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_descriptor: int | None = None
    windows_directory_guard: int | None = None
    try:
        if os.name != "nt":
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                directory_flags |= os.O_CLOEXEC
            directory_descriptor = os.open(responses, directory_flags)
            directory_stat = os.fstat(directory_descriptor)
            if not stat.S_ISDIR(directory_stat.st_mode):
                raise CliError("direct response directory is unsafe", exit_code=EXIT_AUTHORITY)
            descriptor = os.open(filename, flags, 0o600, dir_fd=directory_descriptor)
        else:
            windows_directory_guard = _open_windows_response_directory_guard(responses)
            descriptor = os.open(path, flags, 0o600)
    except CliError:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if windows_directory_guard is not None:
            _close_windows_response_directory_guard(windows_directory_guard)
        raise
    except OSError as exc:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if windows_directory_guard is not None:
            _close_windows_response_directory_guard(windows_directory_guard)
        raise CliError("cannot create direct response file", exit_code=EXIT_USAGE) from exc
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
    except OSError as exc:
        try:
            if directory_descriptor is None:
                path.unlink()
            else:
                os.unlink(filename, dir_fd=directory_descriptor)
        except OSError:
            pass
        if windows_directory_guard is not None:
            _close_windows_response_directory_guard(windows_directory_guard)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise CliError("cannot write direct response file", exit_code=EXIT_USAGE) from exc
    finally:
        os.close(descriptor)

    def remove_unverified_file() -> None:
        try:
            if directory_descriptor is None:
                path.unlink()
            else:
                os.unlink(filename, dir_fd=directory_descriptor)
        except OSError:
            pass

    try:
        observed = (
            os.stat(filename, dir_fd=directory_descriptor, follow_symlinks=False)
            if directory_descriptor is not None
            else path.lstat()
        )
        if (
            stat.S_ISLNK(observed.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != 1
            or observed.st_size != len(content)
            or not _stat_matches(opened, observed, _WINDOWS_FILE_STAT_FIELDS if os.name == "nt" else _FILE_STAT_FIELDS)
        ):
            raise CliError("direct response file changed while being created", exit_code=EXIT_AUTHORITY)
    except CliError:
        remove_unverified_file()
        raise
    except OSError as exc:
        remove_unverified_file()
        raise CliError("cannot finalize direct response file", exit_code=EXIT_USAGE) from exc
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if windows_directory_guard is not None:
            _close_windows_response_directory_guard(windows_directory_guard)
    return path


def _emit_personal_send_ambiguity(
    reservation_id: str, code: str, response_path: Path | None = None
) -> int:
    result: dict[str, object] = {
        "schema": "faultloom.personal-http1-send.v1",
        "reservation": reservation_id,
        "dispatchPerformed": True,
        "networkAccess": "direct_owner_local",
        "reservationState": "unresolved_no_retry",
        "error": code,
    }
    if response_path is not None:
        result["responseFile"] = str(response_path)
    _emit_json(result)
    return EXIT_UNAVAILABLE


def _emit_personal_send_no_dispatch(reservation_id: str) -> int:
    _emit_json(
        {
            "schema": "faultloom.personal-http1-send.v1",
            "reservation": reservation_id,
            "dispatchPerformed": False,
            "networkAccess": "direct_owner_local",
            "reservationState": "unresolved_no_retry",
            "error": "no_dispatch_connection_or_tls_failure",
        }
    )
    return EXIT_UNAVAILABLE


def _scope_send_request_result(arguments: argparse.Namespace) -> tuple[int, dict[str, object]]:
    method = arguments.method.upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        raise CliError("direct personal sender permits GET, HEAD, or OPTIONS only", exit_code=EXIT_AUTHORITY)
    admitted = _admit_raw_request(
        arguments,
        request_cap=PERSONAL_HTTP1_MAX_REQUEST_BYTES,
        response_cap=PERSONAL_HTTP1_MAX_RESPONSE_BYTES,
        require_connection_close=True,
        expected_request_sha256=getattr(arguments, "expected_request_sha256", None),
    )
    response_path = (
        arguments.workspace
        / "responses"
        / f"{admitted.reservation['reservation_id']}.personal-http1.raw"
    )
    request_attempted = False
    response_stored = False
    try:
        expires_at = datetime.fromisoformat(
            str(admitted.reservation["reservation_expires_at"])
        )
        timeout_seconds = min(
            float(arguments.timeout_seconds),
            (expires_at - _utc_now()).total_seconds() - 1,
        )
        if timeout_seconds <= 0:
            raise _PersonalPreDispatchError("reservation has expired")
        deadline = time.monotonic() + timeout_seconds
        _recheck_reserved_request_before_send(
            workspace=arguments.workspace,
            manifest=admitted.manifest,
            reservation_id=str(admitted.reservation["reservation_id"]),
            request_file=arguments.request_file,
        )
        request_attempted = True
        response_content = _send_direct_http11_once(
            hostname=arguments.hostname,
            port=arguments.port,
            scheme=arguments.scheme,
            target=admitted.target,
            request_content=admitted.content,
            response_limit=admitted.response_limit,
            deadline=deadline,
        )
        status_code, header_names, body = _parse_personal_http11_response(
            response_content, method=admitted.method
        )
        response_path = _write_personal_response_file(
            arguments.workspace,
            str(admitted.reservation["reservation_id"]),
            response_content,
        )
        response_stored = True
        completion = _complete_request(
            workspace=arguments.workspace,
            manifest=admitted.manifest,
            reservation_id=str(admitted.reservation["reservation_id"]),
            request_file=arguments.request_file,
            observed_response_bytes=len(response_content),
            response_file=None,
            response_content=response_content,
        )
        result: dict[str, object] = {
            "schema": "faultloom.personal-http1-send.v1",
            "reservation": admitted.reservation["reservation_id"],
            "request": {"size": len(admitted.content), "sha256": admitted.request_sha256},
            "response": {"size": len(response_content), "sha256": completion["response_sha256"]},
            "responseFile": str(response_path),
            "bodySha256": hashlib.sha256(body).hexdigest(),
            "statusCode": status_code,
            "headerNames": header_names,
            "dispatchPerformed": True,
            "networkAccess": "direct_owner_local",
        }
        if arguments.body_preview_chars:
            preview = body.decode("utf-8", errors="replace")
            result["bodyPreview"] = preview[: arguments.body_preview_chars]
            result["previewTruncated"] = len(preview) > arguments.body_preview_chars
        return EXIT_OK, result
    except _PersonalPreDispatchError:
        return EXIT_UNAVAILABLE, {
            "schema": "faultloom.personal-http1-send.v1",
            "reservation": admitted.reservation["reservation_id"],
            "dispatchPerformed": False,
            "networkAccess": "direct_owner_local",
            "reservationState": "unresolved_no_retry",
            "error": "no_dispatch_connection_or_tls_failure",
        }
    except (CliError, OSError):
        if not request_attempted:
            return EXIT_UNAVAILABLE, {
                "schema": "faultloom.personal-http1-send.v1",
                "reservation": admitted.reservation["reservation_id"],
                "dispatchPerformed": False,
                "networkAccess": "direct_owner_local",
                "reservationState": "unresolved_no_retry",
                "error": "no_dispatch_connection_or_tls_failure",
            }
        result = {
            "schema": "faultloom.personal-http1-send.v1",
            "reservation": admitted.reservation["reservation_id"],
            "dispatchPerformed": True,
            "networkAccess": "direct_owner_local",
            "reservationState": "unresolved_no_retry",
            "error": "response_incomplete_or_ambiguous",
        }
        if response_stored:
            result["responseFile"] = str(response_path)
        return EXIT_UNAVAILABLE, result


def _scope_send_request(arguments: argparse.Namespace) -> int:
    exit_code, result = _scope_send_request_result(arguments)
    _emit_json(result)
    return exit_code


def _campaign_records_directory(workspace: Path) -> _CampaignRecordsDirectory:
    """Return stable workspace/campaign directory identities for record creation."""
    try:
        workspace_metadata = workspace.lstat()
        if (
            stat.S_ISLNK(workspace_metadata.st_mode)
            or not stat.S_ISDIR(workspace_metadata.st_mode)
            or workspace.is_junction()
        ):
            raise CliError("manual workspace is not a directory", exit_code=EXIT_AUTHORITY)
        directory = workspace / "campaigns"
        if os.name != "nt":
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            workspace_descriptor = os.open(workspace, flags)
            try:
                pinned_workspace = os.fstat(workspace_descriptor)
                if not _stat_matches(workspace_metadata, pinned_workspace, _DIRECTORY_STAT_FIELDS):
                    raise CliError("manual workspace changed while being opened", exit_code=EXIT_AUTHORITY)
                created = False
                try:
                    os.mkdir("campaigns", 0o700, dir_fd=workspace_descriptor)
                    created = True
                except FileExistsError:
                    pass
                metadata = os.stat("campaigns", dir_fd=workspace_descriptor, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                    raise CliError("campaign records directory is unsafe", exit_code=EXIT_AUTHORITY)
                campaign_descriptor = os.open("campaigns", flags, dir_fd=workspace_descriptor)
                try:
                    pinned_campaign = os.fstat(campaign_descriptor)
                    if not _stat_matches(metadata, pinned_campaign, _DIRECTORY_STAT_FIELDS):
                        raise CliError("campaign records directory changed while being opened", exit_code=EXIT_AUTHORITY)
                finally:
                    os.close(campaign_descriptor)
                if created:
                    os.fsync(workspace_descriptor)
            finally:
                os.close(workspace_descriptor)
        else:
            workspace_guard = _open_windows_response_directory_guard(workspace)
            try:
                pinned_workspace = workspace.lstat()
                if not _stat_matches(workspace_metadata, pinned_workspace, _DIRECTORY_STAT_FIELDS):
                    raise CliError("manual workspace changed while being opened", exit_code=EXIT_AUTHORITY)
                try:
                    os.mkdir(directory, 0o700)
                except FileExistsError:
                    pass
                metadata = directory.lstat()
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISDIR(metadata.st_mode)
                    or directory.is_junction()
                ):
                    raise CliError("campaign records directory is unsafe", exit_code=EXIT_AUTHORITY)
                campaign_guard = _open_windows_response_directory_guard(directory)
                try:
                    pinned_campaign = directory.lstat()
                    if not _stat_matches(metadata, pinned_campaign, _DIRECTORY_STAT_FIELDS):
                        raise CliError("campaign records directory changed while being opened", exit_code=EXIT_AUTHORITY)
                finally:
                    _close_windows_response_directory_guard(campaign_guard)
            finally:
                _close_windows_response_directory_guard(workspace_guard)
    except OSError as exc:
        raise CliError(f"cannot prepare campaign records: {exc}", exit_code=EXIT_USAGE) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or directory.is_junction():
        raise CliError("campaign records directory is unsafe", exit_code=EXIT_AUTHORITY)
    return _CampaignRecordsDirectory(
        workspace=workspace,
        campaigns=directory,
        workspace_stat=pinned_workspace,
        campaigns_stat=pinned_campaign,
    )


def _campaign_record(records: _CampaignRecordsDirectory, campaign_id: str, suffix: str) -> Path:
    return records.campaigns / f"{campaign_id}.{suffix}.json"


def _write_new_campaign_record(
    records: _CampaignRecordsDirectory, path: Path, content: bytes, *, mode: int = 0o600
) -> None:
    """Create one durable campaign record beneath a checked, pinned directory."""
    directory = records.campaigns
    filename = path.name
    if (
        path.parent != directory
        or not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
    ):
        raise CliError("campaign record name is unsafe", exit_code=EXIT_AUTHORITY)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    workspace_descriptor: int | None = None
    directory_descriptor: int | None = None
    windows_workspace_guard: int | None = None
    windows_directory_guard: int | None = None
    descriptor: int | None = None
    try:
        if os.name != "nt":
            directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                directory_flags |= os.O_CLOEXEC
            workspace_descriptor = os.open(records.workspace, directory_flags)
            if not _stat_matches(
                os.fstat(workspace_descriptor), records.workspace_stat, _DIRECTORY_STAT_FIELDS
            ):
                raise CliError("manual workspace changed before campaign record creation", exit_code=EXIT_AUTHORITY)
            directory_descriptor = os.open("campaigns", directory_flags, dir_fd=workspace_descriptor)
            if not _stat_matches(
                os.fstat(directory_descriptor), records.campaigns_stat, _DIRECTORY_STAT_FIELDS
            ):
                raise CliError("campaign records directory is unsafe", exit_code=EXIT_AUTHORITY)
            descriptor = os.open(filename, flags, mode, dir_fd=directory_descriptor)
        else:
            windows_workspace_guard = _open_windows_response_directory_guard(records.workspace)
            workspace_metadata = records.workspace.lstat()
            if not _stat_matches(workspace_metadata, records.workspace_stat, _DIRECTORY_STAT_FIELDS):
                raise CliError("manual workspace changed before campaign record creation", exit_code=EXIT_AUTHORITY)
            windows_directory_guard = _open_windows_response_directory_guard(directory)
            directory_metadata = directory.lstat()
            if (
                directory.is_junction()
                or not _stat_matches(directory_metadata, records.campaigns_stat, _DIRECTORY_STAT_FIELDS)
            ):
                raise CliError("campaign records directory is unsafe", exit_code=EXIT_AUTHORITY)
            descriptor = os.open(path, flags, mode)
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        if os.name != "nt":
            os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        if directory_descriptor is not None:
            os.fsync(directory_descriptor)
    except CliError:
        raise
    except OSError as exc:
        raise CliError(f"cannot create campaign record {path}: {exc}", exit_code=EXIT_USAGE) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        if workspace_descriptor is not None:
            os.close(workspace_descriptor)
        if windows_directory_guard is not None:
            _close_windows_response_directory_guard(windows_directory_guard)
        if windows_workspace_guard is not None:
            _close_windows_response_directory_guard(windows_workspace_guard)


def _capture_campaign_json(path: Path, *, label: str) -> dict[str, object]:
    content = _capture_bounded_local_file(path, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label=label)
    return _parse_campaign_json_content(content, label=label)


def _parse_campaign_json_content(content: bytes, *, label: str) -> dict[str, object]:
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CliError(f"invalid {label}: {exc}", exit_code=EXIT_AUTHORITY) from exc
    if not isinstance(value, dict):
        raise CliError(f"invalid {label}", exit_code=EXIT_AUTHORITY)
    return value


def _capture_bound_campaign_source(
    path_value: str, *, digest: str, maximum_bytes: int, label: str
) -> tuple[Path, bytes]:
    """Capture one absolute, non-symlink v2 provenance source exactly once."""
    path = Path(path_value)
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CliError(f"cannot resolve bound {label}", exit_code=EXIT_AUTHORITY) from exc
    if not path.is_absolute() or str(resolved) != path_value:
        raise CliError(f"bound {label} path is not canonical", exit_code=EXIT_AUTHORITY)
    content = _capture_bounded_local_file(path, maximum_bytes=maximum_bytes, label=label)
    if sha256_hex(content) != digest:
        raise CliError(f"bound {label} digest differs", exit_code=EXIT_AUTHORITY)
    return resolved, content


def _parse_bound_automation_result(content: bytes) -> tuple[dict[str, object], AuthorizedAutomationResult]:
    try:
        text = content.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(value, dict):
            raise ValueError("result must be a JSON object")
        # Validate duplicate keys before JSON-mode conversion: strict pydantic
        # models intentionally accept JSON arrays for their tuple fields.
        return value, AuthorizedAutomationResult.model_validate_json(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise CliError(f"invalid automation result: {exc}", exit_code=EXIT_AUTHORITY) from exc


def _selected_automation_candidate(
    result: AuthorizedAutomationResult, candidate_id: str
) -> tuple[str, ToolCandidate | PoCStep]:
    admitted_matches = [
        plan.selected
        for plan in result.admitted_plans
        if plan.selected.candidate.candidate_id == candidate_id
    ]
    poc_steps = () if result.poc is None else result.poc.recipe.steps
    poc_matches = [step for step in poc_steps if step.step_id == candidate_id]
    if len(admitted_matches) + len(poc_matches) != 1:
        raise CliError("automation candidate is absent or ambiguous", exit_code=EXIT_AUTHORITY)
    if admitted_matches:
        selected = admitted_matches[0]
        if selected.receipt.authority_digest != result.authority_grant_digest:
            raise CliError(
                "automation candidate admission is bound to another authority",
                exit_code=EXIT_AUTHORITY,
            )
        return "admitted_plan", selected.candidate
    if (
        result.poc is None
        or result.poc_context_digest is None
        or len(result.poc.recipe.steps) != 1
        or result.poc.adaptation.removed_unsafe_step_digests
    ):
        raise CliError(
            "compiled safe PoC candidate is incomplete or not a single safe step",
            exit_code=EXIT_AUTHORITY,
        )
    return "compiled_safe_poc_step", poc_matches[0]


def _validate_automation_candidate_for_triad(
    *,
    result: AuthorizedAutomationResult,
    candidate_id: str,
    spec: PersonalHttp1TriadSpec,
    effect_request_sha256: str,
    manifest: dict[str, object],
    grant: AuthorityGrant,
    target: TargetAsset,
    expected_source: str | None = None,
) -> tuple[str, str]:
    """Accept only one offline compiled intent that exactly describes the effect request."""
    if (
        result.provider_network_access != "none"
        or result.target_dispatch_performed is not False
        or result.automatic_submission_performed is not False
        or result.run_id != manifest.get("run_id")
        or result.authority_grant_id != grant.grant_id
        or result.authority_grant_version != grant.grant_version
        or result.authority_grant_digest != sha256_digest(grant)
    ):
        raise CliError("automation result is not bound to the verified workspace", exit_code=EXIT_AUTHORITY)
    policy = grant.action_policy
    request_outside_authority = any(
        (target.methods and request.method not in target.methods)
        or (
            target.paths
            and not any(_path_matches(pattern, request.path) for pattern in target.paths)
        )
        or (policy.allowed_methods and request.method not in policy.allowed_methods)
        or (
            policy.allowed_path_patterns
            and not any(
                _path_matches(pattern, request.path)
                for pattern in policy.allowed_path_patterns
            )
        )
        or any(
            _request_matches_explicit_deny(
                deny,
                target_id=target.target_id,
                hostname=spec.hostname,
                method=request.method,
                path=request.path,
            )
            for deny in policy.denied
        )
        for request in spec.requests
    )
    if (
        not _request_hostname_matches_target(spec.hostname, target)
        or (target.ports and spec.port not in target.ports)
        or (target.protocols and spec.scheme not in target.protocols)
        or OFFLINE_REQUEST_ACTION_FAMILY not in policy.allowed_families
        or OFFLINE_REQUEST_ACTION_CLASS not in policy.allowed_classes
        or request_outside_authority
    ):
        raise CliError(
            "automation candidate is outside current signed authority",
            exit_code=EXIT_AUTHORITY,
        )
    candidate_source, candidate = _selected_automation_candidate(result, candidate_id)
    if expected_source is not None and candidate_source != expected_source:
        raise CliError("automation candidate source differs", exit_code=EXIT_AUTHORITY)
    intent = candidate.intent if isinstance(candidate, ToolCandidate) else candidate.action_intent
    if (
        intent.action_class is not ActionClass.SAFE_PROBE
        or intent.action_kind != OFFLINE_REQUEST_ACTION_FAMILY
        or intent.run_id != result.run_id
        or intent.target_id != target.target_id
        or intent.pack_id != manifest.get("pack_id")
        or intent.resource.target_id != target.target_id
        or (
            intent.subject.identity_id is not None
            and intent.subject.identity_id not in grant.identities
        )
        or any(
            tenant_id is not None and tenant_id not in grant.tenants
            for tenant_id in (intent.subject.tenant_id, intent.resource.tenant_id)
        )
        or intent.protocol != spec.scheme
        or intent.method != spec.effect.method
        or intent.path != spec.effect.path
        or intent.payload_digest != f"sha256:{effect_request_sha256}"
    ):
        raise CliError("automation candidate intent does not match the triad template", exit_code=EXIT_AUTHORITY)
    if candidate_source == "compiled_safe_poc_step":
        poc = result.poc
        if (
            poc is None
            or poc.adaptation.target_id != target.target_id
            or poc.adaptation.route_ref.target_id != target.target_id
            or intent.resource != poc.adaptation.route_ref
            or (
                poc.adaptation.identity_context_id is not None
                and poc.adaptation.identity_context_id not in grant.identities
            )
            or poc.adaptation.transport != spec.scheme
            or poc.recipe.adaptation_id != poc.adaptation.adaptation_id
            or poc.recipe.cleanup_plan_ref != intent.cleanup_plan_ref
        ):
            raise CliError(
                "compiled safe PoC metadata does not match the triad template",
                exit_code=EXIT_AUTHORITY,
            )
    return candidate_source, sha256_digest(candidate.model_dump(mode="json"))


def _validate_automation_result_receipt(
    receipt: dict[str, object],
    *,
    result: AuthorizedAutomationResult,
    result_digest: str,
) -> None:
    expected = {
        "schema",
        "automatic_submission",
        "candidate_digest",
        "candidate_only",
        "entry_id",
        "evidence_existence_independently_verified",
        "independent_verification",
        "network_access",
        "result_digest",
        "target_dispatch",
    }
    candidate_digest = receipt.get("candidate_digest")
    expected_entry_id = f"result.{result_digest.removeprefix('sha256:')[:32]}"
    try:
        expected_candidate_digest = automation_result_candidate_digest(result)
    except CandidateOutboxError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    if (
        set(receipt) != expected
        or receipt.get("schema") != "faultloom.automation.result.receipt.v1"
        or receipt.get("result_digest") != result_digest
        or receipt.get("candidate_only") is not True
        or receipt.get("automatic_submission") is not False
        or receipt.get("evidence_existence_independently_verified") is not False
        or receipt.get("independent_verification") is not False
        or receipt.get("network_access") != "none"
        or receipt.get("target_dispatch") is not False
        or receipt.get("entry_id") != expected_entry_id
        or candidate_digest != expected_candidate_digest
        or (
            candidate_digest is not None
            and (
                not isinstance(candidate_digest, str)
                or re.fullmatch(r"^sha256:[0-9a-f]{64}$", candidate_digest) is None
            )
        )
    ):
        raise CliError("automation result receipt is invalid", exit_code=EXIT_AUTHORITY)


def _triad_template_projection(spec: PersonalHttp1TriadSpec) -> dict[str, object]:
    value = spec.model_dump(by_alias=True, exclude={"automation_binding"}, exclude_none=True)
    value["schema"] = PERSONAL_HTTP1_TRIAD_SCHEMA
    return value


def _automation_binding_provenance(spec: PersonalHttp1TriadSpec) -> dict[str, object] | None:
    binding = spec.automation_binding
    if binding is None:
        return None
    # Preserve the digest/serialization of pre-discriminator v1 bindings while
    # including candidate_source on every newly prepared binding.
    value = binding.model_dump(by_alias=True, exclude_unset=True)
    return {"sha256": sha256_digest(value), "binding": value}


def _validate_bound_triad_spec(
    *,
    spec: PersonalHttp1TriadSpec,
    spec_path: Path,
    manifest: dict[str, object],
    grant: AuthorityGrant,
    target: TargetAsset,
) -> dict[str, object] | None:
    """Re-read every v2 source before creating a start record or opening a socket."""
    binding = spec.automation_binding
    if binding is None:
        return None
    template_path, template_content = _capture_bound_campaign_source(
        binding.template_path,
        digest=binding.template_sha256,
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
        label="campaign template",
    )
    if template_path == spec_path:
        raise CliError("bound campaign template cannot be the output spec", exit_code=EXIT_AUTHORITY)
    try:
        template = parse_personal_http1_triad_spec(template_content)
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    if template.schema_ != PERSONAL_HTTP1_TRIAD_SCHEMA or _triad_template_projection(spec) != _triad_template_projection(template):
        raise CliError("bound campaign spec differs from its v1 template", exit_code=EXIT_AUTHORITY)
    result_path, result_content = _capture_bound_campaign_source(
        binding.result_path,
        digest=binding.result_file_sha256,
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
        label="automation result",
    )
    _ = result_path
    _, result = _parse_bound_automation_result(result_content)
    result_digest = sha256_digest(result.model_dump(mode="json"))
    if result_digest != binding.result_digest:
        raise CliError("bound automation result digest differs", exit_code=EXIT_AUTHORITY)
    _, receipt_content = _capture_bound_campaign_source(
        binding.receipt_path,
        digest=binding.receipt_file_sha256,
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
        label="automation receipt",
    )
    try:
        receipt = json.loads(receipt_content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CliError("invalid automation result receipt", exit_code=EXIT_AUTHORITY) from exc
    if not isinstance(receipt, dict):
        raise CliError("invalid automation result receipt", exit_code=EXIT_AUTHORITY)
    _validate_automation_result_receipt(
        receipt,
        result=result,
        result_digest=result_digest,
    )
    effect_path, effect_content = _capture_bound_campaign_source(
        binding.effect_request_path,
        digest=binding.effect_request_sha256,
        maximum_bytes=PERSONAL_HTTP1_MAX_REQUEST_BYTES,
        label="effect request",
    )
    control_path, control_content = _capture_bound_campaign_source(
        binding.negative_control_request_path,
        digest=binding.negative_control_request_sha256,
        maximum_bytes=PERSONAL_HTTP1_MAX_REQUEST_BYTES,
        label="negative-control request",
    )
    if (
        effect_path != _campaign_request_file(spec_path, spec.effect.request_file).resolve(strict=True)
        or control_path != _campaign_request_file(spec_path, spec.negative_control.request_file).resolve(strict=True)
    ):
        raise CliError("bound request source path differs from the triad spec", exit_code=EXIT_AUTHORITY)
    # The strict raw parser is deliberately called again by _prepare_campaign_requests.
    _ = effect_content, control_content
    candidate_source, candidate_digest = _validate_automation_candidate_for_triad(
        result=result,
        candidate_id=binding.candidate_id,
        spec=spec,
        effect_request_sha256=binding.effect_request_sha256,
        manifest=manifest,
        grant=grant,
        target=target,
        expected_source=binding.candidate_source,
    )
    if (
        binding.candidate_source != candidate_source
        or binding.candidate_digest != candidate_digest
        or binding.run_id != result.run_id
        or binding.grant_id != grant.grant_id
        or binding.grant_version != grant.grant_version
        or binding.grant_digest != sha256_digest(grant)
    ):
        raise CliError("automation binding provenance differs", exit_code=EXIT_AUTHORITY)
    return _automation_binding_provenance(spec)


def _record_campaign_binding(
    *,
    workspace: Path,
    manifest: dict[str, object],
    campaign_id: str,
    role: str,
    result: dict[str, object],
) -> None:
    reservation = result.get("reservation")
    request = result.get("request")
    response = result.get("response")
    body_sha256 = result.get("bodySha256")
    response_file = result.get("responseFile")
    if (
        not _is_reservation_id(reservation)
        or not isinstance(request, dict)
        or not isinstance(request.get("sha256"), str)
        or not isinstance(response, dict)
        or not isinstance(response.get("sha256"), str)
        or not isinstance(body_sha256, str)
        or not isinstance(response_file, str)
    ):
        raise CliError("successful campaign send is missing exact bindings", exit_code=EXIT_AUTHORITY)
    connection = _request_accounting_connection(workspace)
    try:
        _prepare_request_accounting(connection, manifest, campaign_bindings=True)
        row = connection.execute(
            "SELECT request_sha256, response_sha256, completed_at FROM reservations WHERE reservation_id = ?",
            (reservation,),
        ).fetchone()
        if (
            row is None
            or row[2] is None
            or row[0] != request["sha256"]
            or row[1] != response["sha256"]
        ):
            raise CliError("request accounting does not match completed campaign send", exit_code=EXIT_AUTHORITY)
        connection.execute(
            """INSERT INTO campaign_bindings(
                campaign_id, role, reservation_id, request_sha256, response_sha256,
                body_sha256, response_file
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                campaign_id,
                role,
                reservation,
                request["sha256"],
                response["sha256"],
                body_sha256,
                response_file,
            ),
        )
        connection.commit()
    except CliError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise CliError("cannot bind completed campaign request", exit_code=EXIT_AUTHORITY) from exc
    finally:
        connection.close()


def _campaign_bindings(
    *, workspace: Path, manifest: dict[str, object], campaign_id: str
) -> dict[str, dict[str, str]]:
    connection = _request_accounting_connection(workspace)
    try:
        _prepare_request_accounting(connection, manifest)
        rows = connection.execute(
            """SELECT b.role, b.reservation_id, b.request_sha256, b.response_sha256,
                      b.body_sha256, b.response_file, r.request_sha256, r.response_sha256,
                      r.completed_at
               FROM campaign_bindings AS b
               LEFT JOIN reservations AS r ON r.reservation_id = b.reservation_id
               WHERE b.campaign_id = ?""",
            (campaign_id,),
        ).fetchall()
    except CliError:
        connection.rollback()
        raise
    except sqlite3.Error as exc:
        connection.rollback()
        raise CliError("cannot read campaign request bindings", exit_code=EXIT_AUTHORITY) from exc
    finally:
        connection.close()
    expected_roles = {"effect", "reproduction", "negative_control"}
    if len(rows) != 3 or {row[0] for row in rows} != expected_roles:
        raise CliError("campaign accounting lacks exactly three bound requests", exit_code=EXIT_AUTHORITY)
    if len({row[1] for row in rows}) != 3 or len({row[5] for row in rows}) != 3:
        raise CliError("campaign accounting reuses a reservation or response file", exit_code=EXIT_AUTHORITY)
    bindings: dict[str, dict[str, str]] = {}
    for row in rows:
        role, reservation, request_digest, response_digest, body_digest, response_file, account_request, account_response, completed = row
        if (
            completed is None
            or request_digest != account_request
            or response_digest != account_response
            or not all(isinstance(value, str) for value in row[:6])
        ):
            raise CliError("campaign accounting binding is invalid", exit_code=EXIT_AUTHORITY)
        bindings[role] = {
            "reservation": reservation,
            "request_sha256": request_digest,
            "response_sha256": response_digest,
            "body_sha256": body_digest,
            "response_file": response_file,
        }
    return bindings


def _campaign_request_file(spec_path: Path, name: str) -> Path:
    # ``name`` has already passed the strict basename-only model validation.
    return spec_path.parent / name


def _prepare_campaign_requests(
    spec: PersonalHttp1TriadSpec,
    spec_path: Path,
    *,
    expected_sha256: dict[str, str] | None = None,
) -> dict[str, tuple[Path, bytes, str]]:
    prepared: dict[str, tuple[Path, bytes, str]] = {}
    for request in spec.requests:
        request_file = _campaign_request_file(spec_path, request.request_file)
        content, digest = _capture_verified_raw_request(
            request_file,
            maximum_bytes=PERSONAL_HTTP1_MAX_REQUEST_BYTES,
            hostname=spec.hostname,
            port=spec.port,
            scheme=spec.scheme,
            method=request.method,
            request_path=request.path,
            require_connection_close=True,
        )
        if expected_sha256 is not None and digest != expected_sha256[request.role]:
            raise CliError(
                "request file digest differs from the automation binding",
                exit_code=EXIT_AUTHORITY,
            )
        prepared[request.role] = (request_file, content, digest)
    effect_content = prepared["effect"][1]
    control_content = prepared["negative_control"][1]
    effect_line, effect_remainder = effect_content.split(b"\r\n", 1)
    control_line, control_remainder = control_content.split(b"\r\n", 1)
    if effect_remainder != control_remainder or effect_line == control_line:
        raise CliError(
            "effect and negative-control raw requests must differ only by request target",
            exit_code=EXIT_AUTHORITY,
        )
    return prepared


def _campaign_start_record(
    *,
    spec: PersonalHttp1TriadSpec,
    spec_path: Path,
    spec_digest: str,
    manifest: dict[str, object],
    prepared: dict[str, tuple[Path, bytes, str]],
    automation_binding: dict[str, object] | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema": "faultloom.personal-http1-triad-start.v1",
        "campaign_id": spec.campaign_id,
        "run_id": manifest["run_id"],
        "grant_id": manifest["grant_id"],
        "grant_version": manifest["grant_version"],
        "authorization_reference": spec.authorization_reference,
        "authorization_document_sha256": spec.authorization_document_sha256,
        "spec_path": str(spec_path),
        "spec_sha256": spec_digest,
        "endpoint": {"hostname": spec.hostname, "port": spec.port, "scheme": spec.scheme},
        "timeout_seconds": spec.timeout_seconds,
        "classifier": EXACT_BODY_DIGEST_CLASSIFIER,
        "runtime_version": __version__,
        "finding": spec.finding.model_dump(mode="json"),
        "requests": [
            {
                "role": request.role,
                "method": request.method,
                "path": request.path,
                "request_file": str(prepared[request.role][0]),
                "request_sha256": prepared[request.role][2],
                "request_bytes": len(prepared[request.role][1]),
                "response_bytes": request.response_bytes,
            }
            for request in spec.requests
        ],
    }
    if automation_binding is not None:
        record["automation_binding"] = automation_binding["binding"]
        record["automation_binding_digest"] = automation_binding["sha256"]
    return record


def _campaign_unresolved(
    *,
    records: _CampaignRecordsDirectory,
    campaign_id: str,
    start_record: Path,
    dispatch_count: int,
    error: str,
    completed: list[dict[str, object]],
    current: dict[str, object] | None = None,
) -> int:
    summaries: list[dict[str, object]] = []
    for item in [*completed, *( [current] if current is not None else [])]:
        summary = {key: item[key] for key in ("role", "reservation", "statusCode", "dispatchPerformed", "error") if key in item}
        summaries.append(summary)
    unresolved_record = _campaign_record(records, campaign_id, "unresolved")
    _write_new_campaign_record(
        records,
        unresolved_record,
        (json.dumps(
            {
                "schema": "faultloom.personal-http1-triad-unresolved.v1",
                "campaign_id": campaign_id,
                "start_record": str(start_record),
                "dispatch_count": dispatch_count,
                "error": error,
                "completed_requests": summaries,
                "manual_reconciliation_required": True,
                "automatic_submission": False,
            },
            indent=2,
            sort_keys=True,
        ) + "\n").encode("utf-8"),
        mode=0o600,
    )
    _emit_json(
        {
            "schema": "faultloom.personal-http1-triad-run.v1",
            "campaignId": campaign_id,
            "status": "unresolved_no_retry",
            "classifier": EXACT_BODY_DIGEST_CLASSIFIER,
            "dispatchCount": dispatch_count,
            "startRecord": str(start_record),
            "error": error,
            "unresolvedRecord": str(unresolved_record),
            "manualReconciliationRequired": True,
        }
    )
    return EXIT_UNAVAILABLE


def _build_bound_http1_triad_spec(
    arguments: argparse.Namespace,
    *,
    require_active: bool = True,
) -> tuple[dict[str, object], dict[str, object]]:
    """Validate prepare inputs and return the one permitted v2 spec and binding."""
    manifest, grant, target, _ = _verified_request_workspace(
        arguments.workspace, _trusted_key_path(arguments), require_active=require_active
    )
    template_content = _capture_bounded_local_file(
        arguments.template, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign template"
    )
    try:
        template_path = arguments.template.resolve(strict=True)
    except OSError as exc:
        raise CliError("cannot resolve campaign template", exit_code=EXIT_AUTHORITY) from exc
    try:
        template = parse_personal_http1_triad_spec(template_content)
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    if template.schema_ != PERSONAL_HTTP1_TRIAD_SCHEMA:
        raise CliError("campaign template must be an unbound v1 triad", exit_code=EXIT_AUTHORITY)
    try:
        output_parent = arguments.out.parent.resolve(strict=True)
    except OSError as exc:
        raise CliError("cannot resolve bound triad output directory", exit_code=EXIT_AUTHORITY) from exc
    if output_parent != template_path.parent:
        raise CliError("bound triad output must remain beside its template requests", exit_code=EXIT_AUTHORITY)
    prepared = _prepare_campaign_requests(template, template_path)
    result_content = _capture_bounded_local_file(
        arguments.result, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="automation result"
    )
    try:
        result_path = arguments.result.resolve(strict=True)
        receipt_path = arguments.receipt.resolve(strict=True)
    except OSError as exc:
        raise CliError("cannot resolve automation bundle source", exit_code=EXIT_AUTHORITY) from exc
    _, result = _parse_bound_automation_result(result_content)
    result_digest = sha256_digest(result.model_dump(mode="json"))
    receipt_content = _capture_bounded_local_file(
        arguments.receipt, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="automation receipt"
    )
    try:
        receipt = json.loads(receipt_content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CliError("invalid automation result receipt", exit_code=EXIT_AUTHORITY) from exc
    if not isinstance(receipt, dict):
        raise CliError("invalid automation result receipt", exit_code=EXIT_AUTHORITY)
    _validate_automation_result_receipt(
        receipt,
        result=result,
        result_digest=result_digest,
    )
    candidate_source, candidate_digest = _validate_automation_candidate_for_triad(
        result=result,
        candidate_id=arguments.candidate_id,
        spec=template,
        effect_request_sha256=prepared["effect"][2],
        manifest=manifest,
        grant=grant,
        target=target,
    )
    binding: dict[str, object] = {
        "schema": PERSONAL_HTTP1_TRIAD_AUTOMATION_BINDING_SCHEMA,
        "result_path": str(result_path),
        "result_file_sha256": sha256_hex(result_content),
        "result_digest": result_digest,
        "receipt_path": str(receipt_path),
        "receipt_file_sha256": sha256_hex(receipt_content),
        "template_path": str(template_path),
        "template_sha256": sha256_hex(template_content),
        "candidate_id": arguments.candidate_id,
        "candidate_source": candidate_source,
        "candidate_digest": candidate_digest,
        "effect_request_path": str(prepared["effect"][0].resolve(strict=True)),
        "effect_request_sha256": prepared["effect"][2],
        "negative_control_request_path": str(prepared["negative_control"][0].resolve(strict=True)),
        "negative_control_request_sha256": prepared["negative_control"][2],
        "run_id": result.run_id,
        "grant_id": grant.grant_id,
        "grant_version": grant.grant_version,
        "grant_digest": sha256_digest(grant),
    }
    output = cast(dict[str, object], template.model_dump(by_alias=True, exclude_none=True))
    output["schema"] = PERSONAL_HTTP1_TRIAD_BOUND_SCHEMA
    output["automation_binding"] = binding
    return output, binding


def _campaign_prepare_http1_triad(arguments: argparse.Namespace) -> int:
    """Bind one offline compiled candidate to an operator-authored v1 triad."""
    output, binding = _build_bound_http1_triad_spec(arguments)
    _write_new_file(
        arguments.out,
        (json.dumps(output, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )
    _emit_json(
        {
            "schema": "faultloom.personal-http1-triad-prepare.v1",
            "spec": str(arguments.out),
            "bindingDigest": sha256_digest(binding),
            "candidateId": arguments.candidate_id,
            "status": "review_required",
            "targetDispatch": False,
            "automaticSubmission": False,
            "independentVerification": False,
        }
    )
    return EXIT_OK


def _supervised_bound_http1_triad_spec(arguments: argparse.Namespace) -> PersonalHttp1TriadSpec:
    """Create once or verify that ``--out`` is the exact requested v2 binding."""
    try:
        output_metadata = arguments.out.lstat()
    except FileNotFoundError:
        output, _ = _build_bound_http1_triad_spec(arguments)
        _write_new_file(
            arguments.out,
            (json.dumps(output, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            mode=0o600,
        )
        try:
            return parse_personal_http1_triad_spec(json.dumps(output).encode("utf-8"))
        except PersonalCampaignError as exc:  # Defensive: output originated from the typed template.
            raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    except OSError as exc:
        raise CliError("cannot inspect bound triad output", exit_code=EXIT_AUTHORITY) from exc
    if stat.S_ISLNK(output_metadata.st_mode) or not stat.S_ISREG(output_metadata.st_mode):
        raise CliError("bound triad output is not a regular non-symlink file", exit_code=EXIT_AUTHORITY)
    output_content = _capture_bounded_local_file(
        arguments.out, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="bound triad output"
    )
    try:
        spec = parse_personal_http1_triad_spec(output_content)
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    expected, _ = _build_bound_http1_triad_spec(arguments, require_active=False)
    if (
        spec.schema_ != PERSONAL_HTTP1_TRIAD_BOUND_SCHEMA
        or spec.model_dump(by_alias=True, exclude_none=True) != expected
    ):
        raise CliError(
            "existing bound triad output does not match the supplied sources and candidate",
            exit_code=EXIT_AUTHORITY,
        )
    return spec


def _campaign_supervision_acknowledged(campaign_id: str, verb: str) -> bool:
    """Require one exact, campaign-bound acknowledgement without writing to stdout."""
    acknowledgement = f"{verb} {campaign_id}"
    print(
        f"faultloom: type exactly {acknowledgement!r} then press Enter to continue.",
        file=sys.stderr,
        flush=True,
    )
    value = sys.stdin.readline()
    return value.rstrip("\r\n") == acknowledgement and value not in {"", "\n", "\r\n"}


def _emit_campaign_supervision(
    campaign_id: str,
    *,
    status: str,
    next_action: str | None = None,
    receipt: Path | None = None,
    final_status: str | None = None,
    manual_reconciliation_required: bool = False,
    target_dispatch_performed: bool | None = False,
    dispatch_count: int | None = 0,
    dispatch_state: str | None = None,
    response_review: list[dict[str, str]] | None = None,
) -> None:
    output: dict[str, object] = {
        "schema": "faultloom.personal-http1-triad-supervise.v1",
        "campaignId": campaign_id,
        "status": status,
        "automaticSubmission": False,
        "independentVerification": False,
    }
    if target_dispatch_performed is not None:
        output["targetDispatchPerformed"] = target_dispatch_performed
    if dispatch_count is not None:
        output["dispatchCount"] = dispatch_count
    if dispatch_state is not None:
        output["dispatchState"] = dispatch_state
    elif target_dispatch_performed is not None:
        output["dispatchState"] = "performed" if target_dispatch_performed else "not_dispatched"
    if next_action is not None:
        output["nextAction"] = next_action
    if receipt is not None:
        output["receipt"] = str(receipt)
    if final_status is not None:
        output["finalStatus"] = final_status
    if manual_reconciliation_required:
        output["manualReconciliationRequired"] = True
    if response_review is not None:
        output["responseReview"] = response_review
    _emit_json(output)


def _campaign_record_exists(path: Path) -> bool:
    try:
        _ = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CliError("cannot inspect campaign record", exit_code=EXIT_AUTHORITY) from exc
    return True


def _invoke_campaign_handler(
    handler: Callable[[argparse.Namespace], int], arguments: argparse.Namespace
) -> tuple[int, dict[str, object]]:
    """Reuse a phase handler while preserving the supervisor's one-JSON stdout contract."""
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        exit_code = handler(arguments)
    try:
        raw_output = json.loads(
            captured.getvalue(), object_pairs_hook=_reject_duplicate_keys
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise CliError("campaign phase did not produce one JSON result", exit_code=EXIT_AUTHORITY) from exc
    if not isinstance(raw_output, dict):
        raise CliError("campaign phase produced an invalid JSON result", exit_code=EXIT_AUTHORITY)
    output = cast(dict[str, object], raw_output)
    return exit_code, output


def _campaign_response_review(
    arguments: argparse.Namespace, run_result: Path
) -> list[dict[str, str]]:
    """Return review metadata only after the full read-only campaign validation chain."""
    inputs = _validated_campaign_finalization_inputs(arguments)
    try:
        if run_result.resolve(strict=True) != inputs.result_path.resolve(strict=True):
            raise CliError("campaign run result path differs from its workspace record", exit_code=EXIT_AUTHORITY)
    except OSError as exc:
        raise CliError("campaign run result is unavailable", exit_code=EXIT_AUTHORITY) from exc
    requests = inputs.result.get("requests")
    if not isinstance(requests, list) or len(requests) != 3:
        raise CliError("campaign run result is invalid", exit_code=EXIT_AUTHORITY)
    review: list[dict[str, str]] = []
    for (expected_role, _, response_file, body_sha256), item in zip(
        inputs.sources, requests, strict=True
    ):
        response = item.get("response") if isinstance(item, dict) else None
        if (
            not isinstance(item, dict)
            or item.get("role") != expected_role
            or not isinstance(response, dict)
            or not isinstance(response.get("sha256"), str)
        ):
            raise CliError("campaign run result is incomplete", exit_code=EXIT_AUTHORITY)
        review.append(
            {
                "role": expected_role,
                "responseFile": str(response_file),
                "responseSha256": response["sha256"],
                "bodySha256": body_sha256,
            }
        )
    return review


def _campaign_supervise_finalize_http1_triad(
    arguments: argparse.Namespace, campaign_id: str, run_result: Path
) -> int:
    response_review = _campaign_response_review(
        argparse.Namespace(
            workspace=arguments.workspace,
            trusted_key=arguments.trusted_key,
            campaign_id=campaign_id,
        ),
        run_result,
    )
    if not _campaign_supervision_acknowledged(campaign_id, "FINALIZE"):
        _emit_campaign_supervision(
            campaign_id,
            status="review_required",
            next_action=f"review private responses, then acknowledge exactly FINALIZE {campaign_id}",
            target_dispatch_performed=True,
            dispatch_count=3,
            response_review=response_review,
        )
        return EXIT_OK
    exit_code, result = _invoke_campaign_handler(
        _campaign_finalize_http1_triad,
        argparse.Namespace(
            workspace=arguments.workspace,
            trusted_key=arguments.trusted_key,
            campaign_id=campaign_id,
            confirm_reviewed_non_sensitive=True,
        ),
    )
    receipt_value = result.get("receipt")
    status = result.get("status")
    if exit_code != EXIT_OK or not isinstance(receipt_value, str) or not isinstance(status, str):
        raise CliError("campaign finalization did not complete", exit_code=EXIT_AUTHORITY)
    _emit_campaign_supervision(
        campaign_id,
        status="completed",
        receipt=Path(receipt_value),
        final_status=status,
        target_dispatch_performed=True,
        dispatch_count=3,
    )
    return EXIT_OK


def _campaign_supervise_http1_triad(arguments: argparse.Namespace) -> int:
    """Guide one candidate-bound triad through explicit run and finalize checkpoints."""
    spec = _supervised_bound_http1_triad_spec(arguments)
    campaign_id = spec.campaign_id
    try:
        (arguments.workspace / "campaigns").lstat()
    except FileNotFoundError:
        records: _CampaignRecordsDirectory | None = None
    except OSError as exc:
        raise CliError("cannot inspect campaign records", exit_code=EXIT_AUTHORITY) from exc
    else:
        records = _campaign_records_directory(arguments.workspace)
    if records is not None:
        final_receipt = _campaign_record(records, campaign_id, "final-receipt")
        unresolved = _campaign_record(records, campaign_id, "unresolved")
        finalize_start = _campaign_record(records, campaign_id, "finalize-start")
        run_result = _campaign_record(records, campaign_id, "run-result")
        start_record = _campaign_record(records, campaign_id, "start")
        has_final = _campaign_record_exists(final_receipt)
        has_unresolved = _campaign_record_exists(unresolved)
        has_finalize_start = _campaign_record_exists(finalize_start)
        has_run_result = _campaign_record_exists(run_result)
        has_start = _campaign_record_exists(start_record)
        if has_final and has_unresolved:
            raise CliError("campaign lifecycle has conflicting terminal records", exit_code=EXIT_AUTHORITY)
        if has_unresolved and (has_run_result or has_finalize_start):
            raise CliError("campaign lifecycle conflicts with an unresolved record", exit_code=EXIT_AUTHORITY)
        if has_run_result and not has_start:
            raise CliError("campaign run result lacks its start record", exit_code=EXIT_AUTHORITY)
        if has_finalize_start and (not has_start or not has_run_result):
            raise CliError("campaign finalization lacks its run topology", exit_code=EXIT_AUTHORITY)
        if has_final:
            status, dispatch_count = _validate_completed_campaign_finalization(
                argparse.Namespace(
                    workspace=arguments.workspace,
                    trusted_key=arguments.trusted_key,
                    campaign_id=campaign_id,
                ),
                final_receipt,
            )
            _emit_campaign_supervision(
                campaign_id,
                status="completed",
                receipt=final_receipt,
                final_status=status,
                target_dispatch_performed=True,
                dispatch_count=dispatch_count,
            )
            return EXIT_OK
        if has_unresolved:
            unresolved_record = _capture_campaign_json(unresolved, label="campaign unresolved record")
            dispatch_count = unresolved_record.get("dispatch_count")
            if (
                unresolved_record.get("campaign_id") != campaign_id
                or not isinstance(dispatch_count, int)
                or not 0 <= dispatch_count <= 3
            ):
                raise CliError("campaign unresolved record is invalid", exit_code=EXIT_AUTHORITY)
            _emit_campaign_supervision(
                campaign_id,
                status="manual_reconciliation_required",
                next_action="manually reconcile the existing unresolved campaign; do not retry it",
                manual_reconciliation_required=True,
                target_dispatch_performed=dispatch_count > 0,
                dispatch_count=dispatch_count,
            )
            return EXIT_UNAVAILABLE
        if has_finalize_start:
            _emit_campaign_supervision(
                campaign_id,
                status="manual_reconciliation_required",
                next_action="manually reconcile the started finalization; do not rerun it",
                manual_reconciliation_required=True,
                target_dispatch_performed=True,
                dispatch_count=3,
            )
            return EXIT_UNAVAILABLE
        if has_run_result:
            return _campaign_supervise_finalize_http1_triad(arguments, campaign_id, run_result)
        if has_start:
            _emit_campaign_supervision(
                campaign_id,
                status="manual_reconciliation_required",
                next_action="manually reconcile the started campaign; do not rerun it",
                manual_reconciliation_required=True,
                target_dispatch_performed=None,
                dispatch_count=None,
                dispatch_state="unknown",
            )
            return EXIT_UNAVAILABLE
    if not _campaign_supervision_acknowledged(campaign_id, "RUN"):
        _emit_campaign_supervision(
            campaign_id,
            status="review_required",
            next_action=f"review the bound triad, then acknowledge exactly RUN {campaign_id}",
        )
        return EXIT_OK
    if records is None:
        _ = _campaign_records_directory(arguments.workspace)
    exit_code, result = _invoke_campaign_handler(
        _campaign_run_http1_triad,
        argparse.Namespace(
            workspace=arguments.workspace,
            trusted_key=arguments.trusted_key,
            spec=arguments.out,
        ),
    )
    if exit_code != EXIT_OK:
        raw_dispatch_count = result.get("dispatchCount")
        dispatch_count = raw_dispatch_count if type(raw_dispatch_count) is int else 0
        _emit_campaign_supervision(
            campaign_id,
            status="manual_reconciliation_required",
            next_action="manually reconcile the existing unresolved campaign; do not retry it",
            manual_reconciliation_required=True,
            target_dispatch_performed=dispatch_count > 0,
            dispatch_count=dispatch_count,
        )
        return exit_code
    if result.get("status") != "review_required":
        raise CliError("campaign run did not reach response review", exit_code=EXIT_AUTHORITY)
    run_result_value = result.get("runResult")
    if not isinstance(run_result_value, str):
        raise CliError("campaign run result path is unavailable", exit_code=EXIT_AUTHORITY)
    return _campaign_supervise_finalize_http1_triad(arguments, campaign_id, Path(run_result_value))


def _emit_verification_supervision(
    campaign_id: str,
    *,
    status: str,
    next_action: str | None = None,
    dispatch_count: int | None = 0,
    dispatch_state: str | None = None,
    response_review: list[dict[str, str]] | None = None,
    verification: dict[str, object] | None = None,
    manual_reconciliation_required: bool = False,
) -> None:
    """Emit the sole public result for the independent-review coordinator."""
    output: dict[str, object] = {
        "schema": "faultloom.independent-http1-supervise.v1",
        "campaignId": campaign_id,
        "status": status,
        "automaticSubmission": False,
        "independentVerification": True,
    }
    if dispatch_count is not None:
        output["targetDispatchPerformed"] = dispatch_count > 0
        output["dispatchCount"] = dispatch_count
    if dispatch_state is not None:
        output["dispatchState"] = dispatch_state
    elif dispatch_count is not None:
        output["dispatchState"] = "performed" if dispatch_count else "not_dispatched"
    if next_action is not None:
        output["nextAction"] = next_action
    if response_review is not None:
        output["responseReview"] = response_review
    if verification is not None:
        output["verification"] = verification
    if manual_reconciliation_required:
        output["manualReconciliationRequired"] = True
    _emit_json(output)


def _invoke_cli_main_captured(argv: list[str], *, working_directory: Path) -> tuple[int, str]:
    """Run an existing CLI command without allowing its stdout to escape a coordinator."""
    previous_directory = Path.cwd()
    try:
        os.chdir(working_directory)
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            exit_code = main(argv)
    except OSError as exc:
        raise CliError("cannot enter verifier workspace", exit_code=EXIT_AUTHORITY) from exc
    finally:
        try:
            os.chdir(previous_directory)
        except OSError as exc:
            raise CliError("cannot restore working directory", exit_code=EXIT_AUTHORITY) from exc
    return exit_code, captured.getvalue()


def _verification_supervisor_prepare(arguments: argparse.Namespace) -> None:
    exit_code, result = _invoke_campaign_handler(
        _campaign_prepare_verification_http1,
        argparse.Namespace(
            source_workspace=arguments.source_workspace,
            source_trusted_key=arguments.source_trusted_key,
            verifier_workspace=arguments.verifier_workspace,
            verifier_trusted_key=arguments.verifier_trusted_key,
            handoff=arguments.handoff,
            campaign_id=arguments.campaign_id,
            finding_class=arguments.finding_class,
            claim=arguments.claim,
            prerequisite=arguments.prerequisite,
            out=arguments.out,
        ),
    )
    if (
        exit_code != EXIT_OK
        or result.get("status") != "ready_for_existing_triad_runner"
        or result.get("networkAccess") is not False
    ):
        raise CliError("independent verifier preparation did not complete", exit_code=EXIT_AUTHORITY)


def _verification_supervisor_invocation(
    arguments: argparse.Namespace,
) -> tuple[str, list[str]]:
    """Bind the local verify/report argv to the exact compile artifacts."""
    context = _verification_handoff_document(arguments)
    result_path, result_relative = _handoff_output_path(
        context.verifier_workspace, arguments.result_out
    )
    receipt_path, _ = _handoff_output_path(
        context.verifier_workspace, arguments.receipt_out
    )
    result_content = _capture_bounded_local_file(
        result_path,
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
        label="verification result",
    )
    content = _capture_bounded_local_file(
        receipt_path,
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
        label="verification compile receipt",
    )
    receipt = _parse_campaign_json_content(content, label="verification compile receipt")
    candidate_id = f"candidate.independent.{arguments.campaign_id}"
    verifier_run_id = str(context.verifier_manifest["run_id"])
    common_args = [
        "--result", result_relative,
        "--trusted-key", "trusted-key.json",
        "--run-id", verifier_run_id,
        "--run-manifest-digest", sha256_digest(context.verifier_manifest),
        "--authority-digest", sha256_digest(context.source_authority),
        "--engagement-id", f"engagement.{context.source_grant.grant_id}",
        "--source-actor", context.source_grant.issued_to,
        "--verifier-actor", context.verifier_grant.issued_to,
        "--verifier-authority-digest", sha256_digest(context.verifier_authority),
        "--verifier-authority", "authority.json",
        "--verifier-authority-key", "trusted-key.json",
    ]
    expected = {
        "schema": "faultloom.independent-http1-compile.v1",
        "status": "verified",
        "candidateId": candidate_id,
        "result": {"path": result_relative, "sha256": sha256_hex(result_content)},
        "sourceHandoffSha256": sha256_hex(context.handoff_content),
        "verifyArgs": [candidate_id, *common_args],
        "reportArgs": [
            candidate_id,
            "--format", "md",
            "--out-dir", "verification-report-outbox",
            *common_args,
        ],
        "networkAccess": False,
        "automaticReport": False,
        "automaticSubmission": False,
    }
    if receipt != expected:
        raise CliError(
            "verification compile receipt differs from its exact local invocation",
            exit_code=EXIT_AUTHORITY,
        )
    return candidate_id, common_args


def _verification_supervisor_complete(arguments: argparse.Namespace) -> int:
    """Compile, verify, and locally draft a report after verifier finalization only."""
    result_path, _ = _handoff_output_path(arguments.verifier_workspace, arguments.result_out)
    receipt_path, _ = _handoff_output_path(arguments.verifier_workspace, arguments.receipt_out)
    result_exists = _campaign_record_exists(result_path)
    receipt_exists = _campaign_record_exists(receipt_path)
    if result_exists != receipt_exists:
        raise CliError(
            "verification compile artifacts require manual reconciliation",
            exit_code=EXIT_AUTHORITY,
        )
    if not result_exists:
        exit_code, compiled = _invoke_campaign_handler(
            _campaign_compile_verification_http1,
            argparse.Namespace(
                source_workspace=arguments.source_workspace,
                source_trusted_key=arguments.source_trusted_key,
                verifier_workspace=arguments.verifier_workspace,
                verifier_trusted_key=arguments.verifier_trusted_key,
                handoff=arguments.handoff,
                campaign_id=arguments.campaign_id,
                case=arguments.case,
                private_key=arguments.private_key,
                result_out=arguments.result_out,
                receipt_out=arguments.receipt_out,
            ),
        )
        if exit_code != EXIT_OK or compiled.get("status") != "verified":
            raise CliError(
                "independent verifier compilation did not complete",
                exit_code=EXIT_AUTHORITY,
            )
    candidate_id, common_args = _verification_supervisor_invocation(arguments)
    verify_exit, verify_stdout = _invoke_cli_main_captured(
        ["verify", candidate_id, *common_args], working_directory=arguments.verifier_workspace
    )
    try:
        verified = json.loads(verify_stdout, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise CliError("verification command did not produce one JSON result", exit_code=EXIT_AUTHORITY) from exc
    if (
        verify_exit != EXIT_OK
        or not isinstance(verified, dict)
        or verified.get("candidate_id") != candidate_id
        or verified.get("outcome") != "verified"
        or verified.get("network_access") != "none"
        or not isinstance(verified.get("claim_id"), str)
        or not isinstance(verified.get("verdict_id"), str)
        or not isinstance(verified.get("result_artifact_digest"), str)
    ):
        raise CliError("verification command did not complete", exit_code=EXIT_AUTHORITY)
    report_exit, report_stdout = _invoke_cli_main_captured(
        ["report", candidate_id, "--format", "md", *common_args],
        working_directory=arguments.verifier_workspace,
    )
    if report_exit != EXIT_OK or not report_stdout.endswith("\n"):
        raise CliError("verification report did not complete", exit_code=EXIT_AUTHORITY)
    report_content = report_stdout.removesuffix("\n").encode()
    report_digest = f"sha256:{hashlib.sha256(report_content).hexdigest()}"
    report_tag = sha256_hex(candidate_id.encode())[:16]
    workspace = arguments.verifier_workspace.resolve(strict=True)
    report_path, _ = _handoff_output_path(
        workspace, workspace / f"verification-report-{report_tag}.md"
    )
    report_receipt, _ = _handoff_output_path(
        workspace, workspace / f"verification-report-{report_tag}.receipt.json"
    )
    report_receipt_document = {
        "automatic_submission_performed": False,
        "candidate_id": candidate_id,
        "claim_id": verified["claim_id"],
        "finding_id": candidate_id,
        "network_access": "none",
        "report_digest": report_digest,
        "report_format": "md",
        "result_artifact_digest": verified["result_artifact_digest"],
        "schema": "faultloom.report_outbox.receipt.v1",
        "status": "draft_manual_review",
        "verdict_id": verified["verdict_id"],
    }
    report_receipt_content = json.dumps(
        report_receipt_document, sort_keys=True, separators=(",", ":")
    ).encode()
    _write_or_verify_handoff_output(workspace, report_path, report_content)
    _write_or_verify_handoff_output(
        workspace, report_receipt, report_receipt_content
    )
    if (
        _capture_bounded_local_file(
            report_path,
            maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
            label="verification report",
        )
        != report_content
        or _parse_campaign_json_content(
            _capture_bounded_local_file(
                report_receipt,
                maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
                label="verification report receipt",
            ),
            label="verification report receipt",
        )
        != report_receipt_document
    ):
        raise CliError("verification report artifacts differ", exit_code=EXIT_AUTHORITY)
    _emit_verification_supervision(
        arguments.campaign_id,
        status="completed",
        dispatch_count=3,
        verification={
            "status": "verified",
            "result": str(arguments.result_out),
            "compileReceipt": str(arguments.receipt_out),
            "reportStatus": "draft_manual_review",
            "report": str(report_path),
            "reportReceipt": str(report_receipt),
            "automaticSubmission": False,
        },
    )
    return EXIT_OK


def _campaign_supervise_verification_http1(arguments: argparse.Namespace) -> int:
    """Coordinate the existing independent verifier phases without a second sender."""
    if not getattr(arguments, "_skip_prepare", False):
        _verification_supervisor_prepare(arguments)
    records = _campaign_records_directory(arguments.verifier_workspace)
    campaign_id = arguments.campaign_id
    final_receipt = _campaign_record(records, campaign_id, "final-receipt")
    unresolved = _campaign_record(records, campaign_id, "unresolved")
    finalize_start = _campaign_record(records, campaign_id, "finalize-start")
    run_result = _campaign_record(records, campaign_id, "run-result")
    start_record = _campaign_record(records, campaign_id, "start")
    has_final = _campaign_record_exists(final_receipt)
    has_unresolved = _campaign_record_exists(unresolved)
    has_finalize_start = _campaign_record_exists(finalize_start)
    has_run_result = _campaign_record_exists(run_result)
    has_start = _campaign_record_exists(start_record)
    if has_final and has_unresolved:
        raise CliError("campaign lifecycle has conflicting terminal records", exit_code=EXIT_AUTHORITY)
    if has_unresolved and (has_run_result or has_finalize_start):
        raise CliError("campaign lifecycle conflicts with an unresolved record", exit_code=EXIT_AUTHORITY)
    if has_run_result and not has_start:
        raise CliError("campaign run result lacks its start record", exit_code=EXIT_AUTHORITY)
    if has_finalize_start and (not has_start or not has_run_result):
        raise CliError("campaign finalization lacks its run topology", exit_code=EXIT_AUTHORITY)
    if has_final:
        _ = _validate_completed_campaign_finalization(
            argparse.Namespace(
                workspace=arguments.verifier_workspace,
                trusted_key=arguments.verifier_trusted_key,
                campaign_id=campaign_id,
            ),
            final_receipt,
        )
        return _verification_supervisor_complete(arguments)
    if has_unresolved:
        unresolved_record = _capture_campaign_json(unresolved, label="campaign unresolved record")
        dispatch_count = unresolved_record.get("dispatch_count")
        if (
            unresolved_record.get("campaign_id") != campaign_id
            or not isinstance(dispatch_count, int)
            or not 0 <= dispatch_count <= 3
        ):
            raise CliError("campaign unresolved record is invalid", exit_code=EXIT_AUTHORITY)
        _emit_verification_supervision(
            campaign_id,
            status="manual_reconciliation_required",
            next_action="manually reconcile the existing unresolved verifier campaign; do not retry it",
            dispatch_count=dispatch_count,
            manual_reconciliation_required=True,
        )
        return EXIT_UNAVAILABLE
    if has_finalize_start:
        _emit_verification_supervision(
            campaign_id,
            status="manual_reconciliation_required",
            next_action="manually reconcile the started verifier finalization; do not rerun it",
            dispatch_count=3,
            manual_reconciliation_required=True,
        )
        return EXIT_UNAVAILABLE
    if has_run_result:
        response_review = _campaign_response_review(
            argparse.Namespace(
                workspace=arguments.verifier_workspace,
                trusted_key=arguments.verifier_trusted_key,
                campaign_id=campaign_id,
            ),
            run_result,
        )
        if not _campaign_supervision_acknowledged(campaign_id, "FINALIZE"):
            _emit_verification_supervision(
                campaign_id,
                status="review_required",
                next_action=f"review private responses, then acknowledge exactly FINALIZE {campaign_id}",
                dispatch_count=3,
                response_review=response_review,
            )
            return EXIT_OK
        exit_code, finalized = _invoke_campaign_handler(
            _campaign_finalize_http1_triad,
            argparse.Namespace(
                workspace=arguments.verifier_workspace,
                trusted_key=arguments.verifier_trusted_key,
                campaign_id=campaign_id,
                confirm_reviewed_non_sensitive=True,
            ),
        )
        if exit_code != EXIT_OK or not isinstance(finalized.get("receipt"), str):
            raise CliError("verifier campaign finalization did not complete", exit_code=EXIT_AUTHORITY)
        return _verification_supervisor_complete(arguments)
    if has_start:
        _emit_verification_supervision(
            campaign_id,
            status="manual_reconciliation_required",
            next_action="manually reconcile the started verifier campaign; do not rerun it",
            dispatch_count=None,
            dispatch_state="unknown",
            manual_reconciliation_required=True,
        )
        return EXIT_UNAVAILABLE
    if not _campaign_supervision_acknowledged(campaign_id, "RUN"):
        _emit_verification_supervision(
            campaign_id,
            status="review_required",
            next_action=f"review the independent verifier triad, then acknowledge exactly RUN {campaign_id}",
        )
        return EXIT_OK
    exit_code, run = _invoke_campaign_handler(
        _campaign_run_http1_triad,
        argparse.Namespace(
            workspace=arguments.verifier_workspace,
            trusted_key=arguments.verifier_trusted_key,
            spec=arguments.out,
        ),
    )
    if exit_code != EXIT_OK:
        raw_dispatch_count = run.get("dispatchCount")
        dispatch_count = raw_dispatch_count if type(raw_dispatch_count) is int else 0
        _emit_verification_supervision(
            campaign_id,
            status="manual_reconciliation_required",
            next_action="manually reconcile the existing unresolved verifier campaign; do not retry it",
            dispatch_count=dispatch_count,
            manual_reconciliation_required=True,
        )
        return exit_code
    run_result_value = run.get("runResult")
    if run.get("status") != "review_required" or not isinstance(run_result_value, str):
        raise CliError("verifier campaign did not reach response review", exit_code=EXIT_AUTHORITY)
    return _campaign_supervise_verification_http1(
        argparse.Namespace(**vars(arguments), _skip_prepare=True)
    )


def _campaign_run_http1_triad(arguments: argparse.Namespace) -> int:
    spec_content = _capture_bounded_local_file(
        arguments.spec, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign spec"
    )
    try:
        spec_path = arguments.spec.resolve(strict=True)
    except OSError as exc:
        raise CliError("cannot resolve campaign spec", exit_code=EXIT_AUTHORITY) from exc
    try:
        spec = parse_personal_http1_triad_spec(spec_content)
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    manifest, grant, target, now = _verified_request_workspace(
        arguments.workspace, _trusted_key_path(arguments)
    )
    automation_binding = _validate_bound_triad_spec(
        spec=spec,
        spec_path=spec_path,
        manifest=manifest,
        grant=grant,
        target=target,
    )
    expected_sha256 = None
    if spec.automation_binding is not None:
        expected_sha256 = {
            "effect": spec.automation_binding.effect_request_sha256,
            "negative_control": spec.automation_binding.negative_control_request_sha256,
        }
    prepared = _prepare_campaign_requests(
        spec,
        spec_path,
        expected_sha256=expected_sha256,
    )
    records = _campaign_records_directory(arguments.workspace)
    start_record = _campaign_record(records, spec.campaign_id, "start")
    if _campaign_record_exists(start_record):
        raise CliError(
            f"cannot create campaign record {start_record}: already exists",
            exit_code=EXIT_USAGE,
        )
    maximum_request_bytes = min(
        grant.budget.max_request_bytes,
        PERSONAL_HTTP1_MAX_REQUEST_BYTES,
    )
    maximum_response_bytes = min(
        grant.budget.max_response_bytes,
        PERSONAL_HTTP1_MAX_RESPONSE_BYTES,
    )
    for request in spec.requests:
        _validate_request_authority(
            grant=grant,
            target=target,
            hostname=spec.hostname,
            port=spec.port,
            scheme=spec.scheme,
            method=request.method,
            path=request.path,
            request_bytes=len(prepared[request.role][1]),
            response_bytes=request.response_bytes,
            maximum_request_bytes=maximum_request_bytes,
            maximum_response_bytes=maximum_response_bytes,
        )
    _validate_campaign_accounting_capacity(
        workspace=arguments.workspace,
        manifest=manifest,
        grant=grant,
        now=now,
        required_actions=3,
    )
    _write_new_campaign_record(
        records,
        start_record,
        (json.dumps(
            _campaign_start_record(
                spec=spec,
                spec_path=spec_path,
                spec_digest=sha256_hex(spec_content),
                manifest=manifest,
                prepared=prepared,
                automation_binding=automation_binding,
            ),
            indent=2,
            sort_keys=True,
        ) + "\n").encode("utf-8"),
        mode=0o600,
    )

    dispatches = (
        ("effect", spec.effect),
        ("reproduction", spec.effect),
        ("negative_control", spec.negative_control),
    )
    results: list[dict[str, object]] = []
    for role, request in dispatches:
        request_file = prepared[request.role][0]
        send_arguments = argparse.Namespace(
            workspace=arguments.workspace,
            trusted_key=arguments.trusted_key,
            hostname=spec.hostname,
            port=spec.port,
            scheme=spec.scheme,
            method=request.method,
            path=request.path,
            request_file=request_file,
            response_bytes=str(request.response_bytes),
            timeout_seconds=spec.timeout_seconds,
            body_preview_chars=0,
            expected_request_sha256=prepared[request.role][2],
        )
        try:
            exit_code, result = _scope_send_request_result(send_arguments)
        except CliError as exc:
            return _campaign_unresolved(
                campaign_id=spec.campaign_id,
                records=records,
                start_record=start_record,
                dispatch_count=len(results),
                error=str(exc),
                completed=results,
            )
        dispatch_count = len(results) + (1 if result.get("dispatchPerformed") else 0)
        if exit_code != EXIT_OK:
            return _campaign_unresolved(
                campaign_id=spec.campaign_id,
                records=records,
                start_record=start_record,
                dispatch_count=dispatch_count,
                error=str(result.get("error", "request_failed")),
                completed=results,
                current={"role": role, **result},
            )
        completed_result = {"role": role, **result}
        try:
            _record_campaign_binding(
                workspace=arguments.workspace,
                manifest=manifest,
                campaign_id=spec.campaign_id,
                role=role,
                result=completed_result,
            )
        except CliError as exc:
            return _campaign_unresolved(
                campaign_id=spec.campaign_id,
                records=records,
                start_record=start_record,
                dispatch_count=dispatch_count,
                error=str(exc),
                completed=results,
                current=completed_result,
            )
        if result.get("statusCode") == 429:
            return _campaign_unresolved(
                campaign_id=spec.campaign_id,
                records=records,
                start_record=start_record,
                dispatch_count=dispatch_count,
                error="rate_limited_429",
                completed=results,
                current=completed_result,
            )
        results.append(completed_result)

    run_result = _campaign_record(records, spec.campaign_id, "run-result")
    output = {
        "schema": "faultloom.personal-http1-triad-run-result.v1",
        "campaign_id": spec.campaign_id,
        "start_record": str(start_record),
        "start_sha256": sha256_hex(_capture_bounded_local_file(start_record, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign start record")),
        "run_id": manifest["run_id"],
        "grant_id": manifest["grant_id"],
        "grant_version": manifest["grant_version"],
        "classifier": EXACT_BODY_DIGEST_CLASSIFIER,
        "runtime_version": __version__,
        "dispatch_count": 3,
        "requests": results,
        "review_required": True,
        "independent_verification": False,
        "automatic_submission": False,
    }
    if automation_binding is not None:
        output["automation_binding"] = automation_binding["binding"]
        output["automation_binding_digest"] = automation_binding["sha256"]
    _write_new_campaign_record(
        records,
        run_result,
        (json.dumps(output, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )
    _emit_json(
        {
            "schema": "faultloom.personal-http1-triad-run.v1",
            "campaignId": spec.campaign_id,
            "status": "review_required",
            "classifier": EXACT_BODY_DIGEST_CLASSIFIER,
            "dispatchCount": 3,
            "startRecord": str(start_record),
            "runResult": str(run_result),
            "independentVerification": False,
            "automaticSubmission": False,
        }
    )
    return EXIT_OK


def _campaign_exchange_sources(
    *,
    workspace: Path,
    start: dict[str, object],
    result: dict[str, object],
    bindings: dict[str, dict[str, str]],
) -> list[tuple[str, Path, Path, str]]:
    start_requests = start.get("requests")
    dispatched = result.get("requests")
    if not isinstance(start_requests, list) or not isinstance(dispatched, list) or len(dispatched) != 3:
        raise CliError("campaign records have invalid request entries", exit_code=EXIT_AUTHORITY)
    definitions = {
        item.get("role"): item
        for item in start_requests
        if isinstance(item, dict) and item.get("role") in {"effect", "negative_control"}
    }
    if set(definitions) != {"effect", "negative_control"}:
        raise CliError("campaign start record has invalid request roles", exit_code=EXIT_AUTHORITY)
    expected_roles = ("effect", "reproduction", "negative_control")
    sources: list[tuple[str, Path, Path, str]] = []
    for expected_role, item in zip(expected_roles, dispatched, strict=True):
        if not isinstance(item, dict) or item.get("role") != expected_role:
            raise CliError("campaign run result has invalid request order", exit_code=EXIT_AUTHORITY)
        definition = definitions["effect" if expected_role == "reproduction" else expected_role]
        binding = bindings.get(expected_role)
        request_file_value = definition.get("request_file")
        request_digest = definition.get("request_sha256")
        dispatched_request = item.get("request")
        reservation = item.get("reservation")
        response_file_value = item.get("responseFile")
        response = item.get("response")
        body_digest = item.get("bodySha256")
        if (
            binding is None
            or
            not isinstance(request_file_value, str)
            or not isinstance(request_digest, str)
            or not isinstance(dispatched_request, dict)
            or not isinstance(dispatched_request.get("sha256"), str)
            or not _is_reservation_id(reservation)
            or not isinstance(response_file_value, str)
            or not isinstance(response, dict)
            or not isinstance(response.get("sha256"), str)
            or not isinstance(body_digest, str)
        ):
            raise CliError("campaign run result is incomplete", exit_code=EXIT_AUTHORITY)
        if (
            reservation != binding["reservation"]
            or request_digest != binding["request_sha256"]
            or dispatched_request.get("sha256") != binding["request_sha256"]
            or response.get("sha256") != binding["response_sha256"]
            or body_digest != binding["body_sha256"]
            or response_file_value != binding["response_file"]
        ):
            raise CliError("campaign run result does not match request accounting", exit_code=EXIT_AUTHORITY)
        request_file = Path(request_file_value)
        response_file = Path(response_file_value)
        expected_response = workspace / "responses" / f"{reservation}.personal-http1.raw"
        try:
            if response_file.resolve(strict=True) != expected_response.resolve(strict=True):
                raise CliError("campaign response path is not workspace-owned", exit_code=EXIT_AUTHORITY)
        except OSError as exc:
            raise CliError("campaign response file is unavailable", exit_code=EXIT_AUTHORITY) from exc
        request_content = _capture_bounded_local_file(
            request_file, maximum_bytes=PERSONAL_HTTP1_MAX_REQUEST_BYTES, label="campaign request"
        )
        if sha256_hex(request_content) != request_digest:
            raise CliError("campaign request digest changed after dispatch", exit_code=EXIT_AUTHORITY)
        response_content = _capture_bounded_local_file(
            response_file, maximum_bytes=PERSONAL_HTTP1_MAX_RESPONSE_BYTES, label="campaign response"
        )
        if sha256_hex(response_content) != response["sha256"]:
            raise CliError("campaign response digest changed after dispatch", exit_code=EXIT_AUTHORITY)
        method = definition.get("method")
        if not isinstance(method, str):
            raise CliError("campaign start record has invalid method", exit_code=EXIT_AUTHORITY)
        _, _, body = _parse_personal_http11_response(response_content, method=method)
        if sha256_hex(body) != body_digest:
            raise CliError("campaign response body digest changed after dispatch", exit_code=EXIT_AUTHORITY)
        sources.append((expected_role, request_file, response_file, body_digest))
    return sources


@dataclass(frozen=True)
class _CampaignFinalizationInputs:
    manifest: dict[str, object]
    records: _CampaignRecordsDirectory
    start_path: Path
    result_path: Path
    start: dict[str, object]
    result: dict[str, object]
    sources: list[tuple[str, Path, Path, str]]


def _validated_campaign_finalization_inputs(
    arguments: argparse.Namespace,
) -> _CampaignFinalizationInputs:
    """Revalidate every pre-archival campaign input without creating a record."""
    manifest, grant, target, _ = _verified_request_workspace(
        arguments.workspace, _trusted_key_path(arguments), require_active=False
    )
    records = _campaign_records_directory(arguments.workspace)
    start_path = _campaign_record(records, arguments.campaign_id, "start")
    result_path = _campaign_record(records, arguments.campaign_id, "run-result")
    start = _capture_campaign_json(start_path, label="campaign start record")
    result = _capture_campaign_json(result_path, label="campaign run result")
    required_start = {
        "schema": "faultloom.personal-http1-triad-start.v1",
        "campaign_id": arguments.campaign_id,
        "run_id": manifest.get("run_id"),
        "grant_id": manifest.get("grant_id"),
        "grant_version": manifest.get("grant_version"),
        "classifier": EXACT_BODY_DIGEST_CLASSIFIER,
    }
    required_result = {
        "schema": "faultloom.personal-http1-triad-run-result.v1",
        "campaign_id": arguments.campaign_id,
        "run_id": manifest.get("run_id"),
        "grant_id": manifest.get("grant_id"),
        "grant_version": manifest.get("grant_version"),
        "classifier": EXACT_BODY_DIGEST_CLASSIFIER,
        "dispatch_count": 3,
        "review_required": True,
    }
    if any(start.get(key) != value for key, value in required_start.items()) or any(
        result.get(key) != value for key, value in required_result.items()
    ):
        raise CliError("campaign records are not bound to this workspace", exit_code=EXIT_AUTHORITY)
    spec_path_value = start.get("spec_path")
    spec_digest = start.get("spec_sha256")
    if not isinstance(spec_path_value, str) or not isinstance(spec_digest, str):
        raise CliError("campaign start record lacks its spec binding", exit_code=EXIT_AUTHORITY)
    spec_content = _capture_bounded_local_file(
        Path(spec_path_value), maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign spec"
    )
    try:
        spec = parse_personal_http1_triad_spec(spec_content)
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    if (
        sha256_hex(spec_content) != spec_digest
        or spec.campaign_id != arguments.campaign_id
        or spec.authorization_reference != start.get("authorization_reference")
        or spec.authorization_document_sha256 != start.get("authorization_document_sha256")
    ):
        raise CliError("campaign spec changed after dispatch", exit_code=EXIT_AUTHORITY)
    _ = _validate_bound_triad_spec(
        spec=spec,
        spec_path=Path(spec_path_value).resolve(strict=True),
        manifest=manifest,
        grant=grant,
        target=target,
    )
    if result.get("start_sha256") != sha256_hex(
        _capture_bounded_local_file(start_path, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign start record")
    ):
        raise CliError("campaign run result is not bound to its start record", exit_code=EXIT_AUTHORITY)
    bindings = _campaign_bindings(
        workspace=arguments.workspace, manifest=manifest, campaign_id=arguments.campaign_id
    )
    sources = _campaign_exchange_sources(
        workspace=arguments.workspace, start=start, result=result, bindings=bindings
    )
    return _CampaignFinalizationInputs(
        manifest=manifest,
        records=records,
        start_path=start_path,
        result_path=result_path,
        start=start,
        result=result,
        sources=sources,
    )


def _campaign_finalization_digests(
    inputs: _CampaignFinalizationInputs,
) -> tuple[dict[str, str], dict[str, str], str]:
    dispatched = inputs.result.get("requests")
    if not isinstance(dispatched, list) or len(dispatched) != 3:
        raise CliError("campaign run result is invalid", exit_code=EXIT_AUTHORITY)
    body_digests: dict[str, str] = {}
    response_digests: dict[str, str] = {}
    for (role, _, _, body_digest), dispatch in zip(inputs.sources, dispatched, strict=True):
        response = dispatch.get("response") if isinstance(dispatch, dict) else None
        if not isinstance(response, dict) or not isinstance(response.get("sha256"), str):
            raise CliError("campaign run result is invalid", exit_code=EXIT_AUTHORITY)
        body_digests[role] = body_digest
        response_digests[role] = response["sha256"]
    try:
        outcome = classify_exact_body_digest_triad(
            effect_body_sha256=body_digests["effect"],
            reproduction_body_sha256=body_digests["reproduction"],
            negative_control_body_sha256=body_digests["negative_control"],
        )
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    return body_digests, response_digests, outcome.status


def _validated_campaign_evidence(
    *, inputs: _CampaignFinalizationInputs, evidence_ids: list[object]
) -> None:
    if len(evidence_ids) != 3 or not all(isinstance(value, str) for value in evidence_ids):
        raise CliError("campaign final receipt has invalid evidence ids", exit_code=EXIT_AUTHORITY)
    evidence = _workspace_evidence(
        inputs.records.workspace,
        run_id=str(inputs.manifest["run_id"]),
        selected_ids=tuple(cast(str, value) for value in evidence_ids),
    )
    dispatched = inputs.result.get("requests")
    if not isinstance(dispatched, list):
        raise CliError("campaign run result is invalid", exit_code=EXIT_AUTHORITY)
    raw_directory = inputs.records.workspace / "evidence" / "raw"
    for (role, request_file, response_file, _), dispatch, record in zip(
        inputs.sources, dispatched, evidence, strict=True
    ):
        evidence_id = record.get("evidence_id") if isinstance(record, dict) else None
        request = dispatch.get("request") if isinstance(dispatch, dict) else None
        response = dispatch.get("response") if isinstance(dispatch, dict) else None
        reservation = dispatch.get("reservation") if isinstance(dispatch, dict) else None
        archived_request = record.get("request")
        archived_response = record.get("response")
        if (
            not isinstance(request, dict)
            or not isinstance(response, dict)
            or not isinstance(reservation, str)
            or record.get("schema") != "faultloom.manual-evidence.v1"
            or record.get("kind") != "http"
            or record.get("run_id") != inputs.manifest["run_id"]
            or not isinstance(evidence_id, str)
            or record.get("reservation_id") != reservation
            or not isinstance(archived_request, dict)
            or not isinstance(archived_response, dict)
            or archived_request.get("sha256") != request.get("sha256")
            or archived_response.get("sha256") != response.get("sha256")
        ):
            raise CliError("archived campaign evidence is invalid", exit_code=EXIT_AUTHORITY)
        evidence_content = _capture_bounded_local_file(
            raw_directory / f"{evidence_id}.json",
            maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
            label="archived campaign evidence record",
        )
        if _parse_campaign_json_content(
            evidence_content, label="archived campaign evidence record"
        ) != record:
            raise CliError("archived campaign evidence changed while being read", exit_code=EXIT_AUTHORITY)
        for archived, source, label in (
            (archived_request, request_file, "request"),
            (archived_response, response_file, "response"),
        ):
            stored_file = archived.get("stored_file")
            digest = archived.get("sha256")
            if not isinstance(stored_file, str) or Path(stored_file).name != stored_file or not isinstance(digest, str):
                raise CliError("archived campaign evidence is invalid", exit_code=EXIT_AUTHORITY)
            source_content = _capture_bounded_local_file(
                source,
                maximum_bytes=PERSONAL_HTTP1_MAX_RESPONSE_BYTES,
                label=f"campaign {label}",
            )
            archived_content = _capture_bounded_local_file(
                raw_directory / stored_file,
                maximum_bytes=PERSONAL_HTTP1_MAX_RESPONSE_BYTES,
                label=f"archived campaign {label}",
            )
            if archived_content != source_content or sha256_hex(archived_content) != digest:
                raise CliError("archived campaign evidence digest differs", exit_code=EXIT_AUTHORITY)


def _validated_campaign_finding(
    *, inputs: _CampaignFinalizationInputs, receipt: dict[str, object], outcome_status: str, evidence_ids: list[object]
) -> None:
    finding = receipt.get("finding")
    if outcome_status == "negative_campaign":
        if finding is not None:
            raise CliError("negative campaign has an unexpected finding", exit_code=EXIT_AUTHORITY)
        return
    if not isinstance(finding, dict):
        raise CliError("draft campaign finding is invalid", exit_code=EXIT_AUTHORITY)
    finding_id = finding.get("finding_id")
    finding_path = finding.get("finding")
    record_path = finding.get("record")
    if (
        finding.get("status") != "draft_unverified"
        or not isinstance(finding_id, str)
        or not isinstance(finding_path, str)
        or not isinstance(record_path, str)
    ):
        raise CliError("draft campaign finding is invalid", exit_code=EXIT_AUTHORITY)
    findings = inputs.records.workspace / "findings"
    expected_markdown = findings / f"{finding_id}.md"
    expected_record = findings / f"{finding_id}.json"
    try:
        if Path(finding_path).resolve(strict=True) != expected_markdown.resolve(strict=True) or Path(record_path).resolve(strict=True) != expected_record.resolve(strict=True):
            raise CliError("draft campaign finding path is invalid", exit_code=EXIT_AUTHORITY)
    except OSError as exc:
        raise CliError("draft campaign finding is unavailable", exit_code=EXIT_AUTHORITY) from exc
    record = _capture_campaign_json(expected_record, label="draft campaign finding")
    _ = _capture_bounded_local_file(expected_markdown, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="draft campaign finding")
    if (
        record.get("schema") != "faultloom.manual-finding.v1"
        or record.get("finding_id") != finding_id
        or record.get("run_id") != inputs.manifest["run_id"]
        or record.get("status") != "draft_unverified"
        or record.get("evidence_ids") != evidence_ids
    ):
        raise CliError("draft campaign finding does not match its receipt", exit_code=EXIT_AUTHORITY)


def _validate_completed_campaign_finalization(
    arguments: argparse.Namespace, final_receipt: Path
) -> tuple[str, int]:
    """Read-only terminal validation shared by finalization resume and supervision."""
    inputs = _validated_campaign_finalization_inputs(arguments)
    receipt = _capture_campaign_json(final_receipt, label="campaign final receipt")
    finalize_start = _campaign_record(inputs.records, arguments.campaign_id, "finalize-start")
    finalize = _capture_campaign_json(finalize_start, label="campaign finalization start")
    start_digest = sha256_hex(_capture_bounded_local_file(inputs.start_path, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign start record"))
    result_digest = sha256_hex(_capture_bounded_local_file(inputs.result_path, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign run result"))
    if (
        finalize.get("schema") != "faultloom.personal-http1-triad-finalize-start.v1"
        or finalize.get("campaign_id") != arguments.campaign_id
        or finalize.get("start_sha256") != start_digest
        or finalize.get("run_result_sha256") != result_digest
        or finalize.get("reviewed_non_sensitive") is not True
        or finalize.get("classifier") != EXACT_BODY_DIGEST_CLASSIFIER
    ):
        raise CliError("campaign finalization start is invalid", exit_code=EXIT_AUTHORITY)
    body_digests, response_digests, outcome_status = _campaign_finalization_digests(inputs)
    evidence_ids = receipt.get("evidence_ids")
    if not isinstance(evidence_ids, list) or (
        receipt.get("schema") != "faultloom.personal-http1-triad-final-receipt.v1"
        or receipt.get("campaign_id") != arguments.campaign_id
        or receipt.get("status") != outcome_status
        or receipt.get("classifier") != EXACT_BODY_DIGEST_CLASSIFIER
        or receipt.get("dispatch_count") != 3
        or receipt.get("response_sha256") != response_digests
        or receipt.get("body_sha256") != body_digests
        or receipt.get("automatic_submission") is not False
        or receipt.get("independent_verification") is not False
        or receipt.get("manual_review") != "confirmed_non_sensitive_response_review"
    ):
        raise CliError("campaign final receipt is invalid", exit_code=EXIT_AUTHORITY)
    start_binding = inputs.start.get("automation_binding")
    start_binding_digest = inputs.start.get("automation_binding_digest")
    if start_binding is None and start_binding_digest is None:
        if "automation_binding" in receipt or "automation_binding_digest" in receipt:
            raise CliError("campaign final receipt has unexpected automation provenance", exit_code=EXIT_AUTHORITY)
    elif receipt.get("automation_binding") != start_binding or receipt.get("automation_binding_digest") != start_binding_digest:
        raise CliError("campaign final receipt automation provenance differs", exit_code=EXIT_AUTHORITY)
    _validated_campaign_evidence(inputs=inputs, evidence_ids=evidence_ids)
    _validated_campaign_finding(
        inputs=inputs, receipt=receipt, outcome_status=outcome_status, evidence_ids=evidence_ids
    )
    return outcome_status, 3


def _handoff_workspace_file(
    workspace: Path, path: Path, *, label: str, maximum_bytes: int, expected: bytes | None = None
) -> tuple[str, dict[str, object]]:
    """Return a bounded, non-symlink workspace-local file reference."""
    try:
        root = workspace.resolve(strict=True)
        workspace_metadata = workspace.lstat()
        candidate = path if path.is_absolute() else Path.cwd() / path
        relative = candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise CliError(f"{label} path is not workspace-local", exit_code=EXIT_AUTHORITY) from exc
    if (
        stat.S_ISLNK(workspace_metadata.st_mode)
        or not stat.S_ISDIR(workspace_metadata.st_mode)
        or workspace.is_junction()
        or not relative.parts
        or any(component in {"", ".", ".."} for component in relative.parts)
    ):
        raise CliError(f"{label} path is unsafe", exit_code=EXIT_AUTHORITY)
    current = root
    for component in relative.parts[:-1]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise CliError(f"cannot inspect {label} path", exit_code=EXIT_AUTHORITY) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or current.is_junction()
        ):
            raise CliError(f"{label} path is unsafe", exit_code=EXIT_AUTHORITY)
    file_path = current / relative.parts[-1]
    content = _capture_bounded_local_file(file_path, maximum_bytes=maximum_bytes, label=label)
    if expected is not None and content != expected:
        raise CliError(f"{label} changed after finalization validation", exit_code=EXIT_AUTHORITY)
    reference_content = content if expected is None else expected
    return str(relative), {
        "path": str(relative),
        "sizeBytes": len(reference_content),
        "sha256": sha256_hex(reference_content),
    }


def _handoff_output_path(workspace: Path, path: Path) -> tuple[Path, str]:
    """Accept only a direct workspace-child output to keep publication pinned."""
    try:
        root = workspace.resolve(strict=True)
        candidate = path if path.is_absolute() else Path.cwd() / path
        relative = candidate.relative_to(root)
    except (OSError, ValueError) as exc:
        raise CliError("verification handoff output is not workspace-local", exit_code=EXIT_AUTHORITY) from exc
    if len(relative.parts) != 1 or not _is_safe_handoff_filename(relative.name):
        raise CliError("verification handoff output path is unsafe", exit_code=EXIT_AUTHORITY)
    output = root / relative.name
    try:
        metadata = output.lstat()
    except FileNotFoundError:
        return output, str(relative)
    except OSError as exc:
        raise CliError("cannot inspect verification handoff output", exit_code=EXIT_AUTHORITY) from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CliError("verification handoff output is not a regular non-symlink file", exit_code=EXIT_AUTHORITY)
    return output, str(relative)


def _write_or_verify_handoff_output(workspace: Path, output: Path, content: bytes) -> None:
    """Create one direct-child private file through a pinned workspace directory."""
    name = output.name
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if os.name == "nt":
        guard = _open_windows_response_directory_guard(workspace)
        try:
            metadata = workspace.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or workspace.is_junction():
                raise CliError("verification handoff output parent is unsafe", exit_code=EXIT_AUTHORITY)
            created = True
            try:
                descriptor = _windows_open_handoff_child(guard, name, create=True)
            except FileExistsError:
                created = False
                descriptor = _windows_open_handoff_child(guard, name, create=False)
            try:
                import msvcrt

                fd = msvcrt.open_osfhandle(descriptor, os.O_BINARY | os.O_RDWR)
                descriptor = -1
                try:
                    metadata = os.fstat(fd)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_PROTOCOL_FILE_BYTES:
                        raise CliError("verification handoff output is not a regular file", exit_code=EXIT_AUTHORITY)
                    if not created:
                        chunks: list[bytes] = []
                        remaining = metadata.st_size
                        while remaining:
                            chunk = os.read(fd, min(PROTOCOL_READ_CHUNK_BYTES, remaining))
                            if not chunk:
                                raise CliError(
                                    "verification handoff output changed while reading",
                                    exit_code=EXIT_AUTHORITY,
                                )
                            chunks.append(chunk)
                            remaining -= len(chunk)
                        existing = b"".join(chunks)
                        if existing != content:
                            raise CliError("existing verification handoff output differs", exit_code=EXIT_AUTHORITY)
                    else:
                        offset = 0
                        while offset < len(content):
                            offset += os.write(fd, content[offset:])
                        os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                if descriptor != -1:
                    _close_windows_response_directory_guard(descriptor)
        except OSError as exc:
            raise CliError("cannot create verification handoff output", exit_code=EXIT_USAGE) from exc
        finally:
            _close_windows_response_directory_guard(guard)
        return
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    try:
        expected = workspace.lstat()
        directory = os.open(workspace, directory_flags)
        try:
            if not _stat_matches(os.fstat(directory), expected, _DIRECTORY_STAT_FIELDS):
                raise CliError("verification handoff output parent changed", exit_code=EXIT_AUTHORITY)
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=directory)
            except FileExistsError:
                read_flags = os.O_RDONLY | os.O_NOFOLLOW
                if hasattr(os, "O_CLOEXEC"):
                    read_flags |= os.O_CLOEXEC
                descriptor = os.open(name, read_flags, dir_fd=directory)
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_PROTOCOL_FILE_BYTES:
                        raise CliError("verification handoff output is not a regular file", exit_code=EXIT_AUTHORITY)
                    chunks: list[bytes] = []
                    remaining = metadata.st_size
                    while remaining:
                        chunk = os.read(descriptor, min(PROTOCOL_READ_CHUNK_BYTES, remaining))
                        if not chunk:
                            raise CliError("verification handoff output changed while reading", exit_code=EXIT_AUTHORITY)
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    existing = b"".join(chunks)
                    if existing != content:
                        raise CliError("existing verification handoff output differs", exit_code=EXIT_AUTHORITY)
                finally:
                    os.close(descriptor)
                return
            try:
                offset = 0
                while offset < len(content):
                    offset += os.write(descriptor, content[offset:])
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
                os.fsync(directory)
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
    except CliError:
        raise
    except OSError as exc:
        raise CliError("cannot create verification handoff output", exit_code=EXIT_USAGE) from exc


def _campaign_verification_handoff_bytes(arguments: argparse.Namespace) -> bytes:
    """Build one private replay manifest after fully revalidating a finalized v2 campaign."""
    final_receipt = _campaign_record(
        _campaign_records_directory(arguments.workspace), arguments.campaign_id, "final-receipt"
    )
    snapshots: dict[Path, bytes] = {}
    token = _HANDOFF_VALIDATION_SNAPSHOTS.set(snapshots)
    try:
        inputs = _validated_campaign_finalization_inputs(arguments)
        status, _ = _validate_completed_campaign_finalization(arguments, final_receipt)
    finally:
        _HANDOFF_VALIDATION_SNAPSHOTS.reset(token)
    if status != "draft_unverified":
        raise CliError("verification handoff requires a draft_unverified campaign", exit_code=EXIT_AUTHORITY)
    def snapshot(path: Path, *, label: str) -> bytes:
        try:
            return snapshots[path.resolve(strict=True)]
        except (KeyError, OSError) as exc:
            raise CliError(f"{label} was not captured during finalization validation", exit_code=EXIT_AUTHORITY) from exc

    receipt = _parse_campaign_json_content(
        snapshot(final_receipt, label="campaign final receipt"), label="campaign final receipt"
    )
    spec_path_value = inputs.start.get("spec_path")
    if not isinstance(spec_path_value, str):
        raise CliError("campaign start record lacks its spec binding", exit_code=EXIT_AUTHORITY)
    spec_content = snapshot(Path(spec_path_value), label="campaign spec")
    try:
        spec = parse_personal_http1_triad_spec(spec_content)
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    binding = spec.automation_binding
    binding_provenance = _automation_binding_provenance(spec)
    start_binding = inputs.start.get("automation_binding")
    start_binding_digest = inputs.start.get("automation_binding_digest")
    if (
        spec.schema_ != PERSONAL_HTTP1_TRIAD_BOUND_SCHEMA
        or binding is None
        or binding.schema_ != PERSONAL_HTTP1_TRIAD_AUTOMATION_BINDING_SCHEMA
        or not isinstance(start_binding, dict)
        or not isinstance(start_binding_digest, str)
        or binding_provenance is None
        or start_binding != binding_provenance["binding"]
        or start_binding_digest != sha256_digest(start_binding)
        or receipt.get("automation_binding") != start_binding
        or receipt.get("automation_binding_digest") != start_binding_digest
    ):
        raise CliError("verification handoff requires an exact v2 automation binding", exit_code=EXIT_AUTHORITY)
    finding = receipt.get("finding")
    if not isinstance(finding, dict):
        raise CliError("draft campaign finding is invalid", exit_code=EXIT_AUTHORITY)
    finding_id = finding.get("finding_id")
    finding_record_path = finding.get("record")
    finding_markdown_path = finding.get("finding")
    start_finding = inputs.start.get("finding")
    if (
        finding.get("status") != "draft_unverified"
        or not isinstance(finding_id, str)
        or not isinstance(finding_record_path, str)
        or not isinstance(finding_markdown_path, str)
        or not isinstance(start_finding, dict)
    ):
        raise CliError("draft campaign finding is invalid", exit_code=EXIT_AUTHORITY)
    finding_record = _parse_campaign_json_content(
        snapshot(Path(finding_record_path), label="draft campaign finding"), label="draft campaign finding"
    )
    for field in ("title", "severity", "summary", "impact", "remediation"):
        if finding_record.get(field) != start_finding.get(field):
            raise CliError("draft campaign finding prose differs from campaign start", exit_code=EXIT_AUTHORITY)
    if (
        finding_record.get("finding_id") != finding_id
        or finding_record.get("run_id") != inputs.manifest.get("run_id")
        or finding_record.get("status") != "draft_unverified"
        or finding_record.get("evidence_ids") != receipt.get("evidence_ids")
    ):
        raise CliError("draft campaign finding does not match its final receipt", exit_code=EXIT_AUTHORITY)

    refs: dict[str, object] = {}
    for name, path, limit in (
        ("run", inputs.records.workspace / "run.json", MAX_PROTOCOL_FILE_BYTES),
        ("spec", Path(spec_path_value), MAX_PROTOCOL_FILE_BYTES),
        ("start", inputs.start_path, MAX_PROTOCOL_FILE_BYTES),
        ("runResult", inputs.result_path, MAX_PROTOCOL_FILE_BYTES),
        ("finalizeStart", _campaign_record(inputs.records, arguments.campaign_id, "finalize-start"), MAX_PROTOCOL_FILE_BYTES),
        ("finalReceipt", final_receipt, MAX_PROTOCOL_FILE_BYTES),
    ):
        _, refs[name] = _handoff_workspace_file(
            inputs.records.workspace, path, label=name, maximum_bytes=limit,
            expected=snapshot(path, label=name),
        )
    _, finding_record_ref = _handoff_workspace_file(
        inputs.records.workspace, Path(finding_record_path), label="finding record",
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
        expected=snapshot(Path(finding_record_path), label="finding record"),
    )
    # The JSON record is the exact prose/status/evidence source validated above.
    # Do not hand off the human-readable Markdown separately: finalization only
    # requires its presence, so it is not a second immutable prose authority.
    refs["finding"] = {"id": finding_id, "status": "draft_unverified", "record": finding_record_ref}

    binding_refs: dict[str, object] = {}
    for name, path_value, limit in (
        ("result", binding.result_path, MAX_PROTOCOL_FILE_BYTES),
        ("receipt", binding.receipt_path, MAX_PROTOCOL_FILE_BYTES),
        ("template", binding.template_path, MAX_PROTOCOL_FILE_BYTES),
        ("effectRequest", binding.effect_request_path, PERSONAL_HTTP1_MAX_REQUEST_BYTES),
        ("negativeControlRequest", binding.negative_control_request_path, PERSONAL_HTTP1_MAX_REQUEST_BYTES),
    ):
        _, binding_refs[name] = _handoff_workspace_file(
            inputs.records.workspace, Path(path_value), label=f"automation {name}", maximum_bytes=limit,
            expected=snapshot(Path(path_value), label=f"automation {name}"),
        )

    evidence_ids = receipt.get("evidence_ids")
    if not isinstance(evidence_ids, list) or not all(isinstance(value, str) for value in evidence_ids):
        raise CliError("campaign final receipt has invalid evidence ids", exit_code=EXIT_AUTHORITY)
    evidence = _workspace_evidence(
        inputs.records.workspace, run_id=str(inputs.manifest["run_id"]), selected_ids=tuple(evidence_ids)
    )
    dispatched = inputs.result.get("requests")
    if not isinstance(dispatched, list):
        raise CliError("campaign run result is invalid", exit_code=EXIT_AUTHORITY)
    exchanges: list[dict[str, object]] = []
    for (role, _, _, _), record, dispatch in zip(inputs.sources, evidence, dispatched, strict=True):
        request = record.get("request") if isinstance(record, dict) else None
        response = record.get("response") if isinstance(record, dict) else None
        evidence_id = record.get("evidence_id") if isinstance(record, dict) else None
        if (
            not isinstance(request, dict)
            or not isinstance(response, dict)
            or not isinstance(evidence_id, str)
            or not isinstance(request.get("stored_file"), str)
            or not isinstance(response.get("stored_file"), str)
            or not isinstance(dispatch, dict)
            or record.get("reservation_id") != dispatch.get("reservation")
        ):
            raise CliError("archived campaign evidence is invalid", exit_code=EXIT_AUTHORITY)
        dispatched_request = dispatch.get("request")
        dispatched_response = dispatch.get("response")
        body_sha256 = dispatch.get("bodySha256")
        if (
            not isinstance(dispatched_request, dict)
            or not isinstance(dispatched_request.get("sha256"), str)
            or not isinstance(dispatched_response, dict)
            or not isinstance(dispatched_response.get("sha256"), str)
            or not isinstance(body_sha256, str)
        ):
            raise CliError("campaign run result is incomplete", exit_code=EXIT_AUTHORITY)
        record_path = inputs.records.workspace / "evidence" / "raw" / f"{evidence_id}.json"
        raw_directory = inputs.records.workspace / "evidence" / "raw"
        request_path = raw_directory / request["stored_file"]
        response_path = raw_directory / response["stored_file"]
        _, record_ref = _handoff_workspace_file(
            inputs.records.workspace, record_path, label=f"{role} evidence record",
            maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
            expected=snapshot(record_path, label=f"{role} evidence record"),
        )
        _, request_ref = _handoff_workspace_file(
            inputs.records.workspace, request_path, label=f"{role} evidence request",
            maximum_bytes=PERSONAL_HTTP1_MAX_REQUEST_BYTES,
            expected=snapshot(request_path, label=f"{role} evidence request"),
        )
        _, response_ref = _handoff_workspace_file(
            inputs.records.workspace, response_path, label=f"{role} evidence response",
            maximum_bytes=PERSONAL_HTTP1_MAX_RESPONSE_BYTES,
            expected=snapshot(response_path, label=f"{role} evidence response"),
        )
        exchanges.append({
            "role": role,
            "evidenceId": evidence_id,
            "requestSha256": dispatched_request["sha256"],
            "responseSha256": dispatched_response["sha256"],
            "bodySha256": body_sha256,
            "record": record_ref,
            "request": request_ref,
            "response": response_ref,
        })

    manifest = {
        "schema": "faultloom.campaign-verification-handoff.v1",
        "status": "verification_handoff_ready",
        "verificationStatus": "pending",
        "independentVerification": False,
        "targetDispatch": False,
        "networkAccess": False,
        "automaticSubmission": False,
        "campaign": {"id": arguments.campaign_id, "runId": inputs.manifest["run_id"], "grantId": inputs.manifest["grant_id"], "grantVersion": inputs.manifest["grant_version"]},
        "automation": {
            "candidateId": binding.candidate_id,
            "candidateSource": binding.candidate_source,
            "candidateDigest": binding.candidate_digest,
            "bindingDigest": start_binding_digest,
            "signedAuthorityEnvelopeSha256": inputs.manifest.get("authority_sha256"),
            "references": binding_refs,
        },
        "manualFindingId": finding_id,
        "references": refs,
        "evidence": exchanges,
        "replayRequirements": {
            "freshIdentityAndReset": True,
            "positiveReplay": True,
            "negativeControl": True,
            "newVerifierEvidence": True,
            "sourceEvidenceReuse": False,
        },
    }
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _campaign_export_verification_handoff(arguments: argparse.Namespace) -> int:
    output, output_relative = _handoff_output_path(arguments.workspace, arguments.out)
    content = _campaign_verification_handoff_bytes(arguments)
    _write_or_verify_handoff_output(arguments.workspace, output, content)
    _emit_json({
        "schema": "faultloom.campaign-verification-handoff-export.v1",
        "handoff": output_relative,
        "sha256": sha256_hex(content),
        "status": "verification_handoff_ready",
        "verificationStatus": "pending",
        "independentVerification": False,
        "targetDispatch": False,
        "networkAccess": False,
        "automaticSubmission": False,
    })
    return EXIT_OK


@dataclass(frozen=True)
class _IndependentHttp1Context:
    source_workspace: Path
    verifier_workspace: Path
    source_manifest: dict[str, object]
    source_grant: AuthorityGrant
    source_target: TargetAsset
    source_authority: SignedAuthorityGrant
    verifier_manifest: dict[str, object]
    verifier_grant: AuthorityGrant
    verifier_target: TargetAsset
    verifier_authority: SignedAuthorityGrant
    handoff: dict[str, object]
    handoff_content: bytes


def _verification_handoff_document(arguments: argparse.Namespace) -> _IndependentHttp1Context:
    """Rebuild the source handoff and prove a separate active verifier boundary."""
    try:
        require_separate_workspaces(arguments.source_workspace, arguments.verifier_workspace)
    except Http1TriadVerificationError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    source_manifest, source_grant, source_target, _ = _verified_request_workspace(
        arguments.source_workspace, arguments.source_trusted_key, require_active=False
    )
    verifier_manifest, verifier_grant, verifier_target, _ = _verified_request_workspace(
        arguments.verifier_workspace, arguments.verifier_trusted_key
    )
    source_authority_path = arguments.source_workspace / "authority.json"
    verifier_authority_path = arguments.verifier_workspace / "authority.json"
    source_authority = _parse_protocol_file(
        source_authority_path,
        _capture_single_protocol_file(source_authority_path),
        SignedAuthorityGrant,
    )
    verifier_authority = _parse_protocol_file(
        verifier_authority_path,
        _capture_single_protocol_file(verifier_authority_path),
        SignedAuthorityGrant,
    )
    try:
        require_independent_identity(
            source_actor=source_grant.issued_to,
            verifier_actor=verifier_grant.issued_to,
            source_key_id=source_authority.signature.key_id,
            verifier_key_id=verifier_authority.signature.key_id,
            source_authority_digest=sha256_digest(source_authority),
            verifier_authority_digest=sha256_digest(verifier_authority),
        )
    except Http1TriadVerificationError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    if source_target != verifier_target:
        raise CliError("verifier target must exactly match the source target", exit_code=EXIT_AUTHORITY)

    expected = _campaign_verification_handoff_bytes(
        argparse.Namespace(
            workspace=arguments.source_workspace,
            trusted_key=arguments.source_trusted_key,
            campaign_id=arguments.campaign_id,
        )
    )
    handoff_content = _capture_bounded_local_file(
        arguments.handoff, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="verification handoff"
    )
    if handoff_content != expected:
        raise CliError("verification handoff differs from the validated source campaign", exit_code=EXIT_AUTHORITY)
    handoff = _parse_campaign_json_content(handoff_content, label="verification handoff")
    return _IndependentHttp1Context(
        source_workspace=arguments.source_workspace,
        verifier_workspace=arguments.verifier_workspace,
        source_manifest=source_manifest,
        source_grant=source_grant,
        source_target=source_target,
        source_authority=source_authority,
        verifier_manifest=verifier_manifest,
        verifier_grant=verifier_grant,
        verifier_target=verifier_target,
        verifier_authority=verifier_authority,
        handoff=handoff,
        handoff_content=handoff_content,
    )


def _handoff_ref_path(
    workspace: Path, reference: object, *, label: str, maximum_bytes: int
) -> tuple[Path, bytes]:
    if not isinstance(reference, dict):
        raise CliError(f"{label} reference is invalid", exit_code=EXIT_AUTHORITY)
    path_value = reference.get("path")
    size = reference.get("sizeBytes")
    digest = reference.get("sha256")
    if not isinstance(path_value, str) or not isinstance(size, int) or not isinstance(digest, str):
        raise CliError(f"{label} reference is invalid", exit_code=EXIT_AUTHORITY)
    path = workspace / path_value
    relative, captured = _handoff_workspace_file(
        workspace, path, label=label, maximum_bytes=maximum_bytes
    )
    content = _capture_bounded_local_file(path, maximum_bytes=maximum_bytes, label=label)
    if relative != path_value or captured != reference or len(content) != size or sha256_hex(content) != digest:
        raise CliError(f"{label} reference digest differs", exit_code=EXIT_AUTHORITY)
    return path, content


def _source_verification_requests(
    context: _IndependentHttp1Context,
) -> tuple[PersonalHttp1TriadSpec, bytes, bytes, dict[str, str]]:
    references = context.handoff.get("references")
    if not isinstance(references, dict):
        raise CliError("verification handoff references are invalid", exit_code=EXIT_AUTHORITY)
    _, spec_content = _handoff_ref_path(
        context.source_workspace,
        references.get("spec"),
        label="source campaign spec",
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
    )
    try:
        spec = parse_personal_http1_triad_spec(spec_content)
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    if spec.effect.method not in {"GET", "OPTIONS"}:
        raise CliError("verification method must be GET or OPTIONS", exit_code=EXIT_AUTHORITY)
    evidence = context.handoff.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != 3:
        raise CliError("verification handoff evidence is invalid", exit_code=EXIT_AUTHORITY)
    by_role = {
        item.get("role"): item for item in evidence
        if isinstance(item, dict) and isinstance(item.get("role"), str)
    }
    if set(by_role) != {"effect", "reproduction", "negative_control"}:
        raise CliError("verification handoff evidence roles are invalid", exit_code=EXIT_AUTHORITY)
    requests: dict[str, bytes] = {}
    body_digests: dict[str, str] = {}
    for role in ("effect", "reproduction", "negative_control"):
        item = by_role[role]
        _, content = _handoff_ref_path(
            context.source_workspace,
            item.get("request"),
            label=f"source {role} request",
            maximum_bytes=PERSONAL_HTTP1_MAX_REQUEST_BYTES,
        )
        expected_request = item.get("requestSha256")
        body_digest = item.get("bodySha256")
        if sha256_hex(content) != expected_request or not isinstance(body_digest, str):
            raise CliError("source verification evidence digest differs", exit_code=EXIT_AUTHORITY)
        request = spec.effect if role != "negative_control" else spec.negative_control
        _parse_raw_http11_request(
            content,
            hostname=spec.hostname,
            port=spec.port,
            scheme=spec.scheme,
            method=request.method,
            path=request.path,
            require_connection_close=True,
        )
        try:
            strict = parse_strict_http1_request(content)
        except Http1TriadVerificationError as exc:
            raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
        if strict.method != request.method or strict.path != request.path:
            raise CliError("source verification request differs from its spec", exit_code=EXIT_AUTHORITY)
        requests[role] = content
        body_digests[role] = body_digest
    if requests["effect"] != requests["reproduction"]:
        raise CliError("source reproduction request differs from source effect request", exit_code=EXIT_AUTHORITY)
    effect_line, effect_headers = requests["effect"].split(b"\r\n", 1)
    control_line, control_headers = requests["negative_control"].split(b"\r\n", 1)
    if effect_headers != control_headers or effect_line == control_line:
        raise CliError("source requests must differ only by request target", exit_code=EXIT_AUTHORITY)
    return spec, requests["effect"], requests["negative_control"], body_digests


def _campaign_prepare_verification_http1(arguments: argparse.Namespace) -> int:
    context = _verification_handoff_document(arguments)
    source_spec, effect_request, control_request, body_digests = _source_verification_requests(context)
    if not arguments.prerequisite or any(not value.strip() for value in arguments.prerequisite):
        raise CliError("at least one explicit prerequisite is required", exit_code=EXIT_USAGE)
    semantics_value = {
        "findingClass": arguments.finding_class,
        "claim": arguments.claim,
        "prerequisites": list(arguments.prerequisite),
    }
    semantics_digest = sha256_digest(semantics_value)
    semantics_tag = semantics_digest.removeprefix("sha256:")
    campaign_tag = sha256_hex(arguments.campaign_id.encode())[:16]
    references = context.handoff.get("references")
    finding_ref = references.get("finding") if isinstance(references, dict) else None
    record_ref = finding_ref.get("record") if isinstance(finding_ref, dict) else None
    _, finding_content = _handoff_ref_path(
        context.source_workspace,
        record_ref,
        label="source finding record",
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
    )
    finding = _parse_campaign_json_content(finding_content, label="source finding record")
    required_finding = {
        name: finding.get(name) for name in ("title", "severity", "summary", "impact", "remediation")
    }
    if not all(isinstance(value, str) and value for value in required_finding.values()):
        raise CliError("source finding prose is incomplete", exit_code=EXIT_AUTHORITY)

    output, output_relative = _handoff_output_path(context.verifier_workspace, arguments.out)
    effect_name = f"verify-{campaign_tag}-effect-{semantics_tag}.raw"
    control_name = f"verify-{campaign_tag}-negative-{semantics_tag}.raw"
    case_name = f"{arguments.campaign_id}.verification-case.json"
    prepare_receipt_name = f"{arguments.campaign_id}.verification-prepare-receipt.json"
    for name in (effect_name, control_name, case_name, prepare_receipt_name):
        if not _is_safe_handoff_filename(name):
            raise CliError("verification output filename is unsafe", exit_code=EXIT_AUTHORITY)
    triad = {
        "schema": PERSONAL_HTTP1_TRIAD_SCHEMA,
        "campaign_id": arguments.campaign_id,
        "authorization_reference": "authority.json",
        "authorization_document_sha256": context.verifier_manifest["authority_sha256"],
        "hostname": source_spec.hostname,
        "port": source_spec.port,
        "scheme": source_spec.scheme,
        "timeout_seconds": source_spec.timeout_seconds,
        "requests": [
            {
                "role": "effect",
                "method": source_spec.effect.method,
                "path": source_spec.effect.path,
                "request_file": effect_name,
                "response_bytes": source_spec.effect.response_bytes,
            },
            {
                "role": "negative_control",
                "method": source_spec.negative_control.method,
                "path": source_spec.negative_control.path,
                "request_file": control_name,
                "response_bytes": source_spec.negative_control.response_bytes,
            },
        ],
        "finding": required_finding,
    }
    triad_content = (json.dumps(triad, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        _ = parse_personal_http1_triad_spec(triad_content)
        FindingClass(arguments.finding_class)
    except (PersonalCampaignError, ValueError) as exc:
        raise CliError(f"invalid verification case: {exc}", exit_code=EXIT_USAGE) from exc
    case = {
        "schema": "faultloom.independent-http1-case.v1",
        "campaignId": arguments.campaign_id,
        "source": {
            "actor": context.source_grant.issued_to,
            "authorityDigest": sha256_digest(context.source_authority),
            "handoffSha256": sha256_hex(context.handoff_content),
            "runId": context.source_manifest["run_id"],
            "effectBodySha256": body_digests["effect"],
            "negativeControlBodySha256": body_digests["negative_control"],
        },
        "verifier": {
            "actor": context.verifier_grant.issued_to,
            "authorityDigest": sha256_digest(context.verifier_authority),
            "runId": context.verifier_manifest["run_id"],
        },
        "semantics": semantics_value,
        "semanticsDigest": semantics_digest,
        "triad": {
            "spec": {"path": output_relative, "sizeBytes": len(triad_content), "sha256": sha256_hex(triad_content)},
            "effectRequest": {"path": effect_name, "sizeBytes": len(effect_request), "sha256": sha256_hex(effect_request)},
            "negativeControlRequest": {"path": control_name, "sizeBytes": len(control_request), "sha256": sha256_hex(control_request)},
        },
        "networkAccess": False,
        "automaticSubmission": False,
    }
    case_content = (json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n").encode()
    prepare_receipt = {
        "schema": "faultloom.independent-http1-prepare-receipt.v1",
        "campaignId": arguments.campaign_id,
        "sourceHandoffSha256": sha256_hex(context.handoff_content),
        "sourceAuthorityDigest": sha256_digest(context.source_authority),
        "sourceRunId": context.source_manifest["run_id"],
        "verifierAuthorityDigest": sha256_digest(context.verifier_authority),
        "verifierRunId": context.verifier_manifest["run_id"],
        "semanticsDigest": semantics_digest,
        "case": {"path": case_name, "sizeBytes": len(case_content), "sha256": sha256_hex(case_content)},
        "spec": {"path": output_relative, "sizeBytes": len(triad_content), "sha256": sha256_hex(triad_content)},
        "effectRequest": {"path": effect_name, "sizeBytes": len(effect_request), "sha256": sha256_hex(effect_request)},
        "negativeControlRequest": {"path": control_name, "sizeBytes": len(control_request), "sha256": sha256_hex(control_request)},
        "networkAccess": False,
        "automaticSubmission": False,
    }
    prepare_receipt_content = (
        json.dumps(prepare_receipt, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    _write_or_verify_handoff_output(
        context.verifier_workspace, context.verifier_workspace / effect_name, effect_request
    )
    _write_or_verify_handoff_output(
        context.verifier_workspace, context.verifier_workspace / control_name, control_request
    )
    _write_or_verify_handoff_output(context.verifier_workspace, output, triad_content)
    _write_or_verify_handoff_output(
        context.verifier_workspace, context.verifier_workspace / case_name, case_content
    )
    _write_or_verify_handoff_output(
        context.verifier_workspace,
        context.verifier_workspace / prepare_receipt_name,
        prepare_receipt_content,
    )
    _emit_json({
        "schema": "faultloom.independent-http1-prepare.v1",
        "campaignId": arguments.campaign_id,
        "case": case_name,
        "receipt": prepare_receipt_name,
        "triad": output_relative,
        "status": "ready_for_existing_triad_runner",
        "networkAccess": False,
        "automaticSubmission": False,
    })
    return EXIT_OK


def _verification_case_document(
    arguments: argparse.Namespace, context: _IndependentHttp1Context
) -> dict[str, object]:
    try:
        case_path = arguments.case.resolve(strict=True)
        if case_path.parent != context.verifier_workspace.resolve(strict=True):
            raise ValueError("not a direct verifier-workspace child")
    except (OSError, ValueError) as exc:
        raise CliError("verification case path is unsafe", exit_code=EXIT_AUTHORITY) from exc
    case_content = _capture_bounded_local_file(
        case_path, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="verification case"
    )
    case = _parse_campaign_json_content(case_content, label="verification case")
    source = case.get("source")
    verifier = case.get("verifier")
    semantics = case.get("semantics")
    triad = case.get("triad")
    if (
        case.get("schema") != "faultloom.independent-http1-case.v1"
        or case.get("campaignId") != arguments.campaign_id
        or case.get("networkAccess") is not False
        or case.get("automaticSubmission") is not False
        or not isinstance(source, dict)
        or not isinstance(verifier, dict)
        or not isinstance(semantics, dict)
        or not isinstance(triad, dict)
        or case.get("semanticsDigest") != sha256_digest(semantics)
        or source.get("actor") != context.source_grant.issued_to
        or source.get("authorityDigest") != sha256_digest(context.source_authority)
        or source.get("handoffSha256") != sha256_hex(context.handoff_content)
        or source.get("runId") != context.source_manifest["run_id"]
        or verifier.get("actor") != context.verifier_grant.issued_to
        or verifier.get("authorityDigest") != sha256_digest(context.verifier_authority)
        or verifier.get("runId") != context.verifier_manifest["run_id"]
    ):
        raise CliError("verification case boundary differs", exit_code=EXIT_AUTHORITY)
    claim = semantics.get("claim")
    prerequisites = semantics.get("prerequisites")
    try:
        FindingClass(semantics.get("findingClass"))
    except ValueError as exc:
        raise CliError("verification finding class is invalid", exit_code=EXIT_AUTHORITY) from exc
    if (
        not isinstance(claim, str)
        or not claim.strip()
        or not isinstance(prerequisites, list)
        or not prerequisites
        or not all(isinstance(value, str) and value.strip() for value in prerequisites)
    ):
        raise CliError("verification case semantics are incomplete", exit_code=EXIT_AUTHORITY)
    return case


def _verification_prepare_receipt(
    arguments: argparse.Namespace, context: _IndependentHttp1Context
) -> dict[str, object]:
    path = context.verifier_workspace / f"{arguments.campaign_id}.verification-prepare-receipt.json"
    content = _capture_bounded_local_file(
        path, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="verification prepare receipt"
    )
    receipt = _parse_campaign_json_content(content, label="verification prepare receipt")
    if (
        receipt.get("schema") != "faultloom.independent-http1-prepare-receipt.v1"
        or receipt.get("campaignId") != arguments.campaign_id
        or receipt.get("sourceHandoffSha256") != sha256_hex(context.handoff_content)
        or receipt.get("sourceAuthorityDigest") != sha256_digest(context.source_authority)
        or receipt.get("sourceRunId") != context.source_manifest["run_id"]
        or receipt.get("verifierAuthorityDigest") != sha256_digest(context.verifier_authority)
        or receipt.get("verifierRunId") != context.verifier_manifest["run_id"]
        or receipt.get("networkAccess") is not False
        or receipt.get("automaticSubmission") is not False
    ):
        raise CliError("verification prepare receipt boundary differs", exit_code=EXIT_AUTHORITY)
    case_path, _ = _handoff_ref_path(
        context.verifier_workspace,
        receipt.get("case"),
        label="prepared verification case",
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
    )
    try:
        if case_path.resolve(strict=True) != arguments.case.resolve(strict=True):
            raise CliError("verification case differs from its prepare receipt", exit_code=EXIT_AUTHORITY)
    except OSError as exc:
        raise CliError("verification case is unavailable", exit_code=EXIT_AUTHORITY) from exc
    return receipt


def _verification_evidence_refs(
    *, records: list[dict[str, object]], run_id: str, created_at: datetime
) -> tuple[EvidenceRef, EvidenceRef, EvidenceRef]:
    if len(records) != 3:
        raise CliError("verifier evidence ids are invalid", exit_code=EXIT_AUTHORITY)
    references: list[EvidenceRef] = []
    for record in records:
        evidence_id = record.get("evidence_id")
        request = record.get("request")
        response = record.get("response")
        if (
            not isinstance(evidence_id, str)
            or not isinstance(request, dict)
            or not isinstance(response, dict)
            or not isinstance(request.get("sha256"), str)
            or not isinstance(response.get("sha256"), str)
        ):
            raise CliError("verifier evidence record is invalid", exit_code=EXIT_AUTHORITY)
        references.append(EvidenceRef(
            schema_version=SCHEMA_VERSION,
            evidence_id=evidence_id,
            run_id=run_id,
            cas_digest=f"sha256:{response['sha256']}",
            observation_ids=(),
            redaction_digest=None,
            created_at=created_at,
        ))
    return cast(tuple[EvidenceRef, EvidenceRef, EvidenceRef], tuple(references))


def _campaign_compile_verification_http1(arguments: argparse.Namespace) -> int:
    context = _verification_handoff_document(arguments)
    try:
        private_path = arguments.private_key.resolve(strict=True)
        for workspace in (context.source_workspace, context.verifier_workspace):
            try:
                private_path.relative_to(workspace.resolve(strict=True))
            except ValueError:
                continue
            raise CliError(
                "verifier private key must remain outside both workspaces",
                exit_code=EXIT_AUTHORITY,
            )
        _, private_content = _capture_protocol_file_pair(
            arguments.verifier_trusted_key,
            arguments.private_key,
            private_second=True,
        )
        if arguments.private_key.resolve(strict=True) != private_path:
            raise CliError("verifier private key path changed during capture", exit_code=EXIT_AUTHORITY)
        for workspace in (context.source_workspace, context.verifier_workspace):
            try:
                private_path.relative_to(workspace.resolve(strict=True))
            except ValueError:
                continue
            raise CliError(
                "verifier private key must remain outside both workspaces",
                exit_code=EXIT_AUTHORITY,
            )
    except OSError as exc:
        raise CliError("verifier private key is unavailable", exit_code=EXIT_AUTHORITY) from exc
    prepare_receipt = _verification_prepare_receipt(arguments, context)
    case = _verification_case_document(arguments, context)
    if case.get("semanticsDigest") != prepare_receipt.get("semanticsDigest"):
        raise CliError("verification semantics digest differs from prepare receipt", exit_code=EXIT_AUTHORITY)
    source_spec, source_effect_request, source_control_request, source_body = (
        _source_verification_requests(context)
    )
    _ = source_effect_request, source_control_request
    triad_refs = case["triad"]
    if not isinstance(triad_refs, dict):
        raise CliError("verification triad reference is invalid", exit_code=EXIT_AUTHORITY)
    spec_ref = triad_refs.get("spec")
    if spec_ref != prepare_receipt.get("spec"):
        raise CliError("verification spec differs from its prepare receipt", exit_code=EXIT_AUTHORITY)
    _, verifier_spec_content = _handoff_ref_path(
        context.verifier_workspace,
        spec_ref,
        label="verifier triad spec",
        maximum_bytes=MAX_PROTOCOL_FILE_BYTES,
    )
    try:
        verifier_spec = parse_personal_http1_triad_spec(verifier_spec_content)
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    if (
        verifier_spec.schema_ != PERSONAL_HTTP1_TRIAD_SCHEMA
        or verifier_spec.campaign_id != arguments.campaign_id
        or verifier_spec.hostname != source_spec.hostname
        or verifier_spec.port != source_spec.port
        or verifier_spec.scheme != source_spec.scheme
        or verifier_spec.timeout_seconds != source_spec.timeout_seconds
        or verifier_spec.effect.method not in {"GET", "OPTIONS"}
        or verifier_spec.effect.method != source_spec.effect.method
        or verifier_spec.effect.path != source_spec.effect.path
        or verifier_spec.effect.response_bytes != source_spec.effect.response_bytes
        or verifier_spec.negative_control.method != source_spec.negative_control.method
        or verifier_spec.negative_control.path != source_spec.negative_control.path
        or verifier_spec.negative_control.response_bytes != source_spec.negative_control.response_bytes
        or verifier_spec.finding != source_spec.finding
        or verifier_spec.authorization_reference != "authority.json"
        or verifier_spec.authorization_document_sha256
        != context.verifier_manifest.get("authority_sha256")
    ):
        raise CliError("verifier triad differs from source target", exit_code=EXIT_AUTHORITY)
    semantics_digest = case.get("semanticsDigest")
    if not isinstance(semantics_digest, str):
        raise CliError("verification semantics digest is invalid", exit_code=EXIT_AUTHORITY)
    semantics_tag = semantics_digest.removeprefix("sha256:")
    campaign_tag = sha256_hex(arguments.campaign_id.encode())[:16]
    if (
        verifier_spec.effect.request_file
        != f"verify-{campaign_tag}-effect-{semantics_tag}.raw"
        or verifier_spec.negative_control.request_file
        != f"verify-{campaign_tag}-negative-{semantics_tag}.raw"
    ):
        raise CliError("finalized verifier triad is not bound to case semantics", exit_code=EXIT_AUTHORITY)
    effect_case = triad_refs.get("effectRequest")
    control_case = triad_refs.get("negativeControlRequest")
    if (
        not isinstance(effect_case, dict)
        or not isinstance(control_case, dict)
        or effect_case.get("path") != verifier_spec.effect.request_file
        or control_case.get("path") != verifier_spec.negative_control.request_file
        or effect_case != prepare_receipt.get("effectRequest")
        or control_case != prepare_receipt.get("negativeControlRequest")
    ):
        raise CliError("verification case request references differ from its spec", exit_code=EXIT_AUTHORITY)
    _, verifier_effect_request = _handoff_ref_path(
        context.verifier_workspace,
        effect_case,
        label="verifier effect request",
        maximum_bytes=PERSONAL_HTTP1_MAX_REQUEST_BYTES,
    )
    _, verifier_control_request = _handoff_ref_path(
        context.verifier_workspace,
        control_case,
        label="verifier negative-control request",
        maximum_bytes=PERSONAL_HTTP1_MAX_REQUEST_BYTES,
    )
    if verifier_effect_request != source_effect_request or verifier_control_request != source_control_request:
        raise CliError("verifier request templates differ from source requests", exit_code=EXIT_AUTHORITY)

    final_receipt_path = _campaign_record(
        _campaign_records_directory(context.verifier_workspace),
        arguments.campaign_id,
        "final-receipt",
    )
    final_arguments = argparse.Namespace(
        workspace=context.verifier_workspace,
        trusted_key=arguments.verifier_trusted_key,
        campaign_id=arguments.campaign_id,
    )
    snapshots: dict[Path, bytes] = {}
    token = _HANDOFF_VALIDATION_SNAPSHOTS.set(snapshots)
    try:
        status, _ = _validate_completed_campaign_finalization(final_arguments, final_receipt_path)
        inputs = _validated_campaign_finalization_inputs(final_arguments)
        receipt_content = snapshots.get(final_receipt_path.resolve(strict=True))
        if receipt_content is None:
            raise CliError("verifier receipt was not captured during validation", exit_code=EXIT_AUTHORITY)
        receipt = _parse_campaign_json_content(receipt_content, label="verifier final receipt")
        evidence_ids = receipt.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not all(isinstance(value, str) for value in evidence_ids):
            raise CliError("verifier evidence ids are invalid", exit_code=EXIT_AUTHORITY)
        _validated_campaign_evidence(inputs=inputs, evidence_ids=evidence_ids)
        verifier_body, _, _ = _campaign_finalization_digests(inputs)
    finally:
        _HANDOFF_VALIDATION_SNAPSHOTS.reset(token)
    if status != "draft_unverified":
        raise CliError("verifier triad did not reproduce the source effect", exit_code=EXIT_AUTHORITY)
    evidence_records: list[dict[str, object]] = []
    raw_directory = context.verifier_workspace / "evidence" / "raw"
    def validated_snapshot(path: Path, *, label: str, maximum_bytes: int) -> bytes:
        try:
            expected = snapshots[path.resolve(strict=True)]
        except (KeyError, OSError) as exc:
            raise CliError(f"{label} was not captured during validation", exit_code=EXIT_AUTHORITY) from exc
        _handoff_workspace_file(
            context.verifier_workspace,
            path,
            label=label,
            maximum_bytes=maximum_bytes,
            expected=expected,
        )
        return expected

    receipt_content = validated_snapshot(
        final_receipt_path, label="verifier final receipt", maximum_bytes=MAX_PROTOCOL_FILE_BYTES
    )
    for evidence_id in evidence_ids:
        record_path = raw_directory / f"{evidence_id}.json"
        record_content = validated_snapshot(
            record_path, label="verifier evidence record", maximum_bytes=MAX_PROTOCOL_FILE_BYTES
        )
        evidence_records.append(
            _parse_campaign_json_content(record_content, label="verifier evidence record")
        )
    source_case = case.get("source")
    if (
        not isinstance(source_case, dict)
        or source_case.get("effectBodySha256") != source_body["effect"]
        or source_case.get("negativeControlBodySha256") != source_body["negative_control"]
        or verifier_body.get("effect") != source_body["effect"]
        or verifier_body.get("reproduction") != source_body["effect"]
        or verifier_body.get("negative_control") != source_body["negative_control"]
        or source_body["effect"] == source_body["negative_control"]
    ):
        raise CliError("verifier transcript does not independently reproduce source digests", exit_code=EXIT_AUTHORITY)

    now = _utc_now()
    verifier_run_id = str(context.verifier_manifest["run_id"])
    evidence_refs = _verification_evidence_refs(
        records=evidence_records, run_id=verifier_run_id, created_at=now
    )
    semantics = case["semantics"]
    if not isinstance(semantics, dict):
        raise CliError("verification semantics are invalid", exit_code=EXIT_AUTHORITY)
    candidate_id = f"candidate.independent.{arguments.campaign_id}"
    imported_handoff = EvidenceRef(
        schema_version=SCHEMA_VERSION,
        evidence_id=f"evidence.imported-handoff.{sha256_hex(context.handoff_content)[:16]}",
        run_id=verifier_run_id,
        cas_digest=f"sha256:{sha256_hex(context.handoff_content)}",
        observation_ids=(),
        redaction_digest=None,
        created_at=now,
    )
    candidate = FindingCandidate(
        schema_version=SCHEMA_VERSION,
        candidate_id=candidate_id,
        run_id=verifier_run_id,
        finding_class=FindingClass(str(semantics["findingClass"])),
        title=verifier_spec.finding.title,
        hypothesis_ids=(),
        primitive_ids=(),
        effect_ids=(f"effect.independent.{arguments.campaign_id}",),
        evidence_refs=(*evidence_refs, imported_handoff),
        created_at=now,
        confidence_bps=5_000,
        final_effect_observed=True,
    )
    replay_plan = ReplayPlan(
        schema_version=SCHEMA_VERSION,
        replay_plan_id=f"replay.independent.{arguments.campaign_id}",
        chain_plan_id=f"chain.independent.{arguments.campaign_id}",
        fresh_identity_context_ids=(f"identity.{context.verifier_grant.issued_to}",),
        reset_state_refs=(StateRef(
            schema_version=SCHEMA_VERSION,
            state_id=f"state.independent.{arguments.campaign_id}",
            state_kind="finalized_http1_triad",
            state_version=1,
            state_digest=f"sha256:{sha256_hex(receipt_content)}",
        ),),
        edge_ids=(f"edge.independent-positive.{arguments.campaign_id}",),
        negative_control_edge_ids=(f"edge.independent-negative.{arguments.campaign_id}",),
        cleanup_plan_ref=None,
    )
    try:
        claim = assemble_claim_packet(candidate, ClaimDraft(
            claim_id=f"claim.independent.{arguments.campaign_id}",
            claim=str(semantics["claim"]),
            prerequisites=tuple(cast(list[str], semantics["prerequisites"])),
            evidence_refs=(evidence_refs[0], evidence_refs[1]),
            negative_control_refs=(evidence_refs[2],),
            replay_plan=replay_plan,
            cleanup_plan_ref=None,
            created_at=now,
        ))
    except ClaimAssemblyError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    try:
        verifier = authorize_verifier(VerifierAuthorizationRequest(
            source_actor_id=context.source_grant.issued_to,
            verifier_actor_id=context.verifier_grant.issued_to,
            verifier_run_id=verifier_run_id,
            signed_authority=context.verifier_authority,
            trusted_authority_key=_parse_protocol_file(
                arguments.verifier_trusted_key,
                _capture_single_protocol_file(arguments.verifier_trusted_key),
                Ed25519PublicKeyRecord,
            ),
            verification_time=now,
        ))
    except (VerifierAuthorizationError, ValueError) as exc:
        raise CliError(f"verifier authorization failed: {exc}", exit_code=EXIT_AUTHORITY) from exc
    response_by_role = {role: response for role, _, response, _ in inputs.sources}
    executor = FinalizedTriadReplayExecutor(
        replay_plan=replay_plan,
        verifier_run_id=verifier_run_id,
        effect_response=validated_snapshot(response_by_role["effect"], label="verifier effect response", maximum_bytes=PERSONAL_HTTP1_MAX_RESPONSE_BYTES),
        reproduction_response=validated_snapshot(response_by_role["reproduction"], label="verifier reproduction response", maximum_bytes=PERSONAL_HTTP1_MAX_RESPONSE_BYTES),
        negative_response=validated_snapshot(response_by_role["negative_control"], label="verifier negative response", maximum_bytes=PERSONAL_HTTP1_MAX_RESPONSE_BYTES),
        effect_body_digest=verifier_body["effect"],
        reproduction_body_digest=verifier_body["reproduction"],
        negative_body_digest=verifier_body["negative_control"],
        source_effect_body_digest=source_body["effect"],
        source_negative_body_digest=source_body["negative_control"],
        created_at=now,
        cleanup_receipt_digest=f"sha256:{sha256_hex(receipt_content)}",
    )
    try:
        verdict = verify_candidate(VerificationCase(
            candidate=candidate,
            claim=claim,
            replay_plan=replay_plan,
            source_authority_digest=sha256_digest(context.source_authority),
            verifier=verifier,
            verified_at=now,
        ), executor)
    except (VerificationInputError, Http1TriadVerificationError, VerifierAuthorizationError) as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    if verdict.outcome.value != "verified":
        raise CliError("independent verifier verdict is not VERIFIED", exit_code=EXIT_AUTHORITY)
    verdict = verdict.model_copy(update={
        "reasons": (*verdict.reasons, f"faultloom:source_handoff=sha256:{sha256_hex(context.handoff_content)}"),
        "evidence_refs": (*verdict.evidence_refs, imported_handoff),
    })
    signer = _private_signer(arguments.private_key, private_content)
    if signer.key_id != context.verifier_authority.signature.key_id:
        raise CliError("result signer does not match verifier authority key", exit_code=EXIT_AUTHORITY)
    run_manifest_digest = sha256_digest(context.verifier_manifest)
    source_authority_digest = sha256_digest(context.source_authority)
    try:
        result = sign_verification_result(ResultArtifactDraft(
            context=ResultArtifactContext(
                bundle_id=f"bundle.independent.{arguments.campaign_id}",
                bundle_version=1,
                engagement_id=f"engagement.{context.source_grant.grant_id}",
                run_manifest_digest=run_manifest_digest,
                source_authority_digest=source_authority_digest,
                final_checkpoint_digest=f"sha256:{sha256_hex(receipt_content)}",
                generated_at=now,
                expires_at=context.verifier_grant.expires_at,
            ),
            candidate=candidate,
            claim=claim,
            verdict=verdict,
            cleanup_receipt_digests=(f"sha256:{sha256_hex(receipt_content)}",),
        ), signer)
    except ArtifactVerificationError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    result_content = (result.model_dump_json(indent=2) + "\n").encode()
    result_out, result_relative = _handoff_output_path(context.verifier_workspace, arguments.result_out)
    receipt_out, receipt_relative = _handoff_output_path(context.verifier_workspace, arguments.receipt_out)
    common_args = [
        "--result", result_relative,
        "--trusted-key", "trusted-key.json",
        "--run-id", verifier_run_id,
        "--run-manifest-digest", run_manifest_digest,
        "--authority-digest", source_authority_digest,
        "--engagement-id", f"engagement.{context.source_grant.grant_id}",
        "--source-actor", context.source_grant.issued_to,
        "--verifier-actor", context.verifier_grant.issued_to,
        "--verifier-authority-digest", sha256_digest(context.verifier_authority),
        "--verifier-authority", "authority.json",
        "--verifier-authority-key", "trusted-key.json",
    ]
    compile_receipt = {
        "schema": "faultloom.independent-http1-compile.v1",
        "status": "verified",
        "candidateId": candidate_id,
        "result": {"path": result_relative, "sha256": sha256_hex(result_content)},
        "sourceHandoffSha256": sha256_hex(context.handoff_content),
        "verifyArgs": [candidate_id, *common_args],
        "reportArgs": [
            candidate_id,
            "--format", "md",
            "--out-dir", "verification-report-outbox",
            *common_args,
        ],
        "networkAccess": False,
        "automaticReport": False,
        "automaticSubmission": False,
    }
    compile_receipt_content = (
        json.dumps(compile_receipt, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    _write_or_verify_handoff_output(context.verifier_workspace, result_out, result_content)
    _write_or_verify_handoff_output(context.verifier_workspace, receipt_out, compile_receipt_content)
    _emit_json({
        "schema": "faultloom.independent-http1-compile.v1",
        "status": "verified",
        "candidateId": candidate_id,
        "result": result_relative,
        "receipt": receipt_relative,
        "networkAccess": False,
        "automaticReport": False,
        "automaticSubmission": False,
    })
    return EXIT_OK


def _campaign_finalize_http1_triad(arguments: argparse.Namespace) -> int:
    if not arguments.confirm_reviewed_non_sensitive:
        raise CliError(
            "--confirm-reviewed-non-sensitive is required before offline archival",
            exit_code=EXIT_AUTHORITY,
        )
    inputs = _validated_campaign_finalization_inputs(arguments)
    manifest = inputs.manifest
    records = inputs.records
    start_path = inputs.start_path
    result_path = inputs.result_path
    start = inputs.start
    result = inputs.result
    sources = inputs.sources
    finalize_start = _campaign_record(records, arguments.campaign_id, "finalize-start")
    _write_new_campaign_record(
        records,
        finalize_start,
        (json.dumps(
            {
                "schema": "faultloom.personal-http1-triad-finalize-start.v1",
                "campaign_id": arguments.campaign_id,
                "start_sha256": sha256_hex(_capture_bounded_local_file(start_path, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign start record")),
                "run_result_sha256": sha256_hex(_capture_bounded_local_file(result_path, maximum_bytes=MAX_PROTOCOL_FILE_BYTES, label="campaign run result")),
                "reviewed_non_sensitive": True,
                "classifier": EXACT_BODY_DIGEST_CLASSIFIER,
            },
            indent=2,
            sort_keys=True,
        ) + "\n").encode("utf-8"),
        mode=0o600,
    )
    evidence_ids: list[str] = []
    body_digests: dict[str, str] = {}
    response_digests: dict[str, str] = {}
    dispatched = result.get("requests")
    if not isinstance(dispatched, list):
        raise CliError("campaign run result is invalid", exit_code=EXIT_AUTHORITY)
    for (role, request_file, response_file, body_digest), dispatch in zip(sources, dispatched, strict=True):
        if not isinstance(dispatch, dict):
            raise CliError("campaign run result is invalid", exit_code=EXIT_AUTHORITY)
        evidence = _evidence_add_exchange_result(
            argparse.Namespace(
                workspace=arguments.workspace,
                trusted_key=arguments.trusted_key,
                reservation_id=dispatch["reservation"],
                request_file=request_file,
                response_file=response_file,
                title=f"HTTP/1 exact-digest triad {role}",
            )
        )
        evidence_ids.append(str(evidence["evidence_id"]))
        body_digests[role] = body_digest
        response = dispatch.get("response")
        if not isinstance(response, dict) or not isinstance(response.get("sha256"), str):
            raise CliError("campaign run result is invalid", exit_code=EXIT_AUTHORITY)
        response_digests[role] = response["sha256"]
    try:
        outcome = classify_exact_body_digest_triad(
            effect_body_sha256=body_digests["effect"],
            reproduction_body_sha256=body_digests["reproduction"],
            negative_control_body_sha256=body_digests["negative_control"],
        )
    except PersonalCampaignError as exc:
        raise CliError(str(exc), exit_code=EXIT_AUTHORITY) from exc
    finding: dict[str, object] | None = None
    if outcome.status == "draft_unverified":
        metadata = start.get("finding")
        if not isinstance(metadata, dict):
            raise CliError("campaign finding metadata is invalid", exit_code=EXIT_AUTHORITY)
        finding = _finding_new_result(
            argparse.Namespace(
                workspace=arguments.workspace,
                title=metadata["title"],
                severity=metadata["severity"],
                summary=metadata["summary"],
                impact=metadata["impact"],
                remediation=metadata["remediation"],
                steps_file=None,
                evidence=evidence_ids,
            )
        )
    receipt_path = _campaign_record(records, arguments.campaign_id, "final-receipt")
    receipt = {
        "schema": "faultloom.personal-http1-triad-final-receipt.v1",
        "campaign_id": arguments.campaign_id,
        "status": outcome.status,
        "classifier": outcome.classifier,
        "dispatch_count": 3,
        "evidence_ids": evidence_ids,
        "response_sha256": response_digests,
        "body_sha256": body_digests,
        "independent_verification": False,
        "automatic_submission": False,
        "manual_review": "confirmed_non_sensitive_response_review",
        "finding": finding,
    }
    if "automation_binding" in start or "automation_binding_digest" in start:
        binding = start.get("automation_binding")
        binding_digest = start.get("automation_binding_digest")
        if not isinstance(binding, dict) or not isinstance(binding_digest, str):
            raise CliError("campaign start record has invalid automation provenance", exit_code=EXIT_AUTHORITY)
        receipt["automation_binding"] = binding
        receipt["automation_binding_digest"] = binding_digest
    _write_new_campaign_record(
        records,
        receipt_path,
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )
    _emit_json(
        {
            "schema": "faultloom.personal-http1-triad-finalize.v1",
            "campaignId": arguments.campaign_id,
            "status": outcome.status,
            "classifier": outcome.classifier,
            "receipt": str(receipt_path),
            "independentVerification": False,
            "automaticSubmission": False,
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
            GatewayLauncher,
            GatewayLaunchError,
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
    scope_draft.add_argument("--scheme", action="append", choices=("http", "https"))
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
    scope_send_request = scope_commands.add_parser(
        "send-request",
        help="send one scope-gated direct HTTP/1.1 request from a manual workspace",
    )
    scope_send_request.add_argument("--workspace", type=Path, required=True)
    scope_send_request.add_argument("--trusted-key", type=Path)
    scope_send_request.add_argument("--hostname", required=True)
    scope_send_request.add_argument("--port", type=_port, required=True)
    scope_send_request.add_argument("--scheme", choices=("http", "https"), required=True)
    scope_send_request.add_argument("--method", required=True)
    scope_send_request.add_argument("--path", required=True)
    scope_send_request.add_argument("--request-file", type=Path, required=True)
    scope_send_request.add_argument("--response-bytes", required=True)
    scope_send_request.add_argument(
        "--timeout-seconds", type=_personal_timeout_seconds, default=10
    )
    scope_send_request.add_argument(
        "--body-preview-chars", type=_body_preview_chars, default=0
    )
    scope_send_request.set_defaults(handler=_scope_send_request)
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

    campaign = commands.add_parser(
        "campaign", help="run and manually finalize a bounded personal HTTP/1 triad"
    )
    campaign_commands = campaign.add_subparsers(dest="campaign_command", required=True)
    campaign_run_http1_triad = campaign_commands.add_parser(
        "run-http1-triad",
        help="send effect, reproduction, and negative-control requests once each",
    )
    campaign_run_http1_triad.add_argument("--workspace", type=Path, required=True)
    campaign_run_http1_triad.add_argument("--trusted-key", type=Path, required=True)
    campaign_run_http1_triad.add_argument("--spec", type=Path, required=True)
    campaign_run_http1_triad.set_defaults(handler=_campaign_run_http1_triad)
    campaign_prepare_http1_triad = campaign_commands.add_parser(
        "prepare-http1-triad",
        help="bind one offline compiled candidate to an existing v1 triad template",
    )
    campaign_prepare_http1_triad.add_argument("--workspace", type=Path, required=True)
    campaign_prepare_http1_triad.add_argument("--trusted-key", type=Path, required=True)
    campaign_prepare_http1_triad.add_argument("--template", type=Path, required=True)
    campaign_prepare_http1_triad.add_argument("--result", type=Path, required=True)
    campaign_prepare_http1_triad.add_argument("--receipt", type=Path, required=True)
    campaign_prepare_http1_triad.add_argument("--candidate-id", required=True)
    campaign_prepare_http1_triad.add_argument("--out", type=Path, required=True)
    campaign_prepare_http1_triad.set_defaults(handler=_campaign_prepare_http1_triad)
    campaign_supervise_http1_triad = campaign_commands.add_parser(
        "supervise-http1-triad",
        help="prepare or resume one candidate-bound triad through explicit operator checkpoints",
    )
    campaign_supervise_http1_triad.add_argument("--workspace", type=Path, required=True)
    campaign_supervise_http1_triad.add_argument("--trusted-key", type=Path, required=True)
    campaign_supervise_http1_triad.add_argument("--template", type=Path, required=True)
    campaign_supervise_http1_triad.add_argument("--result", type=Path, required=True)
    campaign_supervise_http1_triad.add_argument("--receipt", type=Path, required=True)
    campaign_supervise_http1_triad.add_argument("--candidate-id", required=True)
    campaign_supervise_http1_triad.add_argument("--out", type=Path, required=True)
    campaign_supervise_http1_triad.set_defaults(handler=_campaign_supervise_http1_triad)
    campaign_finalize_http1_triad = campaign_commands.add_parser(
        "finalize-http1-triad",
        help="offline archive a reviewed exact-digest triad result",
    )
    campaign_finalize_http1_triad.add_argument("--workspace", type=Path, required=True)
    campaign_finalize_http1_triad.add_argument("--trusted-key", type=Path, required=True)
    campaign_finalize_http1_triad.add_argument("--campaign-id", type=_campaign_id, required=True)
    campaign_finalize_http1_triad.add_argument(
        "--confirm-reviewed-non-sensitive", action="store_true"
    )
    campaign_finalize_http1_triad.set_defaults(handler=_campaign_finalize_http1_triad)
    campaign_export_verification_handoff = campaign_commands.add_parser(
        "export-verification-handoff",
        help="export a local replay handoff for one finalized v2 draft campaign",
    )
    campaign_export_verification_handoff.add_argument("--workspace", type=Path, required=True)
    campaign_export_verification_handoff.add_argument("--trusted-key", type=Path, required=True)
    campaign_export_verification_handoff.add_argument("--campaign-id", type=_campaign_id, required=True)
    campaign_export_verification_handoff.add_argument("--out", type=Path, required=True)
    campaign_export_verification_handoff.set_defaults(handler=_campaign_export_verification_handoff)
    campaign_prepare_verification_http1 = campaign_commands.add_parser(
        "prepare-verification-http1",
        help="prepare an offline independent verifier case for the existing triad runner",
    )
    for name, destination in (
        ("--source-workspace", "source_workspace"),
        ("--source-trusted-key", "source_trusted_key"),
        ("--verifier-workspace", "verifier_workspace"),
        ("--verifier-trusted-key", "verifier_trusted_key"),
        ("--handoff", "handoff"),
        ("--out", "out"),
    ):
        campaign_prepare_verification_http1.add_argument(name, dest=destination, type=Path, required=True)
    campaign_prepare_verification_http1.add_argument(
        "--campaign-id", type=_campaign_id, required=True
    )
    campaign_prepare_verification_http1.add_argument(
        "--finding-class", choices=tuple(item.value for item in FindingClass), required=True
    )
    campaign_prepare_verification_http1.add_argument("--claim", required=True)
    campaign_prepare_verification_http1.add_argument(
        "--prerequisite", action="append", required=True
    )
    campaign_prepare_verification_http1.set_defaults(
        handler=_campaign_prepare_verification_http1
    )
    campaign_supervise_verification_http1 = campaign_commands.add_parser(
        "supervise-verification-http1",
        help="prepare or resume one independent verifier triad through explicit operator checkpoints",
    )
    for name, destination in (
        ("--source-workspace", "source_workspace"),
        ("--source-trusted-key", "source_trusted_key"),
        ("--verifier-workspace", "verifier_workspace"),
        ("--verifier-trusted-key", "verifier_trusted_key"),
        ("--handoff", "handoff"),
        ("--out", "out"),
        ("--case", "case"),
        ("--private-key", "private_key"),
        ("--result-out", "result_out"),
        ("--receipt-out", "receipt_out"),
    ):
        campaign_supervise_verification_http1.add_argument(
            name, dest=destination, type=Path, required=True
        )
    campaign_supervise_verification_http1.add_argument(
        "--campaign-id", type=_campaign_id, required=True
    )
    campaign_supervise_verification_http1.add_argument(
        "--finding-class", choices=tuple(item.value for item in FindingClass), required=True
    )
    campaign_supervise_verification_http1.add_argument("--claim", required=True)
    campaign_supervise_verification_http1.add_argument(
        "--prerequisite", action="append", required=True
    )
    campaign_supervise_verification_http1.set_defaults(
        handler=_campaign_supervise_verification_http1
    )
    campaign_compile_verification_http1 = campaign_commands.add_parser(
        "compile-verification-http1",
        help="compile a finalized verifier triad into an existing signed verification result",
    )
    for name, destination in (
        ("--source-workspace", "source_workspace"),
        ("--source-trusted-key", "source_trusted_key"),
        ("--verifier-workspace", "verifier_workspace"),
        ("--verifier-trusted-key", "verifier_trusted_key"),
        ("--handoff", "handoff"),
        ("--case", "case"),
        ("--private-key", "private_key"),
        ("--result-out", "result_out"),
        ("--receipt-out", "receipt_out"),
    ):
        campaign_compile_verification_http1.add_argument(
            name, dest=destination, type=Path, required=True
        )
    campaign_compile_verification_http1.add_argument(
        "--campaign-id", type=_campaign_id, required=True
    )
    campaign_compile_verification_http1.set_defaults(
        handler=_campaign_compile_verification_http1
    )

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
    automation_prepare_http1_request = automation_commands.add_parser(
        "prepare-http1-request",
        help="build one signed offline model request from an archived HTTP exchange",
    )
    automation_prepare_http1_request.add_argument("--workspace", type=Path, required=True)
    automation_prepare_http1_request.add_argument("--trusted-key", type=Path, required=True)
    automation_prepare_http1_request.add_argument("--evidence-id", required=True)
    automation_prepare_http1_request.add_argument("--excerpt-file", type=Path, required=True)
    automation_prepare_http1_request.add_argument("--provider-id", required=True)
    automation_prepare_http1_request.add_argument(
        "--disclosure-private-key", type=Path, required=True
    )
    automation_prepare_http1_request.add_argument("--hostname", required=True)
    automation_prepare_http1_request.add_argument("--port", type=_port, required=True)
    automation_prepare_http1_request.add_argument(
        "--scheme", choices=("http", "https"), required=True
    )
    automation_prepare_http1_request.add_argument(
        "--method", type=str.upper, choices=("GET", "HEAD", "OPTIONS"), required=True
    )
    automation_prepare_http1_request.add_argument("--path", required=True)
    automation_prepare_http1_request.add_argument("--out", type=Path, required=True)
    automation_prepare_http1_request.add_argument(
        "--confirm-redacted-non-sensitive", action="store_true"
    )
    automation_prepare_http1_request.set_defaults(
        handler=_automation_prepare_http1_request
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
    automation_export_handoff.add_argument("--model-snapshot", required=True)
    automation_export_handoff.add_argument(
        "--trusted-disclosure-key", type=Path, action="append", required=True
    )
    automation_export_handoff.add_argument("--out", type=Path, required=True)
    automation_export_handoff.set_defaults(handler=_automation_export_handoff)
    automation_provider_turn = automation_commands.add_parser(
        "provider-turn",
        help="run one signed provider-only turn and publish a local candidate",
    )
    automation_provider_turn.add_argument("--workspace", type=Path, required=True)
    automation_provider_turn.add_argument("--trusted-key", type=Path, required=True)
    automation_provider_turn.add_argument(
        "--minimum-grant-version", type=_positive_int, default=1
    )
    automation_provider_turn.add_argument("--request", type=Path, required=True)
    automation_provider_turn.add_argument("--runtime-config", type=Path, required=True)
    automation_provider_turn.add_argument("--base-intent", type=Path, required=True)
    automation_provider_turn.add_argument("--scope-epoch", type=Path, required=True)
    automation_provider_turn.add_argument("--reconciliation-key", type=Path, required=True)
    automation_provider_turn.add_argument(
        "--trusted-disclosure-key", type=Path, action="append", required=True
    )
    automation_provider_turn.add_argument("--egress-state-key", type=Path, required=True)
    automation_provider_turn.add_argument("--provider-state-key", type=Path, required=True)
    automation_provider_turn.add_argument("--proxy-attestation-key", type=Path, required=True)
    automation_provider_turn.add_argument("--runtime-dir", type=Path, required=True)
    automation_provider_turn.set_defaults(handler=_automation_provider_turn)
    automation_sign_provider_config = automation_commands.add_parser(
        "sign-provider-config",
        help="sign all public provider routing facts with the authority key",
    )
    automation_sign_provider_config.add_argument("--config", type=Path, required=True)
    automation_sign_provider_config.add_argument("--authority", type=Path, required=True)
    automation_sign_provider_config.add_argument("--private-key", type=Path, required=True)
    automation_sign_provider_config.add_argument("--out", type=Path, required=True)
    automation_sign_provider_config.set_defaults(
        handler=_automation_sign_provider_config
    )

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
