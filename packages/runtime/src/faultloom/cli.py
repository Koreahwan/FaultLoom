"""Fail-closed FaultLoom v0.1 command-line surface."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import stat
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from faultloom_protocol import (
    PROTOCOL_VERSION,
    Ed25519PublicKeyRecord,
    ProtocolModel,
    SignedAuthorityGrant,
    verify_authority_grant,
)
from faultloom_protocol.signing import SignatureVerificationError

from . import __version__
from .resume_cli import ResumeCliError, ResumeOperation, configure_resume_parser

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3
EXIT_AUTHORITY = 4
MAX_PROTOCOL_FILE_BYTES = 1024 * 1024
MAX_PROTOCOL_JSON_DEPTH = 128
PROTOCOL_READ_CHUNK_BYTES = 64 * 1024
TRUSTED_KEY_ENV = "FAULTLOOM_TRUSTED_AUTHORITY_KEY"
PACK_IDS = {"web": "pack.web", "llm": "pack.llm"}

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


def _doctor(arguments: argparse.Namespace) -> int:
    result = {
        "component": "faultloom",
        "live_dispatch_enabled": False,
        "network_access": "none",
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "runtime_version": __version__,
    }
    if arguments.json:
        _emit_json(result)
    else:
        print("FaultLoom doctor: ok")
        print(f"runtime={__version__} protocol={PROTOCOL_VERSION}")
        print("live_dispatch=disabled network_access=none")
    return EXIT_OK


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
    if arguments.live:
        raise CliError(
            "live dispatch is unavailable until the Gateway executor is integrated",
            exit_code=EXIT_UNAVAILABLE,
        )
    if not _target_is_loopback(targets[0]):
        raise CliError(
            "the v0.1 CLI smoke path accepts loopback targets only",
            exit_code=EXIT_AUTHORITY,
        )

    _emit_json(
        {
            "authority_verified": True,
            "dispatch_performed": False,
            "grant_id": grant.grant_id,
            "mode": "loopback_smoke",
            "network_access": "none",
            "pack_id": pack_id,
            "target_id": targets[0].target_id,
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
    _set_unavailable(key_init, "key init")

    scope = commands.add_parser("scope", help="manage signed scope contracts")
    scope_commands = scope.add_subparsers(dest="scope_command", required=True)
    scope_draft = scope_commands.add_parser("draft", help="create a scope draft")
    scope_draft.add_argument("--template", choices=("lab", "bounty", "consulting"), required=True)
    _set_unavailable(scope_draft, "scope draft")
    scope_approve = scope_commands.add_parser("approve", help="approve a scope draft")
    scope_approve.add_argument("draft", type=Path)
    scope_approve.add_argument("--out", type=Path, required=True)
    _set_unavailable(scope_approve, "scope approve")
    scope_revoke = scope_commands.add_parser("revoke", help="revoke an authority grant")
    scope_revoke.add_argument("grant_id")
    _set_unavailable(scope_revoke, "scope revoke")

    run = commands.add_parser("run", help="start an authorized research run")
    run.add_argument("--authority", type=Path, required=True)
    run.add_argument("--trusted-key", type=Path)
    run.add_argument("--minimum-grant-version", type=_positive_int, default=1)
    run.add_argument("--target", required=True, help="signed target-id; URLs are not accepted")
    run.add_argument("--pack", choices=tuple(PACK_IDS), required=True)
    run.add_argument("--live", action="store_true")
    run.set_defaults(handler=_run)

    resume = commands.add_parser("resume", help="resume a durable run")
    configure_resume_parser(
        resume,
        operation=ResumeOperation.RESUME,
        capture_protocol_pair=_capture_protocol_file_pair,
        validate_json_depth=_validate_json_depth,
        reject_duplicate_keys=_reject_duplicate_keys,
    )
    inspect = commands.add_parser("inspect", help="inspect durable run state")
    configure_resume_parser(
        inspect,
        operation=ResumeOperation.INSPECT,
        capture_protocol_pair=_capture_protocol_file_pair,
        validate_json_depth=_validate_json_depth,
        reject_duplicate_keys=_reject_duplicate_keys,
    )
    verify = commands.add_parser("verify", help="verify a finding candidate")
    verify.add_argument("candidate_id")
    _set_unavailable(verify, "verify")
    report = commands.add_parser("report", help="render a verified finding")
    report.add_argument("finding_id")
    report.add_argument("--format", choices=("md", "json"), required=True)
    _set_unavailable(report, "report")

    for group_name in ("adapter", "pack"):
        group = commands.add_parser(group_name, help=f"inspect {group_name} registry")
        group_commands = group.add_subparsers(dest=f"{group_name}_command", required=True)
        group_list = group_commands.add_parser("list")
        _set_unavailable(group_list, f"{group_name} list")
        for operation in ("doctor", "test"):
            child = group_commands.add_parser(operation)
            child.add_argument(f"{group_name}_id")
            _set_unavailable(child, f"{group_name} {operation}")

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
    except ResumeCliError as exc:
        print(f"faultloom: error: {exc}", file=sys.stderr)
        return EXIT_AUTHORITY


if __name__ == "__main__":
    raise SystemExit(main())
