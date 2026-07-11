"""Fail-closed FaultLoom v0.1 command-line surface."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
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

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3
EXIT_AUTHORITY = 4
MAX_PROTOCOL_FILE_BYTES = 1024 * 1024
TRUSTED_KEY_ENV = "FAULTLOOM_TRUSTED_AUTHORITY_KEY"
PACK_IDS = {"web": "pack.web", "llm": "pack.llm"}

ModelT = TypeVar("ModelT", bound=ProtocolModel)


class CliError(RuntimeError):
    """A concise expected CLI failure with a stable exit code."""

    def __init__(self, message: str, *, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


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


def _read_protocol_file(path: Path, model_type: type[ModelT]) -> ModelT:
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise CliError(
            f"cannot read protocol file {path}: {exc}", exit_code=EXIT_AUTHORITY
        ) from exc
    if len(content) > MAX_PROTOCOL_FILE_BYTES:
        raise CliError(
            f"protocol file exceeds {MAX_PROTOCOL_FILE_BYTES} bytes: {path}",
            exit_code=EXIT_AUTHORITY,
        )
    try:
        text = content.decode("utf-8")
        json.loads(text, object_pairs_hook=_reject_duplicate_keys)
        return model_type.model_validate_json(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
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


def _network_is_loopback(value: str) -> bool:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return network.network_address.is_loopback and network.broadcast_address.is_loopback


def _hostname_is_loopback(value: str) -> bool:
    normalized = value.rstrip(".").casefold()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


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
    envelope = _read_protocol_file(arguments.authority, SignedAuthorityGrant)
    public_key = _read_protocol_file(
        _trusted_key_path(arguments), Ed25519PublicKeyRecord
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
    resume.add_argument("run_id")
    _set_unavailable(resume, "resume")
    inspect = commands.add_parser("inspect", help="inspect durable run state")
    inspect.add_argument("run_id")
    _set_unavailable(inspect, "inspect")
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


if __name__ == "__main__":
    raise SystemExit(main())
