from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from faultloom import cli
from faultloom_protocol import AuthoritySigner, sign_authority_grant
from tests.protocol.factories import NOW, sample_models


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATHS = (
    ROOT,
    ROOT / "packages/protocol/src",
    ROOT / "packages/sdk/src",
    ROOT / "packages/runtime/src",
)


def _authority_files(
    directory: Path,
    *,
    hostnames: tuple[str, ...] = ("localhost",),
    cidrs: tuple[str, ...] = (),
    pack_ids: tuple[str, ...] = ("pack.web",),
    now: datetime = NOW,
    signer_seed: int = 0,
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    grant = sample_models()["AuthorityGrant"]
    target = grant.targets[0].model_copy(
        update={"hostnames": hostnames, "cidrs": cidrs}
    )
    expires_at = now + timedelta(hours=2)
    window = grant.execution_windows[0].model_copy(
        update={"starts_at": now, "ends_at": expires_at}
    )
    grant = grant.model_copy(
        update={
            "issued_at": now,
            "not_before": now,
            "expires_at": expires_at,
            "targets": (target,),
            "pack_ids": pack_ids,
            "execution_windows": (window,),
        }
    )
    private_key = bytes((value + signer_seed) % 256 for value in range(32))
    signer = AuthoritySigner.from_private_bytes(private_key)
    envelope = sign_authority_grant(grant, signer, signed_at=now)
    authority_path = directory / "authority.json"
    authority_path.write_text(envelope.model_dump_json(indent=2), encoding="utf-8")
    key_path = directory / "authority-public-key.json"
    key_path.write_text(
        signer.public_key_record.model_dump_json(indent=2), encoding="utf-8"
    )
    return authority_path, key_path


def _module_environment() -> dict[str, str]:
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    paths = [str(path) for path in SOURCE_PATHS]
    if existing:
        paths.append(existing)
    environment["PYTHONPATH"] = os.pathsep.join(paths)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _run_module(
    arguments: list[str],
    *,
    timeout: float = 30,
    reject_sockets: bool = False,
) -> subprocess.CompletedProcess[str]:
    if reject_sockets:
        bootstrap = """
import faultloom.cli
import runpy
import socket
import sys

def blocked_socket(*args, **kwargs):
    raise AssertionError("network socket opened")

socket.socket = blocked_socket
sys.argv = ["faultloom", *sys.argv[1:]]
runpy.run_module("faultloom", run_name="__main__")
"""
        command = [sys.executable, "-c", bootstrap, *arguments]
    else:
        command = [sys.executable, "-m", "faultloom", *arguments]
    return subprocess.run(
        command,
        cwd=ROOT,
        env=_module_environment(),
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_arguments(authority_path: Path, key_path: Path) -> list[str]:
    return [
        "run",
        "--authority",
        str(authority_path),
        "--trusted-key",
        str(key_path),
        "--target",
        "target.lab",
        "--pack",
        "web",
    ]


def test_doctor_json_is_offline_and_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["doctor", "--json"]) == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "component": "faultloom",
        "live_dispatch_enabled": False,
        "network_access": "none",
        "ok": True,
        "protocol_version": "0.1.0",
        "runtime_version": "0.1.0",
    }


def test_signed_loopback_run_is_validation_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_OK
    captured = capsys.readouterr()
    assert captured.err == ""
    result = json.loads(captured.out)
    assert result["authority_verified"] is True
    assert result["dispatch_performed"] is False
    assert result["network_access"] == "none"
    assert result["target_id"] == "target.lab"
    assert result["pack_id"] == "pack.web"


def test_trusted_key_environment_path_is_supported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    monkeypatch.setenv(cli.TRUSTED_KEY_ENV, str(key_path))
    arguments = _run_arguments(authority_path, key_path)
    key_index = arguments.index("--trusted-key")
    del arguments[key_index : key_index + 2]
    assert cli.main(arguments) == cli.EXIT_OK


def test_relative_protocol_paths_are_descriptor_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_path, key_path = _authority_files(tmp_path / "grant")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(
        _run_arguments(
            authority_path.relative_to(tmp_path),
            key_path.relative_to(tmp_path),
        )
    ) == cli.EXIT_OK


def test_actual_module_loopback_smoke_opens_no_socket(tmp_path: Path) -> None:
    now = datetime.now(UTC) - timedelta(minutes=1)
    authority_path, key_path = _authority_files(tmp_path, now=now)

    process = _run_module(
        _run_arguments(authority_path, key_path),
        reject_sockets=True,
    )

    assert process.returncode == cli.EXIT_OK
    assert process.stderr == ""
    assert json.loads(process.stdout)["dispatch_performed"] is False


@pytest.mark.parametrize(
    "input_kind",
    ("authority_symlink", "key_symlink", "path_symlink", "hardlink"),
)
def test_unsafe_protocol_file_layouts_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    input_kind: str,
) -> None:
    real = tmp_path / "real"
    authority_path, key_path = _authority_files(real)
    selected_authority = authority_path
    selected_key = key_path

    if input_kind == "authority_symlink":
        selected_authority = tmp_path / "authority-link.json"
        selected_authority.symlink_to(authority_path)
    elif input_kind == "key_symlink":
        selected_key = tmp_path / "key-link.json"
        selected_key.symlink_to(key_path)
    elif input_kind == "path_symlink":
        linked_directory = tmp_path / "linked-directory"
        linked_directory.symlink_to(real, target_is_directory=True)
        selected_authority = linked_directory / authority_path.name
        selected_key = linked_directory / key_path.name
    else:
        selected_authority = tmp_path / "authority-hardlink.json"
        os.link(authority_path, selected_authority)

    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    assert cli.main(_run_arguments(selected_authority, selected_key)) == cli.EXIT_AUTHORITY
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "protocol file" in captured.err


@pytest.mark.parametrize("input_kind", ("directory", "device", "unix_socket"))
def test_special_protocol_inputs_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_kind: str,
) -> None:
    _, key_path = _authority_files(tmp_path / "valid")
    local_socket: socket.socket | None = None
    if input_kind == "directory":
        authority_path = tmp_path / "directory"
        authority_path.mkdir()
    elif input_kind == "device":
        authority_path = Path("/dev/null")
    else:
        authority_path = tmp_path / "authority.socket"
        local_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        local_socket.bind(str(authority_path))

    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    try:
        assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY
    finally:
        if local_socket is not None:
            local_socket.close()


@pytest.mark.parametrize("replacement_kind", ("regular", "symlink"))
def test_key_replacement_after_authority_read_cannot_change_trust_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement_kind: str,
) -> None:
    authority_path, matching_key = _authority_files(tmp_path / "signer-a", signer_seed=0)
    _, mismatched_key = _authority_files(tmp_path / "signer-b", signer_seed=17)
    active_key = tmp_path / "active-key.json"
    active_key.write_bytes(mismatched_key.read_bytes())
    pending_key = tmp_path / "pending-key.json"
    pending_key.write_bytes(matching_key.read_bytes())
    original_read = cli._read_bound_protocol_file
    replaced = False

    def replace_after_authority(bound: cli._BoundProtocolFile) -> bytes:
        nonlocal replaced
        content = original_read(bound)
        if bound.path == authority_path and not replaced:
            if replacement_kind == "regular":
                os.replace(pending_key, active_key)
            else:
                active_key.unlink()
                active_key.symlink_to(pending_key)
            replaced = True
        return content

    monkeypatch.setattr(cli, "_read_bound_protocol_file", replace_after_authority)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, active_key)) == cli.EXIT_AUTHORITY
    assert replaced is True


@pytest.mark.parametrize("mutation", ("rename", "in_place_restore"))
def test_authority_mutation_after_capture_starts_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(authority_path.read_bytes())
    original_read = cli._read_bound_protocol_file
    changed = False

    def mutate_after_read(bound: cli._BoundProtocolFile) -> bytes:
        nonlocal changed
        content = original_read(bound)
        if bound.path == authority_path and not changed:
            if mutation == "rename":
                os.replace(replacement, authority_path)
            else:
                with authority_path.open("r+b", buffering=0) as stream:
                    first = stream.read(1)
                    stream.seek(0)
                    stream.write(b"[")
                    stream.seek(0)
                    stream.write(first)
                    os.fsync(stream.fileno())
            changed = True
        return content

    monkeypatch.setattr(cli, "_read_bound_protocol_file", mutate_after_read)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY
    assert changed is True


def test_fifo_protocol_input_fails_promptly_in_actual_module(tmp_path: Path) -> None:
    _, key_path = _authority_files(tmp_path / "valid")
    fifo = tmp_path / "authority.fifo"
    os.mkfifo(fifo)

    process = _run_module(_run_arguments(fifo, key_path))

    assert process.returncode == cli.EXIT_AUTHORITY
    assert process.stdout == ""
    assert "protocol file" in process.stderr
    assert "Traceback" not in process.stderr


def test_oversized_protocol_input_is_rejected_before_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    authority_path.write_bytes(b" " * (cli.MAX_PROTOCOL_FILE_BYTES + 1))
    read_calls = 0
    original_os_read = cli.os.read

    def counted_read(descriptor: int, size: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        return original_os_read(descriptor, size)

    def forbidden_path_read(self: Path) -> bytes:
        raise AssertionError(f"unbounded Path.read_bytes used for {self}")

    monkeypatch.setattr(cli.os, "read", counted_read)
    monkeypatch.setattr(Path, "read_bytes", forbidden_path_read)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY
    assert read_calls == 0


def test_protocol_input_growth_is_bounded_to_limit_plus_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    original_read_bound = cli._read_bound_protocol_file
    original_os_read = cli.os.read
    requested_bytes = 0
    grew = False

    def counted_read(descriptor: int, size: int) -> bytes:
        nonlocal requested_bytes
        requested_bytes += size
        return original_os_read(descriptor, size)

    def grow_before_read(bound: cli._BoundProtocolFile) -> bytes:
        nonlocal grew
        if bound.path == authority_path and not grew:
            with authority_path.open("ab", buffering=0) as stream:
                stream.write(b" " * (cli.MAX_PROTOCOL_FILE_BYTES + 1))
                os.fsync(stream.fileno())
            grew = True
        return original_read_bound(bound)

    monkeypatch.setattr(cli.os, "read", counted_read)
    monkeypatch.setattr(cli, "_read_bound_protocol_file", grow_before_read)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY
    assert grew is True
    assert requested_bytes == cli.MAX_PROTOCOL_FILE_BYTES + 1
    assert "exceeds" in capsys.readouterr().err


def test_deep_json_has_stable_actual_module_failure(tmp_path: Path) -> None:
    _, key_path = _authority_files(tmp_path / "valid")
    nested = tmp_path / "nested.json"
    nested.write_text("[" * 10_000 + "0" + "]" * 10_000, encoding="utf-8")

    process = _run_module(_run_arguments(nested, key_path))

    assert process.returncode == cli.EXIT_AUTHORITY
    assert process.stdout == ""
    assert "JSON nesting exceeds" in process.stderr
    assert "Traceback" not in process.stderr


def test_json_depth_scanner_ignores_brackets_inside_strings() -> None:
    cli._validate_json_depth('{"value":"' + "[" * 10_000 + '"}')
    with pytest.raises(ValueError, match="JSON nesting exceeds"):
        cli._validate_json_depth("[" * (cli.MAX_PROTOCOL_JSON_DEPTH + 1))


@pytest.mark.parametrize(
    ("hostname", "expected"),
    (
        ("localhost", True),
        ("api.localhost", True),
        ("127.0.0.1", True),
        ("127.255.255.255", True),
        ("::1", True),
        ("LOCALHOST", False),
        ("localhost.", False),
        ("example.com\x00.localhost", False),
        ("example.com/.localhost", False),
        ("example.com..localhost", False),
        ("-api.localhost", False),
        ("api-.localhost", False),
        (f"{'a' * 64}.localhost", False),
        ("é.localhost", False),
        ("localhost.evil", False),
        ("2130706433", False),
        ("::1%lo", False),
        ("::ffff:127.0.0.1", False),
    ),
)
def test_loopback_hostname_uses_canonical_ascii_grammar(
    hostname: str,
    expected: bool,
) -> None:
    assert cli._hostname_is_loopback(hostname) is expected


@pytest.mark.parametrize(
    "hostname",
    (
        "LOCALHOST",
        "localhost.",
        "example.com\x00.localhost",
        "example.com/.localhost",
        "example.com..localhost",
        "-api.localhost",
        "api-.localhost",
        "é.localhost",
    ),
)
def test_signed_ambiguous_localhost_values_are_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    hostname: str,
) -> None:
    authority_path, key_path = _authority_files(tmp_path, hostnames=(hostname,))
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY


@pytest.mark.parametrize(
    ("mutation", "expected_fragment"),
    (
        ("tamper", "authority verification failed"),
        ("duplicate", "duplicate JSON object key"),
    ),
)
def test_malformed_or_tampered_authority_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
    expected_fragment: str,
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    if mutation == "tamper":
        raw = json.loads(authority_path.read_text(encoding="utf-8"))
        raw["payload"]["approved_by"] = "operator.tampered"
        authority_path.write_text(json.dumps(raw), encoding="utf-8")
    else:
        authority_path.write_text(
            '{"schema_version":"0.1.0","schema_version":"0.1.0"}',
            encoding="utf-8",
        )
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY
    captured = capsys.readouterr()
    assert captured.out == ""
    assert expected_fragment in captured.err


def test_unsigned_target_pack_url_and_non_loopback_are_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    target_arguments = _run_arguments(authority_path, key_path)
    target_arguments[target_arguments.index("target.lab")] = "https://localhost/"
    assert cli.main(target_arguments) == cli.EXIT_AUTHORITY

    pack_arguments = _run_arguments(authority_path, key_path)
    pack_arguments[pack_arguments.index("web")] = "llm"
    assert cli.main(pack_arguments) == cli.EXIT_AUTHORITY

    external_authority, external_key = _authority_files(
        tmp_path / "external", hostnames=("example.invalid",)
    )
    assert cli.main(_run_arguments(external_authority, external_key)) == cli.EXIT_AUTHORITY


def test_live_mode_is_explicitly_unavailable_after_authority_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    arguments = _run_arguments(authority_path, key_path) + ["--live"]
    assert cli.main(arguments) == cli.EXIT_UNAVAILABLE
    assert "live dispatch is unavailable" in capsys.readouterr().err


@pytest.mark.parametrize(
    "arguments",
    (
        ["key", "init"],
        ["scope", "draft", "--template", "lab"],
        ["scope", "approve", "draft.json", "--out", "grant.json"],
        ["scope", "revoke", "grant.1"],
        ["resume", "run.1"],
        ["inspect", "run.1"],
        ["verify", "candidate.1"],
        ["report", "finding.1", "--format", "md"],
        ["adapter", "list"],
        ["adapter", "doctor", "adapter.http"],
        ["adapter", "test", "adapter.http"],
        ["pack", "list"],
        ["pack", "doctor", "pack.web"],
        ["pack", "test", "pack.web"],
        ["eval", "run", "manifest.json"],
    ),
)
def test_declared_command_surface_fails_closed_until_integrated(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(arguments) == cli.EXIT_UNAVAILABLE
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "declared but unavailable" in captured.err
