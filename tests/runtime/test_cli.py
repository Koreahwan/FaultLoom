from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from faultloom import cli
from faultloom_protocol import AuthoritySigner, SignedAuthorityGrant, sign_authority_grant
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
    ports: tuple[int, ...] | None = None,
    paths: tuple[str, ...] | None = None,
    methods: tuple[str, ...] | None = None,
    protocols: tuple[str, ...] | None = None,
    request_deny: tuple[str, str] | None = None,
    observe_only: bool = False,
    budget_updates: dict[str, int] | None = None,
    now: datetime = NOW,
    signer_seed: int = 0,
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    grant = sample_models()["AuthorityGrant"]
    target = grant.targets[0].model_copy(
        update={
            "hostnames": hostnames,
            "cidrs": cidrs,
            **({"ports": ports} if ports is not None else {}),
            **({"paths": paths} if paths is not None else {}),
            **({"methods": methods} if methods is not None else {}),
            **({"protocols": protocols} if protocols is not None else {}),
        }
    )
    policy = grant.action_policy.model_copy(
        update={
            **({"allowed_path_patterns": paths} if paths is not None else {}),
            **({"allowed_methods": methods} if methods is not None else {}),
        }
    )
    if request_deny is not None:
        denied_method, denied_path = request_deny
        policy = policy.model_copy(
            update={
                "denied": (
                    policy.denied[0].model_copy(
                        update={
                            "action_families": ("http.semantic",),
                            "methods": (denied_method,),
                            "path_pattern": denied_path,
                        }
                    ),
                )
            }
        )
    if observe_only:
        policy = policy.model_copy(update={"allowed_classes": (policy.allowed_classes[0],)})
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
            "action_policy": policy,
            "execution_windows": (window,),
            **(
                {"budget": grant.budget.model_copy(update=budget_updates)}
                if budget_updates is not None
                else {}
            ),
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


def _manual_workspace_for_request_check(
    tmp_path: Path,
    *,
    hostname: str = "example.com",
    ports: tuple[int, ...] = (443,),
    request_deny: tuple[str, str] | None = None,
    observe_only: bool = False,
    budget_updates: dict[str, int] | None = None,
) -> tuple[Path, Path]:
    now = datetime.now(UTC) - timedelta(minutes=1)
    authority_path, key_path = _authority_files(
        tmp_path / "grant",
        hostnames=(hostname,),
        ports=ports,
        paths=("/api/*",),
        methods=("GET",),
        protocols=("https",),
        request_deny=request_deny,
        observe_only=observe_only,
        budget_updates=budget_updates,
        now=now,
    )
    workspace = tmp_path / "manual-run"
    assert cli.main(
        _run_arguments(authority_path, key_path) + ["--workspace", str(workspace)]
    ) == cli.EXIT_OK
    return workspace, key_path


def _check_request_arguments(
    workspace: Path,
    trusted_key: Path,
    **overrides: object,
) -> list[str]:
    values: dict[str, object] = {
        "hostname": "example.com",
        "port": "443",
        "scheme": "https",
        "method": "get",
        "path": "/api/items",
        "request_bytes": "100",
        "response_bytes": "200",
    }
    values.update(overrides)
    request_bytes = int(str(values["request_bytes"]))
    hostname = str(values["hostname"])
    port = int(str(values["port"]))
    scheme = str(values["scheme"])
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        host_authority = hostname
    else:
        host_authority = f"[{address.compressed}]" if address.version == 6 else address.compressed
    host_header = (
        host_authority
        if (scheme, port) in {("https", 443), ("http", 80)}
        else f"{host_authority}:{port}"
    )
    prefix = (
        f"{str(values['method']).upper()} {values['path']} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "X-FaultLoom-Pad: "
    ).encode("ascii")
    suffix = b"\r\n\r\n"
    assert request_bytes >= len(prefix) + len(suffix)
    request_file = workspace / "request.raw"
    request_file.write_bytes(prefix + b"a" * (request_bytes - len(prefix) - len(suffix)) + suffix)
    return [
        "scope",
        "verify-request",
        "--workspace",
        str(workspace),
        "--trusted-key",
        str(trusted_key),
        "--hostname",
        str(values["hostname"]),
        "--port",
        str(values["port"]),
        "--scheme",
        str(values["scheme"]),
        "--method",
        str(values["method"]),
        "--path",
        str(values["path"]),
        "--request-file",
        str(request_file),
        "--response-bytes",
        str(values["response_bytes"]),
    ]


def _complete_request_arguments(
    workspace: Path,
    trusted_key: Path,
    reservation_id: str,
    observed_response_bytes: str,
    *,
    request_file: Path | None = None,
    response_file: Path | None = None,
) -> list[str]:
    arguments = [
        "scope",
        "complete-request",
        "--workspace",
        str(workspace),
        "--trusted-key",
        str(trusted_key),
        "--reservation-id",
        reservation_id,
        "--request-file",
        str(request_file or workspace / "request.raw"),
    ]
    if response_file is None:
        arguments.extend(("--observed-response-bytes", observed_response_bytes))
    else:
        arguments.extend(("--response-file", str(response_file)))
    return arguments


def _add_exchange_arguments(
    workspace: Path,
    trusted_key: Path,
    reservation_id: str,
    request_file: Path,
    response_file: Path,
) -> list[str]:
    return [
        "evidence",
        "add-exchange",
        "--workspace",
        str(workspace),
        "--trusted-key",
        str(trusted_key),
        "--reservation-id",
        reservation_id,
        "--request-file",
        str(request_file),
        "--response-file",
        str(response_file),
    ]


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


def test_doctor_json_reports_posix_controller_provisioned_live_mode(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli.os, "name", "posix")
    assert cli.main(["doctor", "--json"]) == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result == {
        "component": "faultloom",
        "live_dispatch_enabled": True,
        "live_dispatch_mode": "controller_provisioned_single_dispatch",
        "network_access": "gateway_only",
        "ok": True,
        "protocol_version": "0.1.0",
        "runtime_version": "0.1.0",
    }


def test_doctor_json_keeps_windows_personal_runtime_manual_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli.os, "name", "nt")

    assert cli.main(["doctor", "--json"]) == cli.EXIT_OK

    result = json.loads(capsys.readouterr().out)
    assert result["live_dispatch_enabled"] is False
    assert result["live_dispatch_mode"] == "manual_only"
    assert result["network_access"] == "none"


def test_windows_personal_build_includes_registered_candidate_packs() -> None:
    script = (ROOT / "tools" / "build_personal_windows_cli.ps1").read_text(
        encoding="utf-8"
    )

    for package, source_path in (
        ("faultloom_advanced_web", "packs\\advanced_web\\src"),
        ("faultloom_cloud", "packs\\cloud\\src"),
        ("faultloom_mobile", "packs\\mobile\\src"),
        ("faultloom_web3", "packs\\web3\\src"),
    ):
        assert f"'{source_path}'" in script
        assert f"'--hidden-import', '{package}'" in script
        assert f"'--hidden-import', '{package}.manifest'" in script


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


def test_single_operator_key_scope_and_pack_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    key_root = tmp_path / "authority"
    draft_path = tmp_path / "scope-draft.json"
    grant_path = tmp_path / "authority-grant.json"

    assert cli.main(["key", "init", "--out-dir", str(key_root)]) == cli.EXIT_OK
    key_result = json.loads(capsys.readouterr().out)
    private_key = Path(key_result["private_key"])
    public_key = Path(key_result["public_key"])
    assert private_key.stat().st_mode & 0o777 == 0o600
    assert len(private_key.read_text(encoding="ascii").strip()) == 64
    assert public_key.is_file()

    assert cli.main(
        [
            "scope",
            "draft",
            "--template",
            "bounty",
            "--target-id",
            "target.example",
            "--hostname",
            "example.com",
            "--pack",
            "web",
            "--out",
            str(draft_path),
        ]
    ) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["draft"] == str(draft_path)

    assert cli.main(
        [
            "scope",
            "approve",
            str(draft_path),
            "--private-key",
            str(private_key),
            "--out",
            str(grant_path),
        ]
    ) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["authority"] == str(grant_path)

    workspace = tmp_path / "engagement"
    assert cli.main(
        _run_arguments(grant_path, public_key)[:-4]
        + [
            "--target",
            "target.example",
            "--pack",
            "web",
            "--workspace",
            str(workspace),
        ]
    ) == cli.EXIT_OK
    run_result = json.loads(capsys.readouterr().out)
    assert run_result["authority_verified"] is True
    assert run_result["mode"] == "manual_authorized"
    assert run_result["target_id"] == "target.example"
    assert Path(run_result["workspace"]) == workspace
    assert (workspace / "run.json").is_file()

    assert cli.main(["pack", "list"]) == cli.EXIT_OK
    listed = json.loads(capsys.readouterr().out)
    assert [item["pack_id"] for item in listed["packs"]] == [
        "pack.advanced_web",
        "pack.cloud.iam_oauth",
        "pack.llm.agent",
        "pack.mobile",
        "pack.web",
        "pack.web3.future-fixture",
    ]
    assert cli.main(["pack", "doctor", "pack.web"]) == cli.EXIT_OK
    web_doctor = json.loads(capsys.readouterr().out)
    assert web_doctor["ok"] is True
    assert web_doctor["live_dispatch_supported"] is True


@pytest.mark.parametrize(
    ("pack_alias", "pack_id"),
    (
        ("advanced-web", "pack.advanced_web"),
        ("cloud", "pack.cloud.iam_oauth"),
        ("mobile", "pack.mobile"),
        ("web3", "pack.web3.future-fixture"),
    ),
)
def test_candidate_pack_aliases_create_signed_manual_workspaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    pack_alias: str,
    pack_id: str,
) -> None:
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    key_root = tmp_path / "authority"
    draft_path = tmp_path / "scope-draft.json"
    grant_path = tmp_path / "authority-grant.json"
    workspace = tmp_path / "workspace"

    assert cli.main(["key", "init", "--out-dir", str(key_root)]) == cli.EXIT_OK
    key_result = json.loads(capsys.readouterr().out)

    assert cli.main(
        [
            "scope",
            "draft",
            "--template",
            "lab",
            "--target-id",
            "target.example",
            "--hostname",
            "example.com",
            "--pack",
            pack_alias,
            "--out",
            str(draft_path),
        ]
    ) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["pack_id"] == pack_id

    assert cli.main(
        [
            "scope",
            "approve",
            str(draft_path),
            "--private-key",
            key_result["private_key"],
            "--out",
            str(grant_path),
        ]
    ) == cli.EXIT_OK
    capsys.readouterr()

    assert cli.main(
        [
            "run",
            "--authority",
            str(grant_path),
            "--trusted-key",
            key_result["public_key"],
            "--target",
            "target.example",
            "--pack",
            pack_alias,
            "--workspace",
            str(workspace),
        ]
    ) == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result["dispatch_performed"] is False
    assert result["pack_id"] == pack_id
    assert json.loads((workspace / "run.json").read_text(encoding="utf-8"))["pack_id"] == pack_id

    assert cli.main(["pack", "doctor", pack_id]) == cli.EXIT_OK
    pack_doctor = json.loads(capsys.readouterr().out)
    assert pack_doctor["pack_id"] == pack_id
    assert pack_doctor["live_dispatch_supported"] is False


@pytest.mark.parametrize(
    ("pack_alias", "pack_id"),
    (
        ("advanced-web", "pack.advanced_web"),
        ("cloud", "pack.cloud.iam_oauth"),
        ("mobile", "pack.mobile"),
        ("web3", "pack.web3.future-fixture"),
    ),
)
def test_candidate_pack_aliases_reject_live_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    pack_alias: str,
    pack_id: str,
) -> None:
    authority_path, key_path = _authority_files(tmp_path, pack_ids=(pack_id,))
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    arguments = _run_arguments(authority_path, key_path)
    arguments[arguments.index("--pack") + 1] = pack_alias

    assert cli.main([*arguments, "--live"]) == cli.EXIT_UNAVAILABLE
    assert f"manual-only pack {pack_id!r}" in capsys.readouterr().err


def test_external_authorized_run_creates_manual_workspace_without_socket(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC) - timedelta(minutes=1)
    authority_path, key_path = _authority_files(
        tmp_path / "grant",
        hostnames=("example.com",),
        now=now,
    )
    workspace = tmp_path / "customer-run"

    process = _run_module(
        _run_arguments(authority_path, key_path)
        + ["--workspace", str(workspace)],
        reject_sockets=True,
    )

    assert process.returncode == cli.EXIT_OK
    assert process.stderr == ""
    result = json.loads(process.stdout)
    assert result == {
        "authority_verified": True,
        "dispatch_performed": False,
        "grant_id": result["grant_id"],
        "mode": "manual_authorized",
        "network_access": "none",
        "pack_id": "pack.web",
        "run_id": result["run_id"],
        "target_id": "target.lab",
        "workspace": str(workspace),
    }
    manifest = json.loads((workspace / "run.json").read_text(encoding="utf-8"))
    assert manifest["run_id"] == result["run_id"]
    assert manifest["dispatch_performed"] is False
    assert manifest["target"]["hostnames"] == ["example.com"]
    assert len(manifest["authority_sha256"]) == 64
    assert len(manifest["trusted_key_sha256"]) == 64
    assert (workspace / "authority.json").read_bytes() == authority_path.read_bytes()
    assert (workspace / "trusted-key.json").read_bytes() == key_path.read_bytes()
    assert (workspace / "README.md").is_file()
    for relative in (
        "evidence/raw",
        "evidence/normalized",
        "findings",
        "reports",
    ):
        assert (workspace / relative).is_dir()


def test_scope_check_request_is_offline_and_returns_signed_scope(
    tmp_path: Path,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)

    process = _run_module(
        _check_request_arguments(workspace, key_path),
        reject_sockets=True,
    )

    assert process.returncode == cli.EXIT_OK
    assert process.stderr == ""
    result = json.loads(process.stdout)
    assert result["authorized"] is True
    assert result["action_class"] == "safe_probe"
    assert result["dispatch_performed"] is False
    assert result["network_access"] == "none"
    assert result["method"] == "GET"
    assert result["hostname"] == "example.com"
    assert result["target_id"] == "target.lab"
    assert result["pack_id"] == "pack.web"
    assert result["budget_accounting"] == "operator_local_reservation"
    assert result["reservation_id"].startswith("reservation.")
    assert result["request_sha256"] == hashlib.sha256(
        (workspace / "request.raw").read_bytes()
    ).hexdigest()
    assert result["remaining_budget"] == {
        "max_concurrency": 1,
        "rate_per_minute": 9,
        "total_actions": 99,
    }
    assert result["budget"] == {
        "max_concurrency": 2,
        "max_duration_seconds": 3600,
        "max_request_bytes": 4096,
        "max_response_bytes": 65536,
        "rate_per_minute": 10,
        "schema_version": "0.1.0",
        "total_actions": 100,
    }
    completion = _run_module(
        _complete_request_arguments(workspace, key_path, result["reservation_id"], "200"),
        reject_sockets=True,
    )
    assert completion.returncode == cli.EXIT_OK
    assert json.loads(completion.stdout)["observed_response_bytes"] == 200


@pytest.mark.parametrize(
    ("replacement", "expected_error"),
    (
        (b"PUT /api/items HTTP/1.1", "signed method and path"),
        (b"GET /api/other HTTP/1.1", "signed method and path"),
        (b"Host: evil.example", "Host header does not match"),
    ),
)
def test_scope_verify_request_rejects_raw_endpoint_mutations_before_authorizing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    replacement: bytes,
    expected_error: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    arguments = _check_request_arguments(workspace, key_path)
    request_path = workspace / "request.raw"
    content = request_path.read_bytes()
    if replacement.startswith(b"Host:"):
        content = content.replace(b"Host: example.com", replacement)
    else:
        content = content.replace(b"GET /api/items HTTP/1.1", replacement)
    request_path.write_bytes(content)

    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    captured = capsys.readouterr()
    assert captured.out == ""
    assert expected_error in captured.err


@pytest.mark.parametrize("port", (443, 8443))
def test_scope_verify_request_serializes_ipv6_host_authority_with_brackets(
    tmp_path: Path, port: int
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, hostname="::1", ports=(port,)
    )
    arguments = _check_request_arguments(
        workspace,
        key_path,
        hostname="::1",
        port=str(port),
    )

    assert cli.main(arguments) == cli.EXIT_OK


@pytest.mark.parametrize(
    ("host_header", "expected_error"),
    (
        ("::1", "Host header does not match"),
        ("::1:8443", "Host header does not match"),
        ("[::2]", "Host header does not match"),
    ),
)
def test_scope_verify_request_rejects_noncanonical_or_unrelated_ipv6_host(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    host_header: str,
    expected_error: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, hostname="::1", ports=(443, 8443)
    )
    capsys.readouterr()
    arguments = _check_request_arguments(
        workspace, key_path, hostname="::1", port="8443"
    )
    request_path = workspace / "request.raw"
    request_path.write_bytes(
        request_path.read_bytes().replace(b"Host: [::1]:8443", f"Host: {host_header}".encode())
    )

    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert expected_error in capsys.readouterr().err


@pytest.mark.parametrize("mutation", ("header", "body"))
def test_scope_complete_request_rejects_changed_exact_request_digest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    mutation: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    if mutation == "body":
        arguments = _check_request_arguments(workspace, key_path)
        request_path = workspace / "request.raw"
        request_path.write_bytes(
            b"GET /api/items HTTP/1.1\r\nHost: example.com\r\n"
            b"Content-Length: 1\r\n\r\na"
        )
    else:
        arguments = _check_request_arguments(workspace, key_path)
        request_path = workspace / "request.raw"
    assert cli.main(arguments) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    if mutation == "body":
        request_path.write_bytes(request_path.read_bytes().replace(b"\r\n\r\na", b"\r\n\r\nb"))
    else:
        request_path.write_bytes(
            request_path.read_bytes().replace(b"X-FaultLoom-Pad: a", b"X-FaultLoom-Pad: b")
        )

    assert (
        cli.main(
            _complete_request_arguments(
                workspace, key_path, reservation_id, "200", request_file=request_path
            )
        )
        == cli.EXIT_AUTHORITY
    )
    assert "digest does not match" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("raw", "expected_error"),
    (
        (
            b"GET /api/items HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\n\r\n",
            "exactly one Host",
        ),
        (
            b"GET /api/items HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            "duplicate Content-Length",
        ),
        (
            b"GET /api/items HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n",
            "transfer-encoding",
        ),
        (b"GET /api/items HTTP/1.1\nHost: example.com\n\n", "CRLF"),
    ),
)
def test_scope_verify_request_rejects_ambiguous_raw_framing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    raw: bytes,
    expected_error: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    arguments = _check_request_arguments(workspace, key_path)
    (workspace / "request.raw").write_bytes(raw)

    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert expected_error in capsys.readouterr().err


def test_scope_verify_request_rejects_symlink_and_nonregular_raw_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    arguments = _check_request_arguments(workspace, key_path)
    request_path = workspace / "request.raw"
    request_path.unlink()
    request_path.mkdir()
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert "regular non-symlink" in capsys.readouterr().err

    request_path.rmdir()
    source = tmp_path / "raw-source"
    source.write_bytes(b"GET /api/items HTTP/1.1\r\nHost: example.com\r\n\r\n")
    try:
        request_path.symlink_to(source)
    except OSError:
        pytest.skip("symlink creation is unavailable in this environment")
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert "regular non-symlink" in capsys.readouterr().err


def test_scope_complete_request_binds_local_response_digest_without_network(
    tmp_path: Path,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    verified = _run_module(
        _check_request_arguments(workspace, key_path), reject_sockets=True
    )
    assert verified.returncode == cli.EXIT_OK
    reservation_id = json.loads(verified.stdout)["reservation_id"]
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    completed = _run_module(
        [
            "scope",
            "complete-request",
            "--workspace",
            str(workspace),
            "--trusted-key",
            str(key_path),
            "--reservation-id",
            reservation_id,
            "--request-file",
            str(workspace / "request.raw"),
            "--response-file",
            str(response_path),
        ],
        reject_sockets=True,
    )
    assert completed.returncode == cli.EXIT_OK
    result = json.loads(completed.stdout)
    assert result["observed_response_bytes"] == len(response_path.read_bytes())
    assert result["response_sha256"] == hashlib.sha256(response_path.read_bytes()).hexdigest()


def test_scope_complete_request_rejects_response_file_over_reserved_limit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, budget_updates={"max_response_bytes": 200}
    )
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"x" * 201)

    assert (
        cli.main(
            _complete_request_arguments(
                workspace,
                key_path,
                reservation_id,
                "201",
                response_file=response_path,
            )
        )
        == cli.EXIT_AUTHORITY
    )
    assert "response file exceeds the reserved response limit" in capsys.readouterr().err
    connection = sqlite3.connect(workspace / cli.REQUEST_ACCOUNTING_FILENAME)
    try:
        assert connection.execute(
            "SELECT completed_at, observed_response_bytes, response_sha256 "
            "FROM reservations WHERE reservation_id = ?",
            (reservation_id,),
        ).fetchone() == (None, None, None)
    finally:
        connection.close()


def test_manual_workspace_rolls_back_if_accounting_initialization_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority_path, key_path = _authority_files(tmp_path / "grant")
    workspace = tmp_path / "failed-run"
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    def fail_initialize(*args: object, **kwargs: object) -> None:
        raise cli.CliError("injected accounting initialization failure", exit_code=cli.EXIT_USAGE)

    monkeypatch.setattr(cli, "_initialize_request_accounting", fail_initialize)
    assert (
        cli.main(_run_arguments(authority_path, key_path) + ["--workspace", str(workspace)])
        == cli.EXIT_USAGE
    )
    assert not workspace.exists()
    assert "injected accounting initialization failure" in capsys.readouterr().err


def test_scope_check_request_reservation_rejects_total_budget_overrun(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A second authorized request must not exceed a signed one-action budget."""
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, budget_updates={"total_actions": 1}
    )
    capsys.readouterr()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "total action budget" in capsys.readouterr().err


def test_scope_check_request_reservation_rejects_rate_budget_overrun(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, budget_updates={"rate_per_minute": 1}
    )
    capsys.readouterr()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "rate budget" in capsys.readouterr().err


def test_scope_request_completion_releases_concurrency_and_records_observed_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, budget_updates={"max_concurrency": 1}
    )
    capsys.readouterr()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    first = json.loads(capsys.readouterr().out)
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "concurrency budget" in capsys.readouterr().err

    assert (
        cli.main(_complete_request_arguments(workspace, key_path, first["reservation_id"], "150"))
        == cli.EXIT_OK
    )
    completed = json.loads(capsys.readouterr().out)
    assert completed["observed_response_bytes"] == 150
    assert completed["dispatch_performed"] is False
    assert completed["network_access"] == "none"
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK

    connection = sqlite3.connect(workspace / cli.REQUEST_ACCOUNTING_FILENAME)
    try:
        assert connection.execute(
            "SELECT observed_response_bytes FROM reservations WHERE reservation_id = ?",
            (first["reservation_id"],),
        ).fetchone() == (150,)
    finally:
        connection.close()


def test_expired_request_reservations_release_concurrency_but_keep_total_and_rate_usage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path,
        budget_updates={
            "total_actions": 2,
            "rate_per_minute": 2,
            "max_concurrency": 1,
            "max_duration_seconds": 1,
        },
    )
    capsys.readouterr()
    now = datetime.now(UTC)
    monkeypatch.setattr(cli, "_utc_now", lambda: now)
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    capsys.readouterr()
    monkeypatch.setattr(cli, "_utc_now", lambda: now + timedelta(seconds=2))

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result["remaining_budget"] == {
        "max_concurrency": 0,
        "rate_per_minute": 0,
        "total_actions": 0,
    }


def test_expired_request_reservation_cannot_be_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, budget_updates={"max_duration_seconds": 1}
    )
    capsys.readouterr()
    now = datetime.now(UTC)
    monkeypatch.setattr(cli, "_utc_now", lambda: now)
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    monkeypatch.setattr(cli, "_utc_now", lambda: now + timedelta(seconds=2))

    assert (
        cli.main(_complete_request_arguments(workspace, key_path, reservation_id, "200"))
        == cli.EXIT_AUTHORITY
    )
    assert "reservation has expired" in capsys.readouterr().err


def test_scope_request_completion_records_oversized_then_rejects_duplicate_and_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, budget_updates={"max_concurrency": 1}
    )
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]

    assert (
        cli.main(_complete_request_arguments(workspace, key_path, reservation_id, "201"))
        == cli.EXIT_AUTHORITY
    )
    oversized = json.loads(capsys.readouterr().out)
    assert oversized["observed_response_bytes"] == 201
    assert oversized["within_reserved_response_budget"] is False
    connection = sqlite3.connect(workspace / cli.REQUEST_ACCOUNTING_FILENAME)
    try:
        assert connection.execute(
            "SELECT observed_response_bytes FROM reservations WHERE reservation_id = ?",
            (reservation_id,),
        ).fetchone() == (201,)
    finally:
        connection.close()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    capsys.readouterr()
    assert (
        cli.main(_complete_request_arguments(workspace, key_path, reservation_id, "200"))
        == cli.EXIT_AUTHORITY
    )
    assert "already complete" in capsys.readouterr().err
    assert (
        cli.main(_complete_request_arguments(workspace, key_path, "reservation.unknown", "0"))
        == cli.EXIT_AUTHORITY
    )
    assert "unknown request reservation" in capsys.readouterr().err


def test_scope_request_accounting_rejects_tampered_state_bindings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    capsys.readouterr()
    connection = sqlite3.connect(workspace / cli.REQUEST_ACCOUNTING_FILENAME)
    try:
        connection.execute("UPDATE metadata SET value = 'replaced' WHERE key = 'run_id'")
        connection.commit()
    finally:
        connection.close()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "not bound to the verified workspace" in capsys.readouterr().err


def test_scope_request_accounting_rejects_pre_accounting_workspace(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    run_path = workspace / "run.json"
    manifest = json.loads(run_path.read_text(encoding="utf-8"))
    del manifest[cli.REQUEST_ACCOUNTING_STATE_KEY]
    run_path.write_text(json.dumps(manifest), encoding="utf-8")
    capsys.readouterr()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "predates request accounting" in capsys.readouterr().err


def test_scope_verify_request_requires_the_revised_exact_binding_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    state_path = workspace / cli.REQUEST_ACCOUNTING_FILENAME
    connection = sqlite3.connect(state_path)
    try:
        connection.execute("DROP TABLE reservations")
        connection.execute(
            """CREATE TABLE reservations (
                reservation_id TEXT PRIMARY KEY,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                request_fingerprint TEXT NOT NULL,
                request_bytes INTEGER NOT NULL,
                response_limit INTEGER NOT NULL,
                completed_at REAL,
                observed_response_bytes INTEGER
            )"""
        )
        connection.commit()
    finally:
        connection.close()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "unsupported schema; create a new run workspace" in capsys.readouterr().err


@pytest.mark.parametrize("tamper", ("missing", "blank", "extra_table"))
def test_scope_request_accounting_rejects_missing_replaced_or_extended_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], tamper: str
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    state_path = workspace / cli.REQUEST_ACCOUNTING_FILENAME
    if tamper == "missing":
        state_path.unlink()
    elif tamper == "blank":
        state_path.write_bytes(b"")
    else:
        connection = sqlite3.connect(state_path)
        try:
            connection.execute("CREATE TABLE unexpected_state (value TEXT)")
            connection.commit()
        finally:
            connection.close()
    capsys.readouterr()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "request accounting state" in capsys.readouterr().err


def test_scope_request_concurrent_processes_allow_one_active_reservation(
    tmp_path: Path,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path, budget_updates={"max_concurrency": 1}
    )
    command = [sys.executable, "-m", "faultloom", *_check_request_arguments(workspace, key_path)]
    first = subprocess.Popen(
        command,
        cwd=ROOT,
        env=_module_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    second = subprocess.Popen(
        command,
        cwd=ROOT,
        env=_module_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    first_stdout, first_stderr = first.communicate(timeout=30)
    second_stdout, second_stderr = second.communicate(timeout=30)

    assert sorted((first.returncode, second.returncode)) == [cli.EXIT_OK, cli.EXIT_AUTHORITY]
    outcomes = ((first_stdout, first_stderr), (second_stdout, second_stderr))
    dispatched = sum(
        json.loads(stdout)["dispatch_performed"] is False
        for stdout, _ in outcomes
        if stdout
    )
    assert dispatched == 1
    assert sum("concurrency budget" in stderr for _, stderr in outcomes) == 1


@pytest.mark.parametrize(
    ("option", "value"),
    (
        ("hostname", "other.example"),
        ("port", "80"),
        ("scheme", "http"),
        ("method", "POST"),
        ("path", "/other"),
    ),
)
def test_scope_check_request_rejects_target_mismatches(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    option: str,
    value: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()

    assert (
        cli.main(_check_request_arguments(workspace, key_path, **{option: value}))
        == cli.EXIT_AUTHORITY
    )
    assert capsys.readouterr().out == ""


def test_scope_check_request_honors_request_scoped_explicit_deny(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(
        tmp_path,
        request_deny=("GET", "/api/*"),
    )
    capsys.readouterr()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "explicit signed deny" in capsys.readouterr().err


def test_scope_check_request_rejects_observe_only_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path, observe_only=True)
    capsys.readouterr()

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "signed action policy" in capsys.readouterr().err


def test_scope_check_request_rejects_inactive_signed_window(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    authority_path = workspace / "authority.json"
    envelope = SignedAuthorityGrant.model_validate_json(
        authority_path.read_text(encoding="utf-8")
    )
    now = datetime.now(UTC)
    inactive_window = envelope.payload.execution_windows[0].model_copy(
        update={
            "starts_at": now + timedelta(minutes=10),
            "ends_at": now + timedelta(hours=1),
        }
    )
    inactive_grant = envelope.payload.model_copy(
        update={"execution_windows": (inactive_window,)}
    )
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    authority_content = sign_authority_grant(
        inactive_grant,
        signer,
        signed_at=now,
    ).model_dump_json(indent=2).encode("utf-8")
    authority_path.write_bytes(authority_content)
    run_path = workspace / "run.json"
    manifest = json.loads(run_path.read_text(encoding="utf-8"))
    manifest["authority_sha256"] = hashlib.sha256(authority_content).hexdigest()
    manifest["execution_windows"] = [inactive_window.model_dump(mode="json")]
    run_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert "outside every signed execution window" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("request_bytes", "response_bytes"),
    (("4097", "200"), ("100", "65537")),
)
def test_scope_check_request_enforces_signed_byte_limits(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    request_bytes: str,
    response_bytes: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()

    assert (
        cli.main(
            _check_request_arguments(
                workspace,
                key_path,
                request_bytes=request_bytes,
                response_bytes=response_bytes,
            )
        )
        == cli.EXIT_AUTHORITY
    )
    assert "signed byte" in capsys.readouterr().err


@pytest.mark.parametrize("tamper_kind", ("authority", "trusted_key", "digest", "binding"))
def test_scope_check_request_rejects_tampered_workspace_bindings(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    tamper_kind: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    if tamper_kind == "authority":
        authority = workspace / "authority.json"
        authority.write_bytes(authority.read_bytes() + b" ")
    elif tamper_kind == "trusted_key":
        key = workspace / "trusted-key.json"
        key.write_bytes(key.read_bytes() + b" ")
    else:
        run = workspace / "run.json"
        manifest = json.loads(run.read_text(encoding="utf-8"))
        if tamper_kind == "digest":
            manifest["authority_sha256"] = "0" * 64
        else:
            manifest["grant_version"] = 999
        run.write_text(json.dumps(manifest), encoding="utf-8")

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""


def test_scope_check_request_rejects_workspace_key_replacement(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, pinned_key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    now = datetime.now(UTC) - timedelta(minutes=1)
    replacement_authority_path, replacement_key_path = _authority_files(
        tmp_path / "replacement",
        hostnames=("example.com",),
        paths=("/api/*",),
        methods=("GET",),
        protocols=("https",),
        now=now,
        signer_seed=1,
    )
    replacement_authority = replacement_authority_path.read_bytes()
    replacement_key = replacement_key_path.read_bytes()
    envelope = SignedAuthorityGrant.model_validate_json(replacement_authority)
    grant = envelope.payload
    (workspace / "authority.json").write_bytes(replacement_authority)
    (workspace / "trusted-key.json").write_bytes(replacement_key)
    run_path = workspace / "run.json"
    manifest = json.loads(run_path.read_text(encoding="utf-8"))
    manifest.update(
        {
            "authority_sha256": hashlib.sha256(replacement_authority).hexdigest(),
            "trusted_key_sha256": hashlib.sha256(replacement_key).hexdigest(),
            "grant_id": grant.grant_id,
            "grant_version": grant.grant_version,
            "target": grant.targets[0].model_dump(mode="json"),
            "pack_id": grant.pack_ids[0],
            "action_policy": grant.action_policy.model_dump(mode="json"),
            "budget": grant.budget.model_dump(mode="json"),
            "execution_windows": [
                window.model_dump(mode="json") for window in grant.execution_windows
            ],
        }
    )
    run_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert (
        cli.main(_check_request_arguments(workspace, pinned_key_path))
        == cli.EXIT_AUTHORITY
    )
    assert "authority verification failed" in capsys.readouterr().err


def test_manual_evidence_add_streams_file_and_records_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority_path, key_path = _authority_files(
        tmp_path / "grant",
        hostnames=("example.com",),
    )
    workspace = tmp_path / "customer-run"
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    assert cli.main(
        _run_arguments(authority_path, key_path)
        + ["--workspace", str(workspace)]
    ) == cli.EXIT_OK
    capsys.readouterr()
    source = tmp_path / "burp-export.json"
    source.write_bytes(b'{"request":"GET / HTTP/1.1","status":200}\n')

    assert cli.main(
        [
            "evidence",
            "add",
            "--workspace",
            str(workspace),
            "--file",
            str(source),
            "--kind",
            "burp",
            "--title",
            "Landing page response",
        ]
    ) == cli.EXIT_OK

    result = json.loads(capsys.readouterr().out)
    stored = Path(result["stored_file"])
    record_path = Path(result["record"])
    assert stored.parent == workspace / "evidence" / "raw"
    assert stored.read_bytes() == source.read_bytes()
    record = json.loads(record_path.read_text(encoding="utf-8"))
    assert record["kind"] == "burp"
    assert record["title"] == "Landing page response"
    assert record["size_bytes"] == len(source.read_bytes())
    assert record["sha256"] == result["sha256"]
    assert len(record["sha256"]) == 64
    assert record["run_id"].startswith("run.")

    steps = tmp_path / "steps.txt"
    steps.write_text(
        "1. Send the recorded request.\n2. Observe the unauthorized response.\n",
        encoding="utf-8",
    )
    assert cli.main(
        [
            "finding",
            "new",
            "--workspace",
            str(workspace),
            "--title",
            "Unauthenticated data exposure",
            "--severity",
            "high",
            "--summary",
            "A public request returned private account data.",
            "--impact",
            "An unauthenticated party can read another account.",
            "--steps-file",
            str(steps),
            "--remediation",
            "Enforce object-level authorization before serialization.",
            "--evidence",
            result["evidence_id"],
        ]
    ) == cli.EXIT_OK
    finding_result = json.loads(capsys.readouterr().out)
    finding_path = Path(finding_result["finding"])
    report = finding_path.read_text(encoding="utf-8")
    assert "DRAFT — NOT INDEPENDENTLY VERIFIED" in report
    assert "# Unauthenticated data exposure" in report
    assert "Severity: **High**" in report
    assert "Send the recorded request" in report
    assert result["evidence_id"] in report
    assert record["sha256"] in report
    assert "example.com" in report


def test_manual_evidence_add_exchange_archives_completed_pair_and_finding_selects_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    capsys.readouterr()
    verified = _run_module(
        _check_request_arguments(workspace, key_path), reject_sockets=True
    )
    assert verified.returncode == cli.EXIT_OK
    reservation_id = json.loads(verified.stdout)["reservation_id"]
    request_path = workspace / "request.raw"
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    completed = _run_module(
        _complete_request_arguments(
            workspace,
            key_path,
            reservation_id,
            str(len(response_path.read_bytes())),
            request_file=request_path,
            response_file=response_path,
        ),
        reject_sockets=True,
    )
    assert completed.returncode == cli.EXIT_OK

    archived = _run_module(
        _add_exchange_arguments(
            workspace, key_path, reservation_id, request_path, response_path
        ),
        reject_sockets=True,
    )
    assert archived.returncode == cli.EXIT_OK
    result = json.loads(archived.stdout)
    record = json.loads(Path(result["record"]).read_text(encoding="utf-8"))
    assert Path(result["request_stored_file"]).read_bytes() == request_path.read_bytes()
    assert Path(result["response_stored_file"]).read_bytes() == response_path.read_bytes()
    assert record["schema"] == "faultloom.manual-evidence.v1"
    assert record["reservation_id"] == reservation_id
    assert record["request"]["sha256"] == hashlib.sha256(request_path.read_bytes()).hexdigest()
    assert record["response"]["sha256"] == hashlib.sha256(response_path.read_bytes()).hexdigest()
    assert record["request"]["size_bytes"] == len(request_path.read_bytes())
    assert record["response"]["size_bytes"] == len(response_path.read_bytes())

    assert cli.main(
        [
            "finding",
            "new",
            "--workspace",
            str(workspace),
            "--title",
            "Archived exchange",
            "--severity",
            "low",
            "--evidence",
            result["evidence_id"],
        ]
    ) == cli.EXIT_OK
    finding = Path(json.loads(capsys.readouterr().out)["finding"])
    report = finding.read_text(encoding="utf-8")
    assert result["evidence_id"] in report
    for component in (record["request"], record["response"]):
        assert component["stored_file"] in report
        assert str(component["size_bytes"]) in report
        assert component["sha256"] in report

    record["response"]["sha256"] = "not-a-digest"
    Path(result["record"]).write_text(json.dumps(record), encoding="utf-8")
    assert cli.main(
        [
            "finding",
            "new",
            "--workspace",
            str(workspace),
            "--title",
            "Malformed exchange",
            "--severity",
            "low",
            "--evidence",
            result["evidence_id"],
        ]
    ) == cli.EXIT_USAGE
    assert "invalid archived exchange evidence summary" in capsys.readouterr().err


def test_manual_evidence_add_exchange_allows_post_window_archival(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority_path, key_path = _authority_files(
        tmp_path / "grant",
        hostnames=("example.com",),
        ports=(443,),
        paths=("/api/*",),
        methods=("GET",),
        protocols=("https",),
        now=NOW,
    )
    workspace = tmp_path / "manual-run"
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    assert (
        cli.main(_run_arguments(authority_path, key_path) + ["--workspace", str(workspace)])
        == cli.EXIT_OK
    )
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    request_path = workspace / "request.raw"
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"recorded response")
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW + timedelta(minutes=1))
    assert cli.main(
        _complete_request_arguments(
            workspace,
            key_path,
            reservation_id,
            str(len(response_path.read_bytes())),
            response_file=response_path,
        )
    ) == cli.EXIT_OK
    capsys.readouterr()

    monkeypatch.setattr(cli, "_utc_now", lambda: NOW + timedelta(hours=3))
    assert cli.main(
        _add_exchange_arguments(
            workspace, key_path, reservation_id, request_path, response_path
        )
    ) == cli.EXIT_OK


def test_manual_evidence_add_exchange_cleans_partial_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    request_path = workspace / "request.raw"
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"recorded response")
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    assert cli.main(
        _complete_request_arguments(
            workspace,
            key_path,
            reservation_id,
            str(len(response_path.read_bytes())),
            response_file=response_path,
        )
    ) == cli.EXIT_OK
    capsys.readouterr()
    original_write = cli._write_new_file

    def fail_record_write(path: Path, content: bytes, *, mode: int) -> None:
        if path.suffix == ".json":
            raise cli.CliError("injected record failure", exit_code=cli.EXIT_USAGE)
        original_write(path, content, mode=mode)

    monkeypatch.setattr(cli, "_write_new_file", fail_record_write)
    assert cli.main(
        _add_exchange_arguments(
            workspace, key_path, reservation_id, request_path, response_path
        )
    ) == cli.EXIT_USAGE
    assert list((workspace / "evidence" / "raw").glob("evidence.*")) == []
    assert "injected record failure" in capsys.readouterr().err


def test_manual_evidence_add_exchange_rejects_unknown_or_incomplete_reservation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    request_path = workspace / "request.raw"
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"response")
    capsys.readouterr()

    assert cli.main(
        _add_exchange_arguments(
            workspace, key_path, "reservation.unknown", request_path, response_path
        )
    ) == cli.EXIT_AUTHORITY
    assert "unknown request reservation" in capsys.readouterr().err

    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    assert cli.main(
        _add_exchange_arguments(
            workspace, key_path, reservation_id, request_path, response_path
        )
    ) == cli.EXIT_AUTHORITY
    assert "reservation is not complete" in capsys.readouterr().err


def test_manual_evidence_add_exchange_rejects_count_only_completion(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    request_path = workspace / "request.raw"
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"response")
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    assert cli.main(
        _complete_request_arguments(workspace, key_path, reservation_id, "8")
    ) == cli.EXIT_OK
    capsys.readouterr()

    assert cli.main(
        _add_exchange_arguments(
            workspace, key_path, reservation_id, request_path, response_path
        )
    ) == cli.EXIT_AUTHORITY
    assert "without an exact response file" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("changed", "expected_error"),
    (("request", "request file digest"), ("response", "response file size")),
)
def test_manual_evidence_add_exchange_rejects_changed_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    changed: str,
    expected_error: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    request_path = workspace / "request.raw"
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"original response")
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    assert cli.main(
        _complete_request_arguments(
            workspace,
            key_path,
            reservation_id,
            str(len(response_path.read_bytes())),
            response_file=response_path,
        )
    ) == cli.EXIT_OK
    capsys.readouterr()
    if changed == "request":
        request_path.write_bytes(request_path.read_bytes().replace(b"Pad: a", b"Pad: b"))
    else:
        response_path.write_bytes(b"short")

    assert cli.main(
        _add_exchange_arguments(
            workspace, key_path, reservation_id, request_path, response_path
        )
    ) == cli.EXIT_AUTHORITY
    assert expected_error in capsys.readouterr().err


@pytest.mark.parametrize("source", ("request", "response"))
def test_manual_evidence_add_exchange_rejects_symlink_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    source: str,
) -> None:
    workspace, key_path = _manual_workspace_for_request_check(tmp_path)
    request_path = workspace / "request.raw"
    response_path = workspace / "response.raw"
    response_path.write_bytes(b"original response")
    capsys.readouterr()
    assert cli.main(_check_request_arguments(workspace, key_path)) == cli.EXIT_OK
    reservation_id = json.loads(capsys.readouterr().out)["reservation_id"]
    assert cli.main(
        _complete_request_arguments(
            workspace,
            key_path,
            reservation_id,
            str(len(response_path.read_bytes())),
            response_file=response_path,
        )
    ) == cli.EXIT_OK
    capsys.readouterr()
    linked = tmp_path / f"{source}-link.raw"
    linked.symlink_to(request_path if source == "request" else response_path)

    assert cli.main(
        _add_exchange_arguments(
            workspace,
            key_path,
            reservation_id,
            linked if source == "request" else request_path,
            linked if source == "response" else response_path,
        )
    ) == cli.EXIT_AUTHORITY
    assert "regular non-symlink" in capsys.readouterr().err


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


def test_authority_open_triggered_key_replacement_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, trusted_key = _authority_files(tmp_path / "trusted-a", signer_seed=0)
    attacker_authority, attacker_key = _authority_files(
        tmp_path / "attacker-b", signer_seed=37
    )
    active_key = tmp_path / "active-key.json"
    active_key.write_bytes(trusted_key.read_bytes())
    pending_key = tmp_path / "pending-attacker-key.json"
    pending_key.write_bytes(attacker_key.read_bytes())
    original_open = cli._open_bound_protocol_file
    events: list[str] = []
    replaced = False

    def replace_when_authority_opens(
        candidate: object,
    ) -> cli._BoundProtocolFile:
        nonlocal replaced
        path = getattr(candidate, "path", candidate)
        bound = original_open(candidate)  # type: ignore[arg-type]
        events.append(f"open:{Path(path).name}")
        if path == attacker_authority and not replaced:
            os.replace(pending_key, active_key)
            events.append("swap:key-after-authority-open")
            replaced = True
        return bound

    monkeypatch.setattr(cli, "_open_bound_protocol_file", replace_when_authority_opens)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(attacker_authority, active_key)) == cli.EXIT_AUTHORITY
    assert replaced is True
    assert events == [
        "open:active-key.json",
        "open:authority.json",
        "swap:key-after-authority-open",
    ]


def test_both_paths_are_snapshotted_and_bound_before_either_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    original_snapshot = cli._snapshot_protocol_file_path
    original_open = cli._open_bound_protocol_file
    original_read = cli._read_bound_protocol_file
    original_reconcile = cli._reconcile_bound_protocol_file
    events: list[str] = []

    def record_snapshot(path: Path) -> cli._ProtocolFilePathSnapshot:
        snapshot = original_snapshot(path)
        events.append(f"snapshot:{path.name}")
        return snapshot

    def record_open(
        snapshot: cli._ProtocolFilePathSnapshot,
    ) -> cli._BoundProtocolFile:
        bound = original_open(snapshot)
        events.append(f"open:{snapshot.path.name}")
        return bound

    def record_read(bound: cli._BoundProtocolFile) -> bytes:
        content = original_read(bound)
        events.append(f"read:{bound.path.name}")
        return content

    def record_reconcile(bound: cli._BoundProtocolFile) -> None:
        original_reconcile(bound)
        events.append(f"reconcile:{bound.path.name}")

    monkeypatch.setattr(cli, "_snapshot_protocol_file_path", record_snapshot)
    monkeypatch.setattr(cli, "_open_bound_protocol_file", record_open)
    monkeypatch.setattr(cli, "_read_bound_protocol_file", record_read)
    monkeypatch.setattr(cli, "_reconcile_bound_protocol_file", record_reconcile)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_OK
    assert events == [
        "snapshot:authority-public-key.json",
        "snapshot:authority.json",
        "open:authority-public-key.json",
        "open:authority.json",
        "read:authority.json",
        "read:authority-public-key.json",
        "reconcile:authority.json",
        "reconcile:authority-public-key.json",
    ]


@pytest.mark.parametrize("swap_target", ("trusted_key", "authority"))
def test_leaf_replacement_after_pre_snapshot_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    swap_target: str,
) -> None:
    authority_path, key_path = _authority_files(tmp_path / "active")
    selected = key_path if swap_target == "trusted_key" else authority_path
    replacement = tmp_path / f"pending-{swap_target}.json"
    replacement.write_bytes(selected.read_bytes())
    original_snapshot = cli._snapshot_protocol_file_path
    replaced = False

    def replace_after_snapshot(path: Path) -> cli._ProtocolFilePathSnapshot:
        nonlocal replaced
        snapshot = original_snapshot(path)
        if path == selected and not replaced:
            os.replace(replacement, selected)
            replaced = True
        return snapshot

    monkeypatch.setattr(cli, "_snapshot_protocol_file_path", replace_after_snapshot)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY
    assert replaced is True


def test_component_replacement_after_both_pre_snapshots_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active = tmp_path / "active"
    authority_path, key_path = _authority_files(active)
    replacement = tmp_path / "replacement"
    _authority_files(replacement)
    parked = tmp_path / "parked"
    original_snapshot = cli._snapshot_protocol_file_path
    snapshots = 0

    def replace_component_after_snapshots(
        path: Path,
    ) -> cli._ProtocolFilePathSnapshot:
        nonlocal snapshots
        snapshot = original_snapshot(path)
        snapshots += 1
        if snapshots == 2:
            active.rename(parked)
            replacement.rename(active)
        return snapshot

    monkeypatch.setattr(
        cli, "_snapshot_protocol_file_path", replace_component_after_snapshots
    )
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY
    assert snapshots == 2


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
    ("cidr", "expected"),
    (
        ("127.0.0.0/8", True),
        ("127.0.0.1/32", True),
        ("127.255.255.255/32", True),
        ("::1/128", True),
        ("127.0.0.1", False),
        ("127.0.0.1/8", False),
        ("127.1.2.3/8", False),
        ("127.0.0.1/08", False),
        ("127.0.0.1/255.0.0.0", False),
        ("2130706433/32", False),
        ("0:0:0:0:0:0:0:1/128", False),
        ("0:0:0:0:0:0:0:A/128", False),
        ("::1%lo/128", False),
        ("::1%25lo/128", False),
        ("::1%eth0/128", False),
        ("::1/0128", False),
        ("::1/128 ", False),
        (" ::1/128", False),
        ("::ffff:127.0.0.1/128", False),
        ("127.0.0.0/7", False),
    ),
)
def test_loopback_cidr_uses_canonical_ascii_grammar(
    cidr: str,
    expected: bool,
) -> None:
    assert cli._network_is_loopback(cidr) is expected


@pytest.mark.parametrize(
    "cidr",
    (
        "127.0.0.1",
        "127.0.0.1/8",
        "127.1.2.3/8",
        "127.0.0.1/08",
        "127.0.0.1/255.0.0.0",
        "2130706433/32",
        "0:0:0:0:0:0:0:1/128",
        "0:0:0:0:0:0:0:A/128",
        "::1%lo/128",
        "::1%25lo/128",
        "::1%eth0/128",
        "::1/0128",
        "::1/128 ",
        " ::1/128",
        "::ffff:127.0.0.1/128",
        "127.0.0.0/7",
    ),
)
def test_signed_noncanonical_or_non_loopback_cidrs_are_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cidr: str,
) -> None:
    authority_path, key_path = _authority_files(
        tmp_path,
        hostnames=(),
        cidrs=(cidr,),
    )
    if cidr != cidr.strip():
        raw = json.loads(authority_path.read_text(encoding="utf-8"))
        raw["payload"]["targets"][0]["cidrs"] = [cidr]
        authority_path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_AUTHORITY


@pytest.mark.parametrize("cidr", ("127.0.0.0/8", "127.0.0.1/32", "::1/128"))
def test_signed_canonical_loopback_cidrs_are_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cidr: str,
) -> None:
    authority_path, key_path = _authority_files(
        tmp_path,
        hostnames=(),
        cidrs=(cidr,),
    )
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(_run_arguments(authority_path, key_path)) == cli.EXIT_OK


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


def test_live_mode_requires_controller_provisioning_after_authority_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    arguments = _run_arguments(authority_path, key_path) + ["--live"]
    assert cli.main(arguments) == cli.EXIT_UNAVAILABLE
    assert "controller-provisioned --gateway-bundle" in capsys.readouterr().err


def test_gateway_provisioning_inputs_are_rejected_without_live_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authority_path, key_path = _authority_files(tmp_path)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)

    assert cli.main(
        _run_arguments(authority_path, key_path)
        + ["--gateway-bundle", str(tmp_path / "bundle.json")]
    ) == cli.EXIT_USAGE

    assert "require --live" in capsys.readouterr().err


def test_live_mode_dispatches_one_preapproved_command_through_launcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import faultloom.execution as execution
    from faultloom.execution import EndpointScheme, SemanticEndpoint, SemanticHttpRequest
    from faultloom_protocol import SCHEMA_VERSION
    from tests.runtime.execution_helpers import command, completed_result

    grant = sample_models()["AuthorityGrant"]
    target = grant.targets[0].model_copy(
        update={
            "target_id": "target.loopback",
            "hostnames": ("localhost",),
            "ports": (80,),
            "protocols": ("http",),
            "paths": ("/api/*",),
        }
    )
    grant = grant.model_copy(
        update={
            "issued_at": NOW,
            "not_before": NOW,
            "expires_at": NOW + timedelta(hours=1),
            "targets": (target,),
            "execution_windows": (
                grant.execution_windows[0].model_copy(
                    update={"starts_at": NOW, "ends_at": NOW + timedelta(hours=1)}
                ),
            ),
            "budget": grant.budget.model_copy(update={"max_request_bytes": 8192}),
        }
    )
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    envelope = sign_authority_grant(grant, signer, signed_at=NOW)
    authority_path = tmp_path / "authority.json"
    key_path = tmp_path / "authority-public-key.json"
    authority_path.write_text(envelope.model_dump_json(), encoding="utf-8")
    key_path.write_text(signer.public_key_record.model_dump_json(), encoding="utf-8")
    approved = command(
        request=SemanticHttpRequest(
            schema_version=SCHEMA_VERSION,
            endpoint=SemanticEndpoint(
                schema_version=SCHEMA_VERSION,
                scheme=EndpointScheme.HTTP,
                hostname="localhost",
                port=80,
                path="/api/probe",
            ),
            method="GET",
        )
    )
    approved = approved.model_copy(
        update={
            "lease": approved.lease.model_copy(
                update={"authority_key_id": signer.key_id}
            )
        }
    )
    dispatch_path = tmp_path / "dispatch.json"
    dispatch_path.write_text(approved.model_dump_json(), encoding="utf-8")
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text("{}", encoding="utf-8")
    observed: list[object] = []

    class ProvisionedBundle:
        @classmethod
        def load(cls, path: Path) -> object:
            observed.append(path)
            return object()

    class RecordingLauncher:
        def __init__(self, bundle: object) -> None:
            observed.append(bundle)

        def __enter__(self) -> "RecordingLauncher":
            return self

        def __exit__(self, *_: object) -> None:
            observed.append("closed")

        def dispatch(self, supplied: object) -> object:
            observed.append(supplied)
            return completed_result(approved)

    monkeypatch.setattr(execution, "GatewayLaunchBundle", ProvisionedBundle)
    monkeypatch.setattr(execution, "GatewayLauncher", RecordingLauncher)
    monkeypatch.setattr(cli, "_utc_now", lambda: NOW)
    arguments = [
        "run",
        "--authority",
        str(authority_path),
        "--trusted-key",
        str(key_path),
        "--target",
        "target.loopback",
        "--pack",
        "web",
        "--live",
        "--gateway-bundle",
        str(bundle_path),
        "--dispatch-command",
        str(dispatch_path),
    ]

    assert cli.main(arguments) == cli.EXIT_OK
    result = json.loads(capsys.readouterr().out)
    assert result["dispatch_performed"] is True
    assert result["network_access"] == "gateway_only"
    assert observed[0] == bundle_path
    assert observed[-1] == "closed"


@pytest.mark.parametrize(
    "arguments",
    (
        ["scope", "revoke", "grant.1"],
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


@pytest.mark.parametrize(
    "arguments",
    (
        ["verify", "candidate.1"],
        ["report", "finding.1", "--format", "md"],
    ),
    ids=("verify", "report"),
)
def test_verification_command_surface_accepts_documented_syntax_and_fails_closed(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "verification data is unavailable" in captured.err
