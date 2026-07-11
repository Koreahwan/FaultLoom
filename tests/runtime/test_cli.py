from __future__ import annotations

import json
from pathlib import Path

import pytest

from faultloom import cli
from faultloom_protocol import AuthoritySigner, sign_authority_grant
from tests.protocol.factories import NOW, sample_models


def _authority_files(
    directory: Path,
    *,
    hostnames: tuple[str, ...] = ("localhost",),
    pack_ids: tuple[str, ...] = ("pack.web",),
) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    grant = sample_models()["AuthorityGrant"]
    target = grant.targets[0].model_copy(
        update={"hostnames": hostnames, "cidrs": ()}
    )
    grant = grant.model_copy(update={"targets": (target,), "pack_ids": pack_ids})
    signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    envelope = sign_authority_grant(grant, signer, signed_at=NOW)
    authority_path = directory / "authority.json"
    authority_path.write_text(envelope.model_dump_json(indent=2), encoding="utf-8")
    key_path = directory / "authority-public-key.json"
    key_path.write_text(
        signer.public_key_record.model_dump_json(indent=2), encoding="utf-8"
    )
    return authority_path, key_path


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
