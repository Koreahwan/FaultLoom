from __future__ import annotations

import json
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from faultloom import cli

from tests.runtime.test_personal_campaign import (
    _campaign_run_arguments,
    _listener,
    _serve,
    _spec,
    _workspace,
)
from tests.runtime.test_personal_campaign_bridge import _bundle, _prepare_arguments
from tests.runtime.test_cli import _authority_files


def _export_arguments(workspace: Path, key: Path, out: Path) -> list[str]:
    return [
        "campaign", "export-verification-handoff", "--workspace", str(workspace),
        "--trusted-key", str(key), "--campaign-id", "owned-loopback", "--out", str(out),
    ]


def _finalized_v2_campaign(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], *, negative: bool = False
) -> tuple[Path, Path]:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    # The handoff intentionally permits no absolute references, so make every
    # v2 binding source workspace-local just as a portable operator workspace is.
    template = _spec(workspace, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = workspace / "bound.json"
    capsys.readouterr()
    assert cli.main(_prepare_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    capsys.readouterr()
    thread = _serve(
        listener,
        (
            [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3
            if negative
            else [
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
            ]
        ),
        [],
    )
    assert cli.main(_campaign_run_arguments(workspace, key, bound)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_OK
    capsys.readouterr()
    return workspace, key


def test_campaign_export_verification_handoff_is_private_read_only_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    out = workspace / "verification-handoff.json"
    before = {path.relative_to(workspace): path.read_bytes() for path in workspace.rglob("*") if path.is_file()}

    def unexpected_socket(*args: object, **kwargs: object) -> object:
        raise AssertionError("verification handoff must not open a socket")

    monkeypatch.setattr(cli.socket, "socket", unexpected_socket)
    assert cli.main(_export_arguments(workspace, key, out)) == cli.EXIT_OK
    emitted = json.loads(capsys.readouterr().out)
    manifest = json.loads(out.read_text(encoding="utf-8"))
    assert emitted["sha256"] == cli.sha256_hex(out.read_bytes())
    if cli.os.name == "posix":
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert manifest["status"] == "verification_handoff_ready"
    assert manifest["verificationStatus"] == "pending"
    assert manifest["independentVerification"] is False
    assert manifest["targetDispatch"] is False
    assert manifest["networkAccess"] is False
    assert manifest["automaticSubmission"] is False
    assert [exchange["role"] for exchange in manifest["evidence"]] == ["effect", "reproduction", "negative_control"]
    assert all(
        set(("requestSha256", "responseSha256", "bodySha256")) <= set(exchange)
        for exchange in manifest["evidence"]
    )
    assert manifest["replayRequirements"]["sourceEvidenceReuse"] is False
    rendered = out.read_text(encoding="utf-8")
    assert "Content-Length" not in rendered and "HTTP/1.1" not in rendered
    assert str(tmp_path) not in rendered
    assert "secret" not in rendered.lower()
    after = {path.relative_to(workspace): path.read_bytes() for path in workspace.rglob("*") if path.is_file()}
    assert set(after) == {*before, Path("verification-handoff.json")}
    assert all(after[path] == content for path, content in before.items())
    before_stat = out.stat()
    assert cli.main(_export_arguments(workspace, key, out)) == cli.EXIT_OK
    repeated = json.loads(capsys.readouterr().out)
    assert repeated["sha256"] == emitted["sha256"]
    assert out.stat().st_mtime_ns == before_stat.st_mtime_ns
    receipt = json.loads(next((workspace / "campaigns").glob("*.final-receipt.json")).read_text())
    finding = Path(receipt["finding"]["record"])
    finding_value = json.loads(finding.read_text())
    finding_value["summary"] = "changed after export"
    finding.write_text(json.dumps(finding_value), encoding="utf-8")
    assert cli.main(_export_arguments(workspace, key, out)) == cli.EXIT_AUTHORITY
    assert out.stat().st_mtime_ns == before_stat.st_mtime_ns


@pytest.mark.parametrize(
    "mutation",
    ("final_receipt", "spec", "start", "run_result", "accounting", "evidence", "request", "response", "binding", "finding"),
)
def test_campaign_export_verification_handoff_rejects_tampered_finalization(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mutation: str
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    campaigns = workspace / "campaigns"
    if mutation == "final_receipt":
        path = next(campaigns.glob("*.final-receipt.json"))
        value = json.loads(path.read_text())
        value["manual_review"] = "tampered"
        path.write_text(json.dumps(value), encoding="utf-8")
    elif mutation == "spec":
        path = workspace / "bound.json"
        value = json.loads(path.read_text())
        value["finding"]["title"] = "tampered"
        path.write_text(json.dumps(value), encoding="utf-8")
    elif mutation == "start":
        path = next(campaigns.glob("*.start.json"))
        value = json.loads(path.read_text())
        value["finding"]["title"] = "tampered"
        path.write_text(json.dumps(value), encoding="utf-8")
    elif mutation == "run_result":
        path = next(campaigns.glob("*.run-result.json"))
        value = json.loads(path.read_text())
        value["requests"][0]["role"] = "tampered"
        path.write_text(json.dumps(value), encoding="utf-8")
    elif mutation == "accounting":
        with sqlite3.connect(workspace / "request-accounting.sqlite3") as connection:
            connection.execute("UPDATE campaign_bindings SET body_sha256 = ?", ("0" * 64,))
            connection.commit()
    elif mutation == "evidence":
        path = next((workspace / "evidence" / "raw").glob("evidence.*.json"))
        value = json.loads(path.read_text())
        value["response"]["sha256"] = "0" * 64
        path.write_text(json.dumps(value), encoding="utf-8")
    elif mutation == "request":
        (workspace / "effect.raw").write_bytes(b"GET /changed HTTP/1.1\r\nHost: invalid\r\nConnection: close\r\n\r\n")
    elif mutation == "response":
        path = next((workspace / "responses").glob("*.raw"))
        path.write_bytes(path.read_bytes() + b"tampered")
    elif mutation == "binding":
        path = workspace / "bound.json"
        value = json.loads(path.read_text())
        value["automation_binding"]["candidate_id"] = "candidate.other"
        path.write_text(json.dumps(value), encoding="utf-8")
    else:
        receipt = json.loads(next(campaigns.glob("*.final-receipt.json")).read_text())
        finding = Path(receipt["finding"]["record"])
        value = json.loads(finding.read_text())
        value["title"] = "tampered"
        finding.write_text(json.dumps(value), encoding="utf-8")
    assert cli.main(_export_arguments(workspace, key, workspace / "handoff.json")) == cli.EXIT_AUTHORITY
    assert not (workspace / "handoff.json").exists()


def test_campaign_export_verification_handoff_rejects_unbound_negative_and_existing_different_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    out = workspace / "handoff.json"
    out.write_text("{}\n", encoding="utf-8")
    assert cli.main(_export_arguments(workspace, key, out)) == cli.EXIT_AUTHORITY

    receipt = next((workspace / "campaigns").glob("*.final-receipt.json"))
    value = json.loads(receipt.read_text())
    value["status"] = "negative_campaign"
    value["finding"] = None
    receipt.write_text(json.dumps(value), encoding="utf-8")
    assert cli.main(_export_arguments(workspace, key, workspace / "other.json")) == cli.EXIT_AUTHORITY


def test_campaign_export_verification_handoff_rejects_genuine_negative_campaign(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys, negative=True)
    assert cli.main(_export_arguments(workspace, key, workspace / "negative.json")) == cli.EXIT_AUTHORITY
    assert not (workspace / "negative.json").exists()


@pytest.mark.parametrize("source", ("finding", "automation_result"))
def test_campaign_export_verification_handoff_rejects_swap_after_deep_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], source: str
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    original = cli._validate_completed_campaign_finalization

    def swap_after_validation(*args: object, **kwargs: object) -> tuple[str, int]:
        result = original(*args, **kwargs)
        if source == "finding":
            receipt = json.loads(next((workspace / "campaigns").glob("*.final-receipt.json")).read_text())
            path = Path(receipt["finding"]["record"])
        else:
            path = next((workspace / "automation-results").glob("*/result.json"))
        path.write_bytes(path.read_bytes() + b" ")
        return result

    monkeypatch.setattr(cli, "_validate_completed_campaign_finalization", swap_after_validation)
    assert cli.main(_export_arguments(workspace, key, workspace / "handoff.json")) == cli.EXIT_AUTHORITY
    assert not (workspace / "handoff.json").exists()


def test_campaign_export_verification_handoff_rejects_genuine_unbound_v1_draft(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    spec = _spec(workspace, port)
    capsys.readouterr()
    thread = _serve(
        listener,
        [
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
        ],
        [],
    )
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(_export_arguments(workspace, key, workspace / "handoff.json")) == cli.EXIT_AUTHORITY
    assert not (workspace / "handoff.json").exists()


def test_campaign_export_verification_handoff_rejects_wrong_key_and_missing_final_receipt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    _, wrong_key = _authority_files(
        tmp_path / "wrong-grant",
        hostnames=("127.0.0.1",),
        ports=(1,),
        paths=("/",),
        methods=("GET",),
        protocols=("http",),
        now=datetime.now(UTC) - timedelta(minutes=1),
        signer_seed=1,
    )
    assert cli.main(_export_arguments(workspace, wrong_key, workspace / "wrong-key.json")) == cli.EXIT_AUTHORITY
    assert not (workspace / "wrong-key.json").exists()
    next((workspace / "campaigns").glob("*.final-receipt.json")).unlink()
    assert cli.main(_export_arguments(workspace, key, workspace / "missing-final.json")) == cli.EXIT_AUTHORITY
    assert not (workspace / "missing-final.json").exists()


@pytest.mark.skipif(cli.os.name == "nt", reason="symlink behavior is platform-specific")
def test_campaign_export_verification_handoff_rejects_escape_and_symlink_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    assert cli.main(_export_arguments(workspace, key, tmp_path / "outside.json")) == cli.EXIT_AUTHORITY
    linked = workspace / "linked.json"
    linked.symlink_to(tmp_path / "outside.json")
    assert cli.main(_export_arguments(workspace, key, linked)) == cli.EXIT_AUTHORITY


def test_campaign_export_verification_handoff_rejects_nested_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    nested = workspace / "handoffs" / "handoff.json"
    nested.parent.mkdir()
    assert cli.main(_export_arguments(workspace, key, nested)) == cli.EXIT_AUTHORITY
    assert not nested.exists()


@pytest.mark.parametrize(
    "name",
    ("handoff.json:alternate", "CON", ".hidden", "handoff name.json", "handoff.", "handoff.."),
)
def test_campaign_export_verification_handoff_rejects_nonportable_filename(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    output = workspace / name
    assert cli.main(_export_arguments(workspace, key, output)) == cli.EXIT_AUTHORITY
    assert not output.exists()


@pytest.mark.skipif(cli.os.name != "nt", reason="Windows handle-relative open is platform-specific")
def test_windows_handoff_child_remains_bound_to_renamed_workspace(tmp_path: Path) -> None:
    import msvcrt

    workspace = tmp_path / "workspace"
    parked = tmp_path / "workspace-parked"
    workspace.mkdir()
    guard = cli._open_windows_response_directory_guard(workspace)
    descriptor = -1
    try:
        with pytest.raises(cli.CliError):
            cli._windows_open_handoff_child(guard, "handoff.json:alternate", create=True)
        workspace.rename(parked)
        descriptor = cli._windows_open_handoff_child(guard, "handoff.json", create=True)
        fd = msvcrt.open_osfhandle(descriptor, cli.os.O_BINARY | cli.os.O_RDWR)
        descriptor = -1
        try:
            assert cli.os.write(fd, b"bound\n") == len(b"bound\n")
            cli.os.fsync(fd)
        finally:
            cli.os.close(fd)
    finally:
        if descriptor != -1:
            cli._close_windows_response_directory_guard(descriptor)
        cli._close_windows_response_directory_guard(guard)
    assert (parked / "handoff.json").read_bytes() == b"bound\n"
    assert not (workspace / "handoff.json").exists()


@pytest.mark.skipif(cli.os.name == "nt", reason="directory descriptor pinning is POSIX-specific")
def test_campaign_export_verification_handoff_rejects_workspace_parent_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    workspace, key = _finalized_v2_campaign(tmp_path, capsys)
    original = cli._campaign_verification_handoff_bytes
    outside = tmp_path / "outside"
    outside.mkdir()
    parked = tmp_path / "workspace-parked"

    def swap_before_publication(arguments: object) -> bytes:
        content = original(arguments)
        workspace.rename(parked)
        workspace.symlink_to(outside, target_is_directory=True)
        return content

    monkeypatch.setattr(cli, "_campaign_verification_handoff_bytes", swap_before_publication)
    assert cli.main(_export_arguments(workspace, key, workspace / "handoff.json")) == cli.EXIT_USAGE
    assert not (outside / "handoff.json").exists()
