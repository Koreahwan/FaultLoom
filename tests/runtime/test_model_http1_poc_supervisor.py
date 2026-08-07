from __future__ import annotations

import hashlib
import io
import json
import socket
from pathlib import Path

import pytest

from faultloom import cli
from faultloom.automation.models import AuthorizedAutomationResult
from faultloom_protocol import AuthoritySigner

from tests.runtime.test_automation_request_cli import (
    DISCLOSURE_SEED,
    _archived_exchange,
    _prepare_arguments,
    _safe_poc_turn,
    _workspace,
)
from tests.runtime.test_personal_campaign import _listener, _request, _serve


def _prepared_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], *, control: str = "/api/control"
) -> tuple[list[str], Path, Path, int]:
    listener, port = _listener()
    listener.close()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    evidence_id, _ = _archived_exchange(tmp_path, workspace, key, port, capsys)
    excerpt = tmp_path / "excerpt.txt"
    excerpt.write_text("Reviewed non-sensitive owned response.", encoding="utf-8")
    disclosure = tmp_path / "disclosure.key"
    disclosure.write_text(DISCLOSURE_SEED.hex(), encoding="ascii")
    disclosure.chmod(0o600)
    request = tmp_path / "request.json"
    assert cli.main(_prepare_arguments(workspace, key, evidence_id, excerpt, disclosure, port, request)) == 0
    capsys.readouterr()
    turn = tmp_path / "turn.json"
    turn.write_bytes(_safe_poc_turn(json.loads(request.read_text(encoding="utf-8"))))
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({
        "campaign_id": "owned-model-loopback",
        "authorization_reference": "owned loopback external authorization",
        "authorization_document_sha256": "a" * 64,
        "endpoint": {"hostname": "127.0.0.1", "port": port, "scheme": "http", "method": "GET", "path": "/api/effect"},
        "timeout_seconds": 3,
        "response_bytes": 512,
        "finding": {"title": "Operator authored title", "severity": "low", "summary": "Operator authored summary", "impact": "Operator authored impact", "remediation": "Operator authored remediation"},
    }), encoding="utf-8")
    return ([
        "campaign", "supervise-model-http1-poc", "--workspace", str(workspace), "--trusted-key", str(key),
        "--request", str(request), "--model-turn", str(turn), "--evidence-id", evidence_id,
        "--negative-control-path", control, "--metadata", str(metadata), "--out", str(workspace / "model-http1-poc"),
    ], workspace, key, port)


def _one_json(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    captured = capsys.readouterr()
    assert captured.out.count("\n") == 1
    return json.loads(captured.out)


def test_model_http1_poc_supervisor_help(capsys: pytest.CaptureFixture[str]) -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit, match="0"):
        parser.parse_args(["campaign", "supervise-model-http1-poc", "--help"])
    help_text = capsys.readouterr().out
    assert "--negative-control-path" in help_text
    assert "--metadata" in help_text


def test_model_http1_poc_supervisor_happy_resume_and_operator_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments, workspace, _, port = _prepared_command(tmp_path, capsys)
    # Recreate the exact listener on the signed port for the one controlled dispatch.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    captured: list[bytes] = []
    thread = _serve(
        listener,
        [
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
        ],
        captured,
    )
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-model-loopback\nFINALIZE owned-model-loopback\n"))
    assert cli.main(arguments) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    output = _one_json(capsys)
    assert output["status"] == "completed"
    assert output["finalStatus"] == "draft_unverified"
    assert isinstance(output["handoff"], str)
    assert output["handoff"].startswith("campaign-")
    assert output["handoff"].endswith(".verification-handoff.json")
    assert cli._is_safe_handoff_filename(output["handoff"])
    handoff = workspace / output["handoff"]
    assert output["handoffSha256"] == hashlib.sha256(handoff.read_bytes()).hexdigest()
    assert output["handoff"] == (
        f"campaign-{output['handoffSha256']}.verification-handoff.json"
    )
    assert isinstance(output["nextAction"], str)
    assert "supervise-verification-http1" in output["nextAction"]
    assert captured == [_request(port, "/api/effect"), _request(port, "/api/effect"), _request(port, "/api/control")]
    bundle = next((workspace / "model-http1-poc").glob("model-http1-poc.*"))
    assert {path.name for path in bundle.iterdir()} >= {"effect.raw", "control.raw", "triad.v1.json", "result.json", "receipt.json"}
    triad = json.loads((bundle / "triad.v1.json").read_text(encoding="utf-8"))
    assert triad["finding"]["title"] == "Operator authored title"
    assert triad["authorization_reference"] == "owned loopback external authorization"
    assert triad["authorization_document_sha256"] == "a" * 64
    provenance = json.loads((bundle / "provenance.v1.json").read_text(encoding="utf-8"))
    assert provenance["external_authorization_reference_status"] == "operator_asserted_unverified"

    def no_recompile(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("completed resume must not recompile the model output")

    monkeypatch.setattr(cli, "compile_automation_result", no_recompile)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    assert cli.main(arguments) == cli.EXIT_OK
    resumed = _one_json(capsys)
    assert resumed["status"] == "completed"
    assert resumed["handoff"] == output["handoff"]
    assert resumed["handoffSha256"] == hashlib.sha256(handoff.read_bytes()).hexdigest()
    assert len(captured) == 3

    def no_socket(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("completed handoff verification must remain offline")

    monkeypatch.setattr(cli.socket, "socket", no_socket)
    handoff.write_text("different\n", encoding="utf-8")
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""
    handoff.unlink()
    external = tmp_path / "external-handoff.json"
    external.write_text("different\n", encoding="utf-8")
    try:
        handoff.symlink_to(external)
    except OSError:
        return
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""


def test_model_http1_poc_supervisor_pending_finalize_never_writes_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments, workspace, _, port = _prepared_command(tmp_path, capsys)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    captured: list[bytes] = []
    thread = _serve(
        listener,
        [
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
        ],
        captured,
    )
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-model-loopback\nno\n"))
    assert cli.main(arguments) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    output = _one_json(capsys)
    assert output["status"] == "review_required"
    assert len(captured) == 3
    assert not list(workspace.glob("campaign-*.verification-handoff.json"))
    assert "handoff" not in output


def test_model_http1_poc_supervisor_negative_campaign_never_writes_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments, workspace, _, port = _prepared_command(tmp_path, capsys)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    captured: list[bytes] = []
    thread = _serve(
        listener,
        [b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect"] * 3,
        captured,
    )
    monkeypatch.setattr(
        cli.sys, "stdin", io.StringIO("RUN owned-model-loopback\nFINALIZE owned-model-loopback\n")
    )
    assert cli.main(arguments) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    output = _one_json(capsys)
    assert output["status"] == "completed"
    assert output["finalStatus"] == "negative_campaign"
    assert len(captured) == 3
    assert not list(workspace.glob("campaign-*.verification-handoff.json"))
    assert "handoff" not in output


def test_model_http1_poc_supervisor_decline_and_invalid_control_never_open_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments, workspace, _, _ = _prepared_command(tmp_path, capsys)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("no\n"))
    assert cli.main(arguments) == cli.EXIT_OK
    assert _one_json(capsys)["status"] == "review_required"
    assert not (workspace / "campaigns").exists()
    assert not list(workspace.glob("campaign-*.verification-handoff.json"))
    bad, _, _, _ = _prepared_command(tmp_path / "bad", capsys, control="/outside-authority")
    outside, outside_workspace, _, _ = _prepared_command(tmp_path / "outside", capsys)
    outside[outside.index("--out") + 1] = str(tmp_path / "outside-output")

    def no_socket(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("out-of-scope control must fail before a socket")

    monkeypatch.setattr(cli.socket, "socket", no_socket)
    assert cli.main(bad) == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""

    assert cli.main(outside) == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""
    assert not (outside_workspace / "campaigns").exists()
    assert not (tmp_path / "outside-output").exists()


def test_automatic_campaign_handoff_filename_is_safe_for_boundary_campaign_ids() -> None:
    for campaign_id in ("CON", "x" * 128):
        content = f"handoff-for-{campaign_id}".encode("utf-8")
        filename = cli._automatic_campaign_verification_handoff_filename(content)
        assert filename == (
            f"campaign-{hashlib.sha256(content).hexdigest()}.verification-handoff.json"
        )
        assert filename.startswith("campaign-")
        assert filename.endswith(".verification-handoff.json")
        assert len(filename) <= 128
        assert cli._is_safe_handoff_filename(filename)


def test_model_http1_poc_supervisor_rejects_non_immediate_output_before_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments, workspace, _, _ = _prepared_command(tmp_path, capsys)

    def no_socket(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unsafe output must fail before a socket")

    monkeypatch.setattr(cli.socket, "socket", no_socket)
    out_index = arguments.index("--out") + 1
    for unsafe_output in (workspace, workspace / "model-http1-poc" / "nested"):
        arguments[out_index] = str(unsafe_output)
        assert cli.main(arguments) == cli.EXIT_AUTHORITY
        assert capsys.readouterr().out == ""
    assert not (workspace / "campaigns").exists()
    assert not (workspace / "model-http1-poc").exists()


def test_model_http1_poc_supervisor_rejects_tampered_bundle_before_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments, workspace, _, _ = _prepared_command(tmp_path, capsys)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("no\n"))
    assert cli.main(arguments) == cli.EXIT_OK
    _ = _one_json(capsys)
    bundle = next((workspace / "model-http1-poc").glob("model-http1-poc.*"))
    (bundle / "effect.raw").write_bytes(b"tampered")

    def no_socket(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("tampered bundle must fail before a socket")

    monkeypatch.setattr(cli.socket, "socket", no_socket)
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""


def test_model_http1_poc_supervisor_recomputes_pre_run_bundle_before_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    arguments, _, _, _ = _prepared_command(tmp_path, capsys)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("no\n"))
    assert cli.main(arguments) == cli.EXIT_OK
    _ = _one_json(capsys)
    bundle = next((tmp_path / "workspace" / "model-http1-poc").glob("model-http1-poc.*"))
    original = AuthorizedAutomationResult.model_validate_json(
        (bundle / "result.json").read_text(encoding="utf-8")
    )
    altered = original.model_copy(update={"stop_reason": "Different but internally valid result."})
    result_text, receipt_text, result_digest = cli._model_http1_result_receipt(altered)
    (bundle / "result.json").write_text(result_text, encoding="utf-8")
    (bundle / "receipt.json").write_text(receipt_text, encoding="utf-8")
    provenance = json.loads((bundle / "provenance.v1.json").read_text(encoding="utf-8"))
    provenance["result_digest"] = result_digest
    (bundle / "provenance.v1.json").write_text(cli.canonical_json(provenance), encoding="utf-8")

    def no_socket(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("pre-RUN recompile mismatch must fail before a socket")

    monkeypatch.setattr(cli.socket, "socket", no_socket)
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""
