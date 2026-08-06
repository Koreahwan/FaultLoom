from __future__ import annotations

import io
import json
import socket
from pathlib import Path

import pytest

from faultloom import cli

from tests.runtime.test_personal_campaign import _listener, _request, _serve, _spec, _workspace
from tests.runtime.test_personal_campaign_bridge import _bundle, _prepare_arguments


def _supervise_arguments(
    workspace: Path, key: Path, template: Path, result: Path, receipt: Path, out: Path
) -> list[str]:
    return [
        "campaign", "supervise-http1-triad", "--workspace", str(workspace),
        "--trusted-key", str(key), "--template", str(template), "--result", str(result),
        "--receipt", str(receipt), "--candidate-id", "candidate.triad", "--out", str(out),
    ]


def _stdout_json(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    captured = capsys.readouterr()
    assert captured.out.count("\n") == 1
    return json.loads(captured.out)


def test_supervise_happy_owned_loopback_runs_and_finalizes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
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
    capsys.readouterr()
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\nFINALIZE owned-loopback\n"))

    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()

    output = _stdout_json(capsys)
    assert output["status"] == "completed"
    assert output["finalStatus"] == "draft_unverified"
    assert captured == [_request(port, "/api/effect"), _request(port, "/api/effect"), _request(port, "/api/control")]
    assert "effect" not in json.dumps(output)
    assert (workspace / "campaigns" / "owned-loopback.final-receipt.json").is_file()

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO())
    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    resumed = _stdout_json(capsys)
    assert resumed["status"] == "completed"
    assert resumed["dispatchCount"] == 3
    assert len(captured) == 3


def test_supervise_first_decline_creates_no_campaign_record_or_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    capsys.readouterr()
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("no\n"))

    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    output = _stdout_json(capsys)
    assert output["status"] == "review_required"
    assert output["nextAction"] == "review the bound triad, then acknowledge exactly RUN owned-loopback"
    assert bound.is_file()
    assert not (workspace / "campaigns").exists()
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_supervise_second_decline_then_resume_never_resends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    captured: list[bytes] = []
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, captured)
    capsys.readouterr()
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\nno\n"))

    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    thread.join(timeout=3)
    first = _stdout_json(capsys)
    assert first["status"] == "review_required"
    assert first["nextAction"] == "review private responses, then acknowledge exactly FINALIZE owned-loopback"
    assert first["targetDispatchPerformed"] is True
    assert first["dispatchCount"] == 3
    review = first["responseReview"]
    assert isinstance(review, list)
    assert [item["role"] for item in review] == ["effect", "reproduction", "negative_control"]
    assert all(Path(item["responseFile"]).is_file() for item in review)
    assert all(set(item) == {"role", "responseFile", "responseSha256", "bodySha256"} for item in review)
    assert len(captured) == 3
    assert not list((workspace / "evidence" / "raw").glob("*.json"))
    assert not list((workspace / "campaigns").glob("*.final-receipt.json"))

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("FINALIZE owned-loopback\n"))
    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    resumed = _stdout_json(capsys)
    assert resumed["status"] == "completed"
    assert len(captured) == 3


def test_supervise_unresolved_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    captured: list[bytes] = []
    thread = _serve(
        listener,
        [b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx"],
        captured,
    )
    capsys.readouterr()
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\n"))

    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_UNAVAILABLE
    thread.join(timeout=3)
    first = _stdout_json(capsys)
    assert first["status"] == "manual_reconciliation_required"
    assert len(captured) == 1

    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\n"))
    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_UNAVAILABLE
    second = _stdout_json(capsys)
    assert second["status"] == "manual_reconciliation_required"
    assert len(captured) == 1
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_supervise_started_finalization_requires_manual_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    assert cli.main(_prepare_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    capsys.readouterr()
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, [])
    assert cli.main([
        "campaign", "run-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--spec", str(bound),
    ]) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    (workspace / "campaigns" / "owned-loopback.finalize-start.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("FINALIZE owned-loopback\n"))

    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_UNAVAILABLE
    output = _stdout_json(capsys)
    assert output["status"] == "manual_reconciliation_required"
    assert output["dispatchCount"] == 3


def test_supervise_start_only_reports_unknown_dispatch_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    campaign_records = workspace / "campaigns"
    campaign_records.mkdir()
    (campaign_records / "owned-loopback.start.json").write_text("{}\n", encoding="utf-8")
    capsys.readouterr()
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\n"))

    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_UNAVAILABLE
    output = _stdout_json(capsys)
    assert output["status"] == "manual_reconciliation_required"
    assert output["dispatchState"] == "unknown"
    assert "targetDispatchPerformed" not in output
    assert "dispatchCount" not in output
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_supervise_rejects_tampered_completed_receipt_without_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, [])
    capsys.readouterr()
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\nFINALIZE owned-loopback\n"))
    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    final_receipt = workspace / "campaigns" / "owned-loopback.final-receipt.json"
    final = json.loads(final_receipt.read_text(encoding="utf-8"))
    final["response_sha256"]["effect"] = "0" * 64
    final_receipt.write_text(json.dumps(final), encoding="utf-8")

    def unexpected_socket(*args: object, **kwargs: object) -> object:
        raise AssertionError("completed supervisor resume must remain offline")

    monkeypatch.setattr(cli.socket, "socket", unexpected_socket)
    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_AUTHORITY


@pytest.mark.parametrize("field", ("responseFile", "responseSha256", "bodySha256"))
def test_supervise_rejects_tampered_run_review_metadata_before_prompt(
    field: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    assert cli.main(_prepare_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_OK
    capsys.readouterr()
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, [])
    assert cli.main([
        "campaign", "run-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--spec", str(bound),
    ]) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    run_result = workspace / "campaigns" / "owned-loopback.run-result.json"
    run = json.loads(run_result.read_text(encoding="utf-8"))
    if field == "responseFile":
        run["requests"][0][field] = str(tmp_path / "attacker-response.raw")
    elif field == "responseSha256":
        run["requests"][0]["response"]["sha256"] = "0" * 64
    else:
        run["requests"][0][field] = "0" * 64
    run_result.write_text(json.dumps(run), encoding="utf-8")

    def unexpected_socket(*args: object, **kwargs: object) -> object:
        raise AssertionError("review metadata validation must not open a socket")

    monkeypatch.setattr(cli.socket, "socket", unexpected_socket)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("FINALIZE owned-loopback\n"))
    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_AUTHORITY
    assert capsys.readouterr().out == ""


def test_supervise_rejects_tampered_existing_bound_output_before_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    template = _spec(tmp_path, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = tmp_path / "bound.json"
    assert cli.main([
        "campaign", "prepare-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--template", str(template), "--result", str(result), "--receipt", str(receipt),
        "--candidate-id", "candidate.triad", "--out", str(bound),
    ]) == cli.EXIT_OK
    value = json.loads(bound.read_text(encoding="utf-8"))
    value["automation_binding"]["candidate_id"] = "candidate.other"
    bound.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\n"))

    assert cli.main(_supervise_arguments(workspace, key, template, result, receipt, bound)) == cli.EXIT_AUTHORITY
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
