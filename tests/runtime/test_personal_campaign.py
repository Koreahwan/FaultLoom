from __future__ import annotations

import json
import socket
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from faultloom import cli

from tests.runtime.test_cli import _authority_files, _run_arguments


def _workspace(tmp_path: Path, port: int) -> tuple[Path, Path]:
    authority, key = _authority_files(
        tmp_path / "grant",
        hostnames=("127.0.0.1",),
        ports=(port,),
        paths=("/api/*",),
        methods=("GET",),
        protocols=("http",),
        budget_updates={"total_actions": 3, "rate_per_minute": 3, "max_concurrency": 1},
        now=datetime.now(UTC) - timedelta(minutes=1),
    )
    workspace = tmp_path / "workspace"
    assert cli.main(_run_arguments(authority, key) + ["--workspace", str(workspace)]) == 0
    return workspace, key


def _request(port: int, path: str) -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    ).encode()


def _spec(tmp_path: Path, port: int, *, effect_path: str = "/api/effect", control_path: str = "/api/control") -> Path:
    (tmp_path / "effect.raw").write_bytes(_request(port, effect_path))
    (tmp_path / "control.raw").write_bytes(_request(port, control_path))
    spec = {
        "schema": "faultloom.personal-http1-triad.v1",
        "campaign_id": "owned-loopback",
        "authorization_reference": "owned loopback test authorization",
        "authorization_document_sha256": "a" * 64,
        "hostname": "127.0.0.1",
        "port": port,
        "scheme": "http",
        "timeout_seconds": 3,
        "requests": [
            {"role": "effect", "method": "GET", "path": effect_path, "request_file": "effect.raw", "response_bytes": 512},
            {"role": "negative_control", "method": "GET", "path": control_path, "request_file": "control.raw", "response_bytes": 512},
        ],
        "finding": {"title": "Owned triad", "severity": "low", "summary": "s", "impact": "i", "remediation": "r"},
    }
    path = tmp_path / "triad.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def _serve(listener: socket.socket, responses: list[bytes], captured: list[bytes]) -> threading.Thread:
    def serve() -> None:
        for response in responses:
            connection, _ = listener.accept()
            with connection:
                raw = bytearray()
                while b"\r\n\r\n" not in raw:
                    raw.extend(connection.recv(4096))
                captured.append(bytes(raw))
                connection.sendall(response)

    thread = threading.Thread(target=serve)
    thread.start()
    return thread


def _campaign_run_arguments(workspace: Path, key: Path, spec: Path) -> list[str]:
    return [
        "campaign", "run-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key), "--spec", str(spec),
    ]


def _listener() -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(3)
    return listener, listener.getsockname()[1]


def test_campaign_run_then_reviewed_finalize_archives_three_and_drafts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
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

    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    run = json.loads(capsys.readouterr().out)
    assert run["status"] == "review_required"
    assert run["dispatchCount"] == 3
    assert captured == [_request(port, "/api/effect"), _request(port, "/api/effect"), _request(port, "/api/control")]
    assert not list((workspace / "evidence" / "raw").glob("*.json"))
    assert not list((workspace / "findings").glob("*.json"))

    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_OK
    finalized = json.loads(capsys.readouterr().out)
    assert finalized["status"] == "draft_unverified"
    receipt = json.loads(Path(finalized["receipt"]).read_text(encoding="utf-8"))
    assert len(receipt["evidence_ids"]) == 3
    assert receipt["independent_verification"] is False
    assert receipt["automatic_submission"] is False
    assert receipt["finding"]["status"] == "draft_unverified"


def test_campaign_negative_control_match_finalizes_without_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, [])
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_OK
    receipt = json.loads(Path(json.loads(capsys.readouterr().out)["receipt"]).read_text())
    assert receipt["status"] == "negative_campaign"
    assert receipt["finding"] is None
    assert not list((workspace / "findings").glob("*.json"))


def test_campaign_rerun_refuses_before_any_extra_send(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    captured: list[bytes] = []
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, captured)
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_OK
    thread.join(timeout=3)
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_USAGE
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    assert len(captured) == 3


def test_campaign_out_of_scope_stops_at_admission_without_send(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port, effect_path="/outside")
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_UNAVAILABLE
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "unresolved_no_retry"
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_campaign_ambiguous_second_response_stops_before_third_without_retry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    captured: list[bytes] = []
    thread = _serve(
        listener,
        [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx",
        ],
        captured,
    )
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_UNAVAILABLE
    thread.join(timeout=3)
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    assert len(captured) == 2
    assert json.loads(capsys.readouterr().out)["dispatchCount"] == 2
    assert not list((workspace / "campaigns").glob("*.run-result.json"))
    unresolved = list((workspace / "campaigns").glob("*.unresolved.json"))
    assert len(unresolved) == 1
    assert len(json.loads(unresolved[0].read_text())["completed_requests"]) == 2


def test_campaign_rate_limited_response_stops_unresolved_without_followup(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    captured: list[bytes] = []
    thread = _serve(listener, [b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n"], captured)
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_UNAVAILABLE
    thread.join(timeout=3)
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    result = json.loads(capsys.readouterr().out)
    assert result["error"] == "rate_limited_429"
    assert result["dispatchCount"] == 1
    assert len(captured) == 1


def test_campaign_finalize_without_confirmation_never_opens_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected_socket(*args: object, **kwargs: object) -> object:
        raise AssertionError("offline finalization must not open a socket")

    monkeypatch.setattr(cli.socket, "socket", unexpected_socket)
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(tmp_path / "none"), "--trusted-key", str(tmp_path / "none.key"),
        "--campaign-id", "owned-loopback",
    ]) == cli.EXIT_AUTHORITY


@pytest.mark.parametrize("mutation", ["duplicate_role", "unequal_cap", "path_traversal", "symlink_spec", "symlink_request"])
def test_campaign_invalid_spec_or_request_fails_closed(tmp_path: Path, mutation: str) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    spec = _spec(tmp_path, port)
    data = json.loads(spec.read_text())
    if mutation == "duplicate_role":
        data["requests"][1]["role"] = "effect"
        spec.write_text(json.dumps(data))
    elif mutation == "unequal_cap":
        data["requests"][1]["response_bytes"] = 513
        spec.write_text(json.dumps(data))
    elif mutation == "path_traversal":
        data["requests"][0]["request_file"] = "../effect.raw"
        spec.write_text(json.dumps(data))
    elif mutation == "symlink_spec":
        linked = tmp_path / "linked.json"
        linked.symlink_to(spec)
        spec = linked
    else:
        (tmp_path / "effect.raw").unlink()
        (tmp_path / "effect.raw").symlink_to(tmp_path / "control.raw")
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_AUTHORITY
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_campaign_control_header_difference_fails_before_socket(tmp_path: Path) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    spec = _spec(tmp_path, port)
    (tmp_path / "control.raw").write_bytes(
        (
            f"GET /api/control HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            "X-Control-Only: 1\r\nConnection: close\r\n\r\n"
        ).encode()
    )

    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_AUTHORITY
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_campaign_finalize_rejects_mutated_spec_before_archival(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, [])
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    data = json.loads(spec.read_text())
    data["finding"]["title"] = "mutated"
    spec.write_text(json.dumps(data))
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_AUTHORITY
    assert not list((workspace / "evidence" / "raw").glob("*.json"))
    assert not list((workspace / "campaigns").glob("*.finalize-start.json"))


def test_campaign_finalize_rejects_mutated_request_before_archival(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, [])
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    (tmp_path / "effect.raw").write_bytes(_request(port, "/api/effect?changed=1"))
    capsys.readouterr()

    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_AUTHORITY
    assert not list((workspace / "evidence" / "raw").glob("*.json"))
    assert not list((workspace / "campaigns").glob("*.finalize-start.json"))


def test_campaign_reproduction_rechecks_start_digest_before_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    captured: list[bytes] = []
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"], captured)
    original = cli._record_campaign_binding

    def mutate_after_effect(
        *,
        workspace: Path,
        manifest: dict[str, object],
        campaign_id: str,
        role: str,
        result: dict[str, object],
    ) -> None:
        original(
            workspace=workspace,
            manifest=manifest,
            campaign_id=campaign_id,
            role=role,
            result=result,
        )
        if role == "effect":
            (tmp_path / "effect.raw").write_bytes(
                _request(port, "/api/effect").replace(
                    b"Connection: close", b"X-Mutated: 1\r\nConnection: close"
                )
            )

    monkeypatch.setattr(cli, "_record_campaign_binding", mutate_after_effect)
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_UNAVAILABLE
    thread.join(timeout=3)
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    assert captured == [_request(port, "/api/effect")]
    assert json.loads(capsys.readouterr().out)["dispatchCount"] == 1


def test_campaign_finalize_rejects_tampered_reproduction_run_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    thread = _serve(listener, [b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"] * 3, [])
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    run_result = next((workspace / "campaigns").glob("*.run-result.json"))
    data = json.loads(run_result.read_text())
    reproduction = dict(data["requests"][0])
    reproduction["role"] = "reproduction"
    data["requests"][1] = reproduction
    run_result.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace), "--trusted-key", str(key),
        "--campaign-id", "owned-loopback", "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_AUTHORITY
    assert not list((workspace / "evidence" / "raw").glob("*.json"))
    assert not list((workspace / "campaigns").glob("*.finalize-start.json"))


@pytest.mark.skipif(cli.os.name == "nt", reason="directory descriptor durability is POSIX-specific")
def test_campaign_record_writer_fails_when_parent_fsync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    records = cli._campaign_records_directory(workspace)
    actual_fsync = cli.os.fsync

    def fail_parent_sync(descriptor: int) -> None:
        if cli.stat.S_ISDIR(cli.os.fstat(descriptor).st_mode):
            raise OSError("injected parent fsync failure")
        actual_fsync(descriptor)

    monkeypatch.setattr(cli.os, "fsync", fail_parent_sync)
    with pytest.raises(cli.CliError):
        cli._write_new_campaign_record(records, records.campaigns / "one.start.json", b"{}\n")


@pytest.mark.skipif(cli.os.name == "nt", reason="dir_fd identity pinning is POSIX-specific")
def test_campaign_record_writer_rejects_workspace_symlink_swap(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    records = cli._campaign_records_directory(workspace)
    outside = tmp_path / "outside"
    outside.mkdir()
    parked = tmp_path / "workspace-parked"
    workspace.rename(parked)
    workspace.symlink_to(outside, target_is_directory=True)

    with pytest.raises(cli.CliError):
        cli._write_new_campaign_record(records, records.campaigns / "escape.start.json", b"{}\n")
    assert not (outside / "campaigns" / "escape.start.json").exists()


@pytest.mark.skipif(cli.os.name == "nt", reason="directory descriptor durability is POSIX-specific")
def test_campaign_setup_fails_before_send_when_workspace_parent_fsync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    listener, port = _listener()
    workspace, key = _workspace(tmp_path, port)
    capsys.readouterr()
    spec = _spec(tmp_path, port)
    actual_fsync = cli.os.fsync

    def fail_workspace_sync(descriptor: int) -> None:
        if cli.stat.S_ISDIR(cli.os.fstat(descriptor).st_mode):
            raise OSError("injected workspace parent fsync failure")
        actual_fsync(descriptor)

    monkeypatch.setattr(cli.os, "fsync", fail_workspace_sync)
    assert cli.main(_campaign_run_arguments(workspace, key, spec)) == cli.EXIT_USAGE
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    assert not list((workspace / "campaigns").glob("*.start.json"))


def test_campaign_records_reject_junction_marked_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "campaigns").mkdir()
    monkeypatch.setattr(Path, "is_junction", lambda path: path.name == "campaigns")
    with pytest.raises(cli.CliError):
        cli._campaign_records_directory(workspace)
