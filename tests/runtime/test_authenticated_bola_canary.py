from __future__ import annotations

import hashlib
import json
import socket
import threading
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path, PureWindowsPath

import pytest

from faultloom import cli
from faultloom_protocol import AuthoritySigner, SignedAuthorityGrant, sign_authority_grant
from tests.runtime.test_cli import _authority_files, _run_arguments


CAMPAIGN = "owned-canary-read"
OWNER = "identity.owner-a"
REQUESTER = "identity.requester-b"
CANARY = "operator-owned-canary-7d4bc9"
CANARY_SHA256 = hashlib.sha256(CANARY.encode()).hexdigest()
SOURCE_ENV = "FAULTLOOM_SOURCE_B_SESSION"
REVIEWER_ENV = "FAULTLOOM_REVIEWER_B_SESSION"
SOURCE_TOKEN = "source-session-token-7f4ab912"
REVIEWER_TOKEN = "reviewer-session-token-9c2de831"


def _listener(port: int = 0) -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(6)
    return listener, listener.getsockname()[1]


def _response(value: str) -> bytes:
    body = json.dumps({"faultloom_canary": value}, separators=(",", ":")).encode()
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )


def _response_with_extra_header(value: str, header: bytes) -> bytes:
    body = json.dumps({"faultloom_canary": value}, separators=(",", ":")).encode()
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n".encode()
        + header
        + b"\r\n\r\n"
        + body
    )


def _serve(
    listener: socket.socket,
    responses: Sequence[bytes | None],
    captured: list[bytes],
) -> threading.Thread:
    def serve() -> None:
        for response in responses:
            try:
                connection, _ = listener.accept()
            except (OSError, socket.timeout):
                return
            with connection:
                raw = bytearray()
                while b"\r\n\r\n" not in raw:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    raw.extend(chunk)
                captured.append(bytes(raw))
                if response is not None:
                    connection.sendall(response)

    listener.settimeout(5)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread


def _workspace(
    root: Path, port: int, *, actor: str, signer_seed: int
) -> tuple[Path, Path, Path]:
    now = datetime.now(UTC) - timedelta(minutes=1)
    authority, key = _authority_files(
        root / "grant",
        hostnames=("127.0.0.1",),
        ports=(port,),
        paths=("/api/*",),
        methods=("GET",),
        protocols=("http",),
        budget_updates={
            "total_actions": 3,
            "rate_per_minute": 3,
            "max_concurrency": 1,
            "max_response_bytes": 4096,
        },
        now=now,
        signer_seed=signer_seed,
    )
    seed = bytes((value + signer_seed) % 256 for value in range(32))
    signer = AuthoritySigner.from_private_bytes(seed)
    envelope = SignedAuthorityGrant.model_validate_json(authority.read_text())
    grant = envelope.payload.model_copy(
        update={
            "grant_id": f"grant.{actor}",
            "issued_to": actor,
            "identities": (OWNER, REQUESTER),
        }
    )
    authority.write_text(
        sign_authority_grant(grant, signer, signed_at=now).model_dump_json(indent=2),
        encoding="utf-8",
    )
    private_key = root / "authority-private.key"
    private_key.write_text(seed.hex() + "\n", encoding="ascii")
    private_key.chmod(0o600)
    workspace = root / "workspace"
    assert cli.main(_run_arguments(authority, key) + ["--workspace", str(workspace)]) == 0
    return workspace, key, private_key


def _prepare_args(
    workspace: Path,
    key: Path,
    private_key: Path,
    *,
    phase: str,
    env_name: str,
    out: Path,
    source: tuple[Path, Path, Path] | None = None,
    canary_sha256: str = CANARY_SHA256,
    session_expires_at: datetime | None = None,
) -> list[str]:
    args = [
        "campaign", "prepare-authenticated-canary",
        "--workspace", str(workspace),
        "--trusted-key", str(key),
        "--private-key", str(private_key),
        "--phase", phase,
        "--campaign-id", CAMPAIGN,
        "--source-claim", "Requester B can read operator-owned canary A.",
        "--hostname", "127.0.0.1",
        "--port", str(json.loads((workspace / "run.json").read_text())["target"]["ports"][0]),
        "--scheme", "http",
        "--owner-identity", OWNER,
        "--requester-identity", REQUESTER,
        "--canary-path", "/api/owner-a-canary",
        "--missing-control-path", "/api/missing-control",
        "--canary-sha256", canary_sha256,
        "--requester-session-ref", f"secret://target-env/{env_name}",
        "--confirm-operator-owned-canary",
        "--confirm-reviewed-non-sensitive-canary",
        "--requester-session-expires-at",
        (session_expires_at or (datetime.now(UTC) + timedelta(hours=1)))
        .isoformat()
        .replace("+00:00", "Z"),
        "--response-bytes", "4096",
        "--timeout-seconds", "3",
        "--out", str(out),
    ]
    if source is not None:
        source_workspace, source_key, handoff = source
        args.extend(
            [
                "--source-workspace", str(source_workspace),
                "--source-trusted-key", str(source_key),
                "--source-handoff", str(handoff),
            ]
        )
    return args


def _run_args(workspace: Path, key: Path, private_key: Path, case: Path) -> list[str]:
    return [
        "campaign", "run-authenticated-canary",
        "--workspace", str(workspace), "--trusted-key", str(key),
        "--private-key", str(private_key), "--case", str(case),
    ]


def _export_args(
    workspace: Path, key: Path, private_key: Path, case: Path, run: Path, out: Path
) -> list[str]:
    return [
        "campaign", "export-authenticated-canary-handoff",
        "--workspace", str(workspace), "--trusted-key", str(key),
        "--private-key", str(private_key), "--case", str(case),
        "--run-result", str(run), "--out", str(out),
    ]


def _finalize_args(
    source: tuple[Path, Path], reviewer: tuple[Path, Path], handoff: Path,
    reviewer_case: Path, reviewer_run: Path, out: Path,
) -> list[str]:
    return [
        "campaign", "finalize-authenticated-canary-review",
        "--source-workspace", str(source[0]), "--source-trusted-key", str(source[1]),
        "--reviewer-workspace", str(reviewer[0]), "--reviewer-trusted-key", str(reviewer[1]),
        "--handoff", str(handoff), "--reviewer-case", str(reviewer_case),
        "--reviewer-run", str(reviewer_run), "--out", str(out),
    ]


def _assert_no_secret_artifacts(root: Path, *captured_text: str) -> None:
    forbidden = (
        SOURCE_TOKEN.encode(),
        REVIEWER_TOKEN.encode(),
        f"Authorization: Bearer {SOURCE_TOKEN}".encode(),
        f"Authorization: Bearer {REVIEWER_TOKEN}".encode(),
        b"Cookie:",
    )
    token_digests: set[bytes] = set()
    for path in root.rglob("*.canary-start.json"):
        start = json.loads(path.read_text())
        port = json.loads((path.parent / "run.json").read_text())["target"]["ports"][0]
        for token in (SOURCE_TOKEN, REVIEWER_TOKEN):
            for target_path in ("/api/owner-a-canary", "/api/missing-control"):
                raw = (
                    f"GET {target_path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
                    f"Authorization: Bearer {token}\r\nAccept: application/json\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
                token_digests.add(hashlib.sha256(raw).hexdigest().encode())
        assert start["requester_session_ref"]["uri"].startswith("secret://target-env/")
    for path in root.rglob("*"):
        if path.is_file():
            content = path.read_bytes()
            assert all(value not in content for value in forbidden), path
            assert all(value not in content for value in token_digests), path
    joined = "".join(captured_text).encode()
    assert all(value not in joined for value in forbidden)
    assert all(value not in joined for value in token_digests)


def test_handoff_relative_path_uses_posix_separators_for_windows_paths() -> None:
    assert cli._handoff_relative_path(
        PureWindowsPath(r"responses\reservation.personal-http1.raw")
    ) == "responses/reservation.personal-http1.raw"


def test_authenticated_operator_canary_source_and_reviewer_six_exact_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    source, source_key, source_private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=41
    )
    reviewer, reviewer_key, reviewer_private = _workspace(
        tmp_path / "reviewer", port, actor="reviewer.independent", signer_seed=73
    )
    capsys.readouterr()
    source_case = source / "source-canary-case.json"
    assert cli.main(
        _prepare_args(
            source, source_key, source_private,
            phase="source", env_name=SOURCE_ENV, out=source_case,
        )
    ) == cli.EXIT_OK
    prepare_source_out = capsys.readouterr().out
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    source_requests: list[bytes] = []
    source_thread = _serve(
        listener,
        [_response(CANARY), _response(CANARY), _response("missing-control")],
        source_requests,
    )
    assert cli.main(_run_args(source, source_key, source_private, source_case)) == cli.EXIT_OK
    source_thread.join(timeout=3)
    source_out = capsys.readouterr().out
    source_run = source / f"{CAMPAIGN}.source.canary-run.json"
    handoff = source / "source-canary-handoff.json"
    assert cli.main(
        _export_args(source, source_key, source_private, source_case, source_run, handoff)
    ) == cli.EXIT_OK
    handoff_out = capsys.readouterr().out

    reviewer_case = reviewer / "reviewer-canary-case.json"
    assert cli.main(
        _prepare_args(
            reviewer, reviewer_key, reviewer_private,
            phase="reviewer", env_name=REVIEWER_ENV, out=reviewer_case,
            source=(source, source_key, handoff),
        )
    ) == cli.EXIT_OK
    prepare_reviewer_out = capsys.readouterr().out
    monkeypatch.setenv(REVIEWER_ENV, REVIEWER_TOKEN)
    reviewer_requests: list[bytes] = []
    reviewer_thread = _serve(
        listener,
        [_response(CANARY), _response(CANARY), _response("missing-control")],
        reviewer_requests,
    )
    assert cli.main(_run_args(reviewer, reviewer_key, reviewer_private, reviewer_case)) == cli.EXIT_OK
    reviewer_thread.join(timeout=3)
    listener.close()
    reviewer_out = capsys.readouterr().out
    reviewer_run = reviewer / f"{CAMPAIGN}.reviewer.canary-run.json"
    tampered_reviewer_run = reviewer / "tampered-reviewer-run.json"
    tampered_document = json.loads(reviewer_run.read_text())
    tampered_document["run"]["observations"][0]["expected_canary"] = False
    tampered_reviewer_run.write_text(json.dumps(tampered_document), encoding="utf-8")
    tampered_result = reviewer / "tampered-result.json"
    assert cli.main(
        _finalize_args(
            (source, source_key), (reviewer, reviewer_key), handoff,
            reviewer_case, tampered_reviewer_run, tampered_result,
        )
    ) == cli.EXIT_AUTHORITY
    assert not tampered_result.exists()
    capsys.readouterr()
    result_path = reviewer / "operator-canary-result.json"
    assert cli.main(
        _finalize_args(
            (source, source_key), (reviewer, reviewer_key), handoff,
            reviewer_case, reviewer_run, result_path,
        )
    ) == cli.EXIT_OK
    result_stdout = capsys.readouterr().out
    result = json.loads(result_stdout)
    assert result == json.loads(result_path.read_text())
    assert result["status"] == "operator_canary_cross_identity_read_reproduced"
    assert result["source_claim_status"] == "operator_asserted_unverified"
    assert result["owner_relation_status"] == "operator_asserted_owned"
    assert result["sensitivity_status"] == "operator_reviewed_non_sensitive"
    assert result["semantic_verdict"] == "operator_canary_cross_identity_read_reproduced"
    assert result["taxonomy_verdict"] == "not_evaluated"
    assert result["report_status"] == "draft_manual_review"
    source_case_doc = json.loads(source_case.read_text())["case"]
    reviewer_case_doc = json.loads(reviewer_case.read_text())["case"]
    source_run_doc = json.loads(source_run.read_text())["run"]
    reviewer_run_doc = json.loads(reviewer_run.read_text())["run"]
    assert source_case_doc["operator_actor_id"] == "researcher.source"
    assert reviewer_case_doc["operator_actor_id"] == "reviewer.independent"
    assert source_case_doc["requester_identity"] == REQUESTER
    assert source_case_doc["operator_actor_id"] != source_case_doc["requester_identity"]
    assert all(
        observation["response_file"].startswith("responses/")
        and "\\" not in observation["response_file"]
        for observation in source_run_doc["observations"] + reviewer_run_doc["observations"]
    )
    assert len(source_requests + reviewer_requests) == 6
    assert [request.split(b" ", 2)[1] for request in source_requests] == [
        b"/api/owner-a-canary", b"/api/owner-a-canary", b"/api/missing-control"
    ]
    assert [request.split(b" ", 2)[1] for request in reviewer_requests] == [
        b"/api/owner-a-canary", b"/api/owner-a-canary", b"/api/missing-control"
    ]
    assert all(b"Cookie:" not in request for request in source_requests + reviewer_requests)
    assert all(b"Authorization: Bearer " in request for request in source_requests + reviewer_requests)
    assert all(SOURCE_TOKEN.encode() in value for value in source_requests)
    assert all(REVIEWER_TOKEN.encode() in value for value in reviewer_requests)
    _assert_no_secret_artifacts(
        tmp_path,
        prepare_source_out, source_out, handoff_out, prepare_reviewer_out,
        reviewer_out, result_stdout,
    )


@pytest.mark.parametrize("secret_state", ("missing", "expired"))
def test_missing_or_expired_target_secret_makes_zero_connections(
    secret_state: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    source, key, private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=47
    )
    capsys.readouterr()
    case = source / "source-canary-case.json"
    expiry = (
        datetime.now(UTC) - timedelta(minutes=1)
        if secret_state == "expired"
        else None
    )
    assert cli.main(
        _prepare_args(
            source, key, private, phase="source", env_name=SOURCE_ENV, out=case,
            session_expires_at=expiry,
        )
    ) == 0
    capsys.readouterr()
    if secret_state == "missing":
        monkeypatch.delenv(SOURCE_ENV, raising=False)
    else:
        monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    assert cli.main(_run_args(source, key, private, case)) == cli.EXIT_AUTHORITY
    error = capsys.readouterr().err
    assert SOURCE_TOKEN not in error and "Authorization" not in error
    listener.settimeout(0.15)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    assert not (source / f"{CAMPAIGN}.source.canary-start.json").exists()


def test_dropped_connection_is_unresolved_and_never_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    source, key, private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=53
    )
    capsys.readouterr()
    case = source / "source-canary-case.json"
    assert cli.main(
        _prepare_args(source, key, private, phase="source", env_name=SOURCE_ENV, out=case)
    ) == 0
    capsys.readouterr()
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    captured: list[bytes] = []
    thread = _serve(listener, [None], captured)
    assert cli.main(_run_args(source, key, private, case)) == cli.EXIT_UNAVAILABLE
    thread.join(timeout=3)
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "unresolved_not_evaluated"
    assert output["reservationState"] == "unresolved_no_retry"
    assert output["dispatchCount"] == 1
    assert cli.main(_run_args(source, key, private, case)) == cli.EXIT_AUTHORITY
    capsys.readouterr()
    listener.settimeout(0.15)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    assert len(captured) == 1


def test_concurrent_identical_canary_runs_dispatch_only_one_triad(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener, port = _listener()
    workspace, key, private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=55
    )
    case = workspace / "source-canary-case.json"
    assert cli.main(
        _prepare_args(workspace, key, private, phase="source", env_name=SOURCE_ENV, out=case)
    ) == cli.EXIT_OK
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    captured: list[bytes] = []
    thread = _serve(
        listener,
        [_response(CANARY), _response(CANARY), _response("missing-control")],
        captured,
    )
    barrier = threading.Barrier(2)
    validate_capacity = cli._validate_campaign_accounting_capacity

    def synchronize_capacity(*args: object, **kwargs: object) -> None:
        validate_capacity(*args, **kwargs)
        barrier.wait(timeout=3)

    monkeypatch.setattr(cli, "_validate_campaign_accounting_capacity", synchronize_capacity)
    outcomes: list[int] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            outcomes.append(cli.main(_run_args(workspace, key, private, case)))
        except BaseException as exc:  # pragma: no cover - assertion reports unexpected worker errors
            errors.append(exc)

    workers = [threading.Thread(target=run) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
    thread.join(timeout=3)
    listener.close()

    assert not any(worker.is_alive() for worker in workers)
    assert not errors
    assert sorted(outcomes) == [cli.EXIT_OK, cli.EXIT_AUTHORITY]
    assert len(captured) == 3
    start_paths = list(workspace.glob("*.canary-start.json"))
    run_paths = list(workspace.glob("*.canary-run.json"))
    assert len(start_paths) == len(run_paths) == 1
    assert json.loads(run_paths[0].read_text())["run"]["dispatch_count"] == 3
    assert {path.name for path in workspace.glob("*.canary-*.json")} == {
        start_paths[0].name,
        run_paths[0].name,
    }


def test_prepare_requires_explicit_owned_and_non_sensitive_admission(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    workspace, key, private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=57
    )
    capsys.readouterr()
    output = workspace / "case.json"
    arguments = _prepare_args(
        workspace, key, private, phase="source", env_name=SOURCE_ENV, out=output
    )
    arguments.remove("--confirm-reviewed-non-sensitive-canary")
    assert cli.main(arguments) == cli.EXIT_USAGE
    assert not output.exists()
    listener.close()


def test_query_or_non_path_target_is_rejected_before_secret_or_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    workspace, key, private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=58
    )
    capsys.readouterr()
    output = workspace / "case.json"
    arguments = _prepare_args(
        workspace, key, private, phase="source", env_name=SOURCE_ENV, out=output
    )
    arguments[arguments.index("--canary-path") + 1] = "/api/canary?token=forbidden"
    calls = 0

    def reject_secret_resolution(*args: object, **kwargs: object) -> str:
        nonlocal calls
        calls += 1
        raise AssertionError("secret resolution occurred for rejected request target")

    monkeypatch.setattr(cli, "resolve_target_bearer", reject_secret_resolution)
    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    assert calls == 0
    assert not output.exists()
    listener.settimeout(0.15)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_secret_bearing_extra_response_header_is_not_persisted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    marker = b"private-response-marker-d5b99f"
    listener, port = _listener()
    workspace, key, private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=60
    )
    capsys.readouterr()
    case = workspace / "case.json"
    assert cli.main(
        _prepare_args(
            workspace, key, private, phase="source", env_name=SOURCE_ENV, out=case
        )
    ) == cli.EXIT_OK
    capsys.readouterr()
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    captured: list[bytes] = []
    thread = _serve(
        listener,
        [_response_with_extra_header(CANARY, b"Set-Cookie: session=" + marker)],
        captured,
    )
    assert cli.main(_run_args(workspace, key, private, case)) == cli.EXIT_UNAVAILABLE
    thread.join(timeout=3)
    listener.close()
    output = capsys.readouterr()
    assert marker.decode() not in output.out + output.err
    assert len(captured) == 1
    assert not (workspace / "responses").exists()
    for path in workspace.rglob("*"):
        if path.is_file():
            assert marker not in path.read_bytes(), path


def test_foreign_workspace_rejected_before_target_secret_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    source, source_key, source_private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=61
    )
    foreign, foreign_key, foreign_private = _workspace(
        tmp_path / "foreign", port, actor="researcher.foreign", signer_seed=61
    )
    capsys.readouterr()
    case = source / "source-case.json"
    assert cli.main(
        _prepare_args(
            source, source_key, source_private,
            phase="source", env_name=SOURCE_ENV, out=case,
        )
    ) == cli.EXIT_OK
    capsys.readouterr()
    calls = 0

    def reject_secret_resolution(*args: object, **kwargs: object) -> str:
        nonlocal calls
        calls += 1
        raise AssertionError("secret resolution occurred before workspace rejection")

    monkeypatch.setattr(cli, "resolve_target_bearer", reject_secret_resolution)
    assert cli.main(
        _run_args(foreign, foreign_key, foreign_private, case)
    ) == cli.EXIT_AUTHORITY
    assert calls == 0
    assert not (foreign / f"{CAMPAIGN}.source.canary-start.json").exists()
    listener.close()


@pytest.mark.parametrize("tamper", ("signed_run", "raw_response"))
def test_source_handoff_rejects_tampered_run_or_private_response(
    tamper: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    source, key, private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=67
    )
    capsys.readouterr()
    case = source / "source-case.json"
    assert cli.main(
        _prepare_args(source, key, private, phase="source", env_name=SOURCE_ENV, out=case)
    ) == cli.EXIT_OK
    capsys.readouterr()
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    thread = _serve(
        listener,
        [_response(CANARY), _response(CANARY), _response("missing-control")],
        [],
    )
    assert cli.main(_run_args(source, key, private, case)) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    run_path = source / f"{CAMPAIGN}.source.canary-run.json"
    run_document = json.loads(run_path.read_text())
    if tamper == "signed_run":
        run_document["run"]["observations"][0]["expected_canary"] = False
        run_path.write_text(json.dumps(run_document), encoding="utf-8")
    else:
        response_path = source / run_document["run"]["observations"][0]["response_file"]
        response_path.write_bytes(_response("tampered-canary"))
    handoff = source / "handoff.json"
    assert cli.main(
        _export_args(source, key, private, case, run_path, handoff)
    ) == cli.EXIT_AUTHORITY
    assert not handoff.exists()


@pytest.mark.parametrize("mismatch", ("control", "relation"))
def test_canary_or_relation_mismatch_creates_no_semantic_result(
    mismatch: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    source, source_key, source_private = _workspace(
        tmp_path / "source", port, actor="researcher.source", signer_seed=59
    )
    reviewer, reviewer_key, reviewer_private = _workspace(
        tmp_path / "reviewer", port, actor="reviewer.independent", signer_seed=83
    )
    capsys.readouterr()
    source_case = source / "source-case.json"
    assert cli.main(
        _prepare_args(
            source, source_key, source_private,
            phase="source", env_name=SOURCE_ENV, out=source_case,
        )
    ) == 0
    capsys.readouterr()
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    responses = [
        _response(CANARY), _response(CANARY),
        _response(CANARY if mismatch == "control" else "missing-control"),
    ]
    thread = _serve(listener, responses, [])
    assert cli.main(_run_args(source, source_key, source_private, source_case)) == 0
    thread.join(timeout=3)
    capsys.readouterr()
    source_run = source / f"{CAMPAIGN}.source.canary-run.json"
    handoff = source / "handoff.json"
    assert cli.main(
        _export_args(source, source_key, source_private, source_case, source_run, handoff)
    ) == 0
    capsys.readouterr()
    reviewer_case = reviewer / "reviewer-case.json"
    review_hash = "f" * 64 if mismatch == "relation" else CANARY_SHA256
    prepare_code = cli.main(
        _prepare_args(
            reviewer, reviewer_key, reviewer_private,
            phase="reviewer", env_name=REVIEWER_ENV, out=reviewer_case,
            source=(source, source_key, handoff), canary_sha256=review_hash,
        )
    )
    if mismatch == "relation":
        assert prepare_code == cli.EXIT_AUTHORITY
        assert not reviewer_case.exists()
        assert not (reviewer / "semantic-result.json").exists()
        listener.close()
        return
    assert prepare_code == 0
    capsys.readouterr()
    monkeypatch.setenv(REVIEWER_ENV, REVIEWER_TOKEN)
    review_thread = _serve(
        listener,
        [_response(CANARY), _response(CANARY), _response("missing-control")],
        [],
    )
    assert cli.main(_run_args(reviewer, reviewer_key, reviewer_private, reviewer_case)) == 0
    review_thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    result_path = reviewer / "semantic-result.json"
    assert cli.main(
        _finalize_args(
            (source, source_key), (reviewer, reviewer_key), handoff,
            reviewer_case, reviewer / f"{CAMPAIGN}.reviewer.canary-run.json", result_path,
        )
    ) == cli.EXIT_AUTHORITY
    assert not result_path.exists()
