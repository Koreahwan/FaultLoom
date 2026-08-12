"""RED end-to-end contracts for the bounded authenticated BOLA read CLI."""

from __future__ import annotations

import hashlib
import json
import socket
import threading
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from faultloom import cli
from faultloom.bola_read_semantics import (
    SignedBolaReadCase,
    sign_bola_read_case,
    signed_bola_case_bytes,
)
from faultloom_protocol import AuthoritySigner, SignedAuthorityGrant, sign_authority_grant
from tests.runtime.test_cli import _authority_files, _run_arguments


CAMPAIGN = "owned-invoice-read"
TARGET_ID = "target.owned-loopback"
TENANT_ID = "tenant.alpha"
OBJECT_ID = "invoice.7d4bc9"
OBJECT_KIND = "invoice"
OWNER = "identity.owner-a"
REQUESTER = "identity.requester-b"
SOURCE_ACTOR = "researcher.source"
REVIEWER_ACTOR = "reviewer.independent"
PRINCIPAL_PATH = "/api/principal"
OBJECT_PATH = f"/api/invoices/{OBJECT_ID}"
SOURCE_ENV = "FAULTLOOM_SOURCE_B_SESSION"
REVIEWER_ENV = "FAULTLOOM_REVIEWER_B_SESSION"
SOURCE_TOKEN = "source-bearer-token-7f4ab912"
REVIEWER_TOKEN = "reviewer-bearer-token-9c2de831"


def _listener() -> tuple[socket.socket, int]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(6)
    return listener, listener.getsockname()[1]


def _http_response(status: int, body: dict[str, str]) -> bytes:
    reason = {200: "OK", 403: "Forbidden", 400: "Bad Request"}[status]
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return (
        f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
        + b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(encoded)}\r\nConnection: close\r\n\r\n".encode("ascii")
        + encoded
    )


def _read_request(connection: socket.socket) -> bytes:
    raw = bytearray()
    while b"\r\n\r\n" not in raw:
        chunk = connection.recv(4096)
        if not chunk:
            break
        raw.extend(chunk)
    return bytes(raw)


def _serve_bola(
    listener: socket.socket,
    captured: list[bytes],
    *,
    object_ids: Sequence[str] = (OBJECT_ID, OBJECT_ID),
    drop_first: bool = False,
    request_count: int = 6,
) -> threading.Thread:
    """Owned fixture: only each phase's B bearer may read the test object."""

    def serve() -> None:
        for index in range(request_count):
            try:
                connection, _ = listener.accept()
            except (OSError, socket.timeout):
                return
            with connection:
                raw = _read_request(connection)
                captured.append(raw)
                if drop_first and index == 0:
                    return
                phase = index // 3
                role = index % 3
                expected_bearer = (SOURCE_TOKEN, REVIEWER_TOKEN)[phase].encode("ascii")
                expected_path = (PRINCIPAL_PATH, OBJECT_PATH, OBJECT_PATH)[role].encode("ascii")
                if b"\r\n\r\n" not in raw or not raw.startswith(b"GET "):
                    connection.sendall(_http_response(400, {"error": "bad request"}))
                    continue
                request_path = raw.split(b" ", 2)[1]
                authorization = b"Authorization: Bearer " + expected_bearer + b"\r\n"
                if request_path != expected_path:
                    connection.sendall(_http_response(400, {"error": "unexpected path"}))
                elif role == 0 and authorization in raw:
                    connection.sendall(_http_response(200, {"principal_id": REQUESTER}))
                elif role == 1 and authorization in raw:
                    connection.sendall(
                        _http_response(
                            200,
                            {"object_id": object_ids[phase], "owner_id": OWNER, "tenant_id": TENANT_ID},
                        )
                    )
                elif role == 2 and b"Authorization:" not in raw:
                    connection.sendall(_http_response(403, {"error": "authentication required"}))
                else:
                    connection.sendall(_http_response(400, {"error": "wrong authentication mode"}))

    listener.settimeout(4)
    thread = threading.Thread(target=serve)
    thread.start()
    return thread


def _workspace(root: Path, port: int, *, actor: str, signer_seed: int) -> tuple[Path, Path, Path]:
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
    envelope = SignedAuthorityGrant.model_validate_json(authority.read_text(encoding="utf-8"))
    targets = tuple(
        target.model_copy(update={"target_id": TARGET_ID}) for target in envelope.payload.targets
    )
    grant = envelope.payload.model_copy(
        update={
            "grant_id": f"grant.{actor}",
            "issued_to": actor,
            "identities": (OWNER, REQUESTER),
            "targets": targets,
        }
    )
    authority.write_text(
        sign_authority_grant(grant, signer, signed_at=now).model_dump_json(indent=2), encoding="utf-8"
    )
    private_key = root / "authority-private.key"
    private_key.write_text(seed.hex() + "\n", encoding="ascii")
    private_key.chmod(0o600)
    workspace = root / "workspace"
    run_arguments = _run_arguments(authority, key)
    run_arguments[run_arguments.index("--target") + 1] = TARGET_ID
    assert cli.main(run_arguments + ["--workspace", str(workspace)]) == cli.EXIT_OK
    return workspace, key, private_key


def _prepare_args(
    workspace: Path,
    key: Path,
    private_key: Path,
    *,
    phase: str,
    env_name: str,
    port: int,
    out: Path,
    source: tuple[Path, Path, Path] | None = None,
    session_expires_at: datetime | None = None,
) -> list[str]:
    args = [
        "campaign", "prepare-bola-read",
        "--workspace", str(workspace), "--trusted-key", str(key), "--private-key", str(private_key),
        "--phase", phase, "--campaign-id", CAMPAIGN,
        "--source-claim", "Requester B can read owner A's invoice despite owner-only policy.",
        "--target-id", TARGET_ID, "--hostname", "127.0.0.1", "--port", str(port), "--scheme", "http",
        "--tenant-id", TENANT_ID, "--object-id", OBJECT_ID, "--object-kind", OBJECT_KIND,
        "--owner-identity", OWNER, "--requester-identity", REQUESTER,
        "--principal-control-path", PRINCIPAL_PATH, "--object-read-path", OBJECT_PATH,
        "--requester-session-ref", f"secret://target-env/{env_name}",
        "--requester-session-expires-at",
        (session_expires_at or (datetime.now(UTC) + timedelta(hours=1))).isoformat().replace("+00:00", "Z"),
        "--confirm-operator-reviewed-owner-binding", "--confirm-requester-must-not-read",
        "--response-bytes", "4096", "--timeout-seconds", "3", "--out", str(out),
    ]
    if source is not None:
        source_workspace, source_key, handoff = source
        args.extend(["--source-workspace", str(source_workspace), "--source-trusted-key", str(source_key), "--source-handoff", str(handoff)])
    return args


def _run_args(workspace: Path, key: Path, private_key: Path, case: Path) -> list[str]:
    return [
        "campaign", "run-bola-read", "--workspace", str(workspace), "--trusted-key", str(key),
        "--private-key", str(private_key), "--case", str(case),
    ]


def _export_args(workspace: Path, key: Path, private_key: Path, case: Path, run: Path, out: Path) -> list[str]:
    return [
        "campaign", "export-bola-read-handoff", "--workspace", str(workspace), "--trusted-key", str(key),
        "--private-key", str(private_key), "--case", str(case), "--run-result", str(run), "--out", str(out),
    ]


def _finalize_args(
    source: tuple[Path, Path], reviewer: tuple[Path, Path], handoff: Path,
    reviewer_case: Path, reviewer_run: Path, out: Path,
) -> list[str]:
    return [
        "campaign", "finalize-bola-read-review",
        "--source-workspace", str(source[0]), "--source-trusted-key", str(source[1]),
        "--reviewer-workspace", str(reviewer[0]), "--reviewer-trusted-key", str(reviewer[1]),
        "--handoff", str(handoff), "--reviewer-case", str(reviewer_case),
        "--reviewer-run", str(reviewer_run), "--out", str(out),
    ]


def _capture_output(capsys: pytest.CaptureFixture[str], outputs: list[str]) -> str:
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    outputs.append(combined)
    return captured.out


def _close_and_join(listener: socket.socket, server: threading.Thread) -> None:
    listener.close()
    server.join(timeout=3)
    assert not server.is_alive()


def _pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    *,
    object_ids: Sequence[str] = (OBJECT_ID, OBJECT_ID),
) -> tuple[dict[str, object], list[bytes], list[str], Path, Path, Path, Path, Path]:
    listener, port = _listener()
    outputs: list[str] = []
    source, source_key, source_private = _workspace(tmp_path / "source", port, actor=SOURCE_ACTOR, signer_seed=41)
    reviewer, reviewer_key, reviewer_private = _workspace(tmp_path / "reviewer", port, actor=REVIEWER_ACTOR, signer_seed=73)
    _capture_output(capsys, outputs)
    source_case = source / "source-bola-case.json"
    assert cli.main(_prepare_args(source, source_key, source_private, phase="source", env_name=SOURCE_ENV, port=port, out=source_case)) == cli.EXIT_OK
    _capture_output(capsys, outputs)
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    monkeypatch.setenv(REVIEWER_ENV, REVIEWER_TOKEN)
    captured: list[bytes] = []
    server = _serve_bola(listener, captured, object_ids=object_ids)
    assert cli.main(_run_args(source, source_key, source_private, source_case)) == cli.EXIT_OK
    _capture_output(capsys, outputs)
    source_run = source / f"{CAMPAIGN}.source.bola-read-run.json"
    handoff = source / "source-bola-handoff.json"
    assert cli.main(_export_args(source, source_key, source_private, source_case, source_run, handoff)) == cli.EXIT_OK
    _capture_output(capsys, outputs)
    reviewer_case = reviewer / "reviewer-bola-case.json"
    assert cli.main(_prepare_args(reviewer, reviewer_key, reviewer_private, phase="reviewer", env_name=REVIEWER_ENV, port=port, out=reviewer_case, source=(source, source_key, handoff))) == cli.EXIT_OK
    _capture_output(capsys, outputs)
    assert cli.main(_run_args(reviewer, reviewer_key, reviewer_private, reviewer_case)) == cli.EXIT_OK
    _capture_output(capsys, outputs)
    _close_and_join(listener, server)
    reviewer_run = reviewer / f"{CAMPAIGN}.reviewer.bola-read-run.json"
    result_path = reviewer / "bola-result.json"
    return ({"source": source, "source_key": source_key, "reviewer": reviewer, "reviewer_key": reviewer_key,
             "source_case": source_case, "source_run": source_run, "handoff": handoff,
             "reviewer_case": reviewer_case, "reviewer_run": reviewer_run, "result_path": result_path},
            captured, outputs, source, source_key, reviewer, reviewer_key, result_path)


def _assert_no_secret_or_authenticated_request_artifacts(
    root: Path, captured_requests: Sequence[bytes], output_segments: Sequence[str]
) -> set[bytes]:
    authenticated_request_digests = {
        hashlib.sha256(request).hexdigest().encode("ascii")
        for request in captured_requests
        if b"Authorization: Bearer " in request
    }
    assert len(authenticated_request_digests) == 4
    forbidden = (
        SOURCE_TOKEN.encode(),
        REVIEWER_TOKEN.encode(),
        b"Authorization: Bearer ",
        *authenticated_request_digests,
    )
    for artifact in root.rglob("*"):
        if artifact.is_file():
            content = artifact.read_bytes()
            assert all(value not in content for value in forbidden), artifact
    stdout_and_stderr = "".join(output_segments).encode("utf-8")
    assert all(value not in stdout_and_stderr for value in forbidden)
    return authenticated_request_digests


def test_bola_read_source_and_reviewer_run_exact_authenticated_triads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    values, captured, outputs, source, source_key, reviewer, reviewer_key, result_path = _pipeline(tmp_path, monkeypatch, capsys)
    assert cli.main(_finalize_args((source, source_key), (reviewer, reviewer_key), values["handoff"], values["reviewer_case"], values["reviewer_run"], result_path)) == cli.EXIT_OK
    result = json.loads(_capture_output(capsys, outputs))
    assert result == json.loads(result_path.read_text(encoding="utf-8"))
    assert result["status"] == "cross_principal_owner_object_read_reproduced"
    assert result["observed_fact"] == "cross_principal_owner_object_read_reproduced"
    assert result["semantic_verdict"] == "not_evaluated"
    assert result["candidate_class"] == "bola_idor"
    assert result["candidate_class_status"] == "operator_asserted_unverified"
    assert result["owner_binding_status"] == "target_response_observed"
    assert result["authorization_expectation_status"] == "operator_asserted_unverified"
    assert result["taxonomy_verdict"] == "not_evaluated"
    assert result["impact_verdict"] == "not_evaluated"
    assert result["report_status"] == "draft_manual_review"
    assert result["automatic_submission"] is False
    assert len(captured) == 6
    assert [request.split(b" ", 2)[1] for request in captured] == [PRINCIPAL_PATH.encode(), OBJECT_PATH.encode(), OBJECT_PATH.encode()] * 2
    for phase, token in enumerate((SOURCE_TOKEN, REVIEWER_TOKEN)):
        triad = captured[phase * 3 : phase * 3 + 3]
        assert all(b"Authorization: Bearer " + token.encode() in request for request in triad[:2])
        assert b"Authorization:" not in triad[2]
        assert b"Cookie:" not in b"".join(triad)
    authenticated_request_digests = _assert_no_secret_or_authenticated_request_artifacts(
        tmp_path, captured, outputs
    )
    for run_path in (values["source_run"], values["reviewer_run"]):
        observations = json.loads(run_path.read_text(encoding="utf-8"))["run"]["observations"]
        assert all(
            observation["redacted_request_sha256"].encode("ascii")
            not in authenticated_request_digests
            for observation in observations
        )


@pytest.mark.parametrize("secret_state", ("missing", "expired"))
def test_bola_read_missing_or_expired_secret_causes_zero_target_io(
    secret_state: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    workspace, key, private = _workspace(tmp_path / "source", port, actor=SOURCE_ACTOR, signer_seed=47)
    capsys.readouterr()
    case = workspace / "case.json"
    expiry = datetime.now(UTC) - timedelta(minutes=1) if secret_state == "expired" else None
    assert cli.main(_prepare_args(workspace, key, private, phase="source", env_name=SOURCE_ENV, port=port, out=case, session_expires_at=expiry)) == cli.EXIT_OK
    capsys.readouterr()
    if secret_state == "missing":
        monkeypatch.delenv(SOURCE_ENV, raising=False)
    else:
        monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    assert cli.main(_run_args(workspace, key, private, case)) == cli.EXIT_AUTHORITY
    listener.settimeout(0.15)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()
    assert not list(workspace.glob("*.bola-read-start.json"))


def test_bola_read_out_of_scope_case_is_rejected_before_secret_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    workspace, key, private = _workspace(
        tmp_path / "source", port, actor=SOURCE_ACTOR, signer_seed=59
    )
    capsys.readouterr()
    case_path = workspace / "case.json"
    assert cli.main(
        _prepare_args(
            workspace, key, private, phase="source", env_name=SOURCE_ENV,
            port=port, out=case_path,
        )
    ) == cli.EXIT_OK
    capsys.readouterr()
    signed = SignedBolaReadCase.model_validate_json(case_path.read_bytes())
    signer = AuthoritySigner.from_private_bytes(
        bytes((value + 59) % 256 for value in range(32))
    )
    outside = sign_bola_read_case(
        signed.case.model_copy(update={"hostname": "localhost"}), signer
    )
    case_path.write_bytes(signed_bola_case_bytes(outside))
    secret_lookups = 0

    def forbidden_secret_lookup(*args: object, **kwargs: object) -> str:
        nonlocal secret_lookups
        secret_lookups += 1
        raise AssertionError("out-of-scope case resolved a target secret")

    monkeypatch.setattr(cli, "resolve_target_bearer", forbidden_secret_lookup)
    assert cli.main(_run_args(workspace, key, private, case_path)) == cli.EXIT_AUTHORITY
    assert secret_lookups == 0
    assert not list(workspace.glob("*.bola-read-start.json"))
    listener.settimeout(0.15)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_bola_read_completion_failure_removes_orphan_response_and_never_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    workspace, key, private = _workspace(
        tmp_path / "source", port, actor=SOURCE_ACTOR, signer_seed=61
    )
    capsys.readouterr()
    case = workspace / "case.json"
    assert cli.main(
        _prepare_args(
            workspace, key, private, phase="source", env_name=SOURCE_ENV,
            port=port, out=case,
        )
    ) == cli.EXIT_OK
    capsys.readouterr()
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    captured: list[bytes] = []
    server = _serve_bola(listener, captured, request_count=1)

    def fail_completion(*args: object, **kwargs: object) -> dict[str, str]:
        raise cli.CliError("injected accounting completion failure", exit_code=cli.EXIT_AUTHORITY)

    monkeypatch.setattr(cli, "_complete_in_memory_request", fail_completion)
    assert cli.main(_run_args(workspace, key, private, case)) == cli.EXIT_UNAVAILABLE
    _close_and_join(listener, server)
    capsys.readouterr()
    assert len(captured) == 1
    assert not list((workspace / "responses").glob("*.raw"))
    assert cli.main(_run_args(workspace, key, private, case)) == cli.EXIT_AUTHORITY


def test_concurrent_identical_bola_runs_dispatch_only_one_triad(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener, port = _listener()
    workspace, key, private = _workspace(
        tmp_path / "source", port, actor=SOURCE_ACTOR, signer_seed=67
    )
    case = workspace / "case.json"
    assert cli.main(
        _prepare_args(
            workspace, key, private, phase="source", env_name=SOURCE_ENV,
            port=port, out=case,
        )
    ) == cli.EXIT_OK
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    captured: list[bytes] = []
    server = _serve_bola(listener, captured, request_count=3)
    barrier = threading.Barrier(2)
    validate_capacity = cli._validate_campaign_accounting_capacity

    def synchronized_capacity(*args: object, **kwargs: object) -> None:
        validate_capacity(*args, **kwargs)
        barrier.wait(timeout=3)

    monkeypatch.setattr(
        cli, "_validate_campaign_accounting_capacity", synchronized_capacity
    )
    outcomes: list[int] = []
    errors: list[BaseException] = []

    def run() -> None:
        try:
            outcomes.append(cli.main(_run_args(workspace, key, private, case)))
        except BaseException as exc:  # pragma: no cover - reports unexpected worker errors
            errors.append(exc)

    workers = [threading.Thread(target=run) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
    _close_and_join(listener, server)

    assert not any(worker.is_alive() for worker in workers)
    assert not errors
    assert sorted(outcomes) == [cli.EXIT_OK, cli.EXIT_AUTHORITY]
    assert len(captured) == 3
    assert len(list(workspace.glob("*.bola-read-start.json"))) == 1
    assert len(list(workspace.glob("*.bola-read-run.json"))) == 1


def test_bola_read_tampered_response_or_object_identity_mismatch_cannot_finalize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    values, _, _, source, source_key, reviewer, reviewer_key, result_path = _pipeline(tmp_path, monkeypatch, capsys)
    reviewer_observations = json.loads(values["reviewer_run"].read_text(encoding="utf-8"))["run"]["observations"]
    response_path = reviewer / next(item["response_file"] for item in reviewer_observations if item["role"] == "object_read")
    assert response_path.exists(), "planned run must preserve private response evidence for later verification"
    response_path.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    assert cli.main(_finalize_args((source, source_key), (reviewer, reviewer_key), values["handoff"], values["reviewer_case"], values["reviewer_run"], result_path)) == cli.EXIT_AUTHORITY
    assert not result_path.exists()


def test_bola_read_object_identity_mismatch_cannot_create_semantic_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    values, _, _, source, source_key, reviewer, reviewer_key, result_path = _pipeline(
        tmp_path, monkeypatch, capsys, object_ids=(OBJECT_ID, "invoice.wrong-object")
    )
    assert cli.main(_finalize_args((source, source_key), (reviewer, reviewer_key), values["handoff"], values["reviewer_case"], values["reviewer_run"], result_path)) == cli.EXIT_AUTHORITY
    assert not result_path.exists()


def test_bola_read_dropped_connection_is_unresolved_and_never_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    listener, port = _listener()
    workspace, key, private = _workspace(tmp_path / "source", port, actor=SOURCE_ACTOR, signer_seed=53)
    capsys.readouterr()
    case = workspace / "case.json"
    assert cli.main(_prepare_args(workspace, key, private, phase="source", env_name=SOURCE_ENV, port=port, out=case)) == cli.EXIT_OK
    capsys.readouterr()
    monkeypatch.setenv(SOURCE_ENV, SOURCE_TOKEN)
    captured: list[bytes] = []
    server = _serve_bola(listener, captured, drop_first=True)
    assert cli.main(_run_args(workspace, key, private, case)) == cli.EXIT_UNAVAILABLE
    _close_and_join(listener, server)
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "unresolved_not_evaluated"
    assert output["reservationState"] == "unresolved_no_retry"
    assert output["dispatchCount"] == 1
    assert cli.main(_run_args(workspace, key, private, case)) == cli.EXIT_AUTHORITY
    assert len(captured) == 1
