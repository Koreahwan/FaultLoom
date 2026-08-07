from __future__ import annotations

import argparse
import io
import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from faultloom import cli
from faultloom.verification.http1_triad import (
    Http1TriadVerificationError,
    parse_strict_http1_request,
    require_separate_workspaces,
)
from faultloom_protocol import AuthoritySigner, SignedAuthorityGrant, sign_authority_grant
from tests.runtime.test_campaign_verification_handoff import _export_arguments
from tests.runtime.test_cli import _authority_files, _run_arguments
from tests.runtime.test_personal_campaign import _campaign_run_arguments, _request, _serve, _spec, _workspace
from tests.runtime.test_personal_campaign_bridge import _bundle, _prepare_arguments


def _source_campaign(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> tuple[Path, Path]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(3)
    port = listener.getsockname()[1]
    workspace, key = _workspace(tmp_path, port)
    template = _spec(workspace, port)
    result, receipt = _bundle(workspace, key, template, port)
    bound = workspace / "bound.json"
    capsys.readouterr()
    assert cli.main(_prepare_arguments(workspace, key, template, result, receipt, bound)) == 0
    capsys.readouterr()
    thread = _serve(listener, [
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
    ], [])
    assert cli.main(_campaign_run_arguments(workspace, key, bound)) == 0
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(workspace),
        "--trusted-key", str(key), "--campaign-id", "owned-loopback",
        "--confirm-reviewed-non-sensitive",
    ]) == 0
    capsys.readouterr()
    return workspace, key


def _verifier_workspace(
    tmp_path: Path,
    port: int,
    *,
    actor: str = "verifier.independent",
    signer_seed: int = 17,
    now: datetime | None = None,
) -> tuple[Path, Path, Path]:
    issued_at = now or (datetime.now(UTC) - timedelta(minutes=1))
    authority, key = _authority_files(
        tmp_path / "verifier-grant",
        hostnames=("127.0.0.1",),
        ports=(port,),
        paths=("/api/*",),
        methods=("GET",),
        protocols=("http",),
        budget_updates={"total_actions": 3, "rate_per_minute": 3, "max_concurrency": 1},
        now=issued_at,
        signer_seed=signer_seed,
    )
    signer = AuthoritySigner.from_private_bytes(
        bytes((value + signer_seed) % 256 for value in range(32))
    )
    envelope = SignedAuthorityGrant.model_validate_json(authority.read_text())
    changed = envelope.payload.model_copy(
        update={"grant_id": "grant.independent-verifier", "issued_to": actor}
    )
    authority.write_text(
        sign_authority_grant(changed, signer, signed_at=changed.issued_at).model_dump_json(indent=2),
        encoding="utf-8",
    )
    private_key = tmp_path / "verifier-private.key"
    private_key.write_text(
        bytes((value + signer_seed) % 256 for value in range(32)).hex() + "\n"
    )
    private_key.chmod(0o600)
    workspace = tmp_path / "verifier-workspace"
    assert cli.main(_run_arguments(authority, key) + ["--workspace", str(workspace)]) == cli.EXIT_OK
    return workspace, key, private_key


def _prepare_args(
    source: Path, source_key: Path, handoff: Path, verifier: Path, verifier_key: Path
) -> list[str]:
    return [
        "campaign", "prepare-verification-http1",
        "--source-workspace", str(source), "--source-trusted-key", str(source_key),
        "--handoff", str(handoff),
        "--verifier-workspace", str(verifier), "--verifier-trusted-key", str(verifier_key),
        "--campaign-id", "owned-loopback",
        "--finding-class", "http_response_differential",
        "--claim", "The owned effect path deterministically differs from its control.",
        "--prerequisite", "Use the separately authorized verifier identity.",
        "--out", str(verifier / "verification-triad.json"),
    ]


def _compile_args(
    source: Path,
    source_key: Path,
    handoff: Path,
    verifier: Path,
    verifier_key: Path,
    private_key: Path,
) -> list[str]:
    return [
        "campaign", "compile-verification-http1",
        "--source-workspace", str(source), "--source-trusted-key", str(source_key),
        "--handoff", str(handoff),
        "--verifier-workspace", str(verifier), "--verifier-trusted-key", str(verifier_key),
        "--campaign-id", "owned-loopback",
        "--case", str(verifier / "owned-loopback.verification-case.json"),
        "--private-key", str(private_key),
        "--result-out", str(verifier / "verified-result.json"),
        "--receipt-out", str(verifier / "verification-compile-receipt.json"),
    ]


def _supervise_args(
    source: Path,
    source_key: Path,
    handoff: Path,
    verifier: Path,
    verifier_key: Path,
    private_key: Path,
) -> list[str]:
    return [
        "campaign", "supervise-verification-http1",
        "--source-workspace", str(source), "--source-trusted-key", str(source_key),
        "--handoff", str(handoff),
        "--verifier-workspace", str(verifier), "--verifier-trusted-key", str(verifier_key),
        "--campaign-id", "owned-loopback",
        "--finding-class", "http_response_differential",
        "--claim", "The owned effect path deterministically differs from its control.",
        "--prerequisite", "Use the separately authorized verifier identity.",
        "--out", str(verifier / "verification-triad.json"),
        "--case", str(verifier / "owned-loopback.verification-case.json"),
        "--private-key", str(private_key),
        "--result-out", str(verifier / "verified-result.json"),
        "--receipt-out", str(verifier / "verification-compile-receipt.json"),
    ]


def _one_json(capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    captured = capsys.readouterr()
    assert captured.out.count("\n") == 1
    return json.loads(captured.out)


def test_independent_http1_bridge_runs_existing_triad_and_existing_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    source_run = json.loads((source / "run.json").read_text())
    port = source_run["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()

    assert cli.main(_prepare_args(source, source_key, handoff, verifier, verifier_key)) == cli.EXIT_OK
    prepared = json.loads(capsys.readouterr().out)
    assert prepared["status"] == "ready_for_existing_triad_runner"
    assert prepared["networkAccess"] is False

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    captured: list[bytes] = []
    thread = _serve(listener, [
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
    ], captured)
    assert cli.main(_campaign_run_arguments(verifier, verifier_key, verifier / "verification-triad.json")) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()
    assert len(captured) == 3
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(verifier),
        "--trusted-key", str(verifier_key), "--campaign-id", "owned-loopback",
        "--confirm-reviewed-non-sensitive",
    ]) == cli.EXIT_OK
    capsys.readouterr()
    def unexpected_socket(*args: object, **kwargs: object) -> object:
        raise AssertionError("compile, verify, and report must remain offline")

    monkeypatch.setattr(cli.socket, "socket", unexpected_socket)
    assert cli.main(_compile_args(source, source_key, handoff, verifier, verifier_key, private_key)) == cli.EXIT_OK
    compiled = json.loads(capsys.readouterr().out)
    assert compiled["status"] == "observation_reproduced"
    receipt = json.loads((verifier / "verification-compile-receipt.json").read_text())
    assert receipt["automaticReport"] is False and receipt["automaticSubmission"] is False
    assert receipt["observation"] == "exact_http_response_body_differential"
    assert receipt["sourceClaimStatus"] == "operator_asserted_unverified"
    assert receipt["semanticVerdict"] == "not_evaluated"
    assert receipt["taxonomyVerdict"] == "not_evaluated"
    assert "--out-dir" not in receipt["reportArgs"]

    monkeypatch.chdir(verifier)
    assert cli.main(["verify", *receipt["verifyArgs"]]) == cli.EXIT_OK
    verified = json.loads(capsys.readouterr().out)
    assert verified["outcome"] == "observation_reproduced"
    assert verified["network_access"] == "none"
    assert cli.main(["report", *receipt["reportArgs"]]) == cli.EXIT_OK
    report = capsys.readouterr().out
    assert "- Verdict: `observation_reproduced`" in report
    assert "vulnerability semantics not evaluated" in report
    assert "- Semantic verdict: `not_evaluated`" in report
    assert "- Taxonomy verdict: `not_evaluated`" in report
    assert cli.HTTP1_DIFFERENTIAL_OBSERVATION_TITLE in report
    assert cli.HTTP1_DIFFERENTIAL_OBSERVATION_CLAIM in report
    assert "# Owned triad" not in report
    assert "The owned effect path deterministically differs from its control." not in report
    assert not (verifier / "verification-report-outbox").exists()
    json_report_args = list(receipt["reportArgs"])
    json_report_args[json_report_args.index("md")] = "json"
    assert cli.main(["report", *json_report_args]) == cli.EXIT_OK
    json_report = json.loads(capsys.readouterr().out)
    assert json_report["verdict"] == "observation_reproduced"
    assert json_report["protocol_replay_outcome"] == "verified"
    assert json_report["semantic_verdict"] == "not_evaluated"
    assert json_report["taxonomy_verdict"] == "not_evaluated"


def test_supervise_independent_http1_runs_verifier_triad_then_offline_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    captured: list[bytes] = []
    thread = _serve(listener, [
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
    ], captured)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\nFINALIZE owned-loopback\n"))
    outside = tmp_path / "outside-report-dir"
    outside.mkdir()
    legacy_outbox = verifier / "verification-report-outbox"
    original_invoke = cli._invoke_cli_main_captured
    report_argv: list[str] = []

    def swap_legacy_outbox_before_report(
        argv: list[str], *, working_directory: Path
    ) -> tuple[int, str]:
        if argv[0] == "report" and cli.os.name != "nt" and not legacy_outbox.exists():
            legacy_outbox.symlink_to(outside, target_is_directory=True)
        if argv[0] == "report":
            report_argv.extend(argv)
        return original_invoke(argv, working_directory=working_directory)

    monkeypatch.setattr(
        cli, "_invoke_cli_main_captured", swap_legacy_outbox_before_report
    )

    arguments = _supervise_args(
        source, source_key, handoff, verifier, verifier_key, private_key
    )
    assert cli.main(arguments) == cli.EXIT_OK
    thread.join(timeout=3)
    listener.close()

    output = _one_json(capsys)
    assert output["status"] == "completed"
    assert output["automaticSubmission"] is False
    verification = output["verification"]
    assert isinstance(verification, dict)
    assert verification["status"] == "observation_reproduced"
    assert verification["reportStatus"] == "draft_manual_review"
    compile_receipt = json.loads((verifier / "verification-compile-receipt.json").read_text())
    assert report_argv == ["report", *compile_receipt["reportArgs"]]
    assert captured == [
        _request(port, "/api/effect"),
        _request(port, "/api/effect"),
        _request(port, "/api/control"),
    ]
    report_receipt_path = verification["reportReceipt"]
    assert isinstance(report_receipt_path, str)
    report_receipt = json.loads(Path(report_receipt_path).read_text())
    assert report_receipt["status"] == "draft_manual_review"
    assert report_receipt["network_access"] == "none"
    assert report_receipt["automatic_submission_performed"] is False
    assert list(outside.iterdir()) == []
    if legacy_outbox.is_symlink():
        legacy_outbox.unlink()

    def unexpected_compile(arguments: argparse.Namespace) -> int:
        raise AssertionError("completed supervisor resume must not recompile or resend")

    monkeypatch.setattr(cli, "_campaign_compile_verification_http1", unexpected_compile)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO(""))
    capsys.readouterr()
    assert cli.main(arguments) == cli.EXIT_OK
    assert _one_json(capsys)["status"] == "completed"
    assert len(captured) == 3


def test_supervise_independent_http1_rejects_tampered_compile_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    captured: list[bytes] = []
    thread = _serve(listener, [
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
    ], captured)
    original_compile = cli._campaign_compile_verification_http1
    redirected = tmp_path / "redirected"

    def tamper_after_compile(arguments: argparse.Namespace) -> int:
        exit_code = original_compile(arguments)
        receipt_path = verifier / "verification-compile-receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["reportArgs"].extend(["--out-dir", str(redirected)])
        receipt_path.write_text(json.dumps(receipt))
        return exit_code

    monkeypatch.setattr(cli, "_campaign_compile_verification_http1", tamper_after_compile)
    monkeypatch.setattr(
        cli.sys,
        "stdin",
        io.StringIO("RUN owned-loopback\nFINALIZE owned-loopback\n"),
    )

    assert cli.main(
        _supervise_args(source, source_key, handoff, verifier, verifier_key, private_key)
    ) == cli.EXIT_AUTHORITY
    thread.join(timeout=3)
    listener.close()
    assert len(captured) == 3
    assert not redirected.exists()


def test_supervise_independent_http1_declined_run_never_sends(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("no\n"))

    assert cli.main(_supervise_args(source, source_key, handoff, verifier, verifier_key, private_key)) == cli.EXIT_OK
    output = _one_json(capsys)
    assert output["status"] == "review_required"
    assert output["dispatchCount"] == 0
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_supervise_independent_http1_finalize_resume_never_resends(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    captured: list[bytes] = []
    thread = _serve(listener, [
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
    ], captured)
    arguments = _supervise_args(source, source_key, handoff, verifier, verifier_key, private_key)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\nno\n"))

    assert cli.main(arguments) == cli.EXIT_OK
    thread.join(timeout=3)
    assert _one_json(capsys)["status"] == "review_required"
    assert len(captured) == 3
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("FINALIZE owned-loopback\n"))
    assert cli.main(arguments) == cli.EXIT_OK
    output = _one_json(capsys)
    assert output["status"] == "completed"
    assert len(captured) == 3
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


@pytest.mark.parametrize("record", ("unresolved", "start"))
def test_supervise_independent_http1_existing_ambiguous_record_never_retries(
    record: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    campaigns = verifier / "campaigns"
    campaigns.mkdir()
    value = {"campaign_id": "owned-loopback", "dispatch_count": 1} if record == "unresolved" else {}
    (campaigns / f"owned-loopback.{record}.json").write_text(json.dumps(value))
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(1)
    monkeypatch.setattr(cli.sys, "stdin", io.StringIO("RUN owned-loopback\n"))

    assert cli.main(_supervise_args(source, source_key, handoff, verifier, verifier_key, private_key)) == cli.EXIT_UNAVAILABLE
    output = _one_json(capsys)
    assert output["status"] == "manual_reconciliation_required"
    if record == "start":
        assert output["dispatchState"] == "unknown"
        assert "dispatchCount" not in output
    listener.settimeout(0.1)
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


def test_prepare_rejects_same_source_and_verifier_workspace(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(_prepare_args(source, source_key, handoff, source, source_key)) == cli.EXIT_AUTHORITY
    assert not (source / "verification-triad.json").exists()


def test_workspace_boundary_rejects_nesting_in_both_directions(tmp_path: Path) -> None:
    source = tmp_path / "source"
    nested = source / "verifier"
    nested.mkdir(parents=True)
    with pytest.raises(Http1TriadVerificationError):
        require_separate_workspaces(source, nested)
    with pytest.raises(Http1TriadVerificationError):
        require_separate_workspaces(nested, source)


def test_prepare_rejects_tampered_source_handoff_without_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    handoff_document = json.loads(handoff.read_text())
    handoff_document["verificationStatus"] = "verified"
    handoff.write_text(json.dumps(handoff_document))
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, _ = _verifier_workspace(tmp_path, port)
    capsys.readouterr()

    assert cli.main(
        _prepare_args(source, source_key, handoff, verifier, verifier_key)
    ) == cli.EXIT_AUTHORITY
    assert not (verifier / "verification-triad.json").exists()
    assert not (verifier / "owned-loopback.verification-case.json").exists()
    assert not (verifier / "owned-loopback.verification-prepare-receipt.json").exists()


def test_prepare_accepts_historical_source_with_active_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    future = datetime.now(UTC) + timedelta(hours=3)
    monkeypatch.setattr(cli, "_utc_now", lambda: future)
    verifier, verifier_key, _ = _verifier_workspace(
        tmp_path, port, now=future - timedelta(minutes=1)
    )
    capsys.readouterr()

    assert cli.main(
        _prepare_args(source, source_key, handoff, verifier, verifier_key)
    ) == cli.EXIT_OK
    assert (verifier / "verification-triad.json").is_file()


def test_compile_rejects_start_only_verifier_campaign(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == cli.EXIT_OK
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    assert cli.main(_prepare_args(source, source_key, handoff, verifier, verifier_key)) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(_compile_args(source, source_key, handoff, verifier, verifier_key, private_key)) == cli.EXIT_AUTHORITY
    assert not (verifier / "verified-result.json").exists()


def test_compile_rejects_response_swap_after_deep_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == 0
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    assert cli.main(_prepare_args(source, source_key, handoff, verifier, verifier_key)) == 0
    capsys.readouterr()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    thread = _serve(listener, [
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
    ], [])
    assert cli.main(_campaign_run_arguments(verifier, verifier_key, verifier / "verification-triad.json")) == 0
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(verifier),
        "--trusted-key", str(verifier_key), "--campaign-id", "owned-loopback",
        "--confirm-reviewed-non-sensitive",
    ]) == 0
    capsys.readouterr()
    original = cli._validated_campaign_evidence
    validation_calls = 0

    def swap(*args: object, **kwargs: object) -> None:
        nonlocal validation_calls
        value = original(*args, **kwargs)
        validation_calls += 1
        if validation_calls == 2:
            response = next((verifier / "responses").glob("*.raw"))
            response.write_bytes(response.read_bytes() + b"tampered")
        return value

    monkeypatch.setattr(cli, "_validated_campaign_evidence", swap)
    assert cli.main(
        _compile_args(source, source_key, handoff, verifier, verifier_key, private_key)
    ) == cli.EXIT_AUTHORITY
    assert not (verifier / "verified-result.json").exists()


@pytest.mark.parametrize(
    "raw",
    (
        b"HEAD /api/effect HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        b"GET /api/effect HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: x\r\nConnection: close\r\n\r\n",
        b"GET /api/effect HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\nx",
        b"GET /api/effect HTTP/1.1\r\nHost: x\x00y\r\nConnection: close\r\n\r\n",
        b"GET /api/effect HTTP/1.1\r\nHost: x\x7fy\r\nConnection: close\r\n\r\n",
        b"GET /api/effect HTTP/1.1\r\n Host: x\r\nConnection: close\r\n\r\n",
    ),
)
def test_strict_verifier_request_rejects_head_auth_extra_headers_and_body(raw: bytes) -> None:
    with pytest.raises(Http1TriadVerificationError):
        parse_strict_http1_request(raw)


@pytest.mark.parametrize(
    ("actor", "signer_seed", "port_delta"),
    (
        ("researcher.1", 17, 0),
        ("verifier.independent", 0, 0),
        ("verifier.independent", 17, 1),
    ),
)
def test_prepare_rejects_same_actor_same_key_and_wrong_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    actor: str,
    signer_seed: int,
    port_delta: int,
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == 0
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, _ = _verifier_workspace(
        tmp_path, port + port_delta, actor=actor, signer_seed=signer_seed
    )
    capsys.readouterr()
    assert cli.main(_prepare_args(source, source_key, handoff, verifier, verifier_key)) == cli.EXIT_AUTHORITY
    assert not (verifier / "verification-triad.json").exists()


def test_prepare_rejects_expired_verifier_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == 0
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, _ = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    monkeypatch.setattr(cli, "_utc_now", lambda: datetime.now(UTC) + timedelta(hours=3))
    assert cli.main(_prepare_args(source, source_key, handoff, verifier, verifier_key)) == cli.EXIT_AUTHORITY
    assert not (verifier / "verification-triad.json").exists()


def test_prepare_rejects_semantic_vulnerability_class_before_io(tmp_path: Path) -> None:
    arguments = _prepare_args(
        tmp_path / "source",
        tmp_path / "source-key.json",
        tmp_path / "handoff.json",
        tmp_path / "verifier",
        tmp_path / "verifier-key.json",
    )
    arguments[arguments.index("http_response_differential")] = "zero_day_like"

    with pytest.raises(SystemExit) as raised:
        cli.main(arguments)

    assert raised.value.code == cli.EXIT_USAGE
    assert not (tmp_path / "verifier" / "verification-triad.json").exists()


@pytest.mark.parametrize("mutation", ("claim", "finding_class", "prerequisite", "triad_ref"))
def test_compile_rejects_tampered_prepared_case_after_finalization(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], mutation: str
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == 0
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    assert cli.main(_prepare_args(source, source_key, handoff, verifier, verifier_key)) == 0
    capsys.readouterr()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(3)
    thread = _serve(listener, [
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\neffect",
        b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ncontrol",
    ], [])
    assert cli.main(_campaign_run_arguments(verifier, verifier_key, verifier / "verification-triad.json")) == 0
    thread.join(timeout=3)
    listener.close()
    capsys.readouterr()
    assert cli.main([
        "campaign", "finalize-http1-triad", "--workspace", str(verifier),
        "--trusted-key", str(verifier_key), "--campaign-id", "owned-loopback",
        "--confirm-reviewed-non-sensitive",
    ]) == 0
    capsys.readouterr()
    case_path = verifier / "owned-loopback.verification-case.json"
    case = json.loads(case_path.read_text())
    if mutation == "claim":
        case["semantics"]["sourceClaim"] = "tampered"
        case["semanticsDigest"] = cli.sha256_digest(case["semantics"])
    elif mutation == "finding_class":
        case["semantics"]["findingClass"] = "patch_variant"
    elif mutation == "prerequisite":
        case["semantics"]["prerequisites"] = ["tampered"]
    else:
        case["triad"]["effectRequest"]["sha256"] = "0" * 64
    tampered_case = json.dumps(case).encode()
    case_path.write_bytes(tampered_case)
    if mutation == "claim":
        prepare_receipt_path = verifier / "owned-loopback.verification-prepare-receipt.json"
        prepare_receipt = json.loads(prepare_receipt_path.read_text())
        prepare_receipt["semanticsDigest"] = case["semanticsDigest"]
        prepare_receipt["case"]["sizeBytes"] = len(tampered_case)
        prepare_receipt["case"]["sha256"] = cli.sha256_hex(tampered_case)
        prepare_receipt_path.write_text(json.dumps(prepare_receipt))
    assert cli.main(
        _compile_args(source, source_key, handoff, verifier, verifier_key, private_key)
    ) == cli.EXIT_AUTHORITY
    assert not (verifier / "verified-result.json").exists()


@pytest.mark.skipif(cli.os.name == "nt", reason="POSIX secret modes are platform-specific")
def test_compile_rejects_public_or_workspace_local_private_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source, source_key = _source_campaign(tmp_path / "source", capsys)
    handoff = source / "verification-handoff.json"
    assert cli.main(_export_arguments(source, source_key, handoff)) == 0
    capsys.readouterr()
    port = json.loads((source / "run.json").read_text())["target"]["ports"][0]
    verifier, verifier_key, private_key = _verifier_workspace(tmp_path, port)
    capsys.readouterr()
    assert cli.main(_prepare_args(source, source_key, handoff, verifier, verifier_key)) == 0
    capsys.readouterr()
    private_key.chmod(0o644)
    assert cli.main(
        _compile_args(source, source_key, handoff, verifier, verifier_key, private_key)
    ) == cli.EXIT_AUTHORITY
    assert "mode 0600" in capsys.readouterr().err
    local_key = verifier / "private.key"
    local_key.write_bytes(private_key.read_bytes())
    local_key.chmod(0o600)
    assert cli.main(
        _compile_args(source, source_key, handoff, verifier, verifier_key, local_key)
    ) == cli.EXIT_AUTHORITY
    assert not (verifier / "verified-result.json").exists()
