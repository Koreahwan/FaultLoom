from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from pathlib import Path

import pytest

from faultloom import cli, verification_cli
from faultloom.verification import (
    ReportFormat,
    render_finding_report,
    verify_result_artifact,
)
from tests.runtime.verification_support import (
    ReplayFixtureOptions,
    VerificationFixture,
    build_verification_fixture,
)


@dataclass(frozen=True, slots=True)
class _ArtifactPaths:
    result: Path
    result_key: Path
    verifier_authority: Path
    verifier_authority_key: Path


def _write_artifact_inputs(
    directory: Path,
    fixture: VerificationFixture,
) -> _ArtifactPaths:
    result_path = directory / "signed-result.json"
    key_path = directory / "verifier-public-key.json"
    authority_path = directory / "verifier-authority.json"
    authority_key_path = directory / "verifier-authority-public-key.json"
    result_path.write_text(fixture.signed_result.model_dump_json(), encoding="utf-8")
    key_path.write_text(
        fixture.result_signer.public_key_record.model_dump_json(),
        encoding="utf-8",
    )
    authority_path.write_text(
        fixture.expectations.signed_verifier_authority.model_dump_json(),
        encoding="utf-8",
    )
    authority_key_path.write_text(
        fixture.expectations.trusted_verifier_authority_key.model_dump_json(),
        encoding="utf-8",
    )
    return _ArtifactPaths(
        result=result_path,
        result_key=key_path,
        verifier_authority=authority_path,
        verifier_authority_key=authority_key_path,
    )


def _common_arguments(
    fixture: VerificationFixture,
    paths: _ArtifactPaths,
) -> list[str]:
    expected = fixture.expectations
    return [
        "--result",
        str(paths.result),
        "--trusted-key",
        str(paths.result_key),
        "--run-id",
        expected.run_id,
        "--run-manifest-digest",
        expected.run_manifest_digest,
        "--authority-digest",
        expected.source_authority_digest,
        "--engagement-id",
        expected.engagement_id,
        "--source-actor",
        expected.source_actor_id,
        "--verifier-actor",
        expected.verifier_actor_id,
        "--verifier-authority-digest",
        expected.verifier_authority_digest,
        "--verifier-authority",
        str(paths.verifier_authority),
        "--verifier-authority-key",
        str(paths.verifier_authority_key),
        "--minimum-result-version",
        str(expected.minimum_bundle_version),
    ]


def test_verify_and_report_cli_are_offline_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = build_verification_fixture()
    paths = _write_artifact_inputs(tmp_path, fixture)
    monkeypatch.setattr(cli, "_utc_now", lambda: fixture.expectations.verification_time)
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("verification CLI opened a network socket")
        ),
    )

    verify_args = [
        "verify",
        fixture.candidate.candidate_id,
        *_common_arguments(
            fixture,
            paths,
        ),
    ]
    assert cli.main(verify_args) == cli.EXIT_OK
    verification = json.loads(capsys.readouterr().out)
    assert verification["outcome"] == "verified"
    assert verification["network_access"] == "none"

    report_args = [
        "report",
        fixture.candidate.candidate_id,
        "--format",
        "json",
        *_common_arguments(
            fixture,
            paths,
        ),
    ]
    assert cli.main(report_args) == cli.EXIT_OK
    report_output = capsys.readouterr().out
    expected_report = render_finding_report(
        verify_result_artifact(
            fixture.signed_result,
            fixture.result_signer.public_key_record,
            fixture.expectations,
        ),
        fixture.candidate.candidate_id,
        ReportFormat.JSON,
    )
    assert report_output == expected_report.content + "\n"
    report = json.loads(report_output)
    assert report["candidate_id"] == fixture.candidate.candidate_id
    assert report["verdict"] == "verified"


def test_report_cli_writes_verified_report_and_canonical_manual_review_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = build_verification_fixture()
    paths = _write_artifact_inputs(tmp_path, fixture)
    monkeypatch.setattr(cli, "_utc_now", lambda: fixture.expectations.verification_time)
    monkeypatch.setattr(
        socket,
        "socket",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("report outbox opened a network socket")
        ),
    )
    out_dir = tmp_path / "outbox"
    arguments = [
        "report",
        fixture.candidate.candidate_id,
        "--format",
        "json",
        "--out-dir",
        str(out_dir),
        *_common_arguments(fixture, paths),
    ]

    assert cli.main(arguments) == cli.EXIT_OK
    report = render_finding_report(
        verify_result_artifact(
            fixture.signed_result,
            fixture.result_signer.public_key_record,
            fixture.expectations,
        ),
        fixture.candidate.candidate_id,
        ReportFormat.JSON,
    )
    entry_dir = out_dir / fixture.candidate.candidate_id
    assert capsys.readouterr().out == report.content + "\n"
    assert (entry_dir / "report.json").read_text(
        encoding="utf-8"
    ) == report.content
    assert (entry_dir / "receipt.json").read_text(
        encoding="utf-8"
    ) == json.dumps(
        {
            "automatic_submission_performed": False,
            "candidate_id": fixture.candidate.candidate_id,
            "claim_id": fixture.claim.claim_id,
            "finding_id": fixture.candidate.candidate_id,
            "network_access": "none",
            "report_digest": report.receipt.report_digest,
            "report_format": "json",
            "result_artifact_digest": report.receipt.result_artifact_digest,
            "schema": "faultloom.report_outbox.receipt.v1",
            "status": "draft_manual_review",
            "verdict_id": fixture.verdict.verdict_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def test_report_cli_recovers_after_interruption_before_outbox_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = build_verification_fixture()
    paths = _write_artifact_inputs(tmp_path, fixture)
    monkeypatch.setattr(cli, "_utc_now", lambda: fixture.expectations.verification_time)
    out_dir = tmp_path / "outbox"
    arguments = [
        "report",
        fixture.candidate.candidate_id,
        "--format",
        "json",
        "--out-dir",
        str(out_dir),
        *_common_arguments(fixture, paths),
    ]
    original = verification_cli._create_file_once
    calls = 0

    def interrupt_second_file(path: Path, content: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        original(path, content)

    with monkeypatch.context() as interrupted:
        interrupted.setattr(
            verification_cli,
            "_create_file_once",
            interrupt_second_file,
        )
        with pytest.raises(KeyboardInterrupt):
            cli.main(arguments)

    assert not (out_dir / fixture.candidate.candidate_id).exists()
    assert not tuple(out_dir.glob(".*.tmp"))
    assert cli.main(arguments) == cli.EXIT_OK
    assert (out_dir / fixture.candidate.candidate_id / "receipt.json").is_file()
    capsys.readouterr()


def test_report_cli_refuses_to_overwrite_an_outbox_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = build_verification_fixture()
    paths = _write_artifact_inputs(tmp_path, fixture)
    monkeypatch.setattr(cli, "_utc_now", lambda: fixture.expectations.verification_time)
    out_dir = tmp_path / "outbox"
    arguments = [
        "report",
        fixture.candidate.candidate_id,
        "--format",
        "md",
        "--out-dir",
        str(out_dir),
        *_common_arguments(fixture, paths),
    ]

    assert cli.main(arguments) == cli.EXIT_OK
    capsys.readouterr()
    entry_dir = out_dir / fixture.candidate.candidate_id
    written_report = (entry_dir / "report.md").read_text(
        encoding="utf-8"
    )
    written_receipt = (entry_dir / "receipt.json").read_text(
        encoding="utf-8"
    )

    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "report outbox entry already exists" in captured.err
    assert (entry_dir / "report.md").read_text(
        encoding="utf-8"
    ) == written_report
    assert (entry_dir / "receipt.json").read_text(
        encoding="utf-8"
    ) == written_receipt


@pytest.mark.parametrize(
    "options",
    [
        ReplayFixtureOptions(positive_passed=False),
        ReplayFixtureOptions(include_negative_control=False),
    ],
)
def test_report_cli_does_not_create_outbox_for_unreportable_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    options: ReplayFixtureOptions,
) -> None:
    fixture = build_verification_fixture(options)
    paths = _write_artifact_inputs(tmp_path, fixture)
    monkeypatch.setattr(cli, "_utc_now", lambda: fixture.expectations.verification_time)
    out_dir = tmp_path / "outbox"
    arguments = [
        "report",
        fixture.candidate.candidate_id,
        "--format",
        "md",
        "--out-dir",
        str(out_dir),
        *_common_arguments(fixture, paths),
    ]

    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "independently verified" in captured.err
    assert not out_dir.exists()


def test_report_cli_refuses_a_signed_rejected_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fixture = build_verification_fixture(ReplayFixtureOptions(positive_passed=False))
    paths = _write_artifact_inputs(tmp_path, fixture)
    monkeypatch.setattr(cli, "_utc_now", lambda: fixture.expectations.verification_time)
    arguments = [
        "report",
        fixture.candidate.candidate_id,
        "--format",
        "md",
        *_common_arguments(
            fixture,
            paths,
        ),
    ]

    assert cli.main(arguments) == cli.EXIT_AUTHORITY
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "independently verified" in captured.err
