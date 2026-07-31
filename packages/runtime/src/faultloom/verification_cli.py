from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Callable, Protocol, TypeVar

from faultloom_protocol import (
    Ed25519PublicKeyRecord,
    ProtocolModel,
    SignedAuthorityGrant,
    SignedRunResultBundle,
    canonical_json,
)

from .verification import (
    ArtifactVerificationError,
    ReportFormat,
    ReportGateError,
    ReportReceipt,
    ResultExpectations,
    VerifiedResultArtifact,
    render_finding_report,
    verification_summary,
    verify_result_artifact,
)


ModelT = TypeVar("ModelT", bound=ProtocolModel)


class ProtocolPairCapture(Protocol):
    def __call__(self, first_path: Path, second_path: Path) -> tuple[bytes, bytes]: ...


class ProtocolFileParser(Protocol):
    def __call__(
        self,
        path: Path,
        content: bytes,
        model_type: type[ModelT],
    ) -> ModelT: ...


@dataclass(frozen=True, slots=True)
class VerificationCliDependencies:
    capture_protocol_pair: ProtocolPairCapture
    parse_protocol_file: ProtocolFileParser
    now: Callable[[], datetime]


@dataclass(frozen=True, slots=True)
class VerificationCliError(RuntimeError):
    reason: str

    def __str__(self) -> str:
        return self.reason


def _add_result_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--result", type=Path)
    parser.add_argument("--trusted-key", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--run-manifest-digest")
    parser.add_argument("--authority-digest")
    parser.add_argument("--engagement-id")
    parser.add_argument("--source-actor")
    parser.add_argument("--verifier-actor")
    parser.add_argument("--verifier-authority-digest")
    parser.add_argument("--verifier-authority", type=Path)
    parser.add_argument("--verifier-authority-key", type=Path)
    parser.add_argument("--minimum-result-version", type=int, default=1)


def configure_verification_parsers(
    verify_parser: argparse.ArgumentParser,
    report_parser: argparse.ArgumentParser,
    dependencies: VerificationCliDependencies,
) -> None:
    verify_parser.add_argument("candidate_id")
    _add_result_arguments(verify_parser)
    verify_parser.set_defaults(handler=partial(_verify, dependencies=dependencies))
    report_parser.add_argument("finding_id")
    report_parser.add_argument("--format", choices=("md", "json"), required=True)
    report_parser.add_argument("--out-dir", type=Path)
    _add_result_arguments(report_parser)
    report_parser.set_defaults(handler=partial(_report, dependencies=dependencies))


def _load_verified_result(
    arguments: argparse.Namespace,
    dependencies: VerificationCliDependencies,
) -> VerifiedResultArtifact:
    missing = tuple(
        option
        for option, attribute in (
            ("--result", "result"),
            ("--trusted-key", "trusted_key"),
            ("--run-id", "run_id"),
            ("--run-manifest-digest", "run_manifest_digest"),
            ("--authority-digest", "authority_digest"),
            ("--engagement-id", "engagement_id"),
            ("--source-actor", "source_actor"),
            ("--verifier-actor", "verifier_actor"),
            ("--verifier-authority-digest", "verifier_authority_digest"),
            ("--verifier-authority", "verifier_authority"),
            ("--verifier-authority-key", "verifier_authority_key"),
        )
        if getattr(arguments, attribute) is None
    )
    if missing:
        raise VerificationCliError(
            reason="verification data is unavailable; missing configuration: "
            + ", ".join(missing)
        )
    result_content, key_content = dependencies.capture_protocol_pair(
        arguments.result,
        arguments.trusted_key,
    )
    envelope = dependencies.parse_protocol_file(
        arguments.result,
        result_content,
        SignedRunResultBundle,
    )
    trusted_key = dependencies.parse_protocol_file(
        arguments.trusted_key,
        key_content,
        Ed25519PublicKeyRecord,
    )
    authority_content, authority_key_content = dependencies.capture_protocol_pair(
        arguments.verifier_authority,
        arguments.verifier_authority_key,
    )
    signed_verifier_authority = dependencies.parse_protocol_file(
        arguments.verifier_authority,
        authority_content,
        SignedAuthorityGrant,
    )
    trusted_verifier_authority_key = dependencies.parse_protocol_file(
        arguments.verifier_authority_key,
        authority_key_content,
        Ed25519PublicKeyRecord,
    )
    expectations = ResultExpectations(
        engagement_id=arguments.engagement_id,
        run_id=arguments.run_id,
        run_manifest_digest=arguments.run_manifest_digest,
        source_authority_digest=arguments.authority_digest,
        source_actor_id=arguments.source_actor,
        verifier_actor_id=arguments.verifier_actor,
        verifier_authority_digest=arguments.verifier_authority_digest,
        signed_verifier_authority=signed_verifier_authority,
        trusted_verifier_authority_key=trusted_verifier_authority_key,
        verification_time=dependencies.now(),
        minimum_bundle_version=arguments.minimum_result_version,
    )
    try:
        return verify_result_artifact(envelope, trusted_key, expectations)
    except ArtifactVerificationError as exc:
        raise VerificationCliError(reason=str(exc)) from exc


def _verify(
    arguments: argparse.Namespace,
    *,
    dependencies: VerificationCliDependencies,
) -> int:
    artifact = _load_verified_result(arguments, dependencies)
    try:
        summary = verification_summary(artifact, arguments.candidate_id)
    except ReportGateError as exc:
        raise VerificationCliError(reason=str(exc)) from exc
    print(
        json.dumps(
            {
                "candidate_id": summary.candidate_id,
                "claim_id": summary.claim_id,
                "dispatch_performed": False,
                "network_access": "none",
                "outcome": summary.outcome,
                "result_artifact_digest": summary.result_artifact_digest,
                "verdict_id": summary.verdict_id,
                "verifier_run_id": summary.verifier_run_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


def _outbox_paths(
    out_dir: Path,
    finding_id: str,
    report_format: ReportFormat,
) -> tuple[Path, Path, Path]:
    if Path(finding_id).name != finding_id or finding_id in {".", ".."}:
        raise VerificationCliError(reason="finding ID cannot be used as an outbox filename")
    entry_dir = out_dir / finding_id
    return (
        entry_dir,
        entry_dir / f"report.{report_format.value}",
        entry_dir / "receipt.json",
    )


def _create_file_once(path: Path, content: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            descriptor = -1
            _ = output.write(content)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_report_outbox(
    out_dir: Path,
    finding_id: str,
    report_content: str,
    report_receipt: ReportReceipt,
) -> None:
    receipt = report_receipt
    entry_dir, _, _ = _outbox_paths(out_dir, finding_id, receipt.report_format)
    receipt_content = canonical_json(
        {
            "automatic_submission_performed": False,
            "candidate_id": receipt.candidate_id,
            "claim_id": receipt.claim_id,
            "finding_id": finding_id,
            "network_access": "none",
            "report_digest": receipt.report_digest,
            "report_format": receipt.report_format.value,
            "result_artifact_digest": receipt.result_artifact_digest,
            "schema": "faultloom.report_outbox.receipt.v1",
            "status": "draft_manual_review",
            "verdict_id": receipt.verdict_id,
        }
    )
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        if not out_dir.is_dir():
            raise OSError("outbox path is not a directory")
        if os.path.lexists(entry_dir):
            raise FileExistsError("report outbox entry already exists")
    except OSError as exc:
        raise VerificationCliError(reason=f"unable to create report outbox: {exc}") from exc

    try:
        staging_dir = Path(
            tempfile.mkdtemp(prefix=f".{finding_id}.", suffix=".tmp", dir=out_dir)
        )
    except OSError as exc:
        raise VerificationCliError(
            reason=f"unable to create report outbox: {exc}"
        ) from exc
    # Files live only in the private staging directory. The final directory
    # rename is the single commit point that makes the complete pair visible.
    report_path = staging_dir / f"report.{receipt.report_format.value}"
    receipt_path = staging_dir / "receipt.json"
    committed = False
    try:
        _create_file_once(report_path, report_content)
        _create_file_once(receipt_path, receipt_content)
        _fsync_directory(staging_dir)
        if os.path.lexists(entry_dir):
            raise FileExistsError("report outbox entry already exists")
        os.rename(staging_dir, entry_dir)
        committed = True
        _fsync_directory(out_dir)
    except BaseException as exc:
        if not committed:
            shutil.rmtree(staging_dir, ignore_errors=True)
        if isinstance(exc, OSError):
            raise VerificationCliError(
                reason=f"unable to create report outbox: {exc}"
            ) from exc
        raise


def _report(
    arguments: argparse.Namespace,
    *,
    dependencies: VerificationCliDependencies,
) -> int:
    artifact = _load_verified_result(arguments, dependencies)
    try:
        report = render_finding_report(
            artifact,
            arguments.finding_id,
            ReportFormat(arguments.format),
        )
    except ReportGateError as exc:
        raise VerificationCliError(reason=str(exc)) from exc
    if arguments.out_dir is not None:
        _write_report_outbox(
            arguments.out_dir,
            arguments.finding_id,
            report.content,
            report.receipt,
        )
    print(report.content)
    return 0
