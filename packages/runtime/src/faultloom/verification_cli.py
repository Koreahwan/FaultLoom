from __future__ import annotations

import argparse
import json
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
)

from .verification import (
    ArtifactVerificationError,
    ReportFormat,
    ReportGateError,
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
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-manifest-digest", required=True)
    parser.add_argument("--authority-digest", required=True)
    parser.add_argument("--engagement-id", required=True)
    parser.add_argument("--source-actor", required=True)
    parser.add_argument("--verifier-actor", required=True)
    parser.add_argument("--verifier-authority-digest", required=True)
    parser.add_argument("--verifier-authority", type=Path, required=True)
    parser.add_argument("--verifier-authority-key", type=Path, required=True)
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
    _add_result_arguments(report_parser)
    report_parser.set_defaults(handler=partial(_report, dependencies=dependencies))


def _load_verified_result(
    arguments: argparse.Namespace,
    dependencies: VerificationCliDependencies,
) -> VerifiedResultArtifact:
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
    print(report.content)
    return 0
