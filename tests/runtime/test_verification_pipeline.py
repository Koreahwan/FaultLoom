from __future__ import annotations

from dataclasses import fields, replace

import pytest

from faultloom.verification import (
    ArtifactVerificationError,
    ClaimAssemblyError,
    ClaimDraft,
    ReportFormat,
    ReportGateError,
    VerifierAuthorizationError,
    assemble_claim_packet,
    authorize_verifier,
    render_finding_report,
    verify_result_artifact,
)
from faultloom_protocol import VerdictOutcome
from tests.runtime.verification_support import (
    ReplayFixtureOptions,
    build_verification_fixture,
)


def test_independent_replay_produces_a_signed_verified_result() -> None:
    fixture = build_verification_fixture()

    verified = verify_result_artifact(
        fixture.signed_result,
        fixture.result_signer.public_key_record,
        fixture.expectations,
    )

    assert fixture.verdict.outcome is VerdictOutcome.VERIFIED
    assert fixture.verdict.independent_replay is True
    assert len(fixture.executor.requests) == 1
    request_fields = {field.name for field in fields(fixture.executor.requests[0])}
    assert request_fields == {
        "claim_packet_digest",
        "replay_plan",
        "verifier_actor_id",
        "verifier_authority_digest",
        "verifier_run_id",
    }
    assert verified.payload.verification_verdicts == (fixture.verdict,)


def test_same_actor_cannot_be_authorized_as_independent_verifier() -> None:
    fixture = build_verification_fixture()
    invalid_request = replace(
        fixture.authorization_request,
        verifier_actor_id=fixture.authorization_request.source_actor_id,
    )

    with pytest.raises(VerifierAuthorizationError):
        authorize_verifier(invalid_request)


def test_missing_negative_control_is_inconclusive_and_not_reportable() -> None:
    fixture = build_verification_fixture(
        ReplayFixtureOptions(include_negative_control=False)
    )
    verified = verify_result_artifact(
        fixture.signed_result,
        fixture.result_signer.public_key_record,
        fixture.expectations,
    )

    assert fixture.verdict.outcome is VerdictOutcome.INCONCLUSIVE
    with pytest.raises(ReportGateError):
        render_finding_report(verified, fixture.candidate.candidate_id, ReportFormat.JSON)


def test_failed_positive_control_is_rejected_and_not_reportable() -> None:
    fixture = build_verification_fixture(ReplayFixtureOptions(positive_passed=False))
    verified = verify_result_artifact(
        fixture.signed_result,
        fixture.result_signer.public_key_record,
        fixture.expectations,
    )

    assert fixture.verdict.outcome is VerdictOutcome.REJECTED
    with pytest.raises(ReportGateError):
        render_finding_report(verified, fixture.candidate.candidate_id, ReportFormat.MARKDOWN)


def test_claim_packet_requires_a_bound_negative_control() -> None:
    fixture = build_verification_fixture()
    original = fixture.candidate.evidence_refs[0]
    invalid_draft = ClaimDraft(
        claim_id="claim.missing-negative",
        claim="A claim without a control must not pass.",
        prerequisites=("Owned canary",),
        evidence_refs=(original,),
        negative_control_refs=(),
        replay_plan=fixture.replay_plan,
        cleanup_plan_ref=None,
        created_at=fixture.candidate.created_at,
    )

    with pytest.raises(ClaimAssemblyError):
        assemble_claim_packet(fixture.candidate, invalid_draft)


def test_reports_are_deterministic_and_scrub_secret_shaped_text() -> None:
    fixture = build_verification_fixture(
        ReplayFixtureOptions(include_secret_text=True)
    )
    verified = verify_result_artifact(
        fixture.signed_result,
        fixture.result_signer.public_key_record,
        fixture.expectations,
    )

    markdown = render_finding_report(
        verified,
        fixture.candidate.candidate_id,
        ReportFormat.MARKDOWN,
    )
    repeated = render_finding_report(
        verified,
        fixture.candidate.candidate_id,
        ReportFormat.MARKDOWN,
    )
    json_report = render_finding_report(
        verified,
        fixture.candidate.candidate_id,
        ReportFormat.JSON,
    )

    assert markdown == repeated
    assert "should-not-render" not in markdown.content
    assert "raw-token" not in markdown.content
    assert "secret-ref" in markdown.content
    assert "automatic zero-day claim" in markdown.content
    assert json_report.receipt.result_artifact_digest == markdown.receipt.result_artifact_digest
    assert json_report.receipt.report_digest != markdown.receipt.report_digest


def test_result_expectations_bind_the_verifier_authority() -> None:
    fixture = build_verification_fixture()
    mismatched = replace(
        fixture.expectations,
        verifier_authority_digest="sha256:" + "00" * 32,
    )

    with pytest.raises(ArtifactVerificationError):
        verify_result_artifact(
            fixture.signed_result,
            fixture.result_signer.public_key_record,
            mismatched,
        )
