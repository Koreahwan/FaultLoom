from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from faultloom.automation.admission import (
    AutomationAdmission,
    AutomationAdmissionError,
    sign_automation_admission,
)
from faultloom.automation.execution_bridge import (
    AutomationDispatchError,
    execute_admitted_tool_plan,
    persist_automation_dispatch,
)
from faultloom.automation.models import AuthorizedAutomationResult
from faultloom.execution import GatewayDispatchCommand, SemanticHttpExecutor
from faultloom.state import StorageError
from faultloom.tool_planner import (
    PlanningBudget,
    ToolCandidate,
    ToolEvidenceRole,
    ToolEstimate,
    ToolPlan,
    ToolPlanItem,
    ToolPlanReceipt,
)
from faultloom.verification import (
    ArtifactVerificationError,
    AutomationDispatchProvenance,
    ReportFormat,
    ReportGateError,
    ResultArtifactContext,
    ResultArtifactDraft,
    VerificationInputError,
    automation_dispatch_provenance_digest,
    automation_dispatch_provenance_marker,
    load_automation_dispatch_provenance,
    render_finding_report,
    sign_verification_result,
    verify_result_artifact,
)
from faultloom_protocol import AuthoritySigner, sha256_digest, sign_run_result_bundle
from tests.protocol.factories import sample_models
from tests.runtime.execution_helpers import (
    CHANNEL_KEY,
    NOW,
    RecordingGateway,
    command,
    completed_result,
    semantic_request,
)
from tests.runtime.resume_support import open_store
from tests.runtime.verification_support import VerificationFixture, build_verification_fixture


ADMISSION_SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("63" * 32))


def _automation_result(command_value: GatewayDispatchCommand) -> AuthorizedAutomationResult:
    hypothesis = sample_models()["HypothesisRecord"]
    candidate = ToolCandidate(
        candidate_id="candidate.gateway",
        hypothesis_id=hypothesis.hypothesis_id,
        intent=command_value.intent,
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        expected_information_gain_bps=7_000,
        estimate=ToolEstimate(
            rate_slots=1,
            duration_seconds=2,
            bytes=200,
            concurrency=1,
            actions=1,
            cost_microunits=1,
        ),
    )
    receipt = ToolPlanReceipt(
        candidate_id=candidate.candidate_id,
        candidate_digest=sha256_digest(candidate.model_dump(mode="json")),
        hypothesis_id=hypothesis.hypothesis_id,
        hypothesis_digest=sha256_digest(hypothesis.model_dump(mode="json")),
        authority_digest="sha256:" + "1" * 64,
        adapter_id=candidate.adapter_id,
        manifest_digest="sha256:" + "2" * 64,
        admission_snapshot_digest="sha256:" + "3" * 64,
        utility_receipt_digest="sha256:" + "4" * 64,
        budget_digest="sha256:" + "5" * 64,
    )
    plan = ToolPlan(
        hypothesis_id=hypothesis.hypothesis_id,
        selected=ToolPlanItem(
            candidate=candidate,
            evidence_role=ToolEvidenceRole.CANDIDATE,
            receipt=receipt,
        ),
        remaining=PlanningBudget(
            rate_slots=2,
            duration_seconds=18,
            bytes=1_800,
            concurrency=1,
            actions=2,
            cost_microunits=99,
        ),
    )
    return AuthorizedAutomationResult(
        run_id=command_value.intent.run_id,
        authority_grant_digest="sha256:" + "1" * 64,
        authority_grant_id=command_value.decision.grant_id,
        authority_grant_version=command_value.decision.grant_version,
        observation_bundle_digest="sha256:" + "6" * 64,
        action_context_digest="sha256:" + "7" * 64,
        hypotheses=(hypothesis,),
        negative_results=(),
        admitted_plans=(plan,),
        stop_reason="Await independent verification.",
        provider_network_access="none",
    )


def _completed_record(
    command_value: GatewayDispatchCommand | None = None,
    *,
    admission_issued_at=NOW,
    admission_expires_at=None,
    admission_verification_time=NOW,
):
    approved = command_value or command()
    result = _automation_result(approved)
    expires_at = admission_expires_at or admission_issued_at + timedelta(seconds=30)
    admission = sign_automation_admission(
        AutomationAdmission(
            admission_id="automation-admission.verification",
            result=result,
            result_digest=sha256_digest(result.model_dump(mode="json")),
            issued_at=admission_issued_at,
            expires_at=expires_at,
            issuer_key_id=ADMISSION_SIGNER.key_id,
        ),
        ADMISSION_SIGNER,
    )
    executor = SemanticHttpExecutor._for_test(
        RecordingGateway(completed_result),
        channel_key=CHANNEL_KEY,
        now=lambda: NOW,
    )
    return approved, execute_admitted_tool_plan(
        admission=admission,
        trusted_admission_keys={ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record},
        trusted_clock=lambda: admission_verification_time,
        candidate_id="candidate.gateway",
        command=approved,
        executor=executor,
    )


def _record_with_dispatched_at(record, dispatched_at):
    gateway_result = record.gateway_result
    if gateway_result is None:
        raise AssertionError("fixture must have a completed Gateway result")
    receipt = gateway_result.receipt
    completed_at = receipt.completed_at
    if completed_at is not None and completed_at < dispatched_at:
        completed_at = dispatched_at
    result = gateway_result.model_copy(
        update={
            "receipt": receipt.model_copy(
                update={"dispatched_at": dispatched_at, "completed_at": completed_at}
            )
        }
    )
    return record.model_copy(update={"gateway_result": result})


def _provenance(tmp_path: Path) -> AutomationDispatchProvenance:
    approved, record = _completed_record()
    with open_store(tmp_path) as store:
        persist_automation_dispatch(store, record)
        return load_automation_dispatch_provenance(
            store,
            dispatch_id=record.dispatch_id,
            command=approved,
            trusted_admission_keys={
                ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
            },
        )


def _fixture(tmp_path: Path) -> tuple[VerificationFixture, AutomationDispatchProvenance]:
    provenance = _provenance(tmp_path)
    fixture = build_verification_fixture(
        candidate_id="candidate.gateway",
        automation_dispatch_provenance=provenance,
    )
    return fixture, provenance


def _draft(
    fixture: VerificationFixture,
    provenance: AutomationDispatchProvenance,
    *,
    verdict=None,
) -> ResultArtifactDraft:
    bundle = fixture.signed_result.payload
    return ResultArtifactDraft(
        context=ResultArtifactContext(
            bundle_id="result-bundle.provenance-test",
            bundle_version=bundle.bundle_version,
            engagement_id=fixture.expectations.engagement_id,
            run_manifest_digest=fixture.expectations.run_manifest_digest,
            source_authority_digest=fixture.expectations.source_authority_digest,
            final_checkpoint_digest=bundle.final_checkpoint_digest,
            generated_at=bundle.generated_at,
            expires_at=None,
        ),
        candidate=fixture.candidate,
        claim=fixture.claim,
        verdict=fixture.verdict if verdict is None else verdict,
        cleanup_receipt_digests=(),
        automation_dispatch_provenance=provenance,
    )


def test_authenticated_ledger_dispatch_is_bound_through_verification_artifact_and_report(
    tmp_path: Path,
) -> None:
    fixture, provenance = _fixture(tmp_path)

    verified = verify_result_artifact(
        fixture.signed_result,
        fixture.result_signer.public_key_record,
        fixture.expectations,
    )
    report = render_finding_report(
        verified,
        fixture.candidate.candidate_id,
        ReportFormat.JSON,
    )

    marker = automation_dispatch_provenance_marker(provenance)
    assert marker in fixture.verdict.reasons
    assert provenance.dispatch.evidence_ref in fixture.verdict.evidence_refs
    assert provenance.dispatch.evidence_ref in verified.payload.evidence_refs
    assert verified.automation_dispatch_provenance == provenance
    document = json.loads(report.content)
    assert document["automation_dispatch_evidence_id"] == provenance.dispatch.evidence_ref.evidence_id
    assert document["automation_dispatch_provenance_digest"] == (
        automation_dispatch_provenance_digest(provenance)
    )
    assert document["candidate_id"] == fixture.candidate.candidate_id


def test_loader_rejects_forged_admission_wrong_command_and_missing_ledger_event(
    tmp_path: Path,
) -> None:
    approved, record = _completed_record()
    forged_signature = "A" + record.admission.signature[1:]
    forged_record = record.model_copy(
        update={"admission": record.admission.model_copy(update={"signature": forged_signature})}
    )
    with open_store(tmp_path) as store:
        persist_automation_dispatch(store, forged_record)
        with pytest.raises(AutomationAdmissionError, match="Ed25519"):
            load_automation_dispatch_provenance(
                store,
                dispatch_id=forged_record.dispatch_id,
                command=approved,
                trusted_admission_keys={
                    ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
                },
            )

    with open_store(tmp_path / "missing") as store:
        with pytest.raises(StorageError, match="exactly one ledger event"):
            load_automation_dispatch_provenance(
                store,
                dispatch_id=record.dispatch_id,
                command=approved,
                trusted_admission_keys={
                    ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
                },
            )

    with open_store(tmp_path / "command") as store:
        persist_automation_dispatch(store, record)
        with pytest.raises(AutomationDispatchError, match="command digest"):
            load_automation_dispatch_provenance(
                store,
                dispatch_id=record.dispatch_id,
                command=command(request=semantic_request(path="/changed")),
                trusted_admission_keys={
                    ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
                },
            )


def test_loader_uses_authenticated_dispatch_time_not_later_review_time(tmp_path: Path) -> None:
    approved, record = _completed_record(admission_expires_at=NOW + timedelta(seconds=1))
    with open_store(tmp_path) as store:
        persist_automation_dispatch(store, record)
        provenance = load_automation_dispatch_provenance(
            store,
            dispatch_id=record.dispatch_id,
            command=approved,
            trusted_admission_keys={
                ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
            },
        )
    assert provenance.dispatch.envelope.record.gateway_result.receipt.dispatched_at == NOW


def test_loader_rejects_receipt_times_outside_the_admission_window(tmp_path: Path) -> None:
    issued_at = NOW + timedelta(seconds=1)
    approved, before_issuance = _completed_record(
        admission_issued_at=issued_at,
        admission_expires_at=NOW + timedelta(seconds=30),
        admission_verification_time=issued_at,
    )
    with open_store(tmp_path / "before-issuance") as store:
        persist_automation_dispatch(store, before_issuance)
        with pytest.raises(AutomationAdmissionError, match="outside its validity window"):
            load_automation_dispatch_provenance(
                store,
                dispatch_id=before_issuance.dispatch_id,
                command=approved,
                trusted_admission_keys={
                    ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
                },
            )

    expires_at = NOW + timedelta(seconds=10)
    approved, record = _completed_record(admission_expires_at=expires_at)
    at_expiry = _record_with_dispatched_at(record, expires_at)
    with open_store(tmp_path / "at-expiry") as store:
        persist_automation_dispatch(store, at_expiry)
        with pytest.raises(AutomationAdmissionError, match="outside its validity window"):
            load_automation_dispatch_provenance(
                store,
                dispatch_id=at_expiry.dispatch_id,
                command=approved,
                trusted_admission_keys={
                    ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
                },
            )


def test_constructed_persistence_and_proof_reuse_are_rejected(tmp_path: Path) -> None:
    fixture, provenance = _fixture(tmp_path)
    with pytest.raises(TypeError, match="loaded from the ledger"):
        AutomationDispatchProvenance(
            _factory=None,
            dispatch=provenance.dispatch,
            command=provenance.command,
        )

    verified = verify_result_artifact(
        fixture.signed_result,
        fixture.result_signer.public_key_record,
        fixture.expectations,
    )
    object.__setattr__(provenance, "command", command(request=semantic_request(path="/changed")))

    with pytest.raises(ArtifactVerificationError, match="proof is invalid"):
        sign_verification_result(_draft(fixture, provenance), fixture.result_signer)
    with pytest.raises(ArtifactVerificationError, match="proof is invalid"):
        verify_result_artifact(
            fixture.signed_result,
            fixture.result_signer.public_key_record,
            fixture.expectations,
        )
    with pytest.raises(ReportGateError, match="proof is invalid"):
        render_finding_report(verified, fixture.candidate.candidate_id, ReportFormat.MARKDOWN)


def test_candidate_binding_rejects_candidate_a_provenance_for_candidate_b_at_all_gates(
    tmp_path: Path,
) -> None:
    provenance = _provenance(tmp_path)
    with pytest.raises(VerificationInputError, match="different candidate"):
        build_verification_fixture(
            candidate_id="candidate.other",
            automation_dispatch_provenance=provenance,
        )

    fixture = build_verification_fixture(candidate_id="candidate.other")
    with pytest.raises(ArtifactVerificationError, match="different candidate"):
        sign_verification_result(_draft(fixture, provenance), fixture.result_signer)

    marker = automation_dispatch_provenance_marker(provenance)
    verdict = fixture.verdict.model_copy(
        update={
            "reasons": (*fixture.verdict.reasons, marker),
            "evidence_refs": (*fixture.verdict.evidence_refs, provenance.dispatch.evidence_ref),
        }
    )
    payload = fixture.signed_result.payload.model_copy(
        update={
            "verification_verdicts": (verdict,),
            "evidence_refs": (*fixture.signed_result.payload.evidence_refs, provenance.dispatch.evidence_ref),
        }
    )
    forged_envelope = sign_run_result_bundle(
        payload,
        fixture.result_signer,
        signed_at=payload.generated_at,
    )
    with pytest.raises(ArtifactVerificationError, match="does not match expectations"):
        verify_result_artifact(
            forged_envelope,
            fixture.result_signer.public_key_record,
            replace(fixture.expectations, automation_dispatch_provenance=provenance),
        )

    verified = verify_result_artifact(
        fixture.signed_result,
        fixture.result_signer.public_key_record,
        fixture.expectations,
    )
    forged_verified = replace(
        verified,
        automation_dispatch_provenance=provenance,
        _proof=replace(verified._proof, automation_dispatch_provenance=provenance),
    )
    with pytest.raises(ReportGateError, match="does not bind"):
        render_finding_report(
            forged_verified,
            fixture.candidate.candidate_id,
            ReportFormat.MARKDOWN,
        )


def test_duplicate_provenance_markers_are_rejected_without_set_collapse(tmp_path: Path) -> None:
    fixture, provenance = _fixture(tmp_path)
    marker = automation_dispatch_provenance_marker(provenance)
    duplicate_verdict = fixture.verdict.model_copy(
        update={"reasons": (*fixture.verdict.reasons, marker)}
    )
    with pytest.raises(ArtifactVerificationError, match="does not bind"):
        sign_verification_result(
            _draft(fixture, provenance, verdict=duplicate_verdict),
            fixture.result_signer,
        )

    payload = fixture.signed_result.payload.model_copy(
        update={"verification_verdicts": (duplicate_verdict,)}
    )
    duplicate_envelope = sign_run_result_bundle(
        payload,
        fixture.result_signer,
        signed_at=payload.generated_at,
    )
    with pytest.raises(ArtifactVerificationError, match="does not match expectations"):
        verify_result_artifact(
            duplicate_envelope,
            fixture.result_signer.public_key_record,
            fixture.expectations,
        )
