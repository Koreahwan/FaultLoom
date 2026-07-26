from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom_protocol import sha256_digest
from faultloom_sdk import (
    AdapterAdmissionError,
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    AdapterAdmissionState,
    AdmissionGate,
    AdmissionOutcome,
    ModelUtilityEvaluationState,
    ModelUtilityEvidenceSource,
    model_utility_digest,
    reference_adapter_manifest,
    reference_registry,
)

from .model_utility_support import valid_utility_evaluation


def test_model_utility_rejects_caller_declared_metrics_without_evaluation() -> None:
    # Given: contract and fidelity passed for the pinned reference adapter.
    registry = AdapterAdmissionRegistry(reference_registry())
    manifest = reference_adapter_manifest()
    manifest_digest = sha256_digest(manifest)
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY):
        _ = registry.record(
            AdapterAdmissionReceipt(
                adapter_id=manifest.adapter_id,
                manifest_digest=manifest_digest,
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=manifest.output_schema_digest,
            )
        )
    fabricated = {
        "adapter_id": manifest.adapter_id,
        "manifest_digest": manifest_digest,
        "gate": AdmissionGate.MODEL_UTILITY,
        "outcome": AdmissionOutcome.PASSED,
        "artifact_digest": manifest.output_schema_digest,
        "unique_verified_positives": 2,
    }

    # When / Then: a metric-only utility claim cannot cross admission.
    with pytest.raises(ValidationError, match="Extra inputs"):
        _ = AdapterAdmissionReceipt.model_validate(fabricated)


def test_protocol_stub_digest_stays_pending_and_cannot_be_recorded_directly() -> None:
    # Given: a valid evaluator result produced only by deterministic plumbing.
    registry = AdapterAdmissionRegistry(reference_registry())
    manifest = reference_adapter_manifest()
    manifest_digest = sha256_digest(manifest)
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY):
        _ = registry.record(
            AdapterAdmissionReceipt(
                adapter_id=manifest.adapter_id,
                manifest_digest=manifest_digest,
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=manifest.output_schema_digest,
            )
        )
    evaluation = valid_utility_evaluation()

    # When / Then: deterministic fixture evidence cannot stand in for trusted attestation.
    with pytest.raises(
        AdapterAdmissionError,
        match="trusted model utility attestation is unavailable",
    ):
        _ = registry.record_model_utility(evaluation)
    digest = model_utility_digest(evaluation)
    direct = AdapterAdmissionReceipt(
        adapter_id=manifest.adapter_id,
        manifest_digest=manifest_digest,
        gate=AdmissionGate.MODEL_UTILITY,
        outcome=AdmissionOutcome.PASSED,
        artifact_digest=digest,
        evaluation_digest=digest,
    )
    with pytest.raises(AdapterAdmissionError, match="canonical evaluation"):
        _ = registry.record(direct)


def test_model_copy_cannot_promote_protocol_stub_into_admission() -> None:
    # Given: deterministic evidence whose frozen state was bypassed by model_copy.
    registry = AdapterAdmissionRegistry(reference_registry())
    manifest = reference_adapter_manifest()
    manifest_digest = sha256_digest(manifest)
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY):
        _ = registry.record(
            AdapterAdmissionReceipt(
                adapter_id=manifest.adapter_id,
                manifest_digest=manifest_digest,
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=manifest.output_schema_digest,
            )
        )
    forged = valid_utility_evaluation().model_copy(
        update={"state": ModelUtilityEvaluationState.FULLY_DONE}
    )

    # When / Then: admission revalidates and remains pending.
    with pytest.raises(AdapterAdmissionError, match="canonical|trusted") as admission_error:
        _ = registry.record_model_utility(forged)
    assert admission_error.value.__cause__ is None
    assert admission_error.value.__context__ is None
    assert registry.doctor(manifest.adapter_id).state is (
        AdapterAdmissionState.PENDING_MODEL_UTILITY
    )


def test_public_real_model_evaluation_cannot_self_attest_admission() -> None:
    # Given: a fully consistent REAL_MODEL document authored through public models.
    registry = AdapterAdmissionRegistry(reference_registry())
    manifest = reference_adapter_manifest()
    manifest_digest = sha256_digest(manifest)
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY):
        _ = registry.record(
            AdapterAdmissionReceipt(
                adapter_id=manifest.adapter_id,
                manifest_digest=manifest_digest,
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=manifest.output_schema_digest,
            )
        )
    authored = valid_utility_evaluation(ModelUtilityEvidenceSource.REAL_MODEL)

    # When / Then: no caller-authored document can substitute for trusted provenance.
    with pytest.raises(AdapterAdmissionError, match="trusted.*unavailable"):
        _ = registry.record_model_utility(authored)
    assert registry.doctor(manifest.adapter_id).state is (
        AdapterAdmissionState.PENDING_MODEL_UTILITY
    )
