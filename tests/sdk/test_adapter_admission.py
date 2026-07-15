from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom_protocol import AdapterManifest, EvidenceCapability, sha256_digest
from faultloom_sdk import (
    AdapterAdmissionError,
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    AdapterAdmissionState,
    AdapterNotFoundError,
    AdmissionGate,
    AdmissionOutcome,
    ManifestRegistry,
    reference_adapter_manifest,
)


def _receipt(
    gate: AdmissionGate,
    *,
    outcome: AdmissionOutcome = AdmissionOutcome.PASSED,
    prove_with_recall: bool = False,
) -> AdapterAdmissionReceipt:
    manifest = reference_adapter_manifest()
    recall_gain_bps = 1_000 if prove_with_recall else 0
    unique_verified_positives = (
        2 if gate is AdmissionGate.MODEL_UTILITY and not prove_with_recall else 0
    )
    return AdapterAdmissionReceipt(
        adapter_id=manifest.adapter_id,
        manifest_digest=sha256_digest(manifest),
        gate=gate,
        outcome=outcome,
        artifact_digest=manifest.output_schema_digest,
        recall_gain_bps=recall_gain_bps,
        unique_verified_positives=unique_verified_positives,
    )


def _registry_for_manifest(manifest: AdapterManifest) -> AdapterAdmissionRegistry:
    manifest_registry = ManifestRegistry(known_adapter_capabilities=manifest.capabilities)
    manifest_registry.install_adapter(manifest)
    return AdapterAdmissionRegistry(manifest_registry)


def _admit_reference() -> AdapterAdmissionRegistry:
    registry = _registry_for_manifest(reference_adapter_manifest())
    registry.record(_receipt(AdmissionGate.CONTRACT))
    registry.record(_receipt(AdmissionGate.FIDELITY))
    registry.record(_receipt(AdmissionGate.MODEL_UTILITY))
    return registry


def test_admission_snapshot_pins_manifest_and_enforces_gate_order() -> None:
    manifest = reference_adapter_manifest()
    registry = _registry_for_manifest(manifest)

    initial = registry.doctor(manifest.adapter_id)
    assert initial.manifest_digest == sha256_digest(manifest)
    assert initial.state is AdapterAdmissionState.PENDING_CONTRACT
    with pytest.raises(ValidationError, match="frozen"):
        initial.state = AdapterAdmissionState.REJECTED
    with pytest.raises(AdapterAdmissionError, match="expected contract"):
        registry.record(_receipt(AdmissionGate.FIDELITY))

    contract = registry.record(_receipt(AdmissionGate.CONTRACT))
    assert contract.state is AdapterAdmissionState.PENDING_FIDELITY
    assert registry.record(_receipt(AdmissionGate.CONTRACT)) == contract
    fidelity = registry.record(_receipt(AdmissionGate.FIDELITY))
    assert fidelity.state is AdapterAdmissionState.PENDING_MODEL_UTILITY
    admitted = registry.record(
        _receipt(AdmissionGate.MODEL_UTILITY, prove_with_recall=True)
    )
    assert admitted.state is AdapterAdmissionState.ADMITTED_CANDIDATE


def test_admission_rejects_failed_safety_or_unproven_utility() -> None:
    manifest = reference_adapter_manifest()
    source = _receipt(AdmissionGate.CONTRACT).model_dump(mode="python")
    source["dispatched_oos"] = 1
    with pytest.raises(ValidationError, match="safety counters"):
        AdapterAdmissionReceipt.model_validate(source)

    source = _receipt(AdmissionGate.CONTRACT).model_dump(mode="python")
    source["gate"] = AdmissionGate.MODEL_UTILITY
    with pytest.raises(ValidationError, match="utility threshold"):
        AdapterAdmissionReceipt.model_validate(source)

    registry = _registry_for_manifest(manifest)
    rejected = registry.record(
        _receipt(AdmissionGate.CONTRACT, outcome=AdmissionOutcome.FAILED)
    )
    assert rejected.state is AdapterAdmissionState.REJECTED
    with pytest.raises(AdapterAdmissionError, match="terminal"):
        registry.record(_receipt(AdmissionGate.FIDELITY))


def test_evidence_use_requires_capability_and_independent_non_tool_evidence() -> None:
    candidate_registry = _admit_reference()
    with pytest.raises(AdapterAdmissionError, match="candidate-only"):
        candidate_registry.require_evidence_source(
            "adapter.reference", independent_non_tool_evidence=True
        )

    evidence_manifest = reference_adapter_manifest().model_copy(
        update={"evidence_capability": EvidenceCapability.EVIDENCE_CAPABLE}
    )
    evidence_registry = _registry_for_manifest(evidence_manifest)
    digest = sha256_digest(evidence_manifest)
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY):
        evidence_registry.record(
            AdapterAdmissionReceipt(
                adapter_id=evidence_manifest.adapter_id,
                manifest_digest=digest,
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=evidence_manifest.output_schema_digest,
            )
        )
    evidence_registry.record(
        AdapterAdmissionReceipt(
            adapter_id=evidence_manifest.adapter_id,
            manifest_digest=digest,
            gate=AdmissionGate.MODEL_UTILITY,
            outcome=AdmissionOutcome.PASSED,
            artifact_digest=evidence_manifest.output_schema_digest,
            unique_verified_positives=2,
        )
    )

    with pytest.raises(AdapterAdmissionError, match="tool-only"):
        evidence_registry.require_evidence_source(
            evidence_manifest.adapter_id,
            independent_non_tool_evidence=False,
        )
    assert (
        evidence_registry.require_evidence_source(
            evidence_manifest.adapter_id,
            independent_non_tool_evidence=True,
        )
        == evidence_manifest
    )


def test_adapter_interfaces_fail_closed_for_absent_or_unpinned_processes() -> None:
    manifest = reference_adapter_manifest()
    registry = _registry_for_manifest(manifest)

    with pytest.raises(AdapterNotFoundError, match="not installed"):
        registry.doctor("adapter.absent")
    with pytest.raises(AdapterNotFoundError, match="not installed"):
        registry.prepare_test("adapter.absent")

    for field, value in (
        ("argv", ("--target", "example.test")),
        ("environment", {"TARGET": "example.test"}),
        ("auto_update", True),
        ("runtime_template_updates", True),
        ("network_mode", "direct_target_socket"),
    ):
        source = manifest.model_dump(mode="python")
        source[field] = value
        with pytest.raises(ValidationError):
            type(manifest).model_validate(source)
