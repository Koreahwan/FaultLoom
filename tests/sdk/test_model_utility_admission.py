from __future__ import annotations

import pytest
from pydantic import ValidationError

from faultloom_protocol import sha256_digest
from faultloom_protocol import (
    AuthoritySigner,
    ModelProducerAttestation,
    ModelUtilityAdmission,
    ModelUtilityOutcomeCoverage,
    ModelVerifierAttestation,
    SCHEMA_VERSION,
    SignedModelProducerAttestation,
    SignedModelUtilityAdmission,
    SignedModelVerifierAttestation,
    attestation_signing_bytes,
    model_utility_admission_digest,
    model_utility_admission_signing_bytes,
    model_utility_outcome_coverage_digest,
)
from faultloom_sdk import (
    AdapterAdmissionError,
    AdapterAdmissionReceipt,
    AdapterAdmissionRegistry,
    AdapterAdmissionState,
    AdmissionGate,
    AdmissionOutcome,
    ModelUtilityEvaluationState,
    ModelUtilityEvidenceSource,
    ModelUtilityAdmissionError,
    model_utility_digest,
    reference_adapter_manifest,
    reference_registry,
    verify_model_utility_admission,
)

from .model_utility_support import valid_utility_evaluation


CHALLENGE = bytes(range(32)).hex()


def _fingerprint(signer: AuthoritySigner) -> str:
    return "sha256:" + signer.public_key_record.key_id.rsplit(":", 1)[1]


def _signed_producer(signer: AuthoritySigner) -> SignedModelProducerAttestation:
    payload = ModelProducerAttestation(
        schema_version=SCHEMA_VERSION,
        producer_key_id="producer.provisioned.1",
        producer_key_fingerprint=_fingerprint(signer),
        session_id="model-session.1",
        sequence=7,
        evaluator_challenge=CHALLENGE,
        canonical_request_digest="sha256:" + "01" * 32,
        parsed_response_digest="sha256:" + "02" * 32,
        raw_llama_stdout_digest="sha256:" + "03" * 32,
        output_digest="sha256:" + "04" * 32,
        model_digest="sha256:" + "05" * 32,
        runtime_wrapper_digest="sha256:" + "06" * 32,
        runtime_bundle_digest="sha256:" + "07" * 32,
        bwrap_digest="sha256:" + "08" * 32,
        fixed_argv_digest="sha256:" + "09" * 32,
        core_wheel_digest="sha256:" + "0a" * 32,
        profile_digest="sha256:" + "0b" * 32,
        status="accepted",
        prompt_tokens=11,
        completion_tokens=13,
        total_tokens=24,
    )
    digest = sha256_digest(payload)
    return SignedModelProducerAttestation(
        schema_version=SCHEMA_VERSION,
        payload=payload,
        payload_digest=digest,
        signature=signer.sign(attestation_signing_bytes(payload, digest)),
    )


def _signed_verifier(
    signer: AuthoritySigner,
    producer: SignedModelProducerAttestation,
    *,
    case_digest: str,
) -> SignedModelVerifierAttestation:
    payload = ModelVerifierAttestation(
        schema_version=SCHEMA_VERSION,
        verifier_key_id="verifier.provisioned.1",
        verifier_key_fingerprint=_fingerprint(signer),
        session_id="model-session.1",
        sequence=3,
        verifier_artifact_digest="sha256:" + "0c" * 32,
        verifier_profile_digest="sha256:" + "0d" * 32,
        producer_receipt_digest=sha256_digest(producer),
        case_digest=case_digest,
        oracle_digest="sha256:" + "0f" * 32,
        reset_evidence_digest="sha256:" + "10" * 32,
        replay_evidence_digest="sha256:" + "11" * 32,
        outcome="passed",
        safety_preserved=True,
        context_isolated=True,
        independent_replay=True,
    )
    digest = sha256_digest(payload)
    return SignedModelVerifierAttestation(
        schema_version=SCHEMA_VERSION,
        payload=payload,
        payload_digest=digest,
        signature=signer.sign(attestation_signing_bytes(payload, digest)),
    )


def _verified_proof(evaluation=None, manifest=None):
    evaluation = evaluation or valid_utility_evaluation(ModelUtilityEvidenceSource.REAL_MODEL)
    manifest = manifest or reference_adapter_manifest()
    if evaluation.plan.manifest_digest != sha256_digest(manifest):
        evaluation = evaluation.model_copy(
            update={
                "plan": evaluation.plan.model_copy(
                    update={"manifest_digest": sha256_digest(manifest)}
                )
            }
        )
    producer_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    verifier_signer = AuthoritySigner.from_private_bytes(bytes(range(32, 64)))
    producer = _signed_producer(producer_signer)
    verifier = _signed_verifier(
        verifier_signer,
        producer,
        case_digest=evaluation.case_outcomes[0].case_digest,
    )
    coverage = tuple(
        ModelUtilityOutcomeCoverage(
            schema_version=SCHEMA_VERSION,
            case_id=outcome.case_id,
            case_digest=outcome.case_digest,
            arm=outcome.arm.value,
            provider_receipt_digest=outcome.provider_receipt_digest,
            response_artifact_digest=outcome.response_artifact_digest,
            producer_canonical_request_digest=(
                producer.payload.canonical_request_digest
                if index == 0
                else "sha256:" + f"{index + 17:02x}" * 32
            ),
            producer_parsed_response_digest=(
                producer.payload.parsed_response_digest
                if index == 0
                else "sha256:" + f"{index + 33:02x}" * 32
            ),
            producer_output_digest=(
                producer.payload.output_digest
                if index == 0
                else "sha256:" + f"{index + 49:02x}" * 32
            ),
            verifier_case_digest=outcome.case_digest,
            verifier_oracle_digest=(
                verifier.payload.oracle_digest
                if index == 0
                else "sha256:" + f"{index + 65:02x}" * 32
            ),
            verifier_reset_evidence_digest=(
                verifier.payload.reset_evidence_digest
                if index == 0
                else "sha256:" + f"{index + 81:02x}" * 32
            ),
            verifier_replay_evidence_digest=(
                verifier.payload.replay_evidence_digest
                if index == 0
                else "sha256:" + f"{index + 97:02x}" * 32
            ),
        )
        for index, outcome in enumerate(
            sorted(evaluation.case_outcomes, key=lambda item: (item.case_id, item.arm.value))
        )
    )
    payload = ModelUtilityAdmission(
        schema_version=SCHEMA_VERSION,
        verifier_key_id=verifier.payload.verifier_key_id,
        verifier_key_fingerprint=verifier.payload.verifier_key_fingerprint,
        session_id="model-session.1",
        sequence=5,
        evaluator_challenge=CHALLENGE,
        adapter_id=manifest.adapter_id,
        manifest_digest=sha256_digest(manifest),
        evaluation_digest=model_utility_digest(evaluation),
        plan_digest=model_utility_digest(evaluation.plan),
        producer_envelope_digest=sha256_digest(producer),
        verifier_envelope_digest=sha256_digest(verifier),
        outcome_coverage_digest=model_utility_outcome_coverage_digest(coverage),
        outcome_coverage=coverage,
        evidence_source="real_model",
        evaluation_state="fully_done",
        outcome="passed",
        safety_preserved=True,
        dispatched_oos=0,
        escaped_oos=0,
        tool_only_false_verified=0,
    )
    digest = model_utility_admission_digest(payload)
    envelope = SignedModelUtilityAdmission(
        schema_version=SCHEMA_VERSION,
        payload=payload,
        payload_digest=digest,
        signature=verifier_signer.sign(model_utility_admission_signing_bytes(payload, digest)),
    )
    proof = verify_model_utility_admission(
        envelope,
        evaluation=evaluation,
        producer=producer,
        verifier=verifier,
        manifest=manifest,
        producer_trust_registry={producer.payload.producer_key_id: producer_signer.public_key_record},
        verifier_trust_registry={verifier.payload.verifier_key_id: verifier_signer.public_key_record},
        minimum_producer_sequence=7,
        minimum_verifier_sequence=3,
        minimum_admission_sequence=5,
        expected_session_id="model-session.1",
        expected_evaluator_challenge=CHALLENGE,
    )
    return proof, producer_signer, verifier_signer, producer, verifier, envelope


def _admission_registry() -> AdapterAdmissionRegistry:
    registry = AdapterAdmissionRegistry(reference_registry())
    manifest = reference_adapter_manifest()
    for gate in (AdmissionGate.CONTRACT, AdmissionGate.FIDELITY):
        _ = registry.record(
            AdapterAdmissionReceipt(
                adapter_id=manifest.adapter_id,
                manifest_digest=sha256_digest(manifest),
                gate=gate,
                outcome=AdmissionOutcome.PASSED,
                artifact_digest=manifest.output_schema_digest,
            )
        )
    return registry


def _record_verified(registry: AdapterAdmissionRegistry, proof, producer_signer, verifier_signer, producer, verifier):
    return registry.record_verified_model_utility(
        proof,
        producer_trust_registry={producer.payload.producer_key_id: producer_signer.public_key_record},
        verifier_trust_registry={verifier.payload.verifier_key_id: verifier_signer.public_key_record},
        minimum_producer_sequence=7,
        minimum_verifier_sequence=3,
        minimum_admission_sequence=5,
        expected_session_id="model-session.1",
        expected_evaluator_challenge=CHALLENGE,
    )


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


def test_verified_envelope_revalidation_is_the_only_model_utility_success_path() -> None:
    registry = _admission_registry()
    proof, producer_signer, verifier_signer, producer, verifier, _ = _verified_proof()

    snapshot = _record_verified(
        registry, proof, producer_signer, verifier_signer, producer, verifier
    )

    assert snapshot.state is AdapterAdmissionState.ADMITTED_CANDIDATE
    receipt = snapshot.receipts[-1]
    assert receipt.gate is AdmissionGate.MODEL_UTILITY
    assert receipt.evaluation_digest == proof.evaluation_digest


def test_verified_path_rejects_mismatched_evaluation_key_replay_and_forged_proof() -> None:
    proof, producer_signer, verifier_signer, producer, verifier, _ = _verified_proof()
    registry = _admission_registry()

    with pytest.raises(AdapterAdmissionError, match="did not revalidate"):
        _ = registry.record_verified_model_utility(
            proof,
            producer_trust_registry={producer.payload.producer_key_id: producer_signer.public_key_record},
            verifier_trust_registry={verifier.payload.verifier_key_id: verifier_signer.public_key_record},
            minimum_producer_sequence=8,
            minimum_verifier_sequence=3,
            minimum_admission_sequence=5,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )


def test_separately_signed_pair_for_another_case_cannot_cross_covered_evaluation() -> None:
    proof, producer_signer, verifier_signer, producer, verifier, envelope = _verified_proof()
    registry = _admission_registry()
    evaluation = valid_utility_evaluation(ModelUtilityEvidenceSource.REAL_MODEL)
    manifest = reference_adapter_manifest()
    other_producer_signer = AuthoritySigner.from_private_bytes(bytes(range(1, 33)))
    other_verifier_signer = AuthoritySigner.from_private_bytes(bytes(range(64, 96)))
    other_producer = _signed_producer(other_producer_signer)
    other_verifier = _signed_verifier(
        other_verifier_signer,
        other_producer,
        case_digest="sha256:" + "aa" * 32,
    )
    unsigned = envelope.payload.model_copy(
        update={
            "verifier_key_id": other_verifier.payload.verifier_key_id,
            "verifier_key_fingerprint": other_verifier.payload.verifier_key_fingerprint,
            "producer_envelope_digest": sha256_digest(other_producer),
            "verifier_envelope_digest": sha256_digest(other_verifier),
        }
    )
    digest = model_utility_admission_digest(unsigned)
    separately_signed = SignedModelUtilityAdmission(
        schema_version=SCHEMA_VERSION,
        payload=unsigned,
        payload_digest=digest,
        signature=other_verifier_signer.sign(
            model_utility_admission_signing_bytes(unsigned, digest)
        ),
    )

    with pytest.raises(ModelUtilityAdmissionError, match="do not bind one covered"):
        _ = verify_model_utility_admission(
            separately_signed,
            evaluation=evaluation,
            producer=other_producer,
            verifier=other_verifier,
            manifest=manifest,
            producer_trust_registry={
                other_producer.payload.producer_key_id: other_producer_signer.public_key_record
            },
            verifier_trust_registry={
                other_verifier.payload.verifier_key_id: other_verifier_signer.public_key_record
            },
            minimum_producer_sequence=7,
            minimum_verifier_sequence=3,
            minimum_admission_sequence=5,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    with pytest.raises(AdapterAdmissionError, match="did not revalidate"):
        _ = registry.record_verified_model_utility(
            proof,
            producer_trust_registry={producer.payload.producer_key_id: producer_signer.public_key_record},
            verifier_trust_registry={verifier.payload.verifier_key_id: verifier_signer.public_key_record},
            minimum_producer_sequence=7,
            minimum_verifier_sequence=3,
            minimum_admission_sequence=6,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    attacker = AuthoritySigner.from_private_bytes(bytes(range(1, 33)))
    with pytest.raises(AdapterAdmissionError, match="did not revalidate"):
        _ = registry.record_verified_model_utility(
            proof,
            producer_trust_registry={producer.payload.producer_key_id: producer_signer.public_key_record},
            verifier_trust_registry={verifier.payload.verifier_key_id: attacker.public_key_record},
            minimum_producer_sequence=7,
            minimum_verifier_sequence=3,
            minimum_admission_sequence=5,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    copied = object.__new__(type(proof))
    object.__setattr__(
        copied,
        "_VerifiedModelUtilityAdmission__evaluation",
        valid_utility_evaluation(ModelUtilityEvidenceSource.REAL_MODEL).model_copy(
            update={
                "plan": valid_utility_evaluation(
                    ModelUtilityEvidenceSource.REAL_MODEL
                ).plan.model_copy(update={"adapter_id": "adapter.other"})
            }
        ),
    )
    object.__setattr__(copied, "_VerifiedModelUtilityAdmission__producer", producer)
    object.__setattr__(copied, "_VerifiedModelUtilityAdmission__verifier", verifier)
    object.__setattr__(copied, "_VerifiedModelUtilityAdmission__envelope", proof._VerifiedModelUtilityAdmission__envelope)  # noqa: SLF001
    with pytest.raises(AdapterAdmissionError, match="did not revalidate"):
        _ = _record_verified(
            registry, copied, producer_signer, verifier_signer, producer, verifier
        )
    forged = object.__new__(type(proof))
    with pytest.raises(AdapterAdmissionError, match="did not revalidate"):
        _ = registry.record_verified_model_utility(
            forged,
            producer_trust_registry={producer.payload.producer_key_id: producer_signer.public_key_record},
            verifier_trust_registry={verifier.payload.verifier_key_id: verifier_signer.public_key_record},
            minimum_producer_sequence=7,
            minimum_verifier_sequence=3,
            minimum_admission_sequence=5,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
