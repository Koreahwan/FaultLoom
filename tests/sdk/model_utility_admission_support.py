"""Public-path fixtures shared by model-utility admission tests."""

from __future__ import annotations

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
    sha256_digest,
)
from faultloom_sdk import (
    AdapterAdmissionRegistry,
    ModelUtilityEvidenceSource,
    model_utility_digest,
    reference_adapter_manifest,
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


def verified_proof(evaluation=None, manifest=None):
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
        producer_trust_registry={
            producer.payload.producer_key_id: producer_signer.public_key_record
        },
        verifier_trust_registry={
            verifier.payload.verifier_key_id: verifier_signer.public_key_record
        },
        minimum_producer_sequence=7,
        minimum_verifier_sequence=3,
        minimum_admission_sequence=5,
        expected_session_id="model-session.1",
        expected_evaluator_challenge=CHALLENGE,
    )
    return proof, producer_signer, verifier_signer, producer, verifier, envelope


def record_verified(
    registry: AdapterAdmissionRegistry,
    proof,
    producer_signer: AuthoritySigner,
    verifier_signer: AuthoritySigner,
    producer: SignedModelProducerAttestation,
    verifier: SignedModelVerifierAttestation,
):
    return registry.record_verified_model_utility(
        proof,
        producer_trust_registry={
            producer.payload.producer_key_id: producer_signer.public_key_record
        },
        verifier_trust_registry={
            verifier.payload.verifier_key_id: verifier_signer.public_key_record
        },
        minimum_producer_sequence=7,
        minimum_verifier_sequence=3,
        minimum_admission_sequence=5,
        expected_session_id="model-session.1",
        expected_evaluator_challenge=CHALLENGE,
    )
