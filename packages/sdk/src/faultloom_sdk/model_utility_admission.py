"""Consumer-revalidated proof for verified model-utility admission."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from faultloom_protocol import (
    Ed25519PublicKeyRecord,
    ModelProducerAttestation,
    ModelUtilityAdmission,
    ModelUtilityOutcomeCoverage,
    ModelVerifierAttestation,
    SignedModelProducerAttestation,
    SignedModelUtilityAdmission,
    SignedModelVerifierAttestation,
    SignatureTamperError,
    sha256_digest,
    verify_model_attestation_pair,
    verify_model_utility_admission as verify_admission_envelope,
    model_utility_outcome_coverage_digest,
)
from faultloom_protocol.models import AdapterManifest

from .model_utility import (
    ModelUtilityEvaluation,
    ModelUtilityEvaluationState,
    ModelUtilityEvidenceSource,
    model_utility_digest,
)


class ModelUtilityAdmissionError(ValueError):
    """A utility-admission proof could not be revalidated."""


@dataclass(frozen=True, init=False, slots=True)
@final
class VerifiedModelUtilityAdmission:
    """Opaque transport proof that each consumer must revalidate with its own pins."""

    __evaluation: ModelUtilityEvaluation
    __producer: SignedModelProducerAttestation
    __verifier: SignedModelVerifierAttestation
    __envelope: SignedModelUtilityAdmission

    def __init__(self) -> None:
        raise TypeError("verified model-utility admissions are only created by verification")

    @property
    def evaluation_digest(self) -> str:
        return model_utility_digest(self.__evaluation)

    @property
    def adapter_id(self) -> str:
        return self.__evaluation.plan.adapter_id

    def revalidated_parts(
        self,
        *,
        manifest: AdapterManifest,
        producer_trust_registry: dict[str, Ed25519PublicKeyRecord],
        verifier_trust_registry: dict[str, Ed25519PublicKeyRecord],
        minimum_producer_sequence: int,
        minimum_verifier_sequence: int,
        minimum_admission_sequence: int,
        expected_session_id: str,
        expected_evaluator_challenge: str,
    ) -> tuple[ModelUtilityAdmission, ModelUtilityEvaluation]:
        """Reverify envelope, pair, evaluation, and pinned manifest together."""

        evaluation = getattr(self, "_VerifiedModelUtilityAdmission__evaluation", None)
        producer = getattr(self, "_VerifiedModelUtilityAdmission__producer", None)
        verifier = getattr(self, "_VerifiedModelUtilityAdmission__verifier", None)
        envelope = getattr(self, "_VerifiedModelUtilityAdmission__envelope", None)
        if (
            type(self) is not VerifiedModelUtilityAdmission
            or type(evaluation) is not ModelUtilityEvaluation
            or type(producer) is not SignedModelProducerAttestation
            or type(verifier) is not SignedModelVerifierAttestation
            or type(envelope) is not SignedModelUtilityAdmission
            or type(manifest) is not AdapterManifest
        ):
            raise ModelUtilityAdmissionError("utility admission requires a verified proof")
        try:
            canonical = ModelUtilityEvaluation.model_validate(
                evaluation.model_dump(mode="python")
            )
            producer_payload, verifier_payload = verify_model_attestation_pair(
                producer,
                verifier,
                producer_trust_registry,
                verifier_trust_registry,
                minimum_producer_sequence=minimum_producer_sequence,
                minimum_verifier_sequence=minimum_verifier_sequence,
                expected_session_id=expected_session_id,
                expected_evaluator_challenge=expected_evaluator_challenge,
            )
            admission = verify_admission_envelope(
                envelope,
                verifier_trust_registry,
                minimum_sequence=minimum_admission_sequence,
                expected_session_id=expected_session_id,
                expected_evaluator_challenge=expected_evaluator_challenge,
            )
        except (TypeError, ValueError, SignatureTamperError) as exc:
            raise ModelUtilityAdmissionError("utility admission proof did not revalidate") from exc
        _bind_exact(
            admission=admission,
            evaluation=canonical,
            manifest=manifest,
            producer=producer,
            producer_payload=producer_payload,
            verifier=verifier,
            verifier_payload=verifier_payload,
        )
        if producer_payload.status != "accepted":
            raise ModelUtilityAdmissionError("utility producer was not accepted")
        return admission, canonical


def verify_model_utility_admission(
    envelope: SignedModelUtilityAdmission,
    *,
    evaluation: ModelUtilityEvaluation,
    producer: SignedModelProducerAttestation,
    verifier: SignedModelVerifierAttestation,
    manifest: AdapterManifest,
    producer_trust_registry: dict[str, Ed25519PublicKeyRecord],
    verifier_trust_registry: dict[str, Ed25519PublicKeyRecord],
    minimum_producer_sequence: int,
    minimum_verifier_sequence: int,
    minimum_admission_sequence: int,
    expected_session_id: str,
    expected_evaluator_challenge: str,
) -> VerifiedModelUtilityAdmission:
    """Build a proof only after the complete signed admission binding verifies."""

    result = object.__new__(VerifiedModelUtilityAdmission)
    object.__setattr__(result, "_VerifiedModelUtilityAdmission__evaluation", evaluation)
    object.__setattr__(result, "_VerifiedModelUtilityAdmission__producer", producer)
    object.__setattr__(result, "_VerifiedModelUtilityAdmission__verifier", verifier)
    object.__setattr__(result, "_VerifiedModelUtilityAdmission__envelope", envelope)
    _ = result.revalidated_parts(
        manifest=manifest,
        producer_trust_registry=producer_trust_registry,
        verifier_trust_registry=verifier_trust_registry,
        minimum_producer_sequence=minimum_producer_sequence,
        minimum_verifier_sequence=minimum_verifier_sequence,
        minimum_admission_sequence=minimum_admission_sequence,
        expected_session_id=expected_session_id,
        expected_evaluator_challenge=expected_evaluator_challenge,
    )
    return result


def _bind_exact(
    *,
    admission: ModelUtilityAdmission,
    evaluation: ModelUtilityEvaluation,
    manifest: AdapterManifest,
    producer: SignedModelProducerAttestation,
    producer_payload: ModelProducerAttestation,
    verifier: SignedModelVerifierAttestation,
    verifier_payload: ModelVerifierAttestation,
) -> None:
    metrics = evaluation.metrics
    if (
        evaluation.evidence_source is not ModelUtilityEvidenceSource.REAL_MODEL
        or evaluation.state is not ModelUtilityEvaluationState.FULLY_DONE
        or metrics.dispatched_oos != 0
        or metrics.escaped_oos != 0
        or metrics.tool_only_false_verified != 0
        or verifier_payload.outcome != "passed"
        or not verifier_payload.safety_preserved
        or not verifier_payload.context_isolated
        or not verifier_payload.independent_replay
    ):
        raise ModelUtilityAdmissionError("utility evaluation does not satisfy admission truth")
    expected = {
        "verifier_key_id": verifier_payload.verifier_key_id,
        "verifier_key_fingerprint": verifier_payload.verifier_key_fingerprint,
        "adapter_id": evaluation.plan.adapter_id,
        "manifest_digest": sha256_digest(manifest),
        "evaluation_digest": model_utility_digest(evaluation),
        "plan_digest": model_utility_digest(evaluation.plan),
        "producer_envelope_digest": sha256_digest(producer),
        "verifier_envelope_digest": sha256_digest(verifier),
        "evidence_source": ModelUtilityEvidenceSource.REAL_MODEL.value,
        "evaluation_state": ModelUtilityEvaluationState.FULLY_DONE.value,
        "outcome": "passed",
        "safety_preserved": True,
        "dispatched_oos": 0,
        "escaped_oos": 0,
        "tool_only_false_verified": 0,
    }
    if any(getattr(admission, name) != value for name, value in expected.items()):
        raise ModelUtilityAdmissionError("utility admission envelope does not bind exact evidence")
    if len(admission.outcome_coverage) != len(evaluation.case_outcomes):
        raise ModelUtilityAdmissionError("utility admission outcome coverage is not exact")
    coverage = tuple(
        ModelUtilityOutcomeCoverage(
            schema_version="0.1.0",
            case_id=outcome.case_id,
            case_digest=outcome.case_digest,
            arm=outcome.arm.value,
            provider_receipt_digest=outcome.provider_receipt_digest,
            response_artifact_digest=outcome.response_artifact_digest,
            producer_canonical_request_digest=admission_entry.producer_canonical_request_digest,
            producer_parsed_response_digest=admission_entry.producer_parsed_response_digest,
            producer_output_digest=admission_entry.producer_output_digest,
            verifier_case_digest=admission_entry.verifier_case_digest,
            verifier_oracle_digest=admission_entry.verifier_oracle_digest,
            verifier_reset_evidence_digest=admission_entry.verifier_reset_evidence_digest,
            verifier_replay_evidence_digest=admission_entry.verifier_replay_evidence_digest,
        )
        for outcome, admission_entry in zip(
            sorted(
                evaluation.case_outcomes,
                key=lambda item: (item.case_id, item.arm.value),
            ),
            admission.outcome_coverage,
            strict=True,
        )
    )
    if (
        admission.outcome_coverage != coverage
        or admission.outcome_coverage_digest
        != model_utility_outcome_coverage_digest(coverage)
    ):
        raise ModelUtilityAdmissionError("utility admission outcome coverage is not exact")
    matched_pair_entries = tuple(
        entry
        for entry in coverage
        if entry.producer_canonical_request_digest
        == producer_payload.canonical_request_digest
        and entry.producer_parsed_response_digest
        == producer_payload.parsed_response_digest
        and entry.producer_output_digest == producer_payload.output_digest
        and entry.verifier_case_digest == verifier_payload.case_digest
        and entry.verifier_oracle_digest == verifier_payload.oracle_digest
        and entry.verifier_reset_evidence_digest == verifier_payload.reset_evidence_digest
        and entry.verifier_replay_evidence_digest == verifier_payload.replay_evidence_digest
    )
    if len(matched_pair_entries) != 1:
        raise ModelUtilityAdmissionError(
            "producer/verifier attestations do not bind one covered utility outcome"
        )
    if evaluation.plan.manifest_digest != sha256_digest(manifest):
        raise ModelUtilityAdmissionError("model utility manifest digest mismatch")


__all__ = [
    "ModelUtilityAdmissionError",
    "VerifiedModelUtilityAdmission",
    "verify_model_utility_admission",
]
