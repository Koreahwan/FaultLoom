from __future__ import annotations

import hashlib

import pytest

from faultloom_protocol import (
    AuthoritySigner,
    ModelUtilityAdmission,
    ModelUtilityOutcomeCoverage,
    SCHEMA_VERSION,
    SignedModelUtilityAdmission,
    SignatureTamperError,
    UnknownKeyError,
    canonical_model_utility_admission_envelope,
    model_utility_admission_digest,
    model_utility_admission_signing_bytes,
    model_utility_outcome_coverage_digest,
    parse_canonical_model_utility_admission,
    verify_model_utility_admission,
)


CHALLENGE = bytes(range(32)).hex()


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def _fingerprint(signer: AuthoritySigner) -> str:
    return "sha256:" + signer.public_key_record.key_id.rsplit(":", 1)[1]


def _payload(signer: AuthoritySigner) -> ModelUtilityAdmission:
    coverage = (
        ModelUtilityOutcomeCoverage(
            schema_version=SCHEMA_VERSION,
            case_id="case.reference.1",
            case_digest=_digest("case"),
            arm="baseline",
            provider_receipt_digest=_digest("receipt"),
            response_artifact_digest=_digest("response"),
            producer_canonical_request_digest=_digest("request"),
            producer_parsed_response_digest=_digest("parsed"),
            producer_output_digest=_digest("output"),
            verifier_case_digest=_digest("case"),
            verifier_oracle_digest=_digest("oracle"),
            verifier_reset_evidence_digest=_digest("reset"),
            verifier_replay_evidence_digest=_digest("replay"),
        ),
    )
    return ModelUtilityAdmission(
        schema_version=SCHEMA_VERSION,
        verifier_key_id="verifier.provisioned.1",
        verifier_key_fingerprint=_fingerprint(signer),
        session_id="model-session.1",
        sequence=5,
        evaluator_challenge=CHALLENGE,
        adapter_id="adapter.reference",
        manifest_digest=_digest("manifest"),
        evaluation_digest=_digest("evaluation"),
        plan_digest=_digest("plan"),
        producer_envelope_digest=_digest("producer"),
        verifier_envelope_digest=_digest("verifier"),
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


def _signed(signer: AuthoritySigner, payload: ModelUtilityAdmission | None = None) -> SignedModelUtilityAdmission:
    payload = payload or _payload(signer)
    payload_digest = model_utility_admission_digest(payload)
    return SignedModelUtilityAdmission(
        schema_version=SCHEMA_VERSION,
        payload=payload,
        payload_digest=payload_digest,
        signature=signer.sign(model_utility_admission_signing_bytes(payload, payload_digest)),
    )


def _verify(signer: AuthoritySigner, envelope: SignedModelUtilityAdmission) -> ModelUtilityAdmission:
    return verify_model_utility_admission(
        envelope,
        {envelope.payload.verifier_key_id: signer.public_key_record},
        minimum_sequence=5,
        expected_session_id="model-session.1",
        expected_evaluator_challenge=CHALLENGE,
    )


def test_canonical_utility_admission_envelope_binds_truth_and_replay_controls() -> None:
    signer = AuthoritySigner.from_private_bytes(bytes(range(32, 64)))
    envelope = _signed(signer)

    assert _verify(signer, envelope) == envelope.payload
    assert model_utility_admission_signing_bytes(
        envelope.payload, envelope.payload_digest
    ).startswith(b'{"payload":')
    assert parse_canonical_model_utility_admission(
        canonical_model_utility_admission_envelope(envelope)
    ) == envelope
    with pytest.raises(SignatureTamperError, match="sequence"):
        _ = verify_model_utility_admission(
            envelope,
            {envelope.payload.verifier_key_id: signer.public_key_record},
            minimum_sequence=6,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    with pytest.raises(SignatureTamperError, match="session"):
        _ = verify_model_utility_admission(
            envelope,
            {envelope.payload.verifier_key_id: signer.public_key_record},
            minimum_sequence=5,
            expected_session_id="model-session.2",
            expected_evaluator_challenge=CHALLENGE,
        )
    with pytest.raises(SignatureTamperError, match="challenge"):
        _ = verify_model_utility_admission(
            envelope,
            {envelope.payload.verifier_key_id: signer.public_key_record},
            minimum_sequence=5,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=bytes(range(1, 33)).hex(),
        )


def test_untrusted_key_mutation_and_unvalidated_instances_fail_closed() -> None:
    signer = AuthoritySigner.from_private_bytes(bytes(range(32, 64)))
    envelope = _signed(signer)
    attacker = AuthoritySigner.from_private_bytes(bytes(range(1, 33)))

    with pytest.raises(UnknownKeyError):
        _ = verify_model_utility_admission(
            envelope,
            {envelope.payload.verifier_key_id: attacker.public_key_record},
            minimum_sequence=5,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    with pytest.raises(SignatureTamperError, match="payload_digest"):
        _ = _verify(
            signer,
            envelope.model_copy(
                update={"payload": envelope.payload.model_copy(update={"adapter_id": "adapter.other"})}
            ),
        )
    copied_with_extra = envelope.model_copy(update={"attacker_extra": True})
    with pytest.raises(SignatureTamperError, match="malformed"):
        _ = _verify(signer, copied_with_extra)
    payload_with_extra = envelope.model_copy(
        update={"payload": envelope.payload.model_copy(update={"attacker_extra": True})}
    )
    with pytest.raises(SignatureTamperError, match="malformed"):
        _ = _verify(signer, payload_with_extra)
    forged = object.__new__(SignedModelUtilityAdmission)
    with pytest.raises(SignatureTamperError, match="malformed"):
        _ = verify_model_utility_admission(
            forged,
            {"verifier.provisioned.1": signer.public_key_record},
            minimum_sequence=5,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
