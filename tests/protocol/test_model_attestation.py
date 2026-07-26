from __future__ import annotations

import base64
import json

import pytest
from pydantic import ValidationError

from faultloom_protocol import (
    AuthoritySigner,
    EVALUATION_MODEL_TYPES,
    MODEL_ATTESTATION_MODEL_TYPES,
    ModelProducerAttestation,
    ModelVerifierAttestation,
    REQUIRED_MODEL_TYPES,
    SCHEMA_VERSION,
    SignatureTamperError,
    SignedModelProducerAttestation,
    SignedModelVerifierAttestation,
    UnknownKeyError,
    WIRE_MODEL_TYPES,
    attestation_signing_bytes,
    canonical_json_bytes,
    parse_canonical_model_producer_attestation,
    schema_catalog,
    sha256_digest,
    verify_model_attestation_pair,
    verify_model_producer_attestation,
)

DIGESTS = tuple(f"sha256:{index:064x}" for index in range(1, 24))
CHALLENGE = bytes(range(32)).hex()


def _fingerprint(signer: AuthoritySigner) -> str:
    return "sha256:" + signer.public_key_record.key_id.rsplit(":", 1)[1]


def _producer_payload(
    signer: AuthoritySigner,
    *,
    key_id: str = "producer.provisioned.1",
) -> ModelProducerAttestation:
    return ModelProducerAttestation(
        schema_version=SCHEMA_VERSION,
        producer_key_id=key_id,
        producer_key_fingerprint=_fingerprint(signer),
        session_id="model-session.1",
        sequence=7,
        evaluator_challenge=CHALLENGE,
        canonical_request_digest=DIGESTS[0],
        parsed_response_digest=DIGESTS[1],
        raw_llama_stdout_digest=DIGESTS[2],
        output_digest=DIGESTS[3],
        model_digest=DIGESTS[4],
        runtime_wrapper_digest=DIGESTS[5],
        runtime_bundle_digest=DIGESTS[6],
        bwrap_digest=DIGESTS[7],
        fixed_argv_digest=DIGESTS[8],
        core_wheel_digest=DIGESTS[9],
        profile_digest=DIGESTS[10],
        status="accepted",
        prompt_tokens=11,
        completion_tokens=13,
        total_tokens=24,
    )


def _signed_producer(
    signer: AuthoritySigner,
    payload: ModelProducerAttestation | None = None,
) -> SignedModelProducerAttestation:
    payload = payload or _producer_payload(signer)
    digest = sha256_digest(payload)
    return SignedModelProducerAttestation(
        schema_version=SCHEMA_VERSION,
        payload=payload,
        payload_digest=digest,
        signature=signer.sign(attestation_signing_bytes(payload, digest)),
    )


def _verifier_payload(
    signer: AuthoritySigner,
    producer: SignedModelProducerAttestation,
    *,
    key_id: str = "verifier.provisioned.1",
) -> ModelVerifierAttestation:
    return ModelVerifierAttestation(
        schema_version=SCHEMA_VERSION,
        verifier_key_id=key_id,
        verifier_key_fingerprint=_fingerprint(signer),
        session_id="model-session.1",
        sequence=3,
        verifier_artifact_digest=DIGESTS[11],
        verifier_profile_digest=DIGESTS[12],
        producer_receipt_digest=sha256_digest(producer),
        case_digest=DIGESTS[13],
        oracle_digest=DIGESTS[14],
        reset_evidence_digest=DIGESTS[15],
        replay_evidence_digest=DIGESTS[16],
        outcome="passed",
        safety_preserved=True,
        context_isolated=True,
        independent_replay=True,
    )


def _signed_verifier(
    signer: AuthoritySigner,
    producer: SignedModelProducerAttestation,
    payload: ModelVerifierAttestation | None = None,
) -> SignedModelVerifierAttestation:
    payload = payload or _verifier_payload(signer, producer)
    digest = sha256_digest(payload)
    return SignedModelVerifierAttestation(
        schema_version=SCHEMA_VERSION,
        payload=payload,
        payload_digest=digest,
        signature=signer.sign(attestation_signing_bytes(payload, digest)),
    )


def _pair() -> tuple[
    AuthoritySigner,
    AuthoritySigner,
    SignedModelProducerAttestation,
    SignedModelVerifierAttestation,
]:
    producer_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    verifier_signer = AuthoritySigner.from_private_bytes(bytes(range(32, 64)))
    producer = _signed_producer(producer_signer)
    verifier = _signed_verifier(verifier_signer, producer)
    return producer_signer, verifier_signer, producer, verifier


def _verify_pair(
    producer_signer: AuthoritySigner,
    verifier_signer: AuthoritySigner,
    producer: SignedModelProducerAttestation,
    verifier: SignedModelVerifierAttestation,
) -> tuple[ModelProducerAttestation, ModelVerifierAttestation]:
    return verify_model_attestation_pair(
        producer,
        verifier,
        {producer.payload.producer_key_id: producer_signer.public_key_record},
        {verifier.payload.verifier_key_id: verifier_signer.public_key_record},
        minimum_producer_sequence=7,
        minimum_verifier_sequence=3,
        expected_session_id="model-session.1",
        expected_evaluator_challenge=CHALLENGE,
    )


def test_independent_attestations_round_trip_and_bind() -> None:
    producer_signer, verifier_signer, producer, verifier = _pair()
    producer_payload, verifier_payload = _verify_pair(
        producer_signer, verifier_signer, producer, verifier
    )
    assert producer_payload.status == "accepted"
    assert verifier_payload.outcome == "passed"
    assert parse_canonical_model_producer_attestation(canonical_json_bytes(producer)) == producer


def test_authoritative_schema_catalog_registers_attestation_models_once_in_order() -> None:
    catalog = schema_catalog()
    names = tuple(catalog)
    attestation_names = tuple(model.__name__ for model in MODEL_ATTESTATION_MODEL_TYPES)
    authoritative_types = (
        *REQUIRED_MODEL_TYPES,
        *WIRE_MODEL_TYPES,
        *EVALUATION_MODEL_TYPES,
        *MODEL_ATTESTATION_MODEL_TYPES,
    )
    authoritative_names = tuple(model.__name__ for model in authoritative_types)

    assert names == authoritative_names
    assert names[-len(attestation_names) :] == attestation_names
    assert len(names) == len(set(names)) == len(set(authoritative_types))
    for model in MODEL_ATTESTATION_MODEL_TYPES:
        schema = catalog[model.__name__]
        assert schema == model.model_json_schema()
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False


def test_payload_mutation_and_digest_mutation_are_rejected() -> None:
    producer_signer, _, producer, _ = _pair()
    mutated_payload = producer.payload.model_copy(update={"output_digest": DIGESTS[20]})
    mutated = producer.model_copy(update={"payload": mutated_payload})
    with pytest.raises(SignatureTamperError, match="payload_digest"):
        verify_model_producer_attestation(
            mutated,
            {producer.payload.producer_key_id: producer_signer.public_key_record},
            minimum_sequence=7,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    forged_signature = producer.model_copy(update={"signature": "A" * 86})
    with pytest.raises(SignatureTamperError, match="signature verification"):
        verify_model_producer_attestation(
            forged_signature,
            {producer.payload.producer_key_id: producer_signer.public_key_record},
            minimum_sequence=7,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    wrong_digest = producer.model_copy(update={"payload_digest": DIGESTS[21]})
    with pytest.raises(SignatureTamperError, match="payload_digest"):
        verify_model_producer_attestation(
            wrong_digest,
            {producer.payload.producer_key_id: producer_signer.public_key_record},
            minimum_sequence=7,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )


def test_wrong_key_fingerprint_and_self_selected_key_are_rejected() -> None:
    producer_signer, _, producer, _ = _pair()
    attacker = AuthoritySigner.from_private_bytes(bytes(range(1, 33)))
    with pytest.raises(UnknownKeyError, match="absent"):
        verify_model_producer_attestation(
            producer,
            {},
            minimum_sequence=7,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    with pytest.raises(UnknownKeyError):
        verify_model_producer_attestation(
            producer,
            {producer.payload.producer_key_id: attacker.public_key_record},
            minimum_sequence=7,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    wrong_fingerprint_payload = _producer_payload(producer_signer).model_copy(
        update={"producer_key_fingerprint": _fingerprint(attacker)}
    )
    wrong_fingerprint = _signed_producer(producer_signer, wrong_fingerprint_payload)
    with pytest.raises(UnknownKeyError, match="fingerprint"):
        verify_model_producer_attestation(
            wrong_fingerprint,
            {producer.payload.producer_key_id: producer_signer.public_key_record},
            minimum_sequence=7,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )


def test_sequence_session_and_challenge_rebinding_are_rejected() -> None:
    producer_signer, _, producer, _ = _pair()
    registry = {producer.payload.producer_key_id: producer_signer.public_key_record}
    with pytest.raises(SignatureTamperError, match="sequence"):
        verify_model_producer_attestation(
            producer,
            registry,
            minimum_sequence=8,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )
    with pytest.raises(SignatureTamperError, match="session"):
        verify_model_producer_attestation(
            producer,
            registry,
            minimum_sequence=7,
            expected_session_id="model-session.2",
            expected_evaluator_challenge=CHALLENGE,
        )
    with pytest.raises(SignatureTamperError, match="challenge"):
        verify_model_producer_attestation(
            producer,
            registry,
            minimum_sequence=7,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=bytes(range(1, 33)).hex(),
        )


def test_pair_rejects_receipt_rebind_and_producer_verifier_collision() -> None:
    producer_signer, verifier_signer, producer, verifier = _pair()
    rebound_payload = verifier.payload.model_copy(
        update={"producer_receipt_digest": DIGESTS[19]}
    )
    rebound = _signed_verifier(verifier_signer, producer, rebound_payload)
    with pytest.raises(SignatureTamperError, match="bind the producer"):
        _verify_pair(producer_signer, verifier_signer, producer, rebound)

    collision_payload = _verifier_payload(
        producer_signer,
        producer,
        key_id=producer.payload.producer_key_id,
    )
    collision = _signed_verifier(producer_signer, producer, collision_payload)
    with pytest.raises(SignatureTamperError, match="distinct"):
        _verify_pair(producer_signer, producer_signer, producer, collision)


def test_pair_rejects_shared_verifier_profile_or_artifact() -> None:
    producer_signer, verifier_signer, producer, verifier = _pair()
    shared_profile_payload = verifier.payload.model_copy(
        update={"verifier_profile_digest": producer.payload.profile_digest}
    )
    shared_profile = _signed_verifier(verifier_signer, producer, shared_profile_payload)
    with pytest.raises(SignatureTamperError, match="profile"):
        _verify_pair(producer_signer, verifier_signer, producer, shared_profile)
    shared_artifact_payload = verifier.payload.model_copy(
        update={"verifier_artifact_digest": producer.payload.runtime_bundle_digest}
    )
    shared_artifact = _signed_verifier(verifier_signer, producer, shared_artifact_payload)
    with pytest.raises(SignatureTamperError, match="artifact"):
        _verify_pair(producer_signer, verifier_signer, producer, shared_artifact)


def test_noncanonical_json_extra_fields_and_wrong_wire_lengths_are_rejected() -> None:
    producer_signer, _, producer, _ = _pair()
    noncanonical = json.dumps(producer.model_dump(mode="json"), indent=2).encode()
    with pytest.raises(ValueError, match="not canonical"):
        parse_canonical_model_producer_attestation(noncanonical)

    extra = producer.model_dump(mode="json")
    extra["verifier_claim"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        SignedModelProducerAttestation.model_validate(extra)
    payload_extra = producer.payload.model_dump(mode="json")
    payload_extra["safety_preserved"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        ModelProducerAttestation.model_validate(payload_extra)
    with pytest.raises(ValidationError):
        SignedModelProducerAttestation.model_validate(
            {**producer.model_dump(mode="json"), "signature": "A" * 85}
        )
    copied_with_extra = producer.model_copy(update={"verifier_claim": True})
    with pytest.raises(SignatureTamperError, match="malformed"):
        verify_model_producer_attestation(
            copied_with_extra,
            {producer.payload.producer_key_id: producer_signer.public_key_record},
            minimum_sequence=7,
            expected_session_id="model-session.1",
            expected_evaluator_challenge=CHALLENGE,
        )


def test_challenge_token_and_exact_type_constraints_are_enforced() -> None:
    producer_signer = AuthoritySigner.from_private_bytes(bytes(range(32)))
    payload = _producer_payload(producer_signer).model_dump(mode="python")
    payload["evaluator_challenge"] = "00" * 32
    with pytest.raises(ValidationError, match="eight distinct"):
        ModelProducerAttestation.model_validate(payload)
    payload = _producer_payload(producer_signer).model_dump(mode="python")
    payload["sequence"] = True
    with pytest.raises(ValidationError):
        ModelProducerAttestation.model_validate(payload)
    payload = _producer_payload(producer_signer).model_dump(mode="python")
    payload["total_tokens"] = 25
    with pytest.raises(ValidationError, match="total_tokens"):
        ModelProducerAttestation.model_validate(payload)


def test_signature_encoding_is_canonical() -> None:
    _, _, producer, _ = _pair()
    raw = base64.urlsafe_b64decode(producer.signature + "==")
    assert len(raw) == 64
    assert "=" not in producer.signature
