"""Public-safe local model producer and independent verifier attestations.

Only identities, facts, and content digests cross this boundary. Private cases,
oracles, prompts, responses, keys, and replay material remain outside Core.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Annotated, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from pydantic import Field, model_validator

from .base import (
    Identifier,
    MAX_INT64,
    ProtocolModel,
    Sha256Digest,
    _snapshot_protocol_model,  # pyright: ignore[reportPrivateUsage]
)
from .canonical import canonical_json_bytes, sha256_digest
from .models import Ed25519PublicKeyRecord
from .signing import SignatureTamperError, UnknownKeyError, load_public_key

AttestationSequence = Annotated[int, Field(ge=1, le=MAX_INT64)]
TokenCount = Annotated[int, Field(ge=0, le=MAX_INT64)]
EvaluatorChallenge = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Ed25519Signature = Annotated[
    str,
    Field(min_length=86, max_length=86, pattern=r"^[A-Za-z0-9_-]{86}$"),
]


class ModelProducerAttestation(ProtocolModel):
    """Facts asserted by the transient local model producer only."""

    producer_key_id: Identifier
    producer_key_fingerprint: Sha256Digest
    session_id: Identifier
    sequence: AttestationSequence
    evaluator_challenge: EvaluatorChallenge
    canonical_request_digest: Sha256Digest
    parsed_response_digest: Sha256Digest
    raw_llama_stdout_digest: Sha256Digest
    output_digest: Sha256Digest
    model_digest: Sha256Digest
    runtime_wrapper_digest: Sha256Digest
    runtime_bundle_digest: Sha256Digest
    bwrap_digest: Sha256Digest
    fixed_argv_digest: Sha256Digest
    core_wheel_digest: Sha256Digest
    profile_digest: Sha256Digest
    status: Literal["accepted", "rejected", "error"]
    prompt_tokens: TokenCount
    completion_tokens: TokenCount
    total_tokens: TokenCount

    @model_validator(mode="after")
    def _tokens_and_challenge_are_canonical(self) -> "ModelProducerAttestation":
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("total_tokens must equal prompt_tokens plus completion_tokens")
        if len(set(bytes.fromhex(self.evaluator_challenge))) < 8:
            raise ValueError("evaluator_challenge must contain at least eight distinct bytes")
        return self


class ModelVerifierAttestation(ProtocolModel):
    """Facts derived by a verifier independent from the model producer."""

    verifier_key_id: Identifier
    verifier_key_fingerprint: Sha256Digest
    session_id: Identifier
    sequence: AttestationSequence
    verifier_artifact_digest: Sha256Digest
    verifier_profile_digest: Sha256Digest
    producer_receipt_digest: Sha256Digest
    case_digest: Sha256Digest
    oracle_digest: Sha256Digest
    reset_evidence_digest: Sha256Digest
    replay_evidence_digest: Sha256Digest
    outcome: Literal["passed", "failed", "inconclusive"]
    safety_preserved: bool
    context_isolated: bool
    independent_replay: bool


class SignedModelProducerAttestation(ProtocolModel):
    payload: ModelProducerAttestation
    payload_digest: Sha256Digest
    signature: Ed25519Signature


class SignedModelVerifierAttestation(ProtocolModel):
    payload: ModelVerifierAttestation
    payload_digest: Sha256Digest
    signature: Ed25519Signature


def attestation_signing_bytes(
    payload: ModelProducerAttestation | ModelVerifierAttestation,
    payload_digest: str,
) -> bytes:
    """Return deterministic bytes covering both payload and its exact digest."""

    if type(payload) not in (ModelProducerAttestation, ModelVerifierAttestation):
        raise TypeError("payload must be an exact model attestation payload")
    if type(payload_digest) is not str or payload_digest != sha256_digest(payload):
        raise SignatureTamperError("payload_digest does not match canonical payload bytes")
    return canonical_json_bytes({"payload": payload, "payload_digest": payload_digest})


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise SignatureTamperError("signature is not canonical URL-safe base64") from exc
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise SignatureTamperError("signature is not a canonical Ed25519 signature")
    return decoded


def _trusted_key(
    trust_registry: dict[str, Ed25519PublicKeyRecord],
    *,
    key_id: str,
    key_fingerprint: str,
):
    if type(trust_registry) is not dict:
        raise TypeError("trust_registry must be an exact caller-supplied dict")
    if any(
        type(name) is not str or type(record) is not Ed25519PublicKeyRecord
        for name, record in trust_registry.items()
    ):
        raise UnknownKeyError("trust_registry contains a malformed key entry")
    record = trust_registry.get(key_id)
    if record is None:
        raise UnknownKeyError("attestation key_id is absent from the caller trust registry")
    public_key = load_public_key(record)
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    actual_fingerprint = f"sha256:{hashlib.sha256(raw_key).hexdigest()}"
    if not hmac.compare_digest(actual_fingerprint, key_fingerprint):
        raise UnknownKeyError("attestation key fingerprint does not match the trusted key")
    return public_key


def _verify_envelope(
    envelope: SignedModelProducerAttestation | SignedModelVerifierAttestation,
    envelope_type: type[SignedModelProducerAttestation]
    | type[SignedModelVerifierAttestation],
    trust_registry: dict[str, Ed25519PublicKeyRecord],
) -> ModelProducerAttestation | ModelVerifierAttestation:
    if type(envelope) is not envelope_type:
        raise SignatureTamperError("attestation envelope has the wrong exact type")
    try:
        if envelope_type is SignedModelProducerAttestation:
            validated = _snapshot_protocol_model(
                envelope,
                SignedModelProducerAttestation,
                label="producer attestation envelope",
            )
            key_id = validated.payload.producer_key_id
            key_fingerprint = validated.payload.producer_key_fingerprint
        else:
            validated = _snapshot_protocol_model(
                envelope,
                SignedModelVerifierAttestation,
                label="verifier attestation envelope",
            )
            key_id = validated.payload.verifier_key_id
            key_fingerprint = validated.payload.verifier_key_fingerprint
    except (TypeError, ValueError) as exc:
        raise SignatureTamperError("attestation envelope is malformed") from exc
    signing_document = attestation_signing_bytes(validated.payload, validated.payload_digest)
    public_key = _trusted_key(
        trust_registry,
        key_id=key_id,
        key_fingerprint=key_fingerprint,
    )
    try:
        public_key.verify(_decode_signature(validated.signature), signing_document)
    except InvalidSignature as exc:
        raise SignatureTamperError("Ed25519 attestation signature verification failed") from exc
    return validated.payload


def verify_model_producer_attestation(
    envelope: SignedModelProducerAttestation,
    trust_registry: dict[str, Ed25519PublicKeyRecord],
    *,
    minimum_sequence: int,
    expected_session_id: str,
    expected_evaluator_challenge: str,
) -> ModelProducerAttestation:
    """Verify a producer receipt against caller-owned trust and replay controls."""

    if type(minimum_sequence) is not int or not 1 <= minimum_sequence <= MAX_INT64:
        raise ValueError("minimum_sequence must be an exact positive signed int64")
    if type(expected_session_id) is not str or type(expected_evaluator_challenge) is not str:
        raise TypeError("expected session and challenge must be exact strings")
    verified = _verify_envelope(
        envelope,
        SignedModelProducerAttestation,
        trust_registry,
    )
    assert type(verified) is ModelProducerAttestation
    if verified.sequence < minimum_sequence:
        raise SignatureTamperError("producer sequence is below the caller trusted minimum")
    if not hmac.compare_digest(verified.session_id, expected_session_id):
        raise SignatureTamperError("producer session does not match the evaluator session")
    if not hmac.compare_digest(verified.evaluator_challenge, expected_evaluator_challenge):
        raise SignatureTamperError("producer challenge does not match the evaluator challenge")
    return verified


def verify_model_verifier_attestation(
    envelope: SignedModelVerifierAttestation,
    trust_registry: dict[str, Ed25519PublicKeyRecord],
    *,
    minimum_sequence: int,
    expected_session_id: str,
) -> ModelVerifierAttestation:
    """Verify an independent verifier receipt against caller-owned trust."""

    if type(minimum_sequence) is not int or not 1 <= minimum_sequence <= MAX_INT64:
        raise ValueError("minimum_sequence must be an exact positive signed int64")
    if type(expected_session_id) is not str:
        raise TypeError("expected_session_id must be an exact string")
    verified = _verify_envelope(
        envelope,
        SignedModelVerifierAttestation,
        trust_registry,
    )
    assert type(verified) is ModelVerifierAttestation
    if verified.sequence < minimum_sequence:
        raise SignatureTamperError("verifier sequence is below the caller trusted minimum")
    if not hmac.compare_digest(verified.session_id, expected_session_id):
        raise SignatureTamperError("verifier session does not match the evaluator session")
    return verified


def verify_model_attestation_pair(
    producer: SignedModelProducerAttestation,
    verifier: SignedModelVerifierAttestation,
    producer_trust_registry: dict[str, Ed25519PublicKeyRecord],
    verifier_trust_registry: dict[str, Ed25519PublicKeyRecord],
    *,
    minimum_producer_sequence: int,
    minimum_verifier_sequence: int,
    expected_session_id: str,
    expected_evaluator_challenge: str,
) -> tuple[ModelProducerAttestation, ModelVerifierAttestation]:
    """Verify and bind independent producer/verifier receipts fail closed."""

    producer_payload = verify_model_producer_attestation(
        producer,
        producer_trust_registry,
        minimum_sequence=minimum_producer_sequence,
        expected_session_id=expected_session_id,
        expected_evaluator_challenge=expected_evaluator_challenge,
    )
    verifier_payload = verify_model_verifier_attestation(
        verifier,
        verifier_trust_registry,
        minimum_sequence=minimum_verifier_sequence,
        expected_session_id=expected_session_id,
    )
    if (
        producer_payload.producer_key_id == verifier_payload.verifier_key_id
        or producer_payload.producer_key_fingerprint
        == verifier_payload.verifier_key_fingerprint
    ):
        raise SignatureTamperError("producer and verifier identities and keys must be distinct")
    if verifier_payload.verifier_artifact_digest in {
        producer_payload.model_digest,
        producer_payload.runtime_wrapper_digest,
        producer_payload.runtime_bundle_digest,
        producer_payload.bwrap_digest,
        producer_payload.fixed_argv_digest,
        producer_payload.core_wheel_digest,
    }:
        raise SignatureTamperError("verifier artifact must be distinct from producer artifacts")
    if verifier_payload.verifier_profile_digest == producer_payload.profile_digest:
        raise SignatureTamperError("verifier profile must be distinct from producer profile")
    if verifier_payload.producer_receipt_digest != sha256_digest(producer):
        raise SignatureTamperError("verifier receipt does not bind the producer envelope")
    return producer_payload, verifier_payload


def parse_canonical_model_producer_attestation(
    document: bytes,
) -> SignedModelProducerAttestation:
    if type(document) is not bytes:
        raise TypeError("canonical attestation document must be exact bytes")
    envelope = SignedModelProducerAttestation.model_validate_json(document)
    if canonical_json_bytes(envelope) != document:
        raise ValueError("attestation envelope JSON is not canonical")
    return envelope


def parse_canonical_model_verifier_attestation(
    document: bytes,
) -> SignedModelVerifierAttestation:
    if type(document) is not bytes:
        raise TypeError("canonical attestation document must be exact bytes")
    envelope = SignedModelVerifierAttestation.model_validate_json(document)
    if canonical_json_bytes(envelope) != document:
        raise ValueError("attestation envelope JSON is not canonical")
    return envelope


MODEL_ATTESTATION_MODEL_TYPES = (
    ModelProducerAttestation,
    ModelVerifierAttestation,
    SignedModelProducerAttestation,
    SignedModelVerifierAttestation,
)

__all__ = [
    "ModelProducerAttestation",
    "ModelVerifierAttestation",
    "SignedModelProducerAttestation",
    "SignedModelVerifierAttestation",
    "MODEL_ATTESTATION_MODEL_TYPES",
    "attestation_signing_bytes",
    "parse_canonical_model_producer_attestation",
    "parse_canonical_model_verifier_attestation",
    "verify_model_producer_attestation",
    "verify_model_verifier_attestation",
    "verify_model_attestation_pair",
]
