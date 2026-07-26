"""Signed, replay-controlled admission assertions for model utility evidence."""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Literal, Self

from pydantic import model_validator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from .base import MAX_INT64, ProtocolModel
from .canonical import canonical_json_bytes, sha256_digest
from .model_attestation_contracts import (
    AttestationSequence,
    Ed25519Signature,
    EvaluatorChallenge,
)
from .models import Ed25519PublicKeyRecord
from .signing import SignatureTamperError, UnknownKeyError, load_public_key
from .base import Identifier, Sha256Digest


class ModelUtilityAdmission(ProtocolModel):
    """Verifier assertion binding one exact completed utility evaluation."""

    verifier_key_id: Identifier
    verifier_key_fingerprint: Sha256Digest
    session_id: Identifier
    sequence: AttestationSequence
    evaluator_challenge: EvaluatorChallenge
    adapter_id: Identifier
    manifest_digest: Sha256Digest
    evaluation_digest: Sha256Digest
    plan_digest: Sha256Digest
    producer_envelope_digest: Sha256Digest
    verifier_envelope_digest: Sha256Digest
    outcome_coverage_digest: Sha256Digest
    outcome_coverage: tuple[ModelUtilityOutcomeCoverage, ...]
    evidence_source: Literal["real_model"]
    evaluation_state: Literal["fully_done"]
    outcome: Literal["passed"]
    safety_preserved: Literal[True]
    dispatched_oos: Literal[0]
    escaped_oos: Literal[0]
    tool_only_false_verified: Literal[0]

    @model_validator(mode="after")
    def _outcome_coverage_is_canonical(self) -> Self:
        if not self.outcome_coverage:
            raise ValueError("utility admission requires outcome coverage")
        if self.outcome_coverage_digest != model_utility_outcome_coverage_digest(
            self.outcome_coverage
        ):
            raise ValueError("utility admission outcome coverage digest mismatch")
        return self


class ModelUtilityOutcomeCoverage(ProtocolModel):
    """One signed evaluation outcome and its producer/verifier evidence binding."""

    case_id: Identifier
    case_digest: Sha256Digest
    arm: Literal["baseline", "treatment"]
    provider_receipt_digest: Sha256Digest
    response_artifact_digest: Sha256Digest
    producer_canonical_request_digest: Sha256Digest
    producer_parsed_response_digest: Sha256Digest
    producer_output_digest: Sha256Digest
    verifier_case_digest: Sha256Digest
    verifier_oracle_digest: Sha256Digest
    verifier_reset_evidence_digest: Sha256Digest
    verifier_replay_evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def _verifier_case_is_the_covered_case(self) -> Self:
        if self.verifier_case_digest != self.case_digest:
            raise ValueError("outcome coverage verifier case must match covered case")
        return self


class SignedModelUtilityAdmission(ProtocolModel):
    payload: ModelUtilityAdmission
    payload_digest: Sha256Digest
    signature: Ed25519Signature


def model_utility_admission_signing_bytes(
    payload: ModelUtilityAdmission, payload_digest: str
) -> bytes:
    """Return deterministic signing bytes for one utility-admission assertion."""

    canonical_payload = _snapshot(payload, ModelUtilityAdmission, label="utility admission")
    if type(canonical_payload) is not ModelUtilityAdmission:
        raise SignatureTamperError("utility admission has the wrong exact type")
    payload = canonical_payload
    if type(payload_digest) is not str or payload_digest != model_utility_admission_digest(payload):
        raise SignatureTamperError("payload_digest does not match canonical payload bytes")
    return canonical_json_bytes(
        {"payload": payload.model_dump(mode="json"), "payload_digest": payload_digest}
    )


def verify_model_utility_admission(
    envelope: SignedModelUtilityAdmission,
    trust_registry: dict[str, Ed25519PublicKeyRecord],
    *,
    minimum_sequence: int,
    expected_session_id: str,
    expected_evaluator_challenge: str,
) -> ModelUtilityAdmission:
    """Verify a verifier-signed utility-admission assertion fail closed."""

    if type(minimum_sequence) is not int or not 1 <= minimum_sequence <= MAX_INT64:
        raise ValueError("minimum_sequence must be an exact positive signed int64")
    if type(expected_session_id) is not str or type(expected_evaluator_challenge) is not str:
        raise TypeError("expected session and challenge must be exact strings")
    canonical_envelope = _snapshot(
        envelope, SignedModelUtilityAdmission, label="utility admission envelope"
    )
    if type(canonical_envelope) is not SignedModelUtilityAdmission:
        raise SignatureTamperError("utility admission envelope has the wrong exact type")
    signed = canonical_envelope
    payload = signed.payload
    if signed.payload_digest != model_utility_admission_digest(payload):
        raise SignatureTamperError("payload_digest does not match canonical payload bytes")
    public_key = _trusted_key(
        trust_registry,
        key_id=payload.verifier_key_id,
        key_fingerprint=payload.verifier_key_fingerprint,
    )
    try:
        public_key.verify(
            _decode_signature(signed.signature),
            model_utility_admission_signing_bytes(payload, signed.payload_digest),
        )
    except InvalidSignature as exc:
        raise SignatureTamperError("Ed25519 utility-admission signature verification failed") from exc
    if payload.sequence < minimum_sequence:
        raise SignatureTamperError("utility admission sequence is below the caller trusted minimum")
    if not hmac.compare_digest(payload.session_id, expected_session_id):
        raise SignatureTamperError("utility admission session does not match the evaluator session")
    if not hmac.compare_digest(payload.evaluator_challenge, expected_evaluator_challenge):
        raise SignatureTamperError("utility admission challenge does not match the evaluator challenge")
    return payload


def model_utility_admission_digest(value: ModelUtilityAdmission) -> str:
    """Hash the canonical primitive document for this standalone wire contract."""

    canonical_value = _snapshot(value, ModelUtilityAdmission, label="utility admission")
    if type(canonical_value) is not ModelUtilityAdmission:
        raise SignatureTamperError("utility admission has the wrong exact type")
    return sha256_digest(canonical_value.model_dump(mode="json"))


def model_utility_outcome_coverage_digest(
    coverage: tuple[ModelUtilityOutcomeCoverage, ...],
) -> str:
    """Hash the complete canonical outcome-coverage document."""

    if type(coverage) is not tuple or not coverage:
        raise SignatureTamperError("outcome coverage must be a non-empty exact tuple")
    canonical_coverage = tuple(
        _snapshot(item, ModelUtilityOutcomeCoverage, label="utility outcome coverage")
        for item in coverage
    )
    if any(type(item) is not ModelUtilityOutcomeCoverage for item in canonical_coverage):
        raise SignatureTamperError("outcome coverage has the wrong exact type")
    return sha256_digest(tuple(item.model_dump(mode="json") for item in canonical_coverage))


def canonical_model_utility_admission_envelope(
    envelope: SignedModelUtilityAdmission,
) -> bytes:
    """Serialize one exact utility-admission envelope as canonical JSON bytes."""

    canonical_envelope = _snapshot(
        envelope, SignedModelUtilityAdmission, label="utility admission envelope"
    )
    if type(canonical_envelope) is not SignedModelUtilityAdmission:
        raise SignatureTamperError("utility admission envelope has the wrong exact type")
    return canonical_json_bytes(canonical_envelope.model_dump(mode="json"))


def parse_canonical_model_utility_admission(
    document: bytes,
) -> SignedModelUtilityAdmission:
    """Parse only the exact canonical envelope representation."""

    if type(document) is not bytes:
        raise TypeError("canonical utility-admission document must be exact bytes")
    envelope = SignedModelUtilityAdmission.model_validate_json(document)
    if canonical_model_utility_admission_envelope(envelope) != document:
        raise ValueError("utility-admission envelope JSON is not canonical")
    return envelope


def _snapshot(
    value: object,
    model_type: type[ModelUtilityAdmission]
    | type[ModelUtilityOutcomeCoverage]
    | type[SignedModelUtilityAdmission],
    *,
    label: str,
) -> ModelUtilityAdmission | ModelUtilityOutcomeCoverage | SignedModelUtilityAdmission:
    """Rebuild exact local wire types without trusting ``model_copy`` storage."""

    if type(value) is not model_type:
        raise SignatureTamperError(f"{label} has the wrong exact type")
    storage = object.__getattribute__(value, "__dict__")
    fields = tuple(model_type.model_fields)
    if type(storage) is not dict or set(storage) != set(fields):
        raise SignatureTamperError(f"{label} is malformed")
    document = dict(storage)
    if model_type is ModelUtilityAdmission:
        raw_coverage = document["outcome_coverage"]
        if type(raw_coverage) is not tuple:
            raise SignatureTamperError("utility admission outcome coverage is malformed")
        coverage = tuple(
            _snapshot(
                item,
                ModelUtilityOutcomeCoverage,
                label="utility outcome coverage",
            )
            for item in raw_coverage
        )
        if any(type(item) is not ModelUtilityOutcomeCoverage for item in coverage):
            raise SignatureTamperError("utility admission outcome coverage is malformed")
        document["outcome_coverage"] = tuple(
            item.model_dump(mode="python") for item in coverage
        )
    if model_type is SignedModelUtilityAdmission:
        nested = _snapshot(
            document["payload"], ModelUtilityAdmission, label="utility admission payload"
        )
        if type(nested) is not ModelUtilityAdmission:
            raise SignatureTamperError("utility admission payload has the wrong exact type")
        document["payload"] = nested.model_dump(mode="python")
    try:
        rebuilt = model_type.model_validate(document)
    except (TypeError, ValueError) as exc:
        raise SignatureTamperError(f"{label} is malformed") from exc
    return rebuilt


def _trusted_key(
    trust_registry: dict[str, Ed25519PublicKeyRecord], *, key_id: str, key_fingerprint: str
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
        raise UnknownKeyError("utility-admission key_id is absent from the caller trust registry")
    public_key = load_public_key(record)
    raw_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    actual_fingerprint = f"sha256:{hashlib.sha256(raw_key).hexdigest()}"
    if not hmac.compare_digest(actual_fingerprint, key_fingerprint):
        raise UnknownKeyError("utility-admission key fingerprint does not match the trusted key")
    return public_key


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.b64decode(value + "==", altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise SignatureTamperError("signature is not canonical URL-safe base64") from exc
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise SignatureTamperError("signature is not a canonical Ed25519 signature")
    return decoded


__all__ = [
    "ModelUtilityAdmission",
    "ModelUtilityOutcomeCoverage",
    "SignedModelUtilityAdmission",
    "canonical_model_utility_admission_envelope",
    "model_utility_admission_digest",
    "model_utility_admission_signing_bytes",
    "model_utility_outcome_coverage_digest",
    "parse_canonical_model_utility_admission",
    "verify_model_utility_admission",
]
