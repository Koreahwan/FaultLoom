"""Strict wire contracts for local model producer and verifier attestations."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .base import Identifier, MAX_INT64, ProtocolModel, Sha256Digest

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


MODEL_ATTESTATION_MODEL_TYPES: tuple[type[ProtocolModel], ...] = (
    ModelProducerAttestation,
    ModelVerifierAttestation,
    SignedModelProducerAttestation,
    SignedModelVerifierAttestation,
)
