"""Signed, digest-bound approval for evidence disclosed to a model provider."""

from __future__ import annotations

import base64
import hmac
from datetime import datetime

from cryptography.exceptions import InvalidSignature

from faultloom_protocol import (
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    canonical_json_bytes,
    load_public_key,
    sha256_digest,
)

from .models import ModelDisclosureApproval, SignedModelDisclosureApproval


class ModelDisclosureError(ValueError):
    """A model disclosure approval is malformed, untrusted, or out of scope."""


_SIGNING_DOMAIN = "faultloom.model-disclosure-approval.v1"


def model_disclosure_approval_signing_bytes(
    payload: ModelDisclosureApproval,
    payload_digest: str,
) -> bytes:
    """Return domain-separated canonical bytes for one approval envelope."""

    if type(payload) is not ModelDisclosureApproval:
        raise TypeError("model disclosure payload must use the exact approval type")
    exact = ModelDisclosureApproval.model_validate(payload.model_dump(mode="python"))
    observed_digest = sha256_digest(exact.model_dump(mode="json"))
    if type(payload_digest) is not str or not hmac.compare_digest(
        payload_digest, observed_digest
    ):
        raise ModelDisclosureError("model disclosure payload digest mismatch")
    return canonical_json_bytes(
        {
            "domain": _SIGNING_DOMAIN,
            "payload": exact.model_dump(mode="json"),
            "payload_digest": observed_digest,
        }
    )


def sign_model_disclosure_approval(
    payload: ModelDisclosureApproval,
    signer: AuthoritySigner,
) -> SignedModelDisclosureApproval:
    """Sign one exact redacted excerpt approval with an operator-owned key."""

    if type(payload) is not ModelDisclosureApproval:
        raise TypeError("model disclosure payload must use the exact approval type")
    if type(signer) is not AuthoritySigner:
        raise TypeError("model disclosure signer must be an exact AuthoritySigner")
    exact = ModelDisclosureApproval.model_validate(payload.model_dump(mode="python"))
    if not hmac.compare_digest(exact.approver_key_id, signer.key_id):
        raise ModelDisclosureError("model disclosure approver key does not match signer")
    payload_digest = sha256_digest(exact.model_dump(mode="json"))
    return SignedModelDisclosureApproval(
        payload=exact,
        payload_digest=payload_digest,
        signature=signer.sign(
            model_disclosure_approval_signing_bytes(exact, payload_digest)
        ),
    )


def verify_model_disclosure_approval(
    envelope: SignedModelDisclosureApproval,
    trust_registry: dict[str, Ed25519PublicKeyRecord],
    *,
    expected_run_id: str,
    expected_evidence_id: str,
    expected_source_cas_digest: str,
    expected_redaction_digest: str,
    expected_content_digest: str,
    expected_media_type: str,
    expected_data_policy_id: str,
    expected_provider_id: str,
    verification_time: datetime,
) -> ModelDisclosureApproval:
    """Verify signature, lifetime, provider policy, and every evidence binding."""

    if type(envelope) is not SignedModelDisclosureApproval:
        raise ModelDisclosureError("model disclosure envelope has the wrong exact type")
    if type(trust_registry) is not dict or any(
        type(key_id) is not str or type(record) is not Ed25519PublicKeyRecord
        for key_id, record in trust_registry.items()
    ):
        raise ModelDisclosureError(
            "model disclosure trust registry must be an exact caller-supplied key map"
        )
    if type(verification_time) is not datetime or verification_time.tzinfo is None:
        raise ModelDisclosureError("model disclosure verification time must be timezone-aware")

    try:
        exact = SignedModelDisclosureApproval.model_validate(
            envelope.model_dump(mode="python")
        )
    except (TypeError, ValueError) as exc:
        raise ModelDisclosureError("model disclosure envelope is malformed") from exc

    payload = exact.payload
    record = trust_registry.get(payload.approver_key_id)
    if record is None:
        raise ModelDisclosureError(
            "model disclosure approver key is absent from the trust registry"
        )
    if not hmac.compare_digest(record.key_id, payload.approver_key_id):
        raise ModelDisclosureError("model disclosure trust registry key is mismatched")
    try:
        public_key = load_public_key(record)
        public_key.verify(
            _decode_signature(exact.signature),
            model_disclosure_approval_signing_bytes(payload, exact.payload_digest),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise ModelDisclosureError(
            "model disclosure Ed25519 signature verification failed"
        ) from exc

    expected = (
        ("run", payload.run_id, expected_run_id),
        ("evidence", payload.evidence_id, expected_evidence_id),
        ("source CAS", payload.source_cas_digest, expected_source_cas_digest),
        ("redaction", payload.redaction_digest, expected_redaction_digest),
        ("content", payload.content_digest, expected_content_digest),
        ("media type", payload.media_type, expected_media_type),
        ("data policy", payload.data_policy_id, expected_data_policy_id),
    )
    for label, observed, required in expected:
        if type(required) is not str or not hmac.compare_digest(observed, required):
            raise ModelDisclosureError(f"model disclosure {label} binding mismatch")
    if expected_provider_id not in payload.allowed_provider_ids:
        raise ModelDisclosureError("model provider is absent from disclosure approval")
    if not payload.approved_at <= verification_time < payload.expires_at:
        raise ModelDisclosureError("model disclosure approval is outside its validity window")
    return payload


def _decode_signature(value: str) -> bytes:
    if type(value) is not str:
        raise ModelDisclosureError("model disclosure signature must be text")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise ModelDisclosureError(
            "model disclosure signature is not canonical URL-safe base64"
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != 64 or not hmac.compare_digest(canonical, value):
        raise ModelDisclosureError(
            "model disclosure signature is not a canonical Ed25519 signature"
        )
    return decoded


__all__ = [
    "ModelDisclosureError",
    "model_disclosure_approval_signing_bytes",
    "sign_model_disclosure_approval",
    "verify_model_disclosure_approval",
]
