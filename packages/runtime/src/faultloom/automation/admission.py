"""Trusted issuer envelope for one admitted automation result."""

from __future__ import annotations

import base64
import hmac
from datetime import datetime
from typing import Annotated, Self

from cryptography.exceptions import InvalidSignature
from pydantic import BaseModel, ConfigDict, Field, model_validator

from faultloom_protocol import (
    AuthoritySigner,
    Ed25519PublicKeyRecord,
    canonical_json_bytes,
    load_public_key,
    sha256_digest,
)
from faultloom_protocol.base import AwareDatetime, Identifier, Sha256Digest

from .models import AuthorizedAutomationResult


class AutomationAdmissionError(ValueError):
    """An automation result lacks a valid trusted admission envelope."""


class _AdmissionModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        strict=True,
        validate_default=True,
    )


class AutomationAdmission(_AdmissionModel):
    admission_id: Identifier
    result: AuthorizedAutomationResult
    result_digest: Sha256Digest
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    issuer_key_id: Annotated[
        str, Field(pattern=r"^ed25519:sha256:[0-9a-f]{64}$")
    ]

    @model_validator(mode="after")
    def _result_and_lifetime_are_exact(self) -> Self:
        if self.result_digest != sha256_digest(self.result.model_dump(mode="json")):
            raise AutomationAdmissionError("automation admission result digest mismatch")
        if self.expires_at <= self.issued_at:
            raise AutomationAdmissionError("automation admission expiry must follow issuance")
        return self


class SignedAutomationAdmission(_AdmissionModel):
    payload: AutomationAdmission
    payload_digest: Sha256Digest
    signature: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")]

    @model_validator(mode="after")
    def _payload_digest_is_exact(self) -> Self:
        if self.payload_digest != sha256_digest(self.payload.model_dump(mode="json")):
            raise AutomationAdmissionError("automation admission payload digest mismatch")
        return self


_SIGNING_DOMAIN = "faultloom.automation-admission.v1"


def automation_admission_signing_bytes(
    payload: AutomationAdmission,
    payload_digest: str,
) -> bytes:
    if type(payload) is not AutomationAdmission:
        raise TypeError("automation admission payload must use the exact type")
    exact = AutomationAdmission.model_validate(payload.model_dump(mode="python"))
    observed = sha256_digest(exact.model_dump(mode="json"))
    if type(payload_digest) is not str or not hmac.compare_digest(
        payload_digest, observed
    ):
        raise AutomationAdmissionError("automation admission payload digest mismatch")
    return canonical_json_bytes(
        {
            "domain": _SIGNING_DOMAIN,
            "payload": exact.model_dump(mode="json"),
            "payload_digest": observed,
        }
    )


def sign_automation_admission(
    payload: AutomationAdmission,
    signer: AuthoritySigner,
) -> SignedAutomationAdmission:
    if type(payload) is not AutomationAdmission:
        raise TypeError("automation admission payload must use the exact type")
    if type(signer) is not AuthoritySigner:
        raise TypeError("automation admission signer must be an exact AuthoritySigner")
    exact = AutomationAdmission.model_validate(payload.model_dump(mode="python"))
    if not hmac.compare_digest(exact.issuer_key_id, signer.key_id):
        raise AutomationAdmissionError("automation admission issuer key differs from signer")
    digest = sha256_digest(exact.model_dump(mode="json"))
    return SignedAutomationAdmission(
        payload=exact,
        payload_digest=digest,
        signature=signer.sign(automation_admission_signing_bytes(exact, digest)),
    )


def verify_automation_admission(
    envelope: SignedAutomationAdmission,
    trust_registry: dict[str, Ed25519PublicKeyRecord],
    *,
    verification_time: datetime,
) -> AutomationAdmission:
    if type(envelope) is not SignedAutomationAdmission:
        raise AutomationAdmissionError("automation admission envelope has the wrong type")
    if type(trust_registry) is not dict or any(
        type(key_id) is not str or type(record) is not Ed25519PublicKeyRecord
        for key_id, record in trust_registry.items()
    ):
        raise AutomationAdmissionError(
            "automation admission trust registry must be an exact caller-supplied key map"
        )
    if (
        type(verification_time) is not datetime
        or verification_time.tzinfo is None
        or verification_time.utcoffset() is None
    ):
        raise AutomationAdmissionError("automation admission verification time is invalid")
    try:
        exact = SignedAutomationAdmission.model_validate(
            envelope.model_dump(mode="python")
        )
    except (TypeError, ValueError) as exc:
        raise AutomationAdmissionError("automation admission envelope is malformed") from exc

    record = trust_registry.get(exact.payload.issuer_key_id)
    if record is None:
        raise AutomationAdmissionError(
            "automation admission issuer key is absent from the trust registry"
        )
    if not hmac.compare_digest(record.key_id, exact.payload.issuer_key_id):
        raise AutomationAdmissionError("automation admission trust key is mismatched")
    try:
        public_key = load_public_key(record)
        public_key.verify(
            _decode_signature(exact.signature),
            automation_admission_signing_bytes(exact.payload, exact.payload_digest),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise AutomationAdmissionError(
            "automation admission Ed25519 signature verification failed"
        ) from exc
    if not exact.payload.issued_at <= verification_time < exact.payload.expires_at:
        raise AutomationAdmissionError("automation admission is outside its validity window")
    return exact.payload


def _decode_signature(value: str) -> bytes:
    if type(value) is not str:
        raise AutomationAdmissionError("automation admission signature must be text")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise AutomationAdmissionError(
            "automation admission signature is not canonical URL-safe base64"
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != 64 or not hmac.compare_digest(canonical, value):
        raise AutomationAdmissionError(
            "automation admission signature is not a canonical Ed25519 signature"
        )
    return decoded


__all__ = [
    "AutomationAdmission",
    "AutomationAdmissionError",
    "SignedAutomationAdmission",
    "automation_admission_signing_bytes",
    "sign_automation_admission",
    "verify_automation_admission",
]
