"""Ed25519 signing for authority state and cross-repository bundles."""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Literal, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, model_validator

from .base import (
    AwareDatetime,
    PROTOCOL_VERSION,
    ProtocolModel,
    Sha256Digest,
)
from .canonical import canonical_json_bytes, sha256_digest
from .models import AuthorityGrant, EngagementBundle, RunResultBundle, ScopeEpoch

Base64Url = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]+$")]
KeyId = Annotated[str, Field(pattern=r"^ed25519:sha256:[0-9a-f]{64}$")]
T = TypeVar("T", bound=ProtocolModel)


class SignaturePurpose(str, Enum):
    AUTHORITY_GRANT = "authority_grant"
    SCOPE_EPOCH = "scope_epoch"
    ENGAGEMENT_BUNDLE = "engagement_bundle"
    RUN_RESULT_BUNDLE = "run_result_bundle"


class SignatureBlock(ProtocolModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    protocol_version: Literal["0.1.0"] = PROTOCOL_VERSION
    purpose: SignaturePurpose
    key_id: KeyId
    sequence: Annotated[int, Field(ge=1)]
    signed_at: AwareDatetime
    expires_at: AwareDatetime | None = None
    payload_digest: Sha256Digest
    signature: Base64Url

    @model_validator(mode="after")
    def _expiry_ordered(self) -> "SignatureBlock":
        if self.expires_at is not None and self.expires_at <= self.signed_at:
            raise ValueError("signature expiry must follow signing time")
        return self


class Ed25519PublicKeyRecord(ProtocolModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: KeyId
    public_key: Base64Url


class SignedAuthorityGrant(ProtocolModel):
    payload: AuthorityGrant
    signature: SignatureBlock


class SignedScopeEpoch(ProtocolModel):
    payload: ScopeEpoch
    signature: SignatureBlock


class SignedEngagementBundle(ProtocolModel):
    payload: EngagementBundle
    signature: SignatureBlock


class SignedRunResultBundle(ProtocolModel):
    payload: RunResultBundle
    signature: SignatureBlock


class SignatureVerificationError(ValueError):
    """Base class for fail-closed signature verification failures."""


class UnknownKeyError(SignatureVerificationError):
    pass


class SignatureTamperError(SignatureVerificationError):
    pass


class SignatureExpiredError(SignatureVerificationError):
    pass


class SignatureNotYetValidError(SignatureVerificationError):
    pass


class SignatureRollbackError(SignatureVerificationError):
    pass


class AuthorityRevokedError(SignatureVerificationError):
    pass


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise SignatureTamperError("invalid URL-safe base64 signature material") from exc


def _public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _key_id(public_key: Ed25519PublicKey) -> str:
    digest = hashlib.sha256(_public_key_bytes(public_key)).hexdigest()
    return f"ed25519:sha256:{digest}"


class AuthoritySigner:
    """Non-serializable holder for an Ed25519 private key.

    Only the public key record can cross a protocol boundary. The private key
    is deliberately inaccessible through model serialization and is redacted
    from representations.
    """

    __slots__ = ("__private_key", "key_id")

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        self.__private_key = private_key
        self.key_id = _key_id(private_key.public_key())

    @classmethod
    def generate(cls) -> "AuthoritySigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, private_key: bytes) -> "AuthoritySigner":
        if len(private_key) != 32:
            raise ValueError("Ed25519 private key seed must contain exactly 32 bytes")
        return cls(Ed25519PrivateKey.from_private_bytes(private_key))

    @property
    def public_key_record(self) -> Ed25519PublicKeyRecord:
        public_key = self.__private_key.public_key()
        return Ed25519PublicKeyRecord(
            key_id=self.key_id,
            public_key=_b64_encode(_public_key_bytes(public_key)),
        )

    def sign(self, document: bytes) -> str:
        return _b64_encode(self.__private_key.sign(document))

    def __repr__(self) -> str:
        return f"AuthoritySigner(key_id={self.key_id!r}, private_key=<redacted>)"


def load_public_key(record: Ed25519PublicKeyRecord) -> Ed25519PublicKey:
    raw_key = _b64_decode(record.public_key)
    if len(raw_key) != 32:
        raise UnknownKeyError("Ed25519 public key must contain exactly 32 bytes")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(raw_key)
    except ValueError as exc:
        raise UnknownKeyError("invalid Ed25519 public key") from exc
    if _key_id(public_key) != record.key_id:
        raise UnknownKeyError("public key bytes do not match key_id")
    return public_key


def _signature_document(
    payload: ProtocolModel,
    *,
    purpose: SignaturePurpose,
    key_id: str,
    sequence: int,
    signed_at: datetime,
    expires_at: datetime | None,
    payload_digest: str,
) -> dict[str, object]:
    return {
        "algorithm": "Ed25519",
        "expires_at": expires_at,
        "key_id": key_id,
        "payload": payload,
        "payload_digest": payload_digest,
        "protocol_version": PROTOCOL_VERSION,
        "purpose": purpose.value,
        "sequence": sequence,
        "signed_at": signed_at,
    }


def signing_bytes(payload: ProtocolModel, block: SignatureBlock) -> bytes:
    """Reconstruct the exact language-neutral bytes covered by a signature."""

    return canonical_json_bytes(
        _signature_document(
            payload,
            purpose=block.purpose,
            key_id=block.key_id,
            sequence=block.sequence,
            signed_at=block.signed_at,
            expires_at=block.expires_at,
            payload_digest=block.payload_digest,
        )
    )


def _sign(
    payload: T,
    signer: AuthoritySigner,
    *,
    purpose: SignaturePurpose,
    sequence: int,
    signed_at: datetime,
    expires_at: datetime | None,
) -> SignatureBlock:
    payload_digest = sha256_digest(payload)
    unsigned = _signature_document(
        payload,
        purpose=purpose,
        key_id=signer.key_id,
        sequence=sequence,
        signed_at=signed_at,
        expires_at=expires_at,
        payload_digest=payload_digest,
    )
    signature = signer.sign(canonical_json_bytes(unsigned))
    return SignatureBlock(
        purpose=purpose,
        key_id=signer.key_id,
        sequence=sequence,
        signed_at=signed_at,
        expires_at=expires_at,
        payload_digest=payload_digest,
        signature=signature,
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sign_authority_grant(
    grant: AuthorityGrant,
    signer: AuthoritySigner,
    *,
    signed_at: datetime | None = None,
) -> SignedAuthorityGrant:
    grant = AuthorityGrant.model_validate(grant.model_dump(mode="python"))
    signed_at = signed_at or _utc_now()
    if signed_at < grant.issued_at:
        raise ValueError("authority cannot be signed before it is issued")
    block = _sign(
        grant,
        signer,
        purpose=SignaturePurpose.AUTHORITY_GRANT,
        sequence=grant.grant_version,
        signed_at=signed_at,
        expires_at=grant.expires_at,
    )
    return SignedAuthorityGrant(payload=grant, signature=block)


def sign_scope_epoch(
    epoch: ScopeEpoch,
    signer: AuthoritySigner,
    *,
    signed_at: datetime | None = None,
) -> SignedScopeEpoch:
    epoch = ScopeEpoch.model_validate(epoch.model_dump(mode="python"))
    signed_at = signed_at or _utc_now()
    if signed_at < epoch.issued_at:
        raise ValueError("scope epoch cannot be signed before it is issued")
    block = _sign(
        epoch,
        signer,
        purpose=SignaturePurpose.SCOPE_EPOCH,
        sequence=epoch.epoch,
        signed_at=signed_at,
        expires_at=epoch.expires_at,
    )
    return SignedScopeEpoch(payload=epoch, signature=block)


def sign_engagement_bundle(
    bundle: EngagementBundle,
    signer: AuthoritySigner,
    *,
    signed_at: datetime | None = None,
) -> SignedEngagementBundle:
    bundle = EngagementBundle.model_validate(bundle.model_dump(mode="python"))
    signed_at = signed_at or _utc_now()
    if signed_at < bundle.created_at:
        raise ValueError("engagement bundle cannot be signed before creation")
    block = _sign(
        bundle,
        signer,
        purpose=SignaturePurpose.ENGAGEMENT_BUNDLE,
        sequence=bundle.bundle_version,
        signed_at=signed_at,
        expires_at=bundle.expires_at,
    )
    return SignedEngagementBundle(payload=bundle, signature=block)


def sign_run_result_bundle(
    bundle: RunResultBundle,
    signer: AuthoritySigner,
    *,
    signed_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> SignedRunResultBundle:
    bundle = RunResultBundle.model_validate(bundle.model_dump(mode="python"))
    signed_at = signed_at or _utc_now()
    if signed_at < bundle.generated_at:
        raise ValueError("result bundle cannot be signed before generation")
    block = _sign(
        bundle,
        signer,
        purpose=SignaturePurpose.RUN_RESULT_BUNDLE,
        sequence=bundle.bundle_version,
        signed_at=signed_at,
        expires_at=expires_at,
    )
    return SignedRunResultBundle(payload=bundle, signature=block)


def _verify(
    payload: T,
    block: SignatureBlock,
    public_key_record: Ed25519PublicKeyRecord,
    *,
    purpose: SignaturePurpose,
    expected_sequence: int,
    minimum_sequence: int,
    now: datetime,
    maximum_clock_skew: timedelta,
) -> T:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("verification time must include a timezone")
    if block.purpose is not purpose:
        raise SignatureTamperError(
            f"signature purpose {block.purpose.value!r} does not match {purpose.value!r}"
        )
    if block.key_id != public_key_record.key_id:
        raise UnknownKeyError("signature key_id is not the supplied trusted key")
    if block.sequence != expected_sequence:
        raise SignatureTamperError("signature sequence does not match payload version")
    if block.sequence < minimum_sequence:
        raise SignatureRollbackError(
            f"sequence {block.sequence} is below trusted minimum {minimum_sequence}"
        )
    if block.signed_at > now + maximum_clock_skew:
        raise SignatureNotYetValidError("signature time is in the future")
    if block.expires_at is not None and now >= block.expires_at:
        raise SignatureExpiredError("signed artifact has expired")
    computed_digest = sha256_digest(payload)
    if computed_digest != block.payload_digest:
        raise SignatureTamperError("payload digest does not match signed digest")
    public_key = load_public_key(public_key_record)
    try:
        public_key.verify(_b64_decode(block.signature), signing_bytes(payload, block))
    except InvalidSignature as exc:
        raise SignatureTamperError("Ed25519 signature verification failed") from exc
    return payload


def verify_authority_grant(
    envelope: SignedAuthorityGrant,
    public_key: Ed25519PublicKeyRecord,
    *,
    now: datetime | None = None,
    minimum_version: int = 1,
    expected_grant_id: str | None = None,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> AuthorityGrant:
    envelope = SignedAuthorityGrant.model_validate(envelope.model_dump(mode="python"))
    now = now or _utc_now()
    grant = _verify(
        envelope.payload,
        envelope.signature,
        public_key,
        purpose=SignaturePurpose.AUTHORITY_GRANT,
        expected_sequence=envelope.payload.grant_version,
        minimum_sequence=minimum_version,
        now=now,
        maximum_clock_skew=maximum_clock_skew,
    )
    if envelope.signature.expires_at != grant.expires_at:
        raise SignatureTamperError("authority signature expiry differs from grant expiry")
    if expected_grant_id is not None and grant.grant_id != expected_grant_id:
        raise SignatureTamperError("grant_id does not match the expected authority")
    if now < grant.not_before:
        raise SignatureNotYetValidError("authority grant is not active yet")
    if now >= grant.expires_at:
        raise SignatureExpiredError("authority grant has expired")
    return grant


def verify_scope_epoch(
    envelope: SignedScopeEpoch,
    public_key: Ed25519PublicKeyRecord,
    *,
    now: datetime | None = None,
    minimum_epoch: int = 1,
    expected_grant_id: str | None = None,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> ScopeEpoch:
    envelope = SignedScopeEpoch.model_validate(envelope.model_dump(mode="python"))
    now = now or _utc_now()
    epoch = _verify(
        envelope.payload,
        envelope.signature,
        public_key,
        purpose=SignaturePurpose.SCOPE_EPOCH,
        expected_sequence=envelope.payload.epoch,
        minimum_sequence=minimum_epoch,
        now=now,
        maximum_clock_skew=maximum_clock_skew,
    )
    if envelope.signature.expires_at != epoch.expires_at:
        raise SignatureTamperError("scope signature expiry differs from epoch expiry")
    if expected_grant_id is not None and epoch.grant_id != expected_grant_id:
        raise SignatureTamperError("scope epoch belongs to a different grant")
    if epoch.revoked:
        raise AuthorityRevokedError(epoch.revocation_reason or "authority was revoked")
    return epoch


def verify_engagement_bundle(
    envelope: SignedEngagementBundle,
    public_key: Ed25519PublicKeyRecord,
    *,
    now: datetime | None = None,
    minimum_version: int = 1,
    expected_engagement_id: str | None = None,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> EngagementBundle:
    envelope = SignedEngagementBundle.model_validate(envelope.model_dump(mode="python"))
    now = now or _utc_now()
    bundle = _verify(
        envelope.payload,
        envelope.signature,
        public_key,
        purpose=SignaturePurpose.ENGAGEMENT_BUNDLE,
        expected_sequence=envelope.payload.bundle_version,
        minimum_sequence=minimum_version,
        now=now,
        maximum_clock_skew=maximum_clock_skew,
    )
    if envelope.signature.expires_at != bundle.expires_at:
        raise SignatureTamperError("bundle signature expiry differs from bundle expiry")
    if expected_engagement_id is not None and bundle.engagement_id != expected_engagement_id:
        raise SignatureTamperError("engagement_id does not match expected engagement")
    return bundle


def verify_run_result_bundle(
    envelope: SignedRunResultBundle,
    public_key: Ed25519PublicKeyRecord,
    *,
    now: datetime | None = None,
    minimum_version: int = 1,
    expected_engagement_id: str | None = None,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> RunResultBundle:
    envelope = SignedRunResultBundle.model_validate(envelope.model_dump(mode="python"))
    now = now or _utc_now()
    bundle = _verify(
        envelope.payload,
        envelope.signature,
        public_key,
        purpose=SignaturePurpose.RUN_RESULT_BUNDLE,
        expected_sequence=envelope.payload.bundle_version,
        minimum_sequence=minimum_version,
        now=now,
        maximum_clock_skew=maximum_clock_skew,
    )
    if expected_engagement_id is not None and bundle.engagement_id != expected_engagement_id:
        raise SignatureTamperError("result belongs to a different engagement")
    return bundle
