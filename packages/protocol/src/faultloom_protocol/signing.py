"""Ed25519 signing for authority state and cross-repository bundles."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from .base import (
    MAX_INT64,
    PROTOCOL_VERSION,
    ProtocolModel,
    SCHEMA_VERSION,
    _ProtocolSnapshotError,
    _normalize_protocol_datetime,
    _snapshot_protocol_model,
)
from .canonical import canonical_json_bytes, sha256_digest
from .models import (
    AuthorityGrant,
    Ed25519PublicKeyRecord,
    EngagementBundle,
    RunResultBundle,
    ScopeEpoch,
    SignatureBlock,
    SignaturePurpose,
    SignedAuthorityGrant,
    SignedEngagementBundle,
    SignedRunResultBundle,
    SignedScopeEpoch,
)

T = TypeVar("T", bound=ProtocolModel)


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


@dataclass(frozen=True, slots=True)
class _TrustedPublicKey:
    key_id: str
    public_key: Ed25519PublicKey


_SCOPE_VERIFICATION_PROOF = object()


@dataclass(frozen=True, slots=True)
class _VerifiedScopeStatus:
    envelope: SignedScopeEpoch
    epoch: ScopeEpoch
    _proof: object

    def _proved(self) -> tuple[SignedScopeEpoch, ScopeEpoch]:
        if self._proof is not _SCOPE_VERIFICATION_PROOF:
            raise SignatureTamperError("scope verification proof is invalid")
        return self.envelope, self.epoch


def _b64_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise SignatureTamperError("invalid URL-safe base64 signature material") from exc
    if _b64_encode(decoded) != value:
        raise SignatureTamperError("URL-safe base64 value is not canonical")
    return decoded


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
            schema_version=SCHEMA_VERSION,
            key_id=self.key_id,
            public_key=_b64_encode(_public_key_bytes(public_key)),
        )

    def sign(self, document: bytes) -> str:
        return _b64_encode(self.__private_key.sign(document))

    def __repr__(self) -> str:
        return f"AuthoritySigner(key_id={self.key_id!r}, private_key=<redacted>)"


def _snapshot_trusted_public_key(
    record: Ed25519PublicKeyRecord,
) -> _TrustedPublicKey:
    try:
        record = _snapshot_protocol_model(
            record,
            Ed25519PublicKeyRecord,
            label="trusted public key",
        )
    except (TypeError, ValueError) as exc:
        raise UnknownKeyError("trusted public key record is malformed") from exc
    raw_key = _b64_decode(record.public_key)
    if len(raw_key) != 32:
        raise UnknownKeyError("Ed25519 public key must contain exactly 32 bytes")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(raw_key)
    except ValueError as exc:
        raise UnknownKeyError("invalid Ed25519 public key") from exc
    if _key_id(public_key) != record.key_id:
        raise UnknownKeyError("public key bytes do not match key_id")
    return _TrustedPublicKey(key_id=record.key_id, public_key=public_key)


def load_public_key(record: Ed25519PublicKeyRecord) -> Ed25519PublicKey:
    return _snapshot_trusted_public_key(record).public_key


def _signer_key_id(signer: AuthoritySigner) -> str:
    if type(signer) is not AuthoritySigner:
        raise TypeError("signer must be an exact AuthoritySigner")
    private_key = object.__getattribute__(signer, "_AuthoritySigner__private_key")
    derived_key_id = _key_id(private_key.public_key())
    stored_key_id = object.__getattribute__(signer, "key_id")
    if type(stored_key_id) is not str or stored_key_id != derived_key_id:
        raise ValueError("signer key_id does not match its private key")
    return derived_key_id


def _snapshot_payload(payload: T, *, label: str) -> T:
    payload_type = type(payload)
    if not issubclass(payload_type, ProtocolModel):
        raise ValueError(f"{label} must be an exact protocol model")
    return _snapshot_protocol_model(payload, payload_type, label=label)


def _snapshot_signed_model(
    value: object,
    model_type: type[T],
    *,
    label: str,
) -> T:
    try:
        return _snapshot_protocol_model(value, model_type, label=label)
    except _ProtocolSnapshotError as exc:
        if exc.value_kind == "datetime":
            if exc.path.endswith("expires_at"):
                raise SignatureExpiredError(str(exc)) from exc
            raise SignatureNotYetValidError(str(exc)) from exc
        if exc.value_kind == "integer" and ".signature.sequence" in exc.path:
            raise SignatureRollbackError(str(exc)) from exc
        raise SignatureTamperError(str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise SignatureTamperError(f"{label} is malformed") from exc


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

    payload = _snapshot_payload(payload, label="signature payload")
    block = _snapshot_protocol_model(
        block,
        SignatureBlock,
        label="signature block",
    )
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
    key_id = _signer_key_id(signer)
    payload_digest = sha256_digest(payload)
    unsigned = _signature_document(
        payload,
        purpose=purpose,
        key_id=key_id,
        sequence=sequence,
        signed_at=signed_at,
        expires_at=expires_at,
        payload_digest=payload_digest,
    )
    signature = AuthoritySigner.sign(signer, canonical_json_bytes(unsigned))
    return SignatureBlock(
        schema_version=SCHEMA_VERSION,
        purpose=purpose,
        key_id=key_id,
        sequence=sequence,
        signed_at=signed_at,
        expires_at=expires_at,
        payload_digest=payload_digest,
        signature=signature,
    )


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _signing_time(value: datetime | None, *, label: str) -> datetime:
    if value is None:
        return _utc_now()
    return _normalize_protocol_datetime(value, label=label)


def _verification_controls(
    now: datetime | None,
    maximum_clock_skew: timedelta,
    *,
    minimum_sequences: tuple[object, ...],
    expected_strings: tuple[tuple[str, object, bool], ...],
) -> datetime:
    verified_at = (
        _utc_now()
        if now is None
        else _normalize_protocol_datetime(now, label="verification time")
    )
    if (
        type(maximum_clock_skew) is not timedelta
        or maximum_clock_skew < timedelta(0)
    ):
        raise ValueError("maximum_clock_skew must be an exact non-negative timedelta")
    for minimum_sequence in minimum_sequences:
        if (
            type(minimum_sequence) is not int
            or not 1 <= minimum_sequence <= MAX_INT64
        ):
            raise ValueError("minimum trusted sequence must be within signed int64")
    for label, value, optional in expected_strings:
        if value is None and optional:
            continue
        if type(value) is not str:
            raise ValueError(f"{label} must be an exact string")
    return verified_at


def sign_authority_grant(
    grant: AuthorityGrant,
    signer: AuthoritySigner,
    *,
    signed_at: datetime | None = None,
) -> SignedAuthorityGrant:
    signed_at = _signing_time(signed_at, label="signed_at")
    grant = _snapshot_protocol_model(grant, AuthorityGrant, label="authority grant")
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
    return SignedAuthorityGrant(
        schema_version=SCHEMA_VERSION, payload=grant, signature=block
    )


def sign_scope_epoch(
    epoch: ScopeEpoch,
    signer: AuthoritySigner,
    *,
    signed_at: datetime | None = None,
) -> SignedScopeEpoch:
    signed_at = _signing_time(signed_at, label="signed_at")
    epoch = _snapshot_protocol_model(epoch, ScopeEpoch, label="scope epoch")
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
    return SignedScopeEpoch(schema_version=SCHEMA_VERSION, payload=epoch, signature=block)


def sign_engagement_bundle(
    bundle: EngagementBundle,
    signer: AuthoritySigner,
    *,
    signed_at: datetime | None = None,
) -> SignedEngagementBundle:
    signed_at = _signing_time(signed_at, label="signed_at")
    bundle = _snapshot_protocol_model(
        bundle,
        EngagementBundle,
        label="engagement bundle",
    )
    if signed_at < bundle.created_at:
        raise ValueError("engagement bundle cannot be signed before creation")
    if signed_at > bundle.run_manifest.started_at:
        raise ValueError("engagement bundle cannot be signed after the run starts")
    block = _sign(
        bundle,
        signer,
        purpose=SignaturePurpose.ENGAGEMENT_BUNDLE,
        sequence=bundle.bundle_version,
        signed_at=signed_at,
        expires_at=bundle.expires_at,
    )
    return SignedEngagementBundle(
        schema_version=SCHEMA_VERSION, payload=bundle, signature=block
    )


def sign_run_result_bundle(
    bundle: RunResultBundle,
    signer: AuthoritySigner,
    *,
    signed_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> SignedRunResultBundle:
    signed_at = _signing_time(signed_at, label="signed_at")
    expires_at = (
        None
        if expires_at is None
        else _normalize_protocol_datetime(expires_at, label="expires_at")
    )
    bundle = _snapshot_protocol_model(
        bundle,
        RunResultBundle,
        label="run result bundle",
    )
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
    return SignedRunResultBundle(
        schema_version=SCHEMA_VERSION, payload=bundle, signature=block
    )


def _verify(
    payload: T,
    block: SignatureBlock,
    trusted_public_key: _TrustedPublicKey,
    *,
    purpose: SignaturePurpose,
    expected_sequence: int,
    minimum_sequence: int,
    payload_issued_at: datetime,
    now: datetime,
    maximum_clock_skew: timedelta,
) -> T:
    now = _normalize_protocol_datetime(now, label="verification time")
    if type(minimum_sequence) is not int or not 1 <= minimum_sequence <= MAX_INT64:
        raise ValueError("minimum trusted sequence must be within signed int64")
    if block.purpose is not purpose:
        raise SignatureTamperError(
            f"signature purpose {block.purpose.value!r} does not match {purpose.value!r}"
        )
    if block.key_id != trusted_public_key.key_id:
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
    try:
        trusted_public_key.public_key.verify(
            _b64_decode(block.signature), signing_bytes(payload, block)
        )
    except InvalidSignature as exc:
        raise SignatureTamperError("Ed25519 signature verification failed") from exc
    if block.signed_at < payload_issued_at:
        raise SignatureNotYetValidError("signature is before payload issuance")
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
    now = _verification_controls(
        now,
        maximum_clock_skew,
        minimum_sequences=(minimum_version,),
        expected_strings=(("expected_grant_id", expected_grant_id, True),),
    )
    envelope = _snapshot_signed_model(
        envelope,
        SignedAuthorityGrant,
        label="signed authority grant",
    )
    trusted_public_key = _snapshot_trusted_public_key(public_key)
    grant = _verify(
        envelope.payload,
        envelope.signature,
        trusted_public_key,
        purpose=SignaturePurpose.AUTHORITY_GRANT,
        expected_sequence=envelope.payload.grant_version,
        minimum_sequence=minimum_version,
        payload_issued_at=envelope.payload.issued_at,
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


def _verify_scope_epoch_status(
    envelope: SignedScopeEpoch,
    public_key: Ed25519PublicKeyRecord,
    *,
    now: datetime | None = None,
    minimum_epoch: int = 1,
    expected_grant_id: str | None = None,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> _VerifiedScopeStatus:
    now = _verification_controls(
        now,
        maximum_clock_skew,
        minimum_sequences=(minimum_epoch,),
        expected_strings=(("expected_grant_id", expected_grant_id, True),),
    )
    envelope = _snapshot_signed_model(
        envelope,
        SignedScopeEpoch,
        label="signed scope epoch",
    )
    trusted_public_key = _snapshot_trusted_public_key(public_key)
    epoch = _verify(
        envelope.payload,
        envelope.signature,
        trusted_public_key,
        purpose=SignaturePurpose.SCOPE_EPOCH,
        expected_sequence=envelope.payload.epoch,
        minimum_sequence=minimum_epoch,
        payload_issued_at=envelope.payload.issued_at,
        now=now,
        maximum_clock_skew=maximum_clock_skew,
    )
    if envelope.signature.expires_at != epoch.expires_at:
        raise SignatureTamperError("scope signature expiry differs from epoch expiry")
    if expected_grant_id is not None and epoch.grant_id != expected_grant_id:
        raise SignatureTamperError("scope epoch belongs to a different grant")
    return _VerifiedScopeStatus(
        envelope=envelope,
        epoch=epoch,
        _proof=_SCOPE_VERIFICATION_PROOF,
    )


def verify_scope_epoch(
    envelope: SignedScopeEpoch,
    public_key: Ed25519PublicKeyRecord,
    *,
    now: datetime | None = None,
    minimum_epoch: int = 1,
    expected_grant_id: str | None = None,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> ScopeEpoch:
    status = _verify_scope_epoch_status(
        envelope,
        public_key,
        now=now,
        minimum_epoch=minimum_epoch,
        expected_grant_id=expected_grant_id,
        maximum_clock_skew=maximum_clock_skew,
    )
    _, epoch = status._proved()
    if epoch.revoked:
        raise AuthorityRevokedError(epoch.revocation_reason or "authority was revoked")
    return epoch


def verify_engagement_bundle(
    envelope: SignedEngagementBundle,
    public_key: Ed25519PublicKeyRecord,
    *,
    authority_public_key: Ed25519PublicKeyRecord,
    now: datetime | None = None,
    minimum_version: int = 1,
    minimum_authority_version: int = 1,
    expected_engagement_id: str | None = None,
    expected_grant_id: str | None = None,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> EngagementBundle:
    now = _verification_controls(
        now,
        maximum_clock_skew,
        minimum_sequences=(
            minimum_version,
            minimum_authority_version,
        ),
        expected_strings=(
            ("expected_engagement_id", expected_engagement_id, True),
            ("expected_grant_id", expected_grant_id, True),
        ),
    )
    envelope = _snapshot_signed_model(
        envelope,
        SignedEngagementBundle,
        label="signed engagement bundle",
    )
    trusted_public_key = _snapshot_trusted_public_key(public_key)
    bundle = _verify(
        envelope.payload,
        envelope.signature,
        trusted_public_key,
        purpose=SignaturePurpose.ENGAGEMENT_BUNDLE,
        expected_sequence=envelope.payload.bundle_version,
        minimum_sequence=minimum_version,
        payload_issued_at=envelope.payload.created_at,
        now=now,
        maximum_clock_skew=maximum_clock_skew,
    )
    if envelope.signature.expires_at != bundle.expires_at:
        raise SignatureTamperError("bundle signature expiry differs from bundle expiry")
    if envelope.signature.signed_at > bundle.run_manifest.started_at:
        raise SignatureTamperError("engagement bundle was signed after the run started")
    if expected_engagement_id is not None and bundle.engagement_id != expected_engagement_id:
        raise SignatureTamperError("engagement_id does not match expected engagement")
    verify_authority_grant(
        bundle.authority_grant,
        authority_public_key,
        now=now,
        minimum_version=minimum_authority_version,
        expected_grant_id=expected_grant_id,
        maximum_clock_skew=maximum_clock_skew,
    )
    return bundle


def verify_run_result_bundle(
    envelope: SignedRunResultBundle,
    public_key: Ed25519PublicKeyRecord,
    *,
    now: datetime | None = None,
    minimum_version: int = 1,
    expected_engagement_id: str | None = None,
    expected_run_id: str,
    expected_run_manifest_digest: str,
    expected_authority_digest: str,
    maximum_clock_skew: timedelta = timedelta(minutes=5),
) -> RunResultBundle:
    now = _verification_controls(
        now,
        maximum_clock_skew,
        minimum_sequences=(minimum_version,),
        expected_strings=(
            ("expected_engagement_id", expected_engagement_id, True),
            ("expected_run_id", expected_run_id, False),
            ("expected_run_manifest_digest", expected_run_manifest_digest, False),
            ("expected_authority_digest", expected_authority_digest, False),
        ),
    )
    envelope = _snapshot_signed_model(
        envelope,
        SignedRunResultBundle,
        label="signed run result bundle",
    )
    trusted_public_key = _snapshot_trusted_public_key(public_key)
    bundle = _verify(
        envelope.payload,
        envelope.signature,
        trusted_public_key,
        purpose=SignaturePurpose.RUN_RESULT_BUNDLE,
        expected_sequence=envelope.payload.bundle_version,
        minimum_sequence=minimum_version,
        payload_issued_at=envelope.payload.generated_at,
        now=now,
        maximum_clock_skew=maximum_clock_skew,
    )
    if expected_engagement_id is not None and bundle.engagement_id != expected_engagement_id:
        raise SignatureTamperError("result belongs to a different engagement")
    if bundle.run_id != expected_run_id:
        raise SignatureTamperError("result belongs to a different run")
    if bundle.run_manifest_digest != expected_run_manifest_digest:
        raise SignatureTamperError("result run manifest digest does not match expected")
    if bundle.authority_digest != expected_authority_digest:
        raise SignatureTamperError("result authority digest does not match expected")
    return bundle
