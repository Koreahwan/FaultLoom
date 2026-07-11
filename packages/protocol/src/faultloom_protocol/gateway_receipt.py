"""Authenticated T13-to-Gateway receipts for signed scope epochs.

The channel key is injected into the isolated T13 verifier and Gateway at boot.
It is never a protocol model and must not cross model, pack, or adapter RPC.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from datetime import datetime, timezone

from .base import PROTOCOL_VERSION, SCHEMA_VERSION
from .canonical import canonical_json_bytes
from .models import (
    Ed25519PublicKeyRecord,
    SignaturePurpose,
    SignedScopeEpoch,
)
from .signing import AuthorityRevokedError, verify_scope_epoch

_RECEIPT_MAGIC = b"FLER"
_RECEIPT_VERSION = 1
_MAX_RECEIPT_TTL_MILLIS = 5_000
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")


def _valid_boot_secret(value: bytes) -> bool:
    return isinstance(value, bytes) and len(value) == 32 and len(set(value)) >= 8


def _identifier(value: str, *, label: str) -> str:
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} must be a canonical protocol identifier")
    return value


def _millis(value: datetime, *, label: str) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    utc_value = value.astimezone(timezone.utc)
    if utc_value.microsecond % 1_000:
        raise ValueError(f"{label} must be aligned to a millisecond")
    milliseconds = _floor_millis(utc_value)
    if not 0 <= milliseconds <= 2**64 - 1:
        raise ValueError(f"{label} is outside the Gateway clock range")
    return milliseconds


def _canonical_time(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _floor_millis(value: datetime) -> int:
    utc_value = value.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = utc_value - epoch
    return (
        delta.days * 86_400_000
        + delta.seconds * 1_000
        + delta.microseconds // 1_000
    )


def _text(value: str, *, maximum: int = 256) -> bytes:
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > maximum:
        raise ValueError("receipt string is outside its bounded channel representation")
    return struct.pack(">H", len(encoded)) + encoded


def _optional_text(value: str | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + _text(value, maximum=16_384)


class GatewayEpochReceiptIssuer:
    """Non-serializable holder for one Gateway boot's authenticated channel."""

    __slots__ = (
        "__channel_key",
        "channel_key_id",
        "gateway_boot_id",
        "gateway_challenge",
    )

    def __init__(
        self,
        *,
        channel_key_id: str,
        channel_key: bytes,
        gateway_boot_id: str,
        gateway_challenge: bytes,
    ) -> None:
        self.channel_key_id = _identifier(channel_key_id, label="channel_key_id")
        self.gateway_boot_id = _identifier(gateway_boot_id, label="gateway_boot_id")
        if not _valid_boot_secret(channel_key):
            raise ValueError("channel_key must be a fresh high-entropy 32-byte boot secret")
        if not _valid_boot_secret(gateway_challenge):
            raise ValueError("gateway_challenge must be a fresh high-entropy 32-byte value")
        if hmac.compare_digest(channel_key, gateway_challenge):
            raise ValueError("channel_key and gateway_challenge must be independently generated")
        self.__channel_key = bytes(channel_key)
        self.gateway_challenge = bytes(gateway_challenge)

    def issue_scope_epoch_receipt(
        self,
        envelope: SignedScopeEpoch,
        authority_public_key: Ed25519PublicKeyRecord,
        *,
        minimum_epoch: int,
        expected_grant_id: str,
        verified_at: datetime,
        receipt_expires_at: datetime,
        nonce: bytes,
    ) -> bytes:
        """Verify a signed epoch with T13 before authenticating it for one boot."""

        envelope = SignedScopeEpoch.model_validate(envelope.model_dump(mode="python"))
        try:
            epoch = verify_scope_epoch(
                envelope,
                authority_public_key,
                now=verified_at,
                minimum_epoch=minimum_epoch,
                expected_grant_id=expected_grant_id,
            )
        except AuthorityRevokedError:
            # verify_scope_epoch raises this only after purpose, key, sequence,
            # time, digest, Ed25519, expiry, and grant binding all pass.
            if not envelope.payload.revoked:
                raise
            epoch = envelope.payload

        verified_at_millis = _millis(verified_at, label="verified_at")
        receipt_expires_at_millis = _millis(
            receipt_expires_at, label="receipt_expires_at"
        )
        epoch_expires_at_millis = _floor_millis(epoch.expires_at)
        if (
            receipt_expires_at_millis <= verified_at_millis
            or receipt_expires_at_millis - verified_at_millis
            > _MAX_RECEIPT_TTL_MILLIS
            or receipt_expires_at_millis > epoch_expires_at_millis
        ):
            raise ValueError("receipt TTL must be positive, at most five seconds, and within epoch")
        if not isinstance(nonce, bytes) or len(nonce) != 16 or len(set(nonce)) < 4:
            raise ValueError("nonce must be a fresh high-entropy 16-byte value")

        canonical_envelope = canonical_json_bytes(envelope)
        canonical_payload = canonical_json_bytes(epoch)
        if len(canonical_envelope) > 16_384:
            raise ValueError("canonical scope epoch envelope exceeds the Gateway bound")
        payload_digest = hashlib.sha256(canonical_payload).digest()
        expected_payload_digest = f"sha256:{payload_digest.hex()}"
        if envelope.signature.payload_digest != expected_payload_digest:
            raise ValueError("verified payload digest diverged from canonical payload bytes")

        receipt = bytearray(_RECEIPT_MAGIC)
        receipt.append(_RECEIPT_VERSION)
        receipt.extend(_text(self.channel_key_id))
        receipt.extend(_text(self.gateway_boot_id))
        receipt.extend(self.gateway_challenge)
        receipt.extend(_text(PROTOCOL_VERSION))
        receipt.extend(_text(SCHEMA_VERSION))
        receipt.extend(_text(SignaturePurpose.SCOPE_EPOCH.value))
        receipt.extend(struct.pack(">I", len(canonical_envelope)))
        receipt.extend(canonical_envelope)
        receipt.extend(hashlib.sha256(canonical_envelope).digest())
        receipt.extend(payload_digest)
        receipt.extend(_text(envelope.signature.key_id))
        receipt.extend(_text(epoch.grant_id))
        receipt.extend(struct.pack(">Q", epoch.epoch))
        receipt.extend(struct.pack(">Q", envelope.signature.sequence))
        receipt.extend(_text(_canonical_time(epoch.issued_at)))
        receipt.extend(_text(_canonical_time(epoch.expires_at)))
        receipt.append(int(epoch.revoked))
        receipt.extend(_optional_text(epoch.revocation_reason))
        receipt.extend(struct.pack(">Q", verified_at_millis))
        receipt.extend(struct.pack(">Q", receipt_expires_at_millis))
        receipt.extend(nonce)
        receipt.extend(hmac.digest(self.__channel_key, receipt, "sha256"))
        return bytes(receipt)

    def __repr__(self) -> str:
        return (
            "GatewayEpochReceiptIssuer("
            f"channel_key_id={self.channel_key_id!r}, "
            f"gateway_boot_id={self.gateway_boot_id!r}, "
            "channel_key=<redacted>, gateway_challenge=<redacted>)"
        )
