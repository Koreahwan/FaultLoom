from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from faultloom.provider import (
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderPlane,
    ProviderProxyResult,
    ProxyOutcome,
)
from faultloom_protocol import (
    Ed25519PublicKeyRecord,
    canonical_json_bytes,
    load_public_key,
)

from .contracts import ProviderOutputIntegrityError

_KEY_DUMP = Ed25519PublicKeyRecord.model_dump
_KEY_VALIDATE = Ed25519PublicKeyRecord.model_validate
_RECEIPT_DUMP = ProviderCallReceipt.model_dump
_RECEIPT_VALIDATE = ProviderCallReceipt.model_validate
_RESULT_DUMP = ProviderProxyResult.model_dump
_MODEL_PROVIDER_PLANE = ProviderPlane.MODEL_PROVIDER
_COMPLETED_CALL = ProviderCallOutcome.COMPLETED
_COMPLETED_PROXY = ProxyOutcome.COMPLETED


def _decode_signature(value: str) -> bytes:
    if type(value) is not str:
        raise ProviderOutputIntegrityError(
            "provider output proxy attestation is invalid"
        )
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as exc:
        raise ProviderOutputIntegrityError(
            "provider output proxy attestation is invalid"
        ) from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value or len(decoded) != 64:
        raise ProviderOutputIntegrityError(
            "provider output proxy attestation is invalid"
        )
    return decoded


def _attestation_bytes(result: ProviderProxyResult) -> bytes:
    return canonical_json_bytes(
        {
            "purpose": "faultloom.provider_proxy_result.v1",
            "result": _RESULT_DUMP(
                result,
                mode="python",
                exclude={"attestation_signature"},
            ),
        }
    )


class ProviderReceiptVerifier:
    __slots__ = ("_key_id", "_public_key")

    def __init__(self, trusted_key: Ed25519PublicKeyRecord) -> None:
        if type(trusted_key) is not Ed25519PublicKeyRecord:
            raise ProviderOutputIntegrityError(
                "provider output requires an exact proxy attestation key"
            )
        try:
            validated = _KEY_VALIDATE(
                _KEY_DUMP(trusted_key, mode="python")
            )
            public_key = load_public_key(validated)
        except Exception as exc:
            raise ProviderOutputIntegrityError(
                "provider output proxy attestation key is invalid"
            ) from exc
        if not isinstance(public_key, Ed25519PublicKey):
            raise ProviderOutputIntegrityError(
                "provider output proxy attestation key is invalid"
            )
        self._key_id = validated.key_id
        self._public_key = public_key

    def validate(self, receipt: ProviderCallReceipt) -> ProviderCallReceipt:
        if type(receipt) is not ProviderCallReceipt:
            raise ProviderOutputIntegrityError(
                "provider output requires an exact provider receipt"
            )
        try:
            validated = _RECEIPT_VALIDATE(
                _RECEIPT_DUMP(receipt, mode="python")
            )
        except Exception as exc:
            raise ProviderOutputIntegrityError(
                "provider output receipt integrity failed"
            ) from exc
        result = validated.proxy_result
        if (
            validated.outcome is not _COMPLETED_CALL
            or type(result) is not ProviderProxyResult
            or result.outcome is not _COMPLETED_PROXY
            or validated.response_digest is None
            or validated.proxy_receipt_digest is None
        ):
            raise ProviderOutputIntegrityError(
                "provider output requires a completed provider receipt"
            )
        if result.plane is not _MODEL_PROVIDER_PLANE:
            raise ProviderOutputIntegrityError(
                "provider output receipt has a non-provider plane"
            )
        if (
            validated.proxy_attestation_key_id != self._key_id
            or result.attestation_key_id != self._key_id
        ):
            raise ProviderOutputIntegrityError(
                "provider output proxy attestation identity is invalid"
            )
        signature = _decode_signature(result.attestation_signature)
        try:
            self._public_key.verify(signature, _attestation_bytes(result))
        except Exception as exc:
            raise ProviderOutputIntegrityError(
                "provider output proxy attestation is invalid"
            ) from exc
        return validated
