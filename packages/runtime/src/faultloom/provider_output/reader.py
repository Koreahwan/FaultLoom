from __future__ import annotations

import base64
import hmac
import json

from faultloom.state import StateStore
from faultloom_protocol import Ed25519PublicKeyRecord, canonical_json

from ._events import event_artifacts, invocation_from_event
from ._receipt import ProviderReceiptVerifier
from ._store import ProviderOutputStoreBinding
from .contracts import (
    ProviderInvocationResult,
    ProviderOutputCursorKey,
    ProviderOutputIntegrityError,
    ProviderOutputPage,
    ProviderOutputScopeError,
)

MAX_PAGE_BYTES = 1024 * 1024
MAX_CURSOR_BYTES = 4096
_CURSOR_KEY_COPY = ProviderOutputCursorKey._copy_for_hmac
_INVOCATION_DUMP = ProviderInvocationResult.model_dump
_INVOCATION_VALIDATE = ProviderInvocationResult.model_validate
_VERIFY_RECEIPT = ProviderReceiptVerifier.validate


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if type(value) is not str or not value or "=" in value:
        raise ValueError("invalid cursor segment")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _b64encode(decoded) != value:
        raise ValueError("noncanonical cursor segment")
    return decoded


def _validated_invocation(
    invocation: ProviderInvocationResult,
) -> ProviderInvocationResult:
    if type(invocation) is not ProviderInvocationResult:
        raise ProviderOutputIntegrityError(
            "provider output reader requires an exact invocation result"
        )
    try:
        validated = _INVOCATION_VALIDATE(
            _INVOCATION_DUMP(invocation, mode="python")
        )
    except Exception as exc:
        raise ProviderOutputIntegrityError(
            "provider invocation result integrity failed"
        ) from exc
    return validated


def _cursor_document(
    invocation: ProviderInvocationResult,
    *,
    inner_cursor: str,
) -> dict[str, object]:
    output = invocation.output_ref
    observation = output.observation
    return {
        "byte_length": observation.byte_length,
        "cas_digest": observation.cas_digest,
        "engagement_id": output.engagement_id,
        "event_hash": output.event_hash,
        "event_seq": output.event_seq,
        "inner_cursor": inner_cursor,
        "media_type": observation.media_type,
        "observation_id": observation.observation_id,
        "receipt_digest": output.receipt_digest,
        "run_id": observation.run_id,
        "version": 1,
    }


class ProviderOutputReader:
    __slots__ = (
        "_binding",
        "_cursor_key",
        "_maximum_page_bytes",
        "_receipt_verifier",
    )

    def __init__(
        self,
        state: StateStore,
        cursor_key: ProviderOutputCursorKey,
        *,
        trusted_proxy_attestation_key: Ed25519PublicKeyRecord,
        maximum_page_bytes: int = 64 * 1024,
    ) -> None:
        if (
            type(cursor_key) is not ProviderOutputCursorKey
            or type.__getattribute__(
                ProviderOutputCursorKey,
                "__dict__",
            ).get("_copy_for_hmac")
            is not _CURSOR_KEY_COPY
        ):
            raise ProviderOutputIntegrityError(
                "provider output cursor key capability is invalid"
            )
        if (
            type(maximum_page_bytes) is not int
            or not 1 <= maximum_page_bytes <= MAX_PAGE_BYTES
        ):
            raise ValueError("provider output maximum page size is invalid")
        binding = ProviderOutputStoreBinding(state)
        material = _CURSOR_KEY_COPY(cursor_key)
        self._cursor_key = hmac.digest(
            material,
            b"faultloom.provider-output.cursor.v1\0"
            + binding.engagement_id.encode("utf-8"),
            "sha256",
        )
        self._binding = binding
        self._maximum_page_bytes = maximum_page_bytes
        self._receipt_verifier = ProviderReceiptVerifier(
            trusted_proxy_attestation_key
        )

    def read_page(
        self,
        invocation: ProviderInvocationResult,
        *,
        expected_engagement_id: str,
        expected_run_id: str,
        cursor: str | None = None,
        max_bytes: int = 64 * 1024,
    ) -> ProviderOutputPage:
        validated = _validated_invocation(invocation)
        output = validated.output_ref
        observation = output.observation
        if (
            type(expected_engagement_id) is not str
            or expected_engagement_id != self._binding.engagement_id
            or output.engagement_id != expected_engagement_id
        ):
            raise ProviderOutputScopeError(
                "provider output engagement does not match the reader"
            )
        if (
            type(expected_run_id) is not str
            or observation.run_id != expected_run_id
        ):
            raise ProviderOutputScopeError(
                "provider output run does not match the reader"
            )
        if (
            type(max_bytes) is not int
            or not 1 <= max_bytes <= self._maximum_page_bytes
        ):
            raise ProviderOutputIntegrityError(
                "provider output page size is outside the bounded policy"
            )
        verifier = self._receipt_verifier
        if type(verifier) is not ProviderReceiptVerifier:
            raise ProviderOutputIntegrityError(
                "provider output receipt verifier capability changed"
            )
        _VERIFY_RECEIPT(verifier, validated.receipt)
        binding = self._binding
        with binding.lock():
            binding.verify()
            event = binding.find(validated.receipt)
            if event is None:
                raise ProviderOutputIntegrityError(
                    "provider output event is missing"
                )
            recovered = invocation_from_event(
                binding,
                validated.receipt,
                event,
                media_type=observation.media_type,
            )
            if recovered != validated:
                raise ProviderOutputIntegrityError(
                    "provider output reference does not match durable state"
                )
            reference, _ = event_artifacts(event)
            inner_cursor = (
                None if cursor is None else self._decode_cursor(validated, cursor)
            )
            page = binding.read_page(
                reference,
                cursor=inner_cursor,
                max_bytes=max_bytes,
            )
            if (
                type(page.data) is not bytes
                or type(page.offset) is not int
                or type(page.total_bytes) is not int
                or page.total_bytes != observation.byte_length
                or page.offset + len(page.data) > page.total_bytes
            ):
                raise ProviderOutputIntegrityError(
                    "provider output storage page is inconsistent"
                )
            next_cursor = (
                None
                if page.next_cursor is None
                else self._encode_cursor(validated, page.next_cursor)
            )
            return ProviderOutputPage(
                page.data,
                offset=page.offset,
                total_bytes=page.total_bytes,
                next_cursor=next_cursor,
            )

    def _encode_cursor(
        self,
        invocation: ProviderInvocationResult,
        inner_cursor: str,
    ) -> str:
        if type(inner_cursor) is not str or not inner_cursor:
            raise ProviderOutputIntegrityError(
                "provider output storage cursor is invalid"
            )
        payload = canonical_json(
            _cursor_document(invocation, inner_cursor=inner_cursor)
        ).encode("utf-8")
        signature = hmac.digest(self._cursor_key, payload, "sha256")
        return f"{_b64encode(payload)}.{_b64encode(signature)}"

    def _decode_cursor(
        self,
        invocation: ProviderInvocationResult,
        cursor: str,
    ) -> str:
        try:
            if type(cursor) is not str or not 1 <= len(cursor) <= MAX_CURSOR_BYTES:
                raise ValueError("invalid cursor size")
            segments = cursor.split(".")
            if len(segments) != 2:
                raise ValueError("invalid cursor shape")
            payload = _b64decode(segments[0])
            signature = _b64decode(segments[1])
            expected_signature = hmac.digest(self._cursor_key, payload, "sha256")
            if not hmac.compare_digest(signature, expected_signature):
                raise ValueError("invalid cursor signature")
            document = json.loads(payload)
            if type(document) is not dict or type(document.get("inner_cursor")) is not str:
                raise ValueError("invalid cursor document")
            expected = _cursor_document(
                invocation,
                inner_cursor=document["inner_cursor"],
            )
            if document != expected or canonical_json(document).encode("utf-8") != payload:
                raise ValueError("invalid cursor binding")
            return document["inner_cursor"]
        except Exception:
            raise ProviderOutputIntegrityError(
                "provider output cursor is invalid"
            ) from None
