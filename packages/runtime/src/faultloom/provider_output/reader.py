from __future__ import annotations

import hmac
import json
from collections.abc import Callable
from typing import TYPE_CHECKING, NoReturn, final
from weakref import ReferenceType

from faultloom.state import StateStore
from faultloom_protocol import Ed25519PublicKeyRecord, canonical_json

from ._cursor import (
    MAX_CURSOR_BYTES,
    b64decode,
    b64encode,
    cursor_document,
    validated_invocation,
)
from ._events import event_artifacts, invocation_from_event
from ._receipt import ProviderReceiptVerifier
from ._reader_admission import ReaderAdmission, trusted_reader_admission
from ._store import ProviderOutputStoreBinding
from ._vault import identity_vault
from .contracts import (
    ProviderInvocationResult,
    ProviderOutputCursorKey,
    ProviderOutputIntegrityError,
    ProviderOutputPage,
    ProviderOutputScopeError,
)

MAX_PAGE_BYTES = 1024 * 1024
_CURSOR_KEY_COPY = ProviderOutputCursorKey._copy_for_hmac
_VERIFY_RECEIPT = ProviderReceiptVerifier.validate
_reader_vault: tuple[
    Callable[[ProviderOutputReader, ReaderAdmission], None],
    Callable[[ProviderOutputReader], ReaderAdmission],
] = identity_vault("provider output reader")
_bind_reader, _read_reader = _reader_vault


@final
class ProviderOutputReader:
    __slots__ = ("__weakref__",)

    def __init_subclass__(cls) -> None:
        raise ProviderOutputIntegrityError("ProviderOutputReader is final")

    def __init__(
        self,
        state: StateStore,
        cursor_key: ProviderOutputCursorKey,
        *,
        trusted_proxy_attestation_key: Ed25519PublicKeyRecord,
        maximum_page_bytes: int = 64 * 1024,
    ) -> None:
        if TYPE_CHECKING:
            self.__weakref__: ReferenceType[ProviderOutputReader] | None = None
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
        if type(material) is not bytes or len(material) != 32:
            raise ProviderOutputIntegrityError(
                "provider output cursor key capability is invalid"
            )
        derived_key = hmac.digest(
            material,
            b"faultloom.provider-output.cursor.v1\0"
            + binding.engagement_id.encode("utf-8"),
            "sha256",
        )
        _bind_reader(
            self,
            ReaderAdmission(
                binding,
                derived_key,
                maximum_page_bytes,
                ProviderReceiptVerifier(trusted_proxy_attestation_key),
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("ProviderOutputReader is immutable")

    def __delattr__(self, name: str) -> NoReturn:
        raise AttributeError("ProviderOutputReader is immutable")

    def _trusted_admission(self) -> ReaderAdmission:
        return trusted_reader_admission(
            _read_reader(self),
            maximum_page_bytes=MAX_PAGE_BYTES,
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
        admission = self._trusted_admission()
        validated = validated_invocation(invocation)
        output = validated.output_ref
        observation = output.observation
        if (
            type(expected_engagement_id) is not str
            or expected_engagement_id != admission.binding.engagement_id
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
            or not 1 <= max_bytes <= admission.maximum_page_bytes
        ):
            raise ProviderOutputIntegrityError(
                "provider output page size is outside the bounded policy"
            )
        _VERIFY_RECEIPT(admission.verifier, validated.receipt)
        binding = admission.binding
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
                None
                if cursor is None
                else self._decode_cursor(
                    validated,
                    cursor,
                    cursor_key=admission.cursor_key,
                )
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
                else self._encode_cursor(
                    validated,
                    page.next_cursor,
                    cursor_key=admission.cursor_key,
                )
            )
            return ProviderOutputPage(
                page.data,
                offset=page.offset,
                total_bytes=page.total_bytes,
                next_cursor=next_cursor,
            )

    @staticmethod
    def _encode_cursor(
        invocation: ProviderInvocationResult,
        inner_cursor: str,
        *,
        cursor_key: bytes,
    ) -> str:
        if type(inner_cursor) is not str or not inner_cursor:
            raise ProviderOutputIntegrityError(
                "provider output storage cursor is invalid"
            )
        payload = canonical_json(
            cursor_document(invocation, inner_cursor=inner_cursor)
        ).encode("utf-8")
        signature = hmac.digest(cursor_key, payload, "sha256")
        return f"{b64encode(payload)}.{b64encode(signature)}"

    @staticmethod
    def _decode_cursor(
        invocation: ProviderInvocationResult,
        cursor: str,
        *,
        cursor_key: bytes,
    ) -> str:
        try:
            if type(cursor) is not str or not 1 <= len(cursor) <= MAX_CURSOR_BYTES:
                raise ValueError("invalid cursor size")
            segments = cursor.split(".")
            if len(segments) != 2:
                raise ValueError("invalid cursor shape")
            payload = b64decode(segments[0])
            signature = b64decode(segments[1])
            expected_signature = hmac.digest(cursor_key, payload, "sha256")
            if not hmac.compare_digest(signature, expected_signature):
                raise ValueError("invalid cursor signature")
            document = json.loads(payload)
            if (
                type(document) is not dict
                or type(document.get("inner_cursor")) is not str
            ):
                raise ValueError("invalid cursor document")
            expected = cursor_document(
                invocation,
                inner_cursor=document["inner_cursor"],
            )
            if (
                document != expected
                or canonical_json(document).encode("utf-8") != payload
            ):
                raise ValueError("invalid cursor binding")
            return document["inner_cursor"]
        except Exception:
            raise ProviderOutputIntegrityError(
                "provider output cursor is invalid"
            ) from None
