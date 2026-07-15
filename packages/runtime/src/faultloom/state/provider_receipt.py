"""Strict secret-free schema for canonical provider journal receipts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal, assert_never

from .canonical import canonical_json
from .provider_receipt_metadata import ProviderReceiptMetadata
from .provider_receipt_validation import (
    _RECEIPT_KEYS,
    _REQUEST_KEYS,
    _SECRET_REF_KEYS,
    _SNAPSHOT_KEYS,
    _digest,
    _receipt_error,
    _reject_raw_secret_fields,
    _require_digest,
    _require_identifier,
    _require_object,
    _require_positive_int,
    _require_short_text,
)


PROVIDER_RECEIPT_SCHEMA_VERSION = "faultloom.provider-journal-receipt.v1"


@dataclass(frozen=True, slots=True)
class ProviderCanonicalReceipt:
    """Canonical receipt whose indexes and digests are derived from typed metadata."""

    phase: Literal["reserved", "finalized"]
    reservation_receipt_digest: str | None
    metadata: ProviderReceiptMetadata
    result_digest: str | None

    def __post_init__(self) -> None:
        if type(self.metadata) is not ProviderReceiptMetadata:
            raise _receipt_error("metadata type is invalid")
        if type(self.phase) is not str or self.phase not in {"reserved", "finalized"}:
            raise _receipt_error("phase is invalid")
        match self.phase:
            case "reserved":
                if (
                    self.reservation_receipt_digest is not None
                    or self.result_digest is not None
                ):
                    raise _receipt_error("reserved phase cannot contain terminal data")
            case "finalized":
                _require_digest(
                    self.reservation_receipt_digest,
                    field="reservation_receipt_digest",
                )
                _require_digest(self.result_digest, field="result_digest")
            case _ as unreachable:
                assert_never(unreachable)

    def unsigned_document(self) -> dict[str, Any]:
        metadata = self.metadata
        return {
            "attempt": metadata.attempt,
            "attempt_id": metadata.attempt_id,
            "binding_digest": metadata.binding_digest,
            "call_id": metadata.call_id,
            "dispatch_reservation_digest": metadata.dispatch_reservation_digest,
            "phase": self.phase,
            "proxy_request_digest": metadata.proxy_request_digest,
            "request": metadata.request(),
            "reservation_receipt_digest": self.reservation_receipt_digest,
            "result_digest": self.result_digest,
            "schema_version": PROVIDER_RECEIPT_SCHEMA_VERSION,
            "snapshot": metadata.snapshot(),
        }

    @property
    def receipt_digest(self) -> str:
        return _digest(self.unsigned_document())

    def canonical_json_text(self) -> str:
        return canonical_json({**self.unsigned_document(), "receipt_digest": self.receipt_digest})

    @classmethod
    def reserved(cls, metadata: ProviderReceiptMetadata) -> ProviderCanonicalReceipt:
        return cls("reserved", None, metadata, None)

    def finalized(self, result_digest: str) -> ProviderCanonicalReceipt:
        if self.phase != "reserved":
            raise _receipt_error("finalization source is not reserved")
        return ProviderCanonicalReceipt(
            "finalized", self.receipt_digest, self.metadata, result_digest
        )

    @classmethod
    def parse(cls, value: str) -> ProviderCanonicalReceipt:
        if type(value) is not str or not value:
            raise _receipt_error("must be non-empty JSON")
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise _receipt_error("is invalid JSON") from exc
        _reject_raw_secret_fields(parsed)
        root = _require_object(parsed, keys=_RECEIPT_KEYS, field="root")
        snapshot = _require_object(root["snapshot"], keys=_SNAPSHOT_KEYS, field="snapshot")
        request = _require_object(root["request"], keys=_REQUEST_KEYS, field="request")
        secret_ref = _require_object(
            request["credential_ref"],
            keys=_SECRET_REF_KEYS,
            field="credential_ref",
        )
        if (
            root["schema_version"] != PROVIDER_RECEIPT_SCHEMA_VERSION
            or secret_ref["schema_version"] != "0.1.0"
        ):
            raise _receipt_error("schema version is invalid")
        metadata = ProviderReceiptMetadata(
            call_id=_require_identifier(root["call_id"], field="call_id"),
            attempt=_require_positive_int(root["attempt"], field="attempt"),
            attempt_id=_require_identifier(root["attempt_id"], field="attempt_id"),
            provider_id=_require_identifier(snapshot["provider_id"], field="provider_id"),
            endpoint_id=_require_identifier(snapshot["endpoint_id"], field="endpoint_id"),
            profile_digest=_require_digest(snapshot["profile_digest"], field="profile_digest"),
            requested_alias=(
                None
                if snapshot["requested_alias"] is None
                else _require_short_text(
                    snapshot["requested_alias"], field="requested_alias"
                )
            ),
            exact_snapshot=_require_short_text(snapshot["exact_snapshot"], field="exact_snapshot"),
            runtime_version=_require_short_text(
                snapshot["runtime_version"], field="runtime_version"
            ),
            tokenizer_id=_require_short_text(snapshot["tokenizer_id"], field="tokenizer_id"),
            tokenizer_version=_require_short_text(
                snapshot["tokenizer_version"], field="tokenizer_version"
            ),
            context_window=_require_positive_int(
                snapshot["context_window"], field="context_window"
            ),
            prompt_digest=_require_digest(request["prompt_digest"], field="prompt_digest"),
            compiled_context_digest=_require_digest(
                request["compiled_context_digest"],
                field="compiled_context_digest",
            ),
            tool_schema_digest=_require_digest(
                request["tool_schema_digest"], field="tool_schema_digest"
            ),
            credential_ref_uri=_require_short_text(secret_ref["uri"], field="credential_ref URI"),
            credential_ref_purpose=_require_identifier(
                secret_ref["purpose"], field="credential_ref purpose"
            ),
        )
        phase_value = root["phase"]
        if type(phase_value) is not str:
            raise _receipt_error("phase is invalid")
        if phase_value == "reserved":
            phase: Literal["reserved", "finalized"] = "reserved"
        elif phase_value == "finalized":
            phase = "finalized"
        else:
            raise _receipt_error("phase is invalid")
        reservation_digest = (
            None
            if root["reservation_receipt_digest"] is None
            else _require_digest(
                root["reservation_receipt_digest"],
                field="reservation_receipt_digest",
            )
        )
        result_digest = (
            None
            if root["result_digest"] is None
            else _require_digest(root["result_digest"], field="result_digest")
        )
        receipt = cls(phase, reservation_digest, metadata, result_digest)
        if canonical_json(parsed) != value or receipt.canonical_json_text() != value:
            raise _receipt_error("fields, indexes, or digests do not match")
        return receipt
