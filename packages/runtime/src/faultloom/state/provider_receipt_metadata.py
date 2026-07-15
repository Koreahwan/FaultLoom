"""Immutable provider identity used by canonical journal receipts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .provider_receipt_validation import (
    _FLOATING_SNAPSHOTS,
    _SECRET_REF_RE,
    _digest,
    _receipt_error,
    _require_digest,
    _require_identifier,
    _require_positive_int,
    _require_short_text,
)


@dataclass(frozen=True, slots=True)
class ProviderReceiptMetadata:
    """Exact immutable provider identity and secret-reference-safe request metadata."""

    call_id: str
    attempt: int
    attempt_id: str
    provider_id: str
    endpoint_id: str
    profile_digest: str
    requested_alias: str | None
    exact_snapshot: str
    runtime_version: str
    tokenizer_id: str
    tokenizer_version: str
    context_window: int
    prompt_digest: str
    compiled_context_digest: str
    tool_schema_digest: str
    credential_ref_uri: str
    credential_ref_purpose: str

    def __post_init__(self) -> None:
        for field in ("call_id", "attempt_id", "provider_id", "endpoint_id"):
            _require_identifier(getattr(self, field), field=field)
        _require_positive_int(self.attempt, field="attempt")
        for field in (
            "profile_digest",
            "prompt_digest",
            "compiled_context_digest",
            "tool_schema_digest",
        ):
            _require_digest(getattr(self, field), field=field)
        if self.requested_alias is not None:
            _require_short_text(self.requested_alias, field="requested_alias")
        exact_snapshot = _require_short_text(
            self.exact_snapshot, field="exact_snapshot"
        )
        if (
            exact_snapshot.casefold() in _FLOATING_SNAPSHOTS
            or "*" in exact_snapshot
        ):
            raise _receipt_error("requires an exact pinned snapshot")
        if self.requested_alias == exact_snapshot:
            raise _receipt_error(
                "must distinguish requested alias from exact snapshot"
            )
        for field in ("runtime_version", "tokenizer_id", "tokenizer_version"):
            _require_short_text(getattr(self, field), field=field)
        _require_positive_int(self.context_window, field="context_window")
        credential_ref_uri = _require_short_text(
            self.credential_ref_uri, field="credential_ref URI"
        )
        if not _SECRET_REF_RE.fullmatch(credential_ref_uri):
            raise _receipt_error("has invalid credential SecretRef URI")
        _require_identifier(
            self.credential_ref_purpose, field="credential_ref purpose"
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "context_window": self.context_window,
            "endpoint_id": self.endpoint_id,
            "exact_snapshot": self.exact_snapshot,
            "profile_digest": self.profile_digest,
            "provider_id": self.provider_id,
            "requested_alias": self.requested_alias,
            "runtime_version": self.runtime_version,
            "tokenizer_id": self.tokenizer_id,
            "tokenizer_version": self.tokenizer_version,
        }

    @property
    def dispatch_reservation_digest(self) -> str:
        return _digest(
            {
                "metadata": self.snapshot(),
                "purpose": "faultloom.provider-dispatch-reservation.v1",
                "request": self._request_identity(),
            }
        )

    def _request_identity(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "attempt_id": self.attempt_id,
            "call_id": self.call_id,
            "compiled_context_digest": self.compiled_context_digest,
            "context_window": self.context_window,
            "credential_ref": {
                "purpose": self.credential_ref_purpose,
                "schema_version": "0.1.0",
                "uri": self.credential_ref_uri,
            },
            "profile_digest": self.profile_digest,
            "prompt_digest": self.prompt_digest,
            "requested_alias": self.requested_alias,
            "tool_schema_digest": self.tool_schema_digest,
        }

    def request(self) -> dict[str, Any]:
        return {
            **self._request_identity(),
            "dispatch_reservation_digest": self.dispatch_reservation_digest,
            "endpoint_id": self.endpoint_id,
            "exact_snapshot": self.exact_snapshot,
            "provider_id": self.provider_id,
            "runtime_version": self.runtime_version,
            "tokenizer_id": self.tokenizer_id,
            "tokenizer_version": self.tokenizer_version,
        }

    @property
    def proxy_request_digest(self) -> str:
        return _digest(self.request())

    @property
    def binding_digest(self) -> str:
        return _digest(
            {
                "dispatch_reservation_digest": self.dispatch_reservation_digest,
                "metadata": self.snapshot(),
                "proxy_request_digest": self.proxy_request_digest,
                "purpose": "faultloom.provider-journal-binding.v1",
                "request": self._request_identity(),
            }
        )
