"""Validation and digest primitives for provider receipt documents."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .canonical import canonical_json
from .types import StorageError


_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SECRET_REF_RE = re.compile(r"^secret://[A-Za-z0-9][A-Za-z0-9._/-]{0,501}$")
_FLOATING_SNAPSHOTS = frozenset({"current", "default", "latest", "preview", "stable"})
_SECRET_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "cookie",
        "credential",
        "password",
        "private_key",
        "refresh_token",
        "request_body",
        "secret",
        "session_cookie",
        "token",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "attempt",
        "attempt_id",
        "binding_digest",
        "call_id",
        "dispatch_reservation_digest",
        "phase",
        "proxy_request_digest",
        "receipt_digest",
        "request",
        "reservation_receipt_digest",
        "result_digest",
        "schema_version",
        "snapshot",
    }
)
_SNAPSHOT_KEYS = frozenset(
    {
        "context_window",
        "endpoint_id",
        "exact_snapshot",
        "profile_digest",
        "provider_id",
        "requested_alias",
        "runtime_version",
        "tokenizer_id",
        "tokenizer_version",
    }
)
_REQUEST_KEYS = frozenset(
    {
        "attempt",
        "attempt_id",
        "call_id",
        "compiled_context_digest",
        "context_window",
        "credential_ref",
        "dispatch_reservation_digest",
        "endpoint_id",
        "exact_snapshot",
        "profile_digest",
        "prompt_digest",
        "provider_id",
        "requested_alias",
        "runtime_version",
        "tokenizer_id",
        "tokenizer_version",
        "tool_schema_digest",
    }
)
_SECRET_REF_KEYS = frozenset({"purpose", "schema_version", "uri"})


def _receipt_error(reason: str) -> StorageError:
    return StorageError(f"canonical provider receipt {reason}")


def _require_identifier(value: Any, *, field: str) -> str:
    if type(value) is not str or not _IDENTIFIER_RE.fullmatch(value):
        raise _receipt_error(f"has invalid {field}")
    return value


def _require_digest(value: Any, *, field: str) -> str:
    if type(value) is not str or not _DIGEST_RE.fullmatch(value):
        raise _receipt_error(f"has invalid {field}")
    return value


def _require_positive_int(value: Any, *, field: str) -> int:
    if type(value) is not int or not 1 <= value < 2**63:
        raise _receipt_error(f"has invalid {field}")
    return value


def _require_short_text(value: Any, *, field: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 256:
        raise _receipt_error(f"has invalid {field}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _receipt_error(f"has invalid {field}") from exc
    return value


def _normalized_key(value: str) -> str:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", separated).strip("_").casefold()


def _reject_raw_secret_fields(value: Any, *, path: str = "$") -> None:
    if type(value) is dict:
        for key, child in value.items():
            key_text = str(key)
            if _normalized_key(key_text) in _SECRET_KEYS:
                raise _receipt_error(
                    f"contains forbidden raw secret field at {path}.{key_text}"
                )
            _reject_raw_secret_fields(child, path=f"{path}.{key_text}")
    elif type(value) is list:
        for index, child in enumerate(value):
            _reject_raw_secret_fields(child, path=f"{path}[{index}]")


def _require_object(
    value: Any,
    *,
    keys: frozenset[str],
    field: str,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise _receipt_error(f"has invalid {field} schema")
    return value


def _digest(value: Any) -> str:
    try:
        encoded = canonical_json(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _receipt_error("contains text that is not valid UTF-8") from exc
    return "sha256:" + hashlib.sha256(encoded).hexdigest()
