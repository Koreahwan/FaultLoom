from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Callable, Iterable

from faultloom_protocol import sha256_digest
from faultloom_protocol.base import MAX_INT64

from .common import ProviderAdapterError, ProviderPlaneError, SCHEMA_VERSION
from .intent import ProviderCallIntent
from .metadata import ProviderModelProfile, provider_tool_schema_digest

Clock = Callable[[], datetime]
MonotonicClock = Callable[[], int]


def _system_clock() -> datetime:
    return datetime.now(timezone.utc)


def _trusted_now(clock: Clock) -> datetime:
    value = clock()
    if type(value) is not datetime or value.tzinfo is not timezone.utc:
        raise ProviderAdapterError("provider adapter clock must return exact timezone.utc time")
    return value


def _trusted_monotonic(clock: MonotonicClock) -> int:
    value = clock()
    if type(value) is not int or not 0 <= value <= MAX_INT64:
        raise ProviderAdapterError("provider monotonic clock must return a signed-64 integer")
    return value


def _decode_ed25519_signature(value: str) -> bytes:
    if type(value) is not str:
        raise ProviderPlaneError("provider proxy attestation signature is invalid")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise ProviderPlaneError("provider proxy attestation signature is invalid") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value or len(decoded) != 64:
        raise ProviderPlaneError("provider proxy attestation signature is invalid")
    return decoded


def _profile_map(profiles: Iterable[ProviderModelProfile]) -> dict[str, ProviderModelProfile]:
    result: dict[str, ProviderModelProfile] = {}
    for candidate in profiles:
        profile = ProviderModelProfile.model_validate(candidate.model_dump(mode="python"))
        if profile.profile_id in result:
            raise ValueError("provider profile IDs must be unique")
        result[profile.profile_id] = profile
    if not result:
        raise ValueError("provider adapter requires at least one profile")
    return result


def _ceil_cost(tokens: int, rate: int) -> int:
    if tokens == 0 or rate == 0:
        return 0
    return (tokens * rate + 999_999) // 1_000_000


def _logical_request_digest(intent: ProviderCallIntent) -> str:
    # This identity deliberately excludes the selected profile and proxy so an
    # explicitly approved, checkpointed failover can remain the same logical
    # call.  Derived contract digests are included as first-class values so the
    # dispatch contract cannot be weakened by changing its representation.
    return sha256_digest(
        {
            "schema_version": SCHEMA_VERSION,
            "call_id": intent.call_id,
            "run_id": intent.run_id,
            "authority_digest": intent.authority_digest,
            "scope_epoch": intent.scope_epoch,
            "prompt_digest": intent.prompt_digest,
            "compiled_context_digest": intent.compiled_context_digest,
            "tool_schema_digest": provider_tool_schema_digest(intent.tools),
            "config_digest": sha256_digest(intent.generation_config),
            "prompt_bytes": intent.prompt_bytes,
            "input_tokens": intent.input_tokens,
            "tools": intent.tools,
            "output_schema_digest": intent.output_schema_digest,
            "generation_config": intent.generation_config,
            "budget": intent.budget,
            "action_ids": intent.action_ids,
            "policy_ref": intent.policy_ref,
            "data_policy_id": intent.data_policy_id,
            "data_consent_ref": intent.data_consent_ref,
            "credential_ref": intent.credential_ref,
        }
    )
