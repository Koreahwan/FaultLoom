"""Fail-closed bridge from an attested provider tool call to model bytes.

The provider receipt is the trust boundary for model-produced tool calls.  This
module deliberately does not parse the JSON arguments or dispatch a tool; the
automation coordinator owns those later, separately bounded steps.
"""

from __future__ import annotations

from faultloom.provider import (
    OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES,
    ProviderCallOutcome,
    ProviderCallReceipt,
    ProviderProxyResult,
    ProviderToolCall,
    ProxyOutcome,
)
from faultloom.provider_output._receipt import ProviderReceiptVerifier
from faultloom_protocol import Ed25519PublicKeyRecord


# Backwards-compatible automation name backed by the provider's public wire
# contract, so parser and bridge limits cannot drift independently.
MAX_PROVIDER_TOOL_ARGUMENT_BYTES = OPENAI_COMPATIBLE_MAX_TOOL_ARGUMENT_BYTES


class ProviderToolCallBridgeError(ValueError):
    """A provider tool call could not be admitted to the automation boundary."""


def extract_provider_tool_arguments(
    receipt: ProviderCallReceipt,
    *,
    trusted_proxy_attestation_key: Ed25519PublicKeyRecord,
    expected_run_id: str,
    expected_tool_id: str,
    max_bytes: int = MAX_PROVIDER_TOOL_ARGUMENT_BYTES,
) -> bytes:
    """Return the exact UTF-8 arguments for one attested provider tool call.

    The caller-pinned Ed25519 key is mandatory.  The existing provider receipt
    verifier revalidates the receipt and verifies its nested proxy attestation
    before any value is returned.  The returned bytes remain unparsed and
    untrusted; callers must apply their own JSON/schema/scope checks.
    """

    if type(receipt) is not ProviderCallReceipt:
        raise ProviderToolCallBridgeError("provider tool bridge requires an exact receipt")
    if type(expected_run_id) is not str or not expected_run_id:
        raise ProviderToolCallBridgeError("expected run ID must be an exact non-empty string")
    if type(expected_tool_id) is not str or not expected_tool_id:
        raise ProviderToolCallBridgeError("expected tool ID must be an exact non-empty string")
    if (
        type(max_bytes) is not int
        or not 1 <= max_bytes <= MAX_PROVIDER_TOOL_ARGUMENT_BYTES
    ):
        raise ProviderToolCallBridgeError("tool argument byte bound is outside the provider limit")

    try:
        validated = ProviderReceiptVerifier(
            trusted_proxy_attestation_key
        ).validate(receipt)
    except Exception as exc:
        raise ProviderToolCallBridgeError(
            "provider receipt failed attestation validation"
        ) from exc

    if validated.run_id != expected_run_id:
        raise ProviderToolCallBridgeError("provider receipt belongs to another run")
    if validated.outcome is not ProviderCallOutcome.COMPLETED:
        raise ProviderToolCallBridgeError("provider receipt is not completed")

    result = validated.proxy_result
    if type(result) is not ProviderProxyResult:
        raise ProviderToolCallBridgeError("provider receipt has no exact proxy result")
    if result.outcome is not ProxyOutcome.COMPLETED:
        raise ProviderToolCallBridgeError("provider proxy result is not completed")
    if expected_tool_id not in validated.provider_tool_ids:
        raise ProviderToolCallBridgeError("expected tool is absent from the provider contract")

    calls = result.tool_calls
    if len(calls) != 1:
        raise ProviderToolCallBridgeError("provider result must contain exactly one tool call")
    call = calls[0]
    if type(call) is not ProviderToolCall:
        raise ProviderToolCallBridgeError("provider result contains a non-canonical tool call")
    if call.tool_id != expected_tool_id:
        raise ProviderToolCallBridgeError("provider tool call ID does not match the expected tool")
    try:
        arguments = call.arguments_json.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise ProviderToolCallBridgeError("provider tool arguments are not valid UTF-8") from exc
    if len(arguments) > max_bytes:
        raise ProviderToolCallBridgeError("provider tool arguments exceed the requested byte bound")
    return arguments


__all__ = [
    "MAX_PROVIDER_TOOL_ARGUMENT_BYTES",
    "ProviderToolCallBridgeError",
    "extract_provider_tool_arguments",
]
