from __future__ import annotations

import pytest

from faultloom.automation.provider_bridge import (
    MAX_PROVIDER_TOOL_ARGUMENT_BYTES,
    ProviderToolCallBridgeError,
    extract_provider_tool_arguments,
)
from faultloom.provider import ProviderCallOutcome, ProviderToolCall, provider_sha256_digest
from faultloom_protocol import AuthoritySigner

from tests.runtime.provider_test_fixtures import (
    FakeProxy,
    MemoryProviderReceiptJournal,
    PROXY_SIGNER,
    adapter,
    call_intent,
    completed_result,
    profile,
    pre_send_result,
    signed_proxy_result,
    tool,
)


def _receipt(
    *,
    tool_ids: tuple[str, ...] = ("lookup",),
    calls: tuple[ProviderToolCall, ...] = (),
    run_id: str = "run-bridge",
):
    specs = tuple(tool(tool_id) for tool_id in tool_ids)
    model = profile(tools=specs)
    intent = call_intent(tools=specs).model_copy(update={"run_id": run_id})

    def handler(request):
        base = completed_result(request, model, intent)
        payload = base.model_dump(
            mode="python",
            exclude={
                "attestation_key_id",
                "attestation_signature",
                "proxy_receipt_digest",
            },
        )
        payload["tool_calls"] = calls
        return signed_proxy_result(**payload)

    return adapter(
        (model,),
        FakeProxy(handler),
        MemoryProviderReceiptJournal(),
    ).call(intent)


def _call(tool_id: str = "lookup", arguments: str = '{"query":"fixture"}'):
    return ProviderToolCall(
        call_id="provider-call-1",
        tool_id=tool_id,
        name="lookup",
        arguments_json=arguments,
    )


def test_extracts_exact_arguments_from_a_valid_attested_receipt() -> None:
    receipt = _receipt(calls=(_call(),))

    assert extract_provider_tool_arguments(
        receipt,
        trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
        expected_run_id="run-bridge",
        expected_tool_id="lookup",
    ) == b'{"query":"fixture"}'


@pytest.mark.parametrize(
    ("calls", "tool_ids", "expected_tool_id", "expected_run_id", "max_bytes"),
    [
        ((), ("lookup",), "lookup", "run-bridge", 4096),  # missing tool
        ((_call(), _call("other")), ("lookup", "other"), "lookup", "run-bridge", 4096),
        ((_call(),), ("lookup", "other"), "other", "run-bridge", 4096),
        ((_call(),), ("lookup",), "lookup", "another-run", 4096),
        ((_call(arguments="x" * 100),), ("lookup",), "lookup", "run-bridge", 8),
    ],
)
def test_rejects_tool_call_shape_or_binding_mismatches(
    calls, tool_ids, expected_tool_id, expected_run_id, max_bytes
) -> None:
    receipt = _receipt(calls=calls, tool_ids=tool_ids)

    with pytest.raises(ProviderToolCallBridgeError):
        extract_provider_tool_arguments(
            receipt,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            expected_run_id=expected_run_id,
            expected_tool_id=expected_tool_id,
            max_bytes=max_bytes,
        )


def test_rejects_non_completed_provider_receipt() -> None:
    model = profile()
    intent = call_intent()
    receipt = adapter(
        (model,),
        FakeProxy(pre_send_result),
        MemoryProviderReceiptJournal(),
    ).call(intent)

    assert receipt.outcome is ProviderCallOutcome.PRE_SEND_FAILED
    with pytest.raises(ProviderToolCallBridgeError):
        extract_provider_tool_arguments(
            receipt,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            expected_run_id=intent.run_id,
            expected_tool_id="lookup",
        )


def test_rejects_tampered_receipt_before_reading_tool_arguments() -> None:
    receipt = _receipt(calls=(_call(),))
    forged = receipt.model_copy(update={"receipt_digest": provider_sha256_digest("wrong")})

    with pytest.raises(ProviderToolCallBridgeError):
        extract_provider_tool_arguments(
            forged,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            expected_run_id="run-bridge",
            expected_tool_id="lookup",
        )


def test_provider_wire_bound_cannot_be_raised() -> None:
    receipt = _receipt(calls=(_call(),))

    with pytest.raises(ProviderToolCallBridgeError):
        extract_provider_tool_arguments(
            receipt,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            expected_run_id="run-bridge",
            expected_tool_id="lookup",
            max_bytes=MAX_PROVIDER_TOOL_ARGUMENT_BYTES + 1,
        )


def test_rejects_self_consistent_but_unsigned_proxy_result() -> None:
    receipt = _receipt(calls=(_call(),))
    assert receipt.proxy_result is not None
    forged_result = receipt.proxy_result.model_copy(
        update={"attestation_signature": "unsigned"}
    )
    payload = receipt.model_dump(mode="python", exclude={"receipt_digest"})
    payload["proxy_result"] = forged_result
    payload["receipt_digest"] = provider_sha256_digest(payload)
    forged = type(receipt).model_validate(payload)

    with pytest.raises(ProviderToolCallBridgeError, match="attestation"):
        extract_provider_tool_arguments(
            forged,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            expected_run_id="run-bridge",
            expected_tool_id="lookup",
        )


def test_rejects_proxy_result_under_the_wrong_trusted_key() -> None:
    receipt = _receipt(calls=(_call(),))
    wrong_key = AuthoritySigner.from_private_bytes(
        bytes(range(64, 96))
    ).public_key_record

    with pytest.raises(ProviderToolCallBridgeError, match="attestation"):
        extract_provider_tool_arguments(
            receipt,
            trusted_proxy_attestation_key=wrong_key,
            expected_run_id="run-bridge",
            expected_tool_id="lookup",
        )
