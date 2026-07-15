from __future__ import annotations

from tests.runtime.provider_test_fixtures import (
    FailureCode,
    FakeProxy,
    ProviderBudgetError,
    ProviderCallIntent,
    ProviderCallOutcome,
    ProviderPolicyError,
    ValidationError,
    adapter,
    call_intent,
    canonical_json,
    completed_result,
    digest,
    observed,
    pre_send_result,
    profile,
    pytest,
    sha256_digest,
    tool,
)

def test_explicit_conservative_lab_profile_accepts_missing_metadata() -> None:
    model = profile(
        profile_id="lab",
        snapshot="lab-snapshot",
        alias="lab-alias",
        exact=False,
        lab_only=True,
        context_window=2048,
        maximum_input_tokens=1024,
        maximum_output_tokens=256,
    )
    intent = call_intent(profile_id="lab")
    lab_metadata = observed(model, exact=False, missing=True)
    proxy = FakeProxy(
        lambda request: completed_result(
            request, model, intent, metadata=lab_metadata
        )
    )

    receipt = adapter((model,), proxy, live=False).call(intent)

    assert receipt.outcome is ProviderCallOutcome.COMPLETED
    assert receipt.actual_snapshot is None
    assert receipt.metadata_exact is False
    assert receipt.profile_digest == sha256_digest(model)


def test_tool_schema_drift_is_rejected_before_dispatch() -> None:
    configured_tool = tool("configured")
    changed_tool = tool("changed")
    model = profile(tools=(configured_tool,))
    intent = call_intent(tools=(changed_tool,))
    proxy = FakeProxy(pre_send_result)

    with pytest.raises(ProviderPolicyError, match="tool schema drift"):
        adapter((model,), proxy).call(intent)
    assert proxy.requests == []


def test_provider_echo_drift_is_rejected_after_send() -> None:
    configured_tool = tool()
    model = profile(tools=(configured_tool,))
    intent = call_intent(tools=(configured_tool,))
    proxy = FakeProxy(
        lambda request: completed_result(
            request,
            model,
            intent,
            accepted_tool_schema_digest=digest("drifted-tools"),
        )
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.REJECTED_RESPONSE
    assert receipt.failure_code is FailureCode.TOOL_SCHEMA_DRIFT


@pytest.mark.parametrize(
    ("field", "failure"),
    [
        ("prompt", FailureCode.PROMPT_DIGEST_MISMATCH),
        ("context", FailureCode.COMPILED_CONTEXT_DRIFT),
        ("output", FailureCode.OUTPUT_SCHEMA_DRIFT),
        ("config", FailureCode.CONFIG_DRIFT),
        ("policy", FailureCode.POLICY_DRIFT),
        ("data_policy", FailureCode.POLICY_DRIFT),
        ("consent", FailureCode.POLICY_DRIFT),
    ],
)
def test_prompt_output_schema_and_config_echo_drift_is_rejected(field: str, failure) -> None:
    model = profile()
    intent = call_intent()
    overrides = {
        "accepted_prompt_digest": digest("wrong") if field == "prompt" else None,
        "accepted_compiled_context_digest": (
            digest("wrong") if field == "context" else None
        ),
        "accepted_output_schema_digest": digest("wrong") if field == "output" else None,
        "accepted_config_digest": digest("wrong") if field == "config" else None,
        "accepted_policy_ref": "wrong-policy" if field == "policy" else None,
        "accepted_data_policy_id": (
            "wrong-data-policy" if field == "data_policy" else None
        ),
        "accepted_data_consent_ref": "wrong-consent" if field == "consent" else None,
    }
    proxy = FakeProxy(
        lambda request: completed_result(request, model, intent, **overrides)
    )

    receipt = adapter((model,), proxy).call(intent)

    assert receipt.outcome is ProviderCallOutcome.REJECTED_RESPONSE
    assert receipt.failure_code is failure


@pytest.mark.parametrize(
    "intent",
    [
        call_intent(input_tokens=1001),
        call_intent(prompt_bytes=20_000),
        call_intent(remaining_tokens=149),
        call_intent(remaining_cost=199),
        call_intent(max_output_tokens=201),
    ],
)
def test_budget_overflow_fails_before_dispatch(intent: ProviderCallIntent) -> None:
    model = profile()
    proxy = FakeProxy(pre_send_result)

    with pytest.raises(ProviderBudgetError):
        adapter((model,), proxy).call(intent)
    assert proxy.requests == []


def test_reported_usage_and_byte_overflow_are_rejected_after_send() -> None:
    model = profile()
    intent = call_intent()
    token_proxy = FakeProxy(
        lambda request: completed_result(
            request, model, intent, output_tokens=51
        )
    )
    token_receipt = adapter((model,), token_proxy).call(intent)
    assert token_receipt.failure_code is FailureCode.TOKEN_BUDGET_EXCEEDED

    second = call_intent(attempt_id="separate-attempt")
    byte_proxy = FakeProxy(
        lambda request: completed_result(
            request,
            model,
            second,
            bytes_received=model.maximum_response_bytes + 1,
        )
    )
    byte_receipt = adapter((model,), byte_proxy).call(second)
    assert byte_receipt.failure_code is FailureCode.BYTE_BUDGET_EXCEEDED


def test_raw_secret_field_is_not_admitted_and_only_secret_refs_are_receipted() -> None:
    payload = call_intent().model_dump(mode="python")
    payload["api_key"] = "super-secret-provider-key"
    with pytest.raises(ValidationError, match="api_key"):
        ProviderCallIntent.model_validate(payload)

    model = profile()
    intent = call_intent()
    proxy = FakeProxy(lambda request: completed_result(request, model, intent))
    receipt = adapter((model,), proxy).call(intent)
    serialized_request = canonical_json(proxy.requests[0])
    serialized_receipt = canonical_json(receipt)
    assert "super-secret-provider-key" not in serialized_request
    assert "super-secret-provider-key" not in serialized_receipt
    assert "secret://engagement/provider-key" in serialized_request
    assert "secret://engagement/provider-key" in serialized_receipt
