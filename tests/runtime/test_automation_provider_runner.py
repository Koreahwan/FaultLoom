from __future__ import annotations

import json
import socket
from typing import cast

import pytest

from faultloom.automation.provider_contract import (
    MODEL_TURN_TOOL_ID,
    MODEL_TURN_WIRE_NAME,
    model_turn_provider_tool_spec,
)
from faultloom.automation.provider_prompt import (
    OneShotReasoningPromptResolver,
    ReasoningPromptError,
)
from faultloom.automation.models import AutomationRequest, ReasoningTurnRequest
from faultloom.automation.provider_runner import (
    ProviderAutomationRunnerError,
    run_provider_automation_turn,
)
from faultloom.provider import (
    ProviderAdapter,
    ProviderCallIntent,
    ProviderModelProfile,
    ProviderProxyRequest,
    ProviderProxyResult,
    ProviderToolCall,
)
from faultloom_protocol import sha256_digest

from tests.runtime.provider_test_fixtures import (
    FakeProxy,
    MemoryProviderReceiptJournal,
    PROXY_SIGNER,
    adapter,
    call_intent,
    completed_result,
    pre_send_result,
    profile,
    signed_proxy_result,
)
from tests.runtime.test_authorized_automation import (
    DISCLOSURE_SIGNER,
    _coordinator,  # pyright: ignore[reportPrivateUsage]
    _request,  # pyright: ignore[reportPrivateUsage]
)


def _model_turn_arguments() -> str:
    evidence_id = _request().observations.evidence_refs[0].evidence_id
    return json.dumps(
        {
            "hypotheses": [
                {
                    "proposal_id": "hypothesis.provider.1",
                    "statement": "The bounded owned response needs independent replay.",
                    "provenance": ["behavior"],
                    "supporting_evidence_ids": [evidence_id],
                    "contradicting_evidence_ids": [],
                    "prerequisite_ids": [],
                }
            ],
            "negative_results": [],
            "actions": [],
            "stop_reason": "Await independent verification.",
        },
        separators=(",", ":"),
    )


def _base_intent(request: AutomationRequest) -> ProviderCallIntent:
    template = call_intent(
        tools=(model_turn_provider_tool_spec(),),
        input_tokens=1,
        remaining_tokens=8_000,
        remaining_cost=10_000,
    )
    return ProviderCallIntent.model_validate(
        template.model_copy(
            update={
                "run_id": request.observations.run_id,
                "authority_digest": sha256_digest(request.authority_grant),
                "data_policy_id": request.authority_grant.provider_policy.data_policy_id,
                "requested_at": request.issued_at,
                "budget": template.budget.model_copy(
                    update={
                        "maximum_input_tokens": 6_000,
                        "remaining_model_tokens": 8_000,
                        "remaining_cost_microunits": 10_000,
                    }
                ),
            }
        ).model_dump(mode="python")
    )


def _profile(
    request: AutomationRequest,
    *,
    provider_id: str = "provider.test",
    snapshot: str = "frontier-2030-01-01",
) -> ProviderModelProfile:
    return ProviderModelProfile.model_validate(
        profile(
            provider_id=provider_id,
            snapshot=snapshot,
            tools=(model_turn_provider_tool_spec(),),
        ).model_copy(
            update={
                "data_policy_id": request.authority_grant.provider_policy.data_policy_id,
            }
        ).model_dump(mode="python")
    )


def _signed_tool_result(
    request: ProviderProxyRequest,
    model: ProviderModelProfile,
    base_intent: ProviderCallIntent,
    *,
    accepted_data_policy_id: str | None = None,
) -> ProviderProxyResult:
    completed = completed_result(
        request,
        model,
        base_intent,
        accepted_data_policy_id=accepted_data_policy_id,
    )
    payload = cast(
        dict[str, object],
        completed.model_dump(
            mode="python",
            exclude={
                "attestation_key_id",
                "attestation_signature",
                "proxy_receipt_digest",
            },
        ),
    )
    payload["tool_calls"] = (
        ProviderToolCall(
            call_id="provider-call-model-turn-1",
            tool_id=MODEL_TURN_TOOL_ID,
            name=MODEL_TURN_WIRE_NAME,
            arguments_json=_model_turn_arguments(),
        ),
    )
    return signed_proxy_result(**payload)


def _provider_stack(
    request: AutomationRequest,
    *,
    provider_id: str = "provider.test",
    snapshot: str = "frontier-2030-01-01",
    accepted_data_policy_id: str | None = None,
    unsigned: bool = False,
) -> tuple[
    OneShotReasoningPromptResolver,
    ProviderCallIntent,
    FakeProxy,
    ProviderAdapter,
    MemoryProviderReceiptJournal,
]:
    resolver = OneShotReasoningPromptResolver()
    base_intent = _base_intent(request)
    model = _profile(request, provider_id=provider_id, snapshot=snapshot)

    def handler(proxy_request: ProviderProxyRequest) -> ProviderProxyResult:
        _ = resolver.resolve(proxy_request)
        result = _signed_tool_result(
            proxy_request,
            model,
            base_intent,
            accepted_data_policy_id=accepted_data_policy_id,
        )
        if unsigned:
            return result.model_copy(update={"attestation_signature": "unsigned"})
        return result

    proxy = FakeProxy(handler)
    journal = MemoryProviderReceiptJournal()
    runtime = adapter((model,), proxy, journal)
    return resolver, base_intent, proxy, runtime, journal


def test_runs_attested_provider_turn_into_candidate_only_result_without_target_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    resolver, base_intent, proxy, runtime, journal = _provider_stack(request)

    def socket_forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("provider runner attempted direct socket access")

    monkeypatch.setattr(socket, "socket", socket_forbidden)
    result = run_provider_automation_turn(
        request=request,
        base_intent=base_intent,
        resolver=resolver,
        adapter=runtime,
        trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
        trusted_disclosure_keys={
            DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
        },
        coordinator=_coordinator(),
        trusted_clock=lambda: request.issued_at,
    )

    assert len(result.hypotheses) == 1
    assert result.verification_status == "candidate_only_requires_independent_verification"
    assert result.target_dispatch_performed is False
    assert result.automatic_submission_performed is False
    assert len(proxy.requests) == 1
    dispatched = proxy.requests[0]
    assert dispatched.run_id == request.observations.run_id
    assert dispatched.authority_digest == sha256_digest(request.authority_grant)
    assert dispatched.data_policy_id == request.authority_grant.provider_policy.data_policy_id
    assert dispatched.tool_ids == (MODEL_TURN_TOOL_ID,)
    assert dispatched.prompt_digest == dispatched.payload_digest
    assert dispatched.requested_at == request.issued_at
    receipt = journal.by_attempt(base_intent.call_id, base_intent.attempt)
    assert receipt is not None
    assert receipt.planned_input_tokens == receipt.prompt_bytes
    assert receipt.planned_input_tokens != base_intent.input_tokens


@pytest.mark.parametrize(
    ("provider_id", "snapshot", "message"),
    [
        ("provider.outside", "frontier-2030-01-01", "provider"),
        ("provider.test", "frontier-2030-02-01", "snapshot"),
    ],
)
def test_rejects_attested_provider_or_snapshot_outside_the_grant(
    provider_id: str,
    snapshot: str,
    message: str,
) -> None:
    request = _request()
    resolver, base_intent, proxy, runtime, _ = _provider_stack(
        request,
        provider_id=provider_id,
        snapshot=snapshot,
    )

    with pytest.raises(ProviderAutomationRunnerError, match=message):
        _ = run_provider_automation_turn(
            request=request,
            base_intent=base_intent,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={
                DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
            },
            coordinator=_coordinator(),
            trusted_clock=lambda: request.issued_at,
        )
    assert proxy.requests == []


def test_rejects_receipted_data_policy_drift() -> None:
    request = _request()
    resolver, base_intent, _, runtime, _ = _provider_stack(
        request,
        accepted_data_policy_id="policy.outside",
    )

    with pytest.raises(ProviderAutomationRunnerError, match="admitted model turn"):
        _ = run_provider_automation_turn(
            request=request,
            base_intent=base_intent,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={
                DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
            },
            coordinator=_coordinator(),
            trusted_clock=lambda: request.issued_at,
        )


def test_rejects_base_data_policy_mismatch_before_provider_dispatch() -> None:
    request = _request()
    resolver, base_intent, proxy, runtime, _ = _provider_stack(request)
    wrong_policy = ProviderCallIntent.model_validate(
        base_intent.model_copy(
            update={"data_policy_id": "policy.outside"}
        ).model_dump(mode="python")
    )

    with pytest.raises(ProviderAutomationRunnerError, match="data policy"):
        _ = run_provider_automation_turn(
            request=request,
            base_intent=wrong_policy,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={
                DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
            },
            coordinator=_coordinator(),
            trusted_clock=lambda: request.issued_at,
        )
    assert proxy.requests == []


def test_rejects_untrusted_disclosure_approval_before_provider_dispatch() -> None:
    request = _request()
    resolver, base_intent, proxy, runtime, _ = _provider_stack(request)

    with pytest.raises(ProviderAutomationRunnerError, match="disclosure approval"):
        _ = run_provider_automation_turn(
            request=request,
            base_intent=base_intent,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={},
            coordinator=_coordinator(),
            trusted_clock=lambda: request.issued_at,
        )
    assert proxy.requests == []


def test_rejects_denied_context_before_prompt_or_provider_dispatch() -> None:
    request = _request()
    existing_deny = request.authority_grant.action_policy.denied[0]
    denied_policy = request.authority_grant.action_policy.model_copy(
        update={
            "denied": (
                existing_deny.model_copy(
                    update={
                        "action_families": (),
                        "path_pattern": "/api/*",
                        "methods": ("GET",),
                    }
                ),
            )
        }
    )
    denied_request = request.model_copy(
        update={
            "authority_grant": request.authority_grant.model_copy(
                update={"action_policy": denied_policy}
            )
        }
    )
    resolver, base_intent, proxy, runtime, _ = _provider_stack(denied_request)

    with pytest.raises(ProviderAutomationRunnerError, match="pre-provider authority"):
        _ = run_provider_automation_turn(
            request=denied_request,
            base_intent=base_intent,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={
                DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
            },
            coordinator=_coordinator(),
            trusted_clock=lambda: denied_request.issued_at,
        )
    assert proxy.requests == []


def test_rejects_expired_authority_at_trusted_dispatch_time_without_provider_io() -> None:
    request = _request()
    resolver, base_intent, proxy, runtime, _ = _provider_stack(request)

    with pytest.raises(ProviderAutomationRunnerError, match="validity window"):
        _ = run_provider_automation_turn(
            request=request,
            base_intent=base_intent,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={
                DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
            },
            coordinator=_coordinator(),
            trusted_clock=lambda: request.authority_grant.expires_at,
        )
    assert proxy.requests == []


def test_rejects_cross_run_base_intent_before_provider_dispatch() -> None:
    request = _request()
    resolver, base_intent, proxy, runtime, _ = _provider_stack(request)
    cross_run = ProviderCallIntent.model_validate(
        base_intent.model_copy(update={"run_id": "run.other"}).model_dump(mode="python")
    )

    with pytest.raises(ProviderAutomationRunnerError, match="another run"):
        _ = run_provider_automation_turn(
            request=request,
            base_intent=cross_run,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={
                DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
            },
            coordinator=_coordinator(),
            trusted_clock=lambda: request.issued_at,
        )
    assert proxy.requests == []


def test_rejects_unsigned_provider_result() -> None:
    request = _request()
    resolver, base_intent, _, runtime, _ = _provider_stack(request, unsigned=True)

    with pytest.raises(ProviderAutomationRunnerError, match="admitted model turn"):
        _ = run_provider_automation_turn(
            request=request,
            base_intent=base_intent,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={
                DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
            },
            coordinator=_coordinator(),
            trusted_clock=lambda: request.issued_at,
        )


def test_provider_failure_never_calls_the_candidate_coordinator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _request()
    resolver = OneShotReasoningPromptResolver()
    base_intent = _base_intent(request)
    model = _profile(request)
    runtime = adapter(
        (model,),
        FakeProxy(pre_send_result),
        MemoryProviderReceiptJournal(),
    )
    coordinator = _coordinator()
    calls = 0

    def forbidden_run(*_args: object, **_kwargs: object):
        nonlocal calls
        calls += 1
        raise AssertionError("coordinator ran after provider failure")

    monkeypatch.setattr(coordinator, "run", forbidden_run)
    with pytest.raises(ProviderAutomationRunnerError, match="admitted model turn"):
        _ = run_provider_automation_turn(
            request=request,
            base_intent=base_intent,
            resolver=resolver,
            adapter=runtime,
            trusted_proxy_attestation_key=PROXY_SIGNER.public_key_record,
            trusted_disclosure_keys={
                DISCLOSURE_SIGNER.key_id: DISCLOSURE_SIGNER.public_key_record
            },
            coordinator=coordinator,
            trusted_clock=lambda: request.issued_at,
        )
    assert calls == 0
    with pytest.raises(ReasoningPromptError, match="create-once"):
        _ = resolver.publish(
            request_id=base_intent.attempt_id,
            context=ReasoningTurnRequest.from_request(request),
            generation=base_intent.generation_config,
        )
