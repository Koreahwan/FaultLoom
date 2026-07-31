from __future__ import annotations

import ast
import hashlib
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
import faultloom_protocol.models as protocol_models

from faultloom.automation.admission import (
    AutomationAdmission,
    AutomationAdmissionError,
    SignedAutomationAdmission,
    sign_automation_admission,
)
from faultloom.automation.models import AuthorizedAutomationResult
from faultloom.automation.execution_bridge import (
    AUTOMATION_DISPATCH_EVENT_TYPE,
    AutomationDispatchError,
    execute_admitted_tool_plan,
    load_automation_dispatch,
    persist_automation_dispatch,
)
from faultloom.execution import (
    AuthenticatedGatewayClient,
    DispatchReplayError,
    ExecutionContractError,
    GatewayDeniedResult,
    GatewayChannelConfig,
    GatewayDispatchCommand,
    GatewayDispatchResult,
    SemanticHttpExecutor,
    canonical_dispatch_receipt_id,
    gateway_dispatch_frame,
    gateway_frame_digest,
)
from faultloom.tool_planner import (
    PlanningBudget,
    ToolCandidate,
    ToolEvidenceRole,
    ToolEstimate,
    ToolPlan,
    ToolPlanItem,
    ToolPlanReceipt,
)
from faultloom_protocol import AuthoritySigner, sha256_digest
from tests.runtime.execution_helpers import CHANNEL_KEY, NOW, RecordingGateway, command, completed_result
from tests.runtime.resume_support import open_store
from tests.protocol.factories import sample_models


ADMISSION_SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("63" * 32))
UNTRUSTED_ADMISSION_SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("64" * 32))


def _result(*, command_value: GatewayDispatchCommand | None = None) -> AuthorizedAutomationResult:
    command_value = command_value or command()
    hypothesis = sample_models()["HypothesisRecord"]
    candidate = ToolCandidate(
        candidate_id="candidate.gateway",
        hypothesis_id=hypothesis.hypothesis_id,
        intent=command_value.intent,
        adapter_id="adapter.reference",
        capability="reference.digest_normalizer",
        expected_information_gain_bps=7_000,
        estimate=ToolEstimate(
            rate_slots=1,
            duration_seconds=2,
            bytes=200,
            concurrency=1,
            actions=1,
            cost_microunits=1,
        ),
    )
    receipt = ToolPlanReceipt(
        candidate_id=candidate.candidate_id,
        candidate_digest=sha256_digest(candidate.model_dump(mode="json")),
        hypothesis_id=hypothesis.hypothesis_id,
        hypothesis_digest=sha256_digest(hypothesis.model_dump(mode="json")),
        authority_digest="sha256:" + "1" * 64,
        adapter_id=candidate.adapter_id,
        manifest_digest="sha256:" + "2" * 64,
        admission_snapshot_digest="sha256:" + "3" * 64,
        utility_receipt_digest="sha256:" + "4" * 64,
        budget_digest="sha256:" + "5" * 64,
    )
    plan = ToolPlan(
        hypothesis_id=hypothesis.hypothesis_id,
        selected=ToolPlanItem(
            candidate=candidate,
            evidence_role=ToolEvidenceRole.CANDIDATE,
            receipt=receipt,
        ),
        remaining=PlanningBudget(
            rate_slots=2,
            duration_seconds=18,
            bytes=1_800,
            concurrency=1,
            actions=2,
            cost_microunits=99,
        ),
    )
    return AuthorizedAutomationResult(
        run_id=command_value.intent.run_id,
        authority_grant_digest="sha256:" + "1" * 64,
        authority_grant_id=command_value.decision.grant_id,
        authority_grant_version=command_value.decision.grant_version,
        observation_bundle_digest="sha256:" + "6" * 64,
        action_context_digest="sha256:" + "7" * 64,
        hypotheses=(hypothesis,),
        negative_results=(),
        admitted_plans=(plan,),
        stop_reason="Await independent verification.",
        provider_network_access="none",
    )


def _executor(handler):
    return SemanticHttpExecutor._for_test(
        RecordingGateway(handler), channel_key=CHANNEL_KEY, now=lambda: NOW
    )


def _admission(
    result: AuthorizedAutomationResult,
    *,
    signer: AuthoritySigner = ADMISSION_SIGNER,
) -> SignedAutomationAdmission:
    return sign_automation_admission(
        AutomationAdmission(
            admission_id="automation-admission.test",
            result=result,
            result_digest=sha256_digest(result.model_dump(mode="json")),
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
            issuer_key_id=signer.key_id,
        ),
        signer,
    )


def _execute(
    *,
    result: AuthorizedAutomationResult,
    candidate_id: str,
    command: GatewayDispatchCommand,
    executor: SemanticHttpExecutor,
):
    return execute_admitted_tool_plan(
        admission=_admission(result),
        trusted_admission_keys={
            ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
        },
        trusted_clock=lambda: NOW,
        candidate_id=candidate_id,
        command=command,
        executor=executor,
    )


def test_exact_admitted_command_executes_once_and_persists_encrypted_idempotently(tmp_path) -> None:
    approved = command()
    body = b"raw response body must remain encrypted"
    gateway = RecordingGateway(lambda value: completed_result(value, body=body))
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    record = _execute(
        result=_result(command_value=approved),
        candidate_id="candidate.gateway",
        command=approved,
        executor=executor,
    )

    assert record.status == "completed"
    assert len(gateway.calls) == 1
    assert record.target_dispatch_performed is True
    assert record.automatic_submission_performed is False
    assert record.independent_verification_performed is False

    with open_store(tmp_path) as store:
        first = persist_automation_dispatch(store, record)
        second = persist_automation_dispatch(store, record)

        assert second == first
        assert first.event.event_type == AUTOMATION_DISPATCH_EVENT_TYPE
        assert first.evidence_ref.run_id == record.run_id
        assert first.evidence_ref.redaction_digest is None
        assert first.evidence_ref.cas_digest == first.observation_ref.cas_digest
        assert load_automation_dispatch(store, first.event) == first.envelope
        assert store.ledger is not None
        events = tuple(
            event
            for event in store.ledger.events(limit=100)
            if event.event_type == AUTOMATION_DISPATCH_EVENT_TYPE
        )
        assert events == (first.event,)
        assert body.decode() not in str(first.event.payload)
        assert "body" not in first.event.payload


def test_caller_constructed_result_without_trusted_admission_never_reaches_gateway() -> None:
    approved = command()
    forged_result = _result(command_value=approved)
    untrusted_admission = _admission(
        forged_result,
        signer=UNTRUSTED_ADMISSION_SIGNER,
    )
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    with pytest.raises(AutomationAdmissionError, match="absent"):
        execute_admitted_tool_plan(
            admission=untrusted_admission,
            trusted_admission_keys={
                ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
            },
            trusted_clock=lambda: NOW,
            candidate_id="candidate.gateway",
            command=approved,
            executor=executor,
        )
    assert gateway.calls == []


def test_expired_or_tampered_admission_never_reaches_gateway() -> None:
    approved = command()
    result = _result(command_value=approved)
    admission = _admission(result)
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    trust = {ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record}

    with pytest.raises(AutomationAdmissionError, match="validity window"):
        execute_admitted_tool_plan(
            admission=admission,
            trusted_admission_keys=trust,
            trusted_clock=lambda: admission.payload.expires_at,
            candidate_id="candidate.gateway",
            command=approved,
            executor=executor,
        )
    tampered = admission.model_copy(
        update={
            "signature": (
                ("A" if admission.signature[0] != "A" else "B")
                + admission.signature[1:]
            )
        }
    )
    with pytest.raises(AutomationAdmissionError, match="signature"):
        execute_admitted_tool_plan(
            admission=tampered,
            trusted_admission_keys=trust,
            trusted_clock=lambda: NOW,
            candidate_id="candidate.gateway",
            command=approved,
            executor=executor,
        )
    assert gateway.calls == []


def test_bridge_accepts_exact_production_executor_boundary_but_not_untrusted_admission() -> None:
    executable = "/usr/bin/python3"
    process = subprocess.Popen(
        (
            executable,
            "-c",
            "import sys; sys.stdin.buffer.read()",
            "--supervised-stdio",
        ),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    client = AuthenticatedGatewayClient(
        process,
        GatewayChannelConfig(
            key_id="channel-key.bridge",
            key=bytes(range(1, 33)),
            boot_id="gateway-boot.bridge",
            nonce=bytes(range(16)),
            issued_at_millis=1_000,
            expires_at_millis=31_000,
        ),
        expected_binary_digest=(
            "sha256:" + hashlib.sha256(Path(executable).read_bytes()).hexdigest()
        ),
    )
    try:
        approved = command()
        executor = SemanticHttpExecutor(client, now=lambda: NOW)
        with pytest.raises(AutomationAdmissionError, match="absent"):
            execute_admitted_tool_plan(
                admission=_admission(
                    _result(command_value=approved),
                    signer=UNTRUSTED_ADMISSION_SIGNER,
                ),
                trusted_admission_keys={
                    ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
                },
                trusted_clock=lambda: NOW,
                candidate_id="candidate.gateway",
                command=approved,
                executor=executor,
            )
        assert process.poll() is None
    finally:
        client.interrupt()
        client.close()


def _mutate_candidate_intent(
    result: AuthorizedAutomationResult,
    **updates: object,
) -> AuthorizedAutomationResult:
    plan = result.admitted_plans[0]
    item = plan.selected
    candidate = item.candidate.model_copy(
        update={"intent": item.candidate.intent.model_copy(update=updates)}
    )
    receipt = item.receipt.model_copy(
        update={"candidate_digest": sha256_digest(candidate.model_dump(mode="json"))}
    )
    selected = ToolPlanItem(
        candidate=candidate,
        evidence_role=item.evidence_role,
        receipt=receipt,
    )
    return result.model_copy(
        update={"admitted_plans": (plan.model_copy(update={"selected": selected}),)}
    )


@pytest.mark.parametrize(
    ("result_mutation", "message"),
    (
        (
            lambda value: _mutate_candidate_intent(value, action_id="action.other"),
            "intent differs",
        ),
        (
            lambda value: _mutate_candidate_intent(value, payload_digest=None),
            "payload digest",
        ),
        (
            lambda value: value.model_copy(update={"authority_grant_version": 4}),
            "result grant",
        ),
    ),
)
def test_invalid_binding_never_calls_the_gateway(result_mutation, message: str) -> None:
    approved = command()
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    with pytest.raises(AutomationDispatchError, match=message):
        _execute(
            result=result_mutation(_result(command_value=approved)),
            candidate_id="candidate.gateway",
            command=approved,
            executor=executor,
        )
    assert gateway.calls == []


def test_denial_and_unknown_are_not_retried() -> None:
    approved = command()
    frame = gateway_dispatch_frame(approved)
    denied = GatewayDeniedResult(
        schema_version="0.1.0",
        action_id=approved.intent.action_id,
        request_digest=gateway_frame_digest(frame),
        reason_code="scope.revoked",
    )
    denied_gateway = RecordingGateway(lambda _: denied)
    denied_executor = SemanticHttpExecutor._for_test(
        denied_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    denied_record = _execute(
        result=_result(command_value=approved),
        candidate_id="candidate.gateway",
        command=approved,
        executor=denied_executor,
    )
    assert denied_record.status == "denied"
    assert denied_record.target_dispatch_performed is False
    assert len(denied_gateway.calls) == 1

    unknown = command(action_id="action.unknown", lease_id="lease.unknown")
    unknown_gateway = RecordingGateway(lambda _: (_ for _ in ()).throw(RuntimeError("lost")))
    unknown_executor = SemanticHttpExecutor._for_test(
        unknown_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    unknown_result = _result(command_value=unknown)
    unknown_record = _execute(
        result=unknown_result,
        candidate_id="candidate.gateway",
        command=unknown,
        executor=unknown_executor,
    )
    assert unknown_record.status == "unknown_requires_reconciliation"
    assert unknown_record.target_dispatch_performed is None
    assert len(unknown_gateway.calls) == 1
    with pytest.raises(DispatchReplayError):
        _execute(
            result=unknown_result,
            candidate_id="candidate.gateway",
            command=unknown,
            executor=unknown_executor,
        )
    assert len(unknown_gateway.calls) == 1


def test_post_dispatch_validation_error_is_durable_unknown_but_pre_dispatch_error_propagates() -> None:
    approved = command()
    valid = completed_result(approved)
    receipt_values = valid.receipt.model_dump(mode="python")
    receipt_values["lease_id"] = "lease.forged"
    provisional = protocol_models.DispatchReceipt.model_validate(receipt_values)
    receipt_values["receipt_id"] = canonical_dispatch_receipt_id(provisional)
    forged = GatewayDispatchResult(
        schema_version="0.1.0",
        receipt=protocol_models.DispatchReceipt.model_validate(receipt_values),
        observation=valid.observation,
    )
    gateway = RecordingGateway(lambda _: forged)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    record = _execute(
        result=_result(command_value=approved),
        candidate_id="candidate.gateway",
        command=approved,
        executor=executor,
    )
    assert record.status == "unknown_requires_reconciliation"
    assert record.target_dispatch_performed is None
    assert len(gateway.calls) == 1

    pre_gateway = RecordingGateway(completed_result)
    pre_executor = SemanticHttpExecutor._for_test(
        pre_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW.replace(year=2031)
    )
    with pytest.raises(ExecutionContractError, match="not currently valid"):
        _execute(
            result=_result(command_value=approved),
            candidate_id="candidate.gateway",
            command=approved,
            executor=pre_executor,
        )
    assert pre_gateway.calls == []


def test_bridge_has_no_direct_socket_import() -> None:
    source = (
        Path(__file__).parents[2]
        / "packages"
        / "runtime"
        / "src"
        / "faultloom"
        / "automation"
        / "execution_bridge.py"
    )
    tree = ast.parse(source.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    )
    assert "socket" not in imports
