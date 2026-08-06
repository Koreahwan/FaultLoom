from __future__ import annotations

from datetime import timedelta
from typing import cast

import pytest

import faultloom.automation as automation
import faultloom.automation.controller as controller
from faultloom.automation.admission import (
    AutomationAdmission,
    AutomationAdmissionError,
    SignedAutomationAdmission,
    sign_automation_admission,
)
from faultloom.automation.execution_bridge import (
    AUTOMATION_DISPATCH_EVENT_TYPE,
    AutomationDispatchError,
    AutomationDispatchPersistence,
    execute_admitted_tool_plan,
    persist_automation_dispatch,
)
from faultloom.state import StateStore, StorageError
from faultloom.automation.models import AuthorizedAutomationResult
from faultloom.execution import (
    GatewayDeniedResult,
    GatewayDispatchCommand,
    SemanticHttpExecutor,
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
from faultloom_protocol.models import HypothesisRecord
from tests.protocol.factories import sample_models
from tests.runtime.execution_helpers import (
    CHANNEL_KEY,
    NOW,
    RecordingGateway,
    command,
    completed_result,
)
from tests.runtime.resume_support import open_store


ADMISSION_SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("63" * 32))
UNTRUSTED_ADMISSION_SIGNER = AuthoritySigner.from_private_bytes(bytes.fromhex("64" * 32))


def _result(command_value: GatewayDispatchCommand) -> AuthorizedAutomationResult:
    hypothesis = cast(HypothesisRecord, sample_models()["HypothesisRecord"])
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


def _admission(
    result: AuthorizedAutomationResult,
    *,
    signer: AuthoritySigner = ADMISSION_SIGNER,
    admission_id: str = "automation-admission.controller",
) -> SignedAutomationAdmission:
    return sign_automation_admission(
        AutomationAdmission(
            admission_id=admission_id,
            result=result,
            result_digest=sha256_digest(result.model_dump(mode="json")),
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
            issuer_key_id=signer.key_id,
        ),
        signer,
    )


def _dispatch(
    *,
    store: StateStore,
    admission: SignedAutomationAdmission,
    command_value: GatewayDispatchCommand,
    executor: SemanticHttpExecutor,
) -> AutomationDispatchPersistence:
    return controller.execute_and_persist_admitted_tool_plan(
        admission=admission,
        trusted_admission_keys={
            ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
        },
        trusted_clock=lambda: NOW,
        candidate_id="candidate.gateway",
        command=command_value,
        executor=executor,
        store=store,
    )


def test_campaign_control_exports() -> None:
    assert automation.CampaignControl is controller.CampaignControl
    assert automation.revoke_campaign is controller.revoke_campaign


def test_controller_presents_once_persists_and_returns_prior_dispatch(tmp_path) -> None:
    approved = command()
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    admission = _admission(_result(approved))

    with open_store(tmp_path) as store:
        first = _dispatch(
            store=store,
            admission=admission,
            command_value=approved,
            executor=executor,
        )
    replay_gateway = RecordingGateway(completed_result)
    replay_executor = SemanticHttpExecutor._for_test(
        replay_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    with open_store(tmp_path) as store:
        second = _dispatch(
            store=store,
            admission=admission,
            command_value=approved,
            executor=replay_executor,
        )
        assert store.ledger is not None
        events = tuple(
            event
            for event in store.ledger.events(limit=100)
            if event.event_type == AUTOMATION_DISPATCH_EVENT_TYPE
        )

    assert first == second
    assert first.envelope.record.status == "completed"
    assert len(gateway.calls) == 1
    assert replay_gateway.calls == []
    assert events == (first.event,)


@pytest.mark.parametrize(
    "invalid", ("untrusted", "tampered_signature", "tampered_binding")
)
def test_controller_rejects_untrusted_or_tampered_binding_before_gateway(
    tmp_path, invalid: str
) -> None:
    approved = command()
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    admission = _admission(
        _result(approved),
        signer=(
            UNTRUSTED_ADMISSION_SIGNER if invalid == "untrusted" else ADMISSION_SIGNER
        ),
    )
    if invalid == "tampered_signature":
        admission = admission.model_copy(
            update={
                "signature": (
                    ("A" if admission.signature[0] != "A" else "B")
                    + admission.signature[1:]
                )
            }
        )
    submitted_command = (
        command(action_id="action.tampered", lease_id="lease.tampered")
        if invalid == "tampered_binding"
        else approved
    )

    with open_store(tmp_path) as store:
        with pytest.raises((AutomationAdmissionError, AutomationDispatchError)):
            _dispatch(
                store=store,
                admission=admission,
                command_value=submitted_command,
                executor=executor,
            )

    assert gateway.calls == []


def test_campaign_revocation_survives_reopen_and_blocks_gateway(tmp_path) -> None:
    approved = command(action_id="action.revoked", lease_id="lease.revoked")
    admission = _admission(_result(approved))
    first_gateway = RecordingGateway(completed_result)
    first_executor = SemanticHttpExecutor._for_test(
        first_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    with open_store(tmp_path) as store:
        control = controller.revoke_campaign(
            store=store,
            run_id=approved.intent.run_id,
            epoch=1,
            reason="operator emergency stop",
        )
        assert store.ledger is not None
        events = tuple(
            event
            for event in store.ledger.events(limit=100)
            if event.event_type == controller.AUTOMATION_CAMPAIGN_CONTROL_EVENT_TYPE
        )

    replay_gateway = RecordingGateway(completed_result)
    replay_executor = SemanticHttpExecutor._for_test(
        replay_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    with open_store(tmp_path) as store:
        with pytest.raises(controller.CampaignRevokedError, match="emergency stop"):
            _dispatch(
                store=store,
                admission=admission,
                command_value=approved,
                executor=replay_executor,
            )

    assert control.revoked is True
    assert len(events) == 1
    assert first_gateway.calls == []
    assert replay_gateway.calls == []


def test_completed_dispatch_remains_retrievable_after_campaign_revoke(tmp_path) -> None:
    approved = command(action_id="action.completed", lease_id="lease.completed")
    admission = _admission(_result(approved))
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    with open_store(tmp_path) as store:
        first = _dispatch(
            store=store,
            admission=admission,
            command_value=approved,
            executor=executor,
        )
        controller.revoke_campaign(
            store=store,
            run_id=approved.intent.run_id,
            epoch=1,
            reason="stop after completed dispatch",
        )

    replay_gateway = RecordingGateway(completed_result)
    replay_executor = SemanticHttpExecutor._for_test(
        replay_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    with open_store(tmp_path) as store:
        second = _dispatch(
            store=store,
            admission=admission,
            command_value=approved,
            executor=replay_executor,
        )

    assert first == second
    assert len(gateway.calls) == 1
    assert replay_gateway.calls == []


def test_campaign_control_rejects_epoch_rollback_and_unrevoke(tmp_path) -> None:
    approved = command(action_id="action.epoch", lease_id="lease.epoch")

    with open_store(tmp_path) as store:
        controller.revoke_campaign(
            store=store,
            run_id=approved.intent.run_id,
            epoch=2,
            reason="first emergency stop",
        )
        with pytest.raises(controller.CampaignControlError, match="epoch rollback"):
            controller.revoke_campaign(
                store=store,
                run_id=approved.intent.run_id,
                epoch=1,
                reason="older control",
            )
        with pytest.raises(controller.CampaignControlError, match="cannot be cleared"):
            controller.revoke_campaign(
                store=store,
                run_id=approved.intent.run_id,
                epoch=3,
                reason="attempted unrevoke",
                revoked=False,
            )

def test_controller_persists_gateway_denial(tmp_path) -> None:
    approved = command(action_id="action.denied", lease_id="lease.denied")
    denied = GatewayDeniedResult(
        schema_version="0.1.0",
        action_id=approved.intent.action_id,
        request_digest=gateway_frame_digest(gateway_dispatch_frame(approved)),
        reason_code="scope.revoked",
    )
    gateway = RecordingGateway(lambda _: denied)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    with open_store(tmp_path) as store:
        dispatch = _dispatch(
            store=store,
            admission=_admission(_result(approved)),
            command_value=approved,
            executor=executor,
        )
        assert store.ledger is not None
        events = tuple(
            event
            for event in store.ledger.events(limit=100)
            if event.event_type == AUTOMATION_DISPATCH_EVENT_TYPE
        )

    assert dispatch.envelope.record.status == "denied"
    assert dispatch.envelope.record.target_dispatch_performed is False
    assert len(gateway.calls) == 1
    assert events == (dispatch.event,)


def test_controller_persists_ambiguous_dispatch_without_retrying(tmp_path) -> None:
    approved = command(action_id="action.unknown", lease_id="lease.unknown")
    gateway = RecordingGateway(lambda _: (_ for _ in ()).throw(RuntimeError("lost")))
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    admission = _admission(_result(approved))

    with open_store(tmp_path) as store:
        first = _dispatch(
            store=store,
            admission=admission,
            command_value=approved,
            executor=executor,
        )
        second = _dispatch(
            store=store,
            admission=admission,
            command_value=approved,
            executor=executor,
        )
        assert store.ledger is not None
        events = tuple(
            event
            for event in store.ledger.events(limit=100)
            if event.event_type == AUTOMATION_DISPATCH_EVENT_TYPE
        )

    assert first == second
    assert first.envelope.record.status == "unknown_requires_reconciliation"
    assert first.envelope.record.target_dispatch_performed is None
    assert len(gateway.calls) == 1
    assert events == (first.event,)


def test_reservation_after_interruption_is_sealed_unknown_without_presentation(
    tmp_path, monkeypatch
) -> None:
    approved = command(action_id="action.reserved", lease_id="lease.reserved")
    admission = _admission(_result(approved))
    first_gateway = RecordingGateway(completed_result)
    first_executor = SemanticHttpExecutor._for_test(
        first_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    def interrupted(**_kwargs):
        raise RuntimeError("fault injected after reservation")

    with open_store(tmp_path) as store:
        monkeypatch.setattr(controller, "execute_admitted_tool_plan", interrupted)
        with pytest.raises(RuntimeError, match="after reservation"):
            _dispatch(
                store=store,
                admission=admission,
                command_value=approved,
                executor=first_executor,
            )
    assert first_gateway.calls == []

    replay_gateway = RecordingGateway(completed_result)
    replay_executor = SemanticHttpExecutor._for_test(
        replay_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    with open_store(tmp_path) as store:
        dispatch = _dispatch(
            store=store,
            admission=admission,
            command_value=approved,
            executor=replay_executor,
        )

    assert dispatch.envelope.record.status == "unknown_requires_reconciliation"
    assert dispatch.envelope.record.target_dispatch_performed is None
    assert replay_gateway.calls == []


def test_controller_rejects_different_durable_admission_without_presentation(
    tmp_path,
) -> None:
    approved = command(action_id="action.admission", lease_id="lease.admission")
    result = _result(approved)
    stored_admission = _admission(result, admission_id="automation-admission.stored")
    current_admission = _admission(result)
    writer_gateway = RecordingGateway(completed_result)
    writer_executor = SemanticHttpExecutor._for_test(
        writer_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    with open_store(tmp_path) as store:
        stored = execute_admitted_tool_plan(
            admission=stored_admission,
            trusted_admission_keys={
                ADMISSION_SIGNER.key_id: ADMISSION_SIGNER.public_key_record
            },
            trusted_clock=lambda: NOW,
            candidate_id="candidate.gateway",
            command=approved,
            executor=writer_executor,
        )
        persist_automation_dispatch(store, stored)

    attempted_gateway = RecordingGateway(completed_result)
    attempted_executor = SemanticHttpExecutor._for_test(
        attempted_gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )
    with open_store(tmp_path) as store:
        with pytest.raises(AutomationDispatchError, match="admission differs"):
            _dispatch(
                store=store,
                admission=current_admission,
                command_value=approved,
                executor=attempted_executor,
            )

    assert writer_gateway.calls
    assert attempted_gateway.calls == []


def test_reservation_persistence_failure_never_presents_gateway(tmp_path, monkeypatch) -> None:
    approved = command(action_id="action.append-fail", lease_id="lease.append-fail")
    gateway = RecordingGateway(completed_result)
    executor = SemanticHttpExecutor._for_test(
        gateway, channel_key=CHANNEL_KEY, now=lambda: NOW
    )

    def append_failure(*_args, **_kwargs):
        raise StorageError("fault injected reservation append failure")

    monkeypatch.setattr(controller, "append_encrypted", append_failure)
    with open_store(tmp_path) as store:
        with pytest.raises(StorageError, match="reservation append"):
            _dispatch(
                store=store,
                admission=_admission(_result(approved)),
                command_value=approved,
                executor=executor,
            )

    assert gateway.calls == []
