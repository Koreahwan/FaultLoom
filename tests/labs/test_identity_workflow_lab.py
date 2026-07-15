from __future__ import annotations

from faultloom_protocol import ActionClass
from faultloom_web.identity_workflow import (
    IdentityActionFamily,
    IdentitySafetyGate,
    IdentitySafetyRequest,
    WorkflowKind,
)
from labs.identity_workflow import (
    FixtureMode,
    IdentityWorkflowFixture,
    IdentityWorkflowLab,
    clean_identity_replay,
    identity_workflow_fixture,
)
from tests.web.identity_support import registered_vault


def test_fixture_is_versioned_multi_identity_multi_tenant_and_workflow_complete() -> None:
    # Given / When
    fixture = identity_workflow_fixture()

    # Then
    assert fixture.schema_version == "0.1.0"
    assert fixture.namespace == "faultloom.lab.web.identity_workflow.v1"
    assert len(fixture.identities) == 3
    assert len(fixture.tenants) == 2
    assert len(fixture.identity_contexts) == 6
    assert {trace.workflow_kind for trace in fixture.workflows} == {
        WorkflowKind.INVITE,
        WorkflowKind.ADMIN,
        WorkflowKind.BILLING,
        WorkflowKind.RECOVERY,
    }


def test_idor_fixture_has_owner_control_vulnerable_positive_and_denied_negative() -> None:
    # Given
    fixture = identity_workflow_fixture()
    lab = IdentityWorkflowLab(fixture)

    # When
    owner = lab.inspect_idor(fixture.idor_case.owner_context_id, FixtureMode.DENIED)
    vulnerable = lab.inspect_idor(
        fixture.idor_case.outsider_context_id,
        FixtureMode.VULNERABLE,
    )
    denied = lab.inspect_idor(
        fixture.idor_case.outsider_context_id,
        FixtureMode.DENIED,
    )

    # Then
    assert owner.status_code == 200
    assert owner.data_exposed is True
    assert vulnerable.status_code == 200
    assert vulnerable.data_exposed is True
    assert denied.status_code == 403
    assert denied.data_exposed is False
    assert denied.state_changed is False
    assert denied.effect_occurred is False


def test_clean_replay_is_repeatable_and_always_restores_fixture_state() -> None:
    # Given
    fixture = identity_workflow_fixture()
    lab = IdentityWorkflowLab(fixture)
    gate = IdentitySafetyGate(registered_vault(fixture))
    final_digests: list[str] = []

    # When
    for replay_index in range(2):
        with clean_identity_replay(lab):
            final = lab.snapshot()
            for trace in fixture.workflows:
                step = trace.steps[0]
                admission = gate.admit(
                    IdentitySafetyRequest(
                        request_id=f"replay.{replay_index}.{trace.workflow_kind.value}",
                        identity_context_id=step.identity_context_id,
                        action_class=ActionClass.STATE_CHANGE,
                        action_family=IdentityActionFamily.WORKFLOW_TRANSITION,
                        canary_id=f"canary.{trace.workflow_kind.value}",
                        cleanup_plan_id=f"cleanup.{trace.workflow_kind.value}",
                    )
                )
                final = lab.apply_workflow(trace, admission)
            final_digests.append(final.state_digest)
            assert final.generation == 4
        assert lab.snapshot().generation == 0

    # Then
    assert final_digests[0] == final_digests[1]


def test_fixture_round_trip_preserves_all_identity_workflow_and_session_ids() -> None:
    # Given
    fixture = identity_workflow_fixture()

    # When
    restored = IdentityWorkflowFixture.model_validate_json(fixture.model_dump_json())

    # Then
    assert tuple(item.identity_id for item in restored.identities) == tuple(
        item.identity_id for item in fixture.identities
    )
    assert tuple(item.identity_context_id for item in restored.identity_contexts) == tuple(
        item.identity_context_id for item in fixture.identity_contexts
    )
    assert tuple(item.graph_id for item in restored.workflows) == tuple(
        item.graph_id for item in fixture.workflows
    )
