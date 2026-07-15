from __future__ import annotations

from datetime import timedelta

from faultloom_protocol import IdentityGraph, WorkflowGraph
from faultloom_web.identity_workflow import (
    DifferentialDimension,
    DifferentialObservation,
    DifferentialPlanSeed,
    IdentityGraphSeed,
    MultiUserDifferentialPlanner,
    WorkflowMiner,
    WorkflowTrace,
    analyze_auth_semantics,
    build_identity_graph,
    identity_workflow_manifest,
    race_hypotheses,
)
from labs.identity_workflow import (
    FixtureMode,
    IdentityWorkflowLab,
    LabAccessOutcome,
    identity_workflow_fixture,
)

from .identity_support import registered_vault


def _observation(
    case_id: str,
    outcome: LabAccessOutcome,
) -> DifferentialObservation:
    return DifferentialObservation(
        case_id=case_id,
        identity_context_id=outcome.context_id,
        status_code=outcome.status_code,
        data_digest=outcome.data_digest,
        state_digest=outcome.state_digest,
        effect_digest=outcome.effect_digest,
        data_exposed=outcome.data_exposed,
        state_changed=outcome.state_changed,
        effect_occurred=outcome.effect_occurred,
    )


def test_identity_and_workflow_graph_ids_survive_serialized_context_reset() -> None:
    # Given
    fixture = identity_workflow_fixture()
    identity_graph = build_identity_graph(
        IdentityGraphSeed(
            graph_id="graph.identity.fixture",
            run_id=fixture.run_id,
            identities=fixture.identities,
            tenants=fixture.tenants,
            role_grants=fixture.role_grants,
            relationships=fixture.relationships,
            version=1,
        )
    )
    workflow = WorkflowMiner(registered_vault(fixture)).mine(fixture.workflows[0]).graph

    # When
    restored_identity = IdentityGraph.model_validate_json(identity_graph.model_dump_json())
    restored_workflow = WorkflowGraph.model_validate_json(workflow.model_dump_json())

    # Then
    assert restored_identity.graph_id == identity_graph.graph_id
    assert tuple(item.identity_id for item in restored_identity.identities) == tuple(
        item.identity_id for item in identity_graph.identities
    )
    assert restored_workflow.graph_id == workflow.graph_id
    assert tuple(item.transition_id for item in restored_workflow.transitions) == tuple(
        item.transition_id for item in workflow.transitions
    )


def test_workflow_miner_links_ui_actions_to_backend_operations_and_invariants() -> None:
    # Given
    fixture = identity_workflow_fixture()
    miner = WorkflowMiner(registered_vault(fixture))

    # When
    results = tuple(miner.mine(trace) for trace in fixture.workflows)

    # Then
    assert {result.graph.workflow_kind for result in results} == {
        "invite",
        "admin",
        "billing",
        "recovery",
    }
    assert all(result.graph.invariant_ids for result in results)
    assert all(
        binding.backend_operation_id == result.graph.transitions[0].operation_id
        for result in results
        for binding in result.operation_bindings
    )


def test_race_contract_records_semantic_hypothesis_without_single_packet_executor() -> None:
    # Given
    fixture = identity_workflow_fixture()
    trace = fixture.workflows[0]
    first = trace.steps[0]
    branch_state = trace.states[1].model_copy(
        update={
            "workflow_state_id": "state.invite.cancelled",
            "state_name": "invite.cancelled",
        }
    )
    branch_step = first.model_copy(
        update={
            "transition_id": "transition.invite.cancel",
            "to_state_id": branch_state.workflow_state_id,
            "backend_operation_id": "operation.invite.cancel",
            "occurred_at": first.occurred_at + timedelta(seconds=1),
        }
    )
    branched_trace = WorkflowTrace(
        graph_id=trace.graph_id,
        run_id=trace.run_id,
        workflow_id=trace.workflow_id,
        workflow_kind=trace.workflow_kind,
        states=(*trace.states, branch_state),
        steps=(first, branch_step),
        version=trace.version,
    )

    # When
    hypotheses = race_hypotheses(
        WorkflowMiner(registered_vault(fixture)).mine(branched_trace)
    )

    # Then
    assert len(hypotheses) == 1
    assert hypotheses[0].execution_contract == "semantic_parallel_only"
    assert hypotheses[0].single_packet_supported is False


def test_multi_user_plan_varies_all_dimensions_and_evaluates_data_state_effect() -> None:
    # Given
    fixture = identity_workflow_fixture()
    planner = MultiUserDifferentialPlanner(registered_vault(fixture))
    seed = DifferentialPlanSeed(
        plan_id="plan.identity.fixture",
        run_id=fixture.run_id,
        workflow_graph_id=fixture.workflows[0].graph_id,
        created_at=fixture.workflows[0].steps[0].occurred_at,
        variants=fixture.differential_variants,
    )
    lab = IdentityWorkflowLab(fixture)
    variant = next(
        item
        for item in fixture.differential_variants
        if item.dimension is DifferentialDimension.TENANT
    )
    owner = lab.inspect_idor(variant.baseline_identity_context_id, FixtureMode.DENIED)
    denied = lab.inspect_idor(variant.comparison_identity_context_id, FixtureMode.DENIED)
    exposed = lab.inspect_idor(
        variant.comparison_identity_context_id,
        FixtureMode.VULNERABLE,
    )

    # When
    plan = planner.plan(seed)
    denied_comparison = planner.compare(
        variant,
        (_observation(variant.case_id, owner), _observation(variant.case_id, denied)),
    )
    exposed_comparison = planner.compare(
        variant,
        (_observation(variant.case_id, owner), _observation(variant.case_id, exposed)),
    )

    # Then
    assert {case.varied_dimension for case in plan.cases} == {
        dimension.value for dimension in DifferentialDimension
    }
    assert plan.negative_control_case_ids == ("case.session",)
    assert denied_comparison.data_equal is False
    assert denied_comparison.state_equal is True
    assert denied_comparison.effect_equal is True
    assert denied_comparison.invariant_holds is True
    assert exposed_comparison.invariant_holds is False


def test_auth_semantics_rejects_audience_mismatch_without_signature_parser_claim() -> None:
    # Given
    trace = identity_workflow_fixture().auth_traces[0]
    mismatched = trace.model_copy(update={"observed_audiences": ("audience.other",)})

    # When
    accepted = analyze_auth_semantics(trace)
    rejected = analyze_auth_semantics(mismatched)

    # Then
    assert accepted.accepted is True
    assert rejected.accepted is False
    assert rejected.signature_parser_used is False


def test_pack_manifest_requires_process_isolation_and_gateway_features() -> None:
    # Given / When
    manifest = identity_workflow_manifest()

    # Then
    assert manifest.process_isolation == "required"
    assert set(manifest.required_gateway_features) == {
        "gateway.action_lease",
        "gateway.scope_epoch",
        "gateway.target_egress",
    }
