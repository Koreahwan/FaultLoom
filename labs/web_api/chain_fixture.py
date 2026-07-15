from __future__ import annotations

import hashlib

from faultloom.chain import (
    AssetClass,
    ChainAuthority,
    ChainBudget,
    ChainSearchSettings,
    EdgeAuthorityBinding,
    PrimitiveStatus,
)
from faultloom_protocol import (
    ChainEdge,
    ChainGraph,
    ObservationRef,
    PrimitiveRecord,
    SCHEMA_VERSION,
    sha256_digest,
)
from faultloom_web.web_api import (
    ActionBoundaryRecord,
    CapabilitySpec,
    ChainRunInput,
    WebApiSource,
)
from labs.identity_workflow import IdentityWorkflowFixture

from .authority_fixture import build_authorized_action


def build_chain_fixture(
    fixture: IdentityWorkflowFixture,
    async_effect_id: str,
) -> tuple[ChainRunInput, ChainRunInput, ActionBoundaryRecord]:
    authorized = build_authorized_action(fixture, async_effect_id)
    transition = fixture.workflows[0].steps[0]
    evidence = transition.evidence_refs[0]
    identity_effect_id = "effect.web-api.identity-authorized"
    identity_spec = CapabilitySpec(
        source=WebApiSource.IDENTITY_WORKFLOW,
        admission_id="admission.web-api.identity",
        capability_id="capability.web-api.identity",
        primitive=PrimitiveRecord(
            schema_version=SCHEMA_VERSION,
            primitive_id="primitive.web-api.identity",
            run_id=fixture.run_id,
            primitive_kind="workflow.identity_authorized",
            subject=authorized.subject,
            resource=authorized.resource,
            pre_state=authorized.before,
            post_state=authorized.before,
            action_intent_digest=transition.action_intent_digest,
            dispatch_receipt_digest=transition.dispatch_receipt_digest,
            evidence_refs=(evidence,),
            verified=True,
        ),
        capability_kind="workflow.identity_authorized",
        source_pack_id="pack.web.identity_workflow",
        status=PrimitiveStatus.VERIFIED,
        effect_ids=(identity_effect_id,),
    )
    api_spec = CapabilitySpec(
        source=WebApiSource.API_ASYNC,
        admission_id="admission.web-api.async",
        capability_id="capability.web-api.async",
        primitive=PrimitiveRecord(
            schema_version=SCHEMA_VERSION,
            primitive_id="primitive.web-api.async",
            run_id=fixture.run_id,
            primitive_kind="api.async_job",
            subject=authorized.subject,
            resource=authorized.resource,
            pre_state=authorized.before,
            post_state=authorized.after,
            action_intent_digest=sha256_digest(authorized.intent),
            dispatch_receipt_digest=_digest("dispatch.receipt"),
            evidence_refs=(evidence,),
            verified=True,
        ),
        capability_kind="api.async_job",
        source_pack_id="pack.web.api_async",
        status=PrimitiveStatus.VERIFIED,
        precondition_ids=(identity_effect_id,),
        effect_ids=(async_effect_id,),
    )
    edge = ChainEdge(
        schema_version=SCHEMA_VERSION,
        edge_id="edge.web-api.identity-to-async",
        source_capability_id=identity_spec.capability_id,
        target_capability_id=api_spec.capability_id,
        preconditions=("the provisioned owner identity authorizes the job observation",),
        input_subject=authorized.subject,
        input_resource=authorized.resource,
        input_state=authorized.before,
        action_intent=authorized.intent,
        action_lease_id=authorized.lease.lease_id,
        scope_decision_digest=sha256_digest(authorized.decision),
        expected_effect=authorized.effect,
        observed_effect=authorized.effect,
        identity_transition_id=transition.transition_id,
        evidence_refs=(evidence,),
        negative_control_refs=(evidence,),
        reversible=True,
        cleanup_receipt_digest=authorized.effect.cleanup_receipt_digest,
        action_cost=1,
        time_cost_seconds=1,
        confidence_bps=9000,
    )
    graph = ChainGraph(
        schema_version=SCHEMA_VERSION,
        graph_id="chain-graph.web-api",
        run_id=fixture.run_id,
        capabilities=(),
        edges=(edge,),
        impact_goal="Demonstrate one inert identity-bound async job effect.",
        action_budget=1,
        time_budget_seconds=60,
        version=1,
    )
    authority = ChainAuthority(
        grant=authorized.grant,
        edge_bindings=(
            EdgeAuthorityBinding(
                binding_id="binding.web-api.identity-to-async",
                edge_id=edge.edge_id,
                lease=authorized.lease,
                decision=authorized.decision,
                asset_class=AssetClass.PUBLIC,
                explicitly_granted=True,
                impact_cost=1,
            ),
        ),
    )
    settings = ChainSearchSettings(
        start_capability_ids=(identity_spec.capability_id,),
        goal_effect_id=async_effect_id,
        budget=ChainBudget(actions=1, time_seconds=60, impact=1),
    )
    positive = ChainRunInput(
        capabilities=(identity_spec, api_spec),
        graph_template=graph,
        authority=authority,
        settings=settings,
    )
    negative = positive.model_copy(
        update={
            "capabilities": (
                identity_spec,
                api_spec.model_copy(update={"precondition_ids": ("effect.missing",)}),
            )
        }
    )
    action = ActionBoundaryRecord(
        intent=authorized.intent,
        lease=authorized.lease,
        observation=ObservationRef(
            schema_version=SCHEMA_VERSION,
            observation_id="observation.web-api.job",
            run_id=fixture.run_id,
            cas_digest=_digest("observation.job"),
            media_type="application/json",
            byte_length=64,
            created_at=authorized.effect.observed_at,
        ),
    )
    return positive, negative, action


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"
