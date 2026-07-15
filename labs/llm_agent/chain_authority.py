from datetime import timedelta

from faultloom.chain import AssetClass, EdgeAuthorityBinding
from faultloom_protocol import (
    ActionBudget,
    ActionClass,
    ActionPolicy,
    AuthorityGrant,
    CallbackPolicy,
    ChainEdge,
    EffectRecord,
    ProviderPolicy,
    RetentionPolicy,
    StateChangePolicy,
    TargetAsset,
    TimeWindow,
    sha256_digest,
)

from .chain_contracts import EdgeSeed
from .fixture import D1, D4, NOW, LlmAgentFixture
from .lease import decision_lease_for_intent


def build_edge(
    fixture: LlmAgentFixture,
    seed: EdgeSeed,
) -> tuple[ChainEdge, EdgeAuthorityBinding]:
    decision_lease = decision_lease_for_intent(seed.intent, fixture, seed.lease_id)
    effect = EffectRecord(
        schema_version="0.1.0",
        effect_id=seed.effect_id,
        run_id=fixture.web_content.run_id,
        effect_kind=seed.effect_kind,
        subject=fixture.subject,
        resource=seed.intent.resource,
        state=seed.effect_state,
        observed_at=NOW,
        evidence_refs=(fixture.prompt_evidence,),
        reversible=True,
        cleanup_receipt_digest=D4,
    )
    edge = ChainEdge(
        schema_version="0.1.0",
        edge_id=seed.edge_id,
        source_capability_id=seed.source_capability_id,
        target_capability_id=seed.target_capability_id,
        preconditions=("owned deterministic lab state",),
        input_subject=fixture.subject,
        input_resource=seed.intent.resource,
        input_state=seed.input_state,
        action_intent=seed.intent,
        action_lease_id=decision_lease.lease.lease_id,
        scope_decision_digest=sha256_digest(decision_lease.decision),
        expected_effect=effect,
        observed_effect=effect,
        evidence_refs=(fixture.prompt_evidence,),
        negative_control_refs=(fixture.prompt_evidence,),
        reversible=True,
        cleanup_receipt_digest=D4,
        action_cost=1,
        time_cost_seconds=1,
        confidence_bps=9000,
    )
    binding = EdgeAuthorityBinding(
        binding_id=f"binding.{seed.edge_id}",
        edge_id=edge.edge_id,
        lease=decision_lease.lease,
        decision=decision_lease.decision,
        asset_class=AssetClass.PUBLIC,
        explicitly_granted=True,
        impact_cost=1,
    )
    return edge, binding


def authority_grant(
    fixture: LlmAgentFixture,
    action_kinds: tuple[str, str],
) -> AuthorityGrant:
    target = TargetAsset(
        schema_version="0.1.0",
        target_id="target.llm.loopback",
        hostnames=("loopback.invalid",),
        protocols=("agent_local", "mcp"),
        paths=("/agent", "/mcp"),
        methods=("OBSERVE", "CALL"),
    )
    return AuthorityGrant(
        schema_version="0.1.0",
        grant_id=fixture.active_epoch.grant_id,
        grant_version=1,
        draft_digest=D1,
        issued_at=NOW,
        not_before=NOW,
        expires_at=NOW + timedelta(minutes=10),
        issued_to="operator.llm.lab",
        approved_by="operator.llm.lab",
        targets=(target,),
        pack_ids=("pack.web.identity_workflow", "pack.llm.agent"),
        action_policy=ActionPolicy(
            schema_version="0.1.0",
            allowed_classes=(ActionClass.OBSERVE, ActionClass.SAFE_PROBE),
            allowed_families=action_kinds,
            allowed_methods=target.methods,
            allowed_path_patterns=("/agent/*", "/mcp/*"),
        ),
        identities=(fixture.subject.identity_id,),
        tenants=(fixture.subject.tenant_id,),
        execution_windows=(
            TimeWindow(
                schema_version="0.1.0",
                starts_at=NOW,
                ends_at=NOW + timedelta(minutes=10),
            ),
        ),
        budget=ActionBudget(
            schema_version="0.1.0",
            total_actions=3,
            rate_per_minute=10,
            max_concurrency=1,
            max_request_bytes=4096,
            max_response_bytes=4096,
            max_duration_seconds=30,
        ),
        callback_policy=CallbackPolicy(
            schema_version="0.1.0",
            maximum_ttl_seconds=60,
        ),
        provider_policy=ProviderPolicy(
            schema_version="0.1.0",
            allowed_providers=(),
            allowed_model_snapshots=(),
            data_policy_id="data-policy.local-only",
        ),
        retention_policy=RetentionPolicy(
            schema_version="0.1.0",
            policy_id="retention.llm.lab",
            retain_until=NOW + timedelta(minutes=10),
            delete_after_seconds=0,
        ),
        state_change_policy=StateChangePolicy(schema_version="0.1.0"),
        emergency_contact_ref="contact.operator.llm.lab",
    )
