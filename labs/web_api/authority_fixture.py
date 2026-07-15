from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta

from faultloom_protocol import (
    ActionBudget,
    ActionClass,
    ActionIntent,
    ActionLease,
    ActionPolicy,
    AuthorityGrant,
    BudgetReservation,
    CallbackPolicy,
    DecisionOutcome,
    EffectRecord,
    EgressPlane,
    PolicyDecision,
    ProviderPolicy,
    ResourceRef,
    RetentionPolicy,
    SCHEMA_VERSION,
    StateChangePolicy,
    StateRef,
    SubjectRef,
    TargetAsset,
    TimeWindow,
    sha256_digest,
)
from labs.identity_workflow import IdentityWorkflowFixture


@dataclass(frozen=True, slots=True)
class AuthorizedActionFixture:
    subject: SubjectRef
    resource: ResourceRef
    before: StateRef
    after: StateRef
    intent: ActionIntent
    grant: AuthorityGrant
    decision: PolicyDecision
    lease: ActionLease
    effect: EffectRecord


def build_authorized_action(
    fixture: IdentityWorkflowFixture,
    async_effect_id: str,
) -> AuthorizedActionFixture:
    transition = fixture.workflows[0].steps[0]
    evidence = transition.evidence_refs[0]
    now = transition.occurred_at
    later = now + timedelta(hours=1)
    subject = SubjectRef(
        schema_version=SCHEMA_VERSION,
        subject_id="subject.web-api.owner",
        subject_kind="test_identity",
        identity_id="identity.owner",
        tenant_id="tenant.alpha",
    )
    resource = ResourceRef(
        schema_version=SCHEMA_VERSION,
        resource_id="resource.web-api.job-canary",
        resource_kind="background_job",
        target_id=fixture.target_id,
        tenant_id="tenant.alpha",
    )
    before = StateRef(
        schema_version=SCHEMA_VERSION,
        state_id="state.web-api.job",
        state_kind="submitted",
        state_version=1,
        state_digest=_digest("state.before"),
    )
    after = StateRef(
        schema_version=SCHEMA_VERSION,
        state_id="state.web-api.job",
        state_kind="complete",
        state_version=2,
        state_digest=_digest("state.after"),
    )
    action_kind = "web.api.observe_job"
    intent = ActionIntent(
        schema_version=SCHEMA_VERSION,
        action_id="action.web-api.observe-job",
        run_id=fixture.run_id,
        target_id=fixture.target_id,
        pack_id="pack.web.api_async",
        action_kind=action_kind,
        action_class=ActionClass.SAFE_PROBE,
        subject=subject,
        resource=resource,
        state=before,
        protocol="https",
        method="POST",
        path="/v1/jobs/canary",
        payload_digest=_digest("semantic.action"),
        requested_at=now,
    )
    grant = AuthorityGrant(
        schema_version=SCHEMA_VERSION,
        grant_id="grant.web-api",
        grant_version=1,
        draft_digest=_digest("scope.draft"),
        issued_at=now,
        not_before=now,
        expires_at=later,
        issued_to="researcher.web-api",
        approved_by="operator.web-api",
        targets=(
            TargetAsset(
                schema_version=SCHEMA_VERSION,
                target_id=fixture.target_id,
                hostnames=("web-api.loopback.test",),
                ports=(443,),
                protocols=("https",),
                paths=("/v1",),
                methods=("POST",),
            ),
        ),
        pack_ids=("pack.web.identity_workflow", "pack.web.api_async"),
        adapter_ids=("adapter.semantic-http",),
        action_policy=ActionPolicy(
            schema_version=SCHEMA_VERSION,
            allowed_classes=(ActionClass.SAFE_PROBE,),
            allowed_families=(action_kind,),
            allowed_methods=("POST",),
            allowed_path_patterns=("/v1/*",),
        ),
        identities=("identity.owner",),
        roles=("role.owner",),
        tenants=("tenant.alpha",),
        execution_windows=(
            TimeWindow(
                schema_version=SCHEMA_VERSION,
                starts_at=now,
                ends_at=later,
            ),
        ),
        budget=ActionBudget(
            schema_version=SCHEMA_VERSION,
            total_actions=2,
            rate_per_minute=2,
            max_concurrency=1,
            max_request_bytes=4096,
            max_response_bytes=4096,
            max_duration_seconds=60,
        ),
        callback_policy=CallbackPolicy(
            schema_version=SCHEMA_VERSION,
            owned_domains=("callbacks.loopback.test",),
            maximum_ttl_seconds=300,
        ),
        provider_policy=ProviderPolicy(
            schema_version=SCHEMA_VERSION,
            allowed_providers=("provider.loopback",),
            allowed_model_snapshots=("model.loopback",),
            data_policy_id="policy.synthetic-only",
        ),
        retention_policy=RetentionPolicy(
            schema_version=SCHEMA_VERSION,
            policy_id="retention.web-api",
            retain_until=later,
            delete_after_seconds=0,
        ),
        state_change_policy=StateChangePolicy(schema_version=SCHEMA_VERSION),
        emergency_contact_ref="contact.web-api.stop",
    )
    decision = PolicyDecision(
        schema_version=SCHEMA_VERSION,
        decision_id="decision.web-api.observe-job",
        intent_digest=sha256_digest(intent),
        grant_id=grant.grant_id,
        grant_version=grant.grant_version,
        scope_epoch=7,
        outcome=DecisionOutcome.ALLOW,
        reason_codes=("explicit.allow",),
        evaluated_at=now,
        lease_id="lease.web-api.observe-job",
    )
    lease = ActionLease(
        schema_version=SCHEMA_VERSION,
        lease_id="lease.web-api.observe-job",
        lease_key_id="lease-key.web-api",
        action_id=intent.action_id,
        correlation_id="correlation.web-api.job",
        intent_digest=sha256_digest(intent),
        decision_digest=sha256_digest(decision),
        grant_id=grant.grant_id,
        grant_version=grant.grant_version,
        scope_epoch=7,
        authority_key_id=f"ed25519:sha256:{'12' * 32}",
        scope_epoch_binding_digest=_digest("scope.epoch"),
        gateway_boot_id="gateway-boot.web-api",
        boot_challenge_digest=_digest("gateway.challenge"),
        target_id=fixture.target_id,
        identity_id="identity.owner",
        tenant_id="tenant.alpha",
        action_kind=action_kind,
        semantic_action_digest=_digest("semantic.action"),
        request_binding_digest=_digest("request.binding"),
        resolution_digest=_digest("resolution"),
        egress_plane=EgressPlane.TARGET_GATEWAY,
        dispatch_nonce="00112233445566778899aabbccddeeff",
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
        reservation=BudgetReservation(
            schema_version=SCHEMA_VERSION,
            request_bytes=128,
            response_bytes=256,
            duration_seconds=5,
        ),
    )
    effect = EffectRecord(
        schema_version=SCHEMA_VERSION,
        effect_id=async_effect_id,
        run_id=fixture.run_id,
        effect_kind="async_job_correlated",
        subject=subject,
        resource=resource,
        state=after,
        observed_at=now + timedelta(seconds=2),
        evidence_refs=(evidence,),
        reversible=True,
        cleanup_receipt_digest=_digest("cleanup"),
    )
    return AuthorizedActionFixture(
        subject=subject,
        resource=resource,
        before=before,
        after=after,
        intent=intent,
        grant=grant,
        decision=decision,
        lease=lease,
        effect=effect,
    )


def _digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"
