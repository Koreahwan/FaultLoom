from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import timedelta

from faultloom_protocol import (
    ActionIntent,
    ActionLease,
    BudgetReservation,
    DecisionOutcome,
    EgressPlane,
    PolicyDecision,
    sha256_digest,
)
from faultloom_llm import CompiledToolAction, LeaseBindingRequest

from .fixture import D4, D5, D6, D7, NOW, LlmAgentFixture


@dataclass(frozen=True, slots=True)
class DecisionLease:
    decision: PolicyDecision
    lease: ActionLease


def decision_lease_for(
    compiled: CompiledToolAction,
    fixture: LlmAgentFixture,
    lease_id: str = "lease.llm.tool",
) -> DecisionLease:
    return decision_lease_for_intent(compiled.intent, fixture, lease_id)


def decision_lease_for_intent(
    intent: ActionIntent,
    fixture: LlmAgentFixture,
    lease_id: str,
) -> DecisionLease:
    decision = PolicyDecision(
        schema_version="0.1.0",
        decision_id=f"decision.{lease_id}",
        intent_digest=sha256_digest(intent),
        grant_id=fixture.active_epoch.grant_id,
        grant_version=1,
        scope_epoch=fixture.active_epoch.epoch,
        outcome=DecisionOutcome.ALLOW,
        reason_codes=("explicit.allow",),
        evaluated_at=NOW,
        lease_id=lease_id,
    )
    lease = ActionLease(
        schema_version="0.1.0",
        lease_id=lease_id,
        lease_key_id="lease-key.llm.lab",
        action_id=intent.action_id,
        correlation_id=f"correlation.{lease_id}",
        intent_digest=sha256_digest(intent),
        decision_digest=sha256_digest(decision),
        grant_id=fixture.active_epoch.grant_id,
        grant_version=1,
        scope_epoch=fixture.active_epoch.epoch,
        authority_key_id="ed25519:sha256:" + "aa" * 32,
        scope_epoch_binding_digest=D4,
        gateway_boot_id="gateway-boot.llm.lab",
        boot_challenge_digest=D5,
        target_id=intent.target_id,
        identity_id=intent.subject.identity_id,
        tenant_id=intent.subject.tenant_id,
        action_kind=intent.action_kind,
        semantic_action_digest=intent.payload_digest,
        request_binding_digest=D6,
        resolution_digest=D7,
        egress_plane=EgressPlane.TARGET_GATEWAY,
        dispatch_nonce=hashlib.sha256(lease_id.encode()).hexdigest()[:32],
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
        reservation=BudgetReservation(
            schema_version="0.1.0",
            request_bytes=1024,
            response_bytes=1024,
            duration_seconds=10,
        ),
    )
    return DecisionLease(decision=decision, lease=lease)


def lease_binding_request(
    compiled: CompiledToolAction,
    fixture: LlmAgentFixture,
    revoked: bool = False,
) -> LeaseBindingRequest:
    binding = decision_lease_for(compiled, fixture)
    return LeaseBindingRequest(
        compiled=compiled,
        lease=binding.lease,
        scope_epoch=fixture.revoked_epoch if revoked else fixture.active_epoch,
        evaluated_at=NOW + timedelta(seconds=1),
    )
