use std::sync::Arc;

use crate::Digest;
use crate::ipc::{DispatchOutcome, DispatchReceipt, DispatchRequest};
use crate::lease::{
    ControlPlaneReconciliationHold, GrantBudget, LeaseAuthority, LeaseSpec,
    ReconciliationAuthority, ReconciliationTerminal,
};
use crate::policy::{LeaseApproval, LeaseCompletion, LeaseVerifier};
use crate::supervisor_journal::{JournalSnapshot, PreparedDispatchBinding};
use crate::supervisor_protocol::SupervisorReconciliation;

use super::lease_request::{dispatch_request, lease_spec};

pub(super) const NOW: u64 = 1_000_000;
pub(super) const LEASE_KEY: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
pub(super) const RECONCILIATION_KEY: [u8; 32] = *b"fedcba9876543210fedcba9876543210";

pub(super) struct ActiveFixture {
    pub(super) lease: Arc<LeaseAuthority>,
    pub(super) reconciler: ReconciliationAuthority,
    pub(super) spec: LeaseSpec,
    pub(super) request: DispatchRequest,
    pub(super) approval: LeaseApproval,
    pub(super) snapshot: JournalSnapshot,
}

pub(super) fn active_fixture(label: &str) -> ActiveFixture {
    let lease = Arc::new(
        LeaseAuthority::new_with_reconciliation_verifier(
            "lease-key:test".to_owned(),
            LEASE_KEY,
            "gateway:boot:test".to_owned(),
            Digest::of(b"gateway challenge:test"),
            "reconciliation-key:test".to_owned(),
            RECONCILIATION_KEY,
        )
        .expect("lease authority"),
    );
    lease
        .register_grant(
            "grant:1",
            3,
            GrantBudget {
                total_actions: 4,
                rate_per_minute: 4,
                max_concurrency: 2,
                max_request_bytes: 64,
                max_response_bytes: 128,
                max_duration_seconds: 5,
            },
        )
        .expect("register grant");
    let spec = lease_spec(
        &format!("lease:{label}"),
        format!("intent:{label}").as_bytes(),
    );
    let issued = lease.issue(spec.clone()).expect("issue lease");
    let request = dispatch_request(&spec, issued.proof);
    let approval = lease.reserve(&request, NOW).expect("reserve lease");
    let checkpoint = lease.checkpoint().expect("checkpoint active lease");
    let prepared = PreparedDispatchBinding {
        request_frame_digest: Digest::of(format!("request-frame:{label}").as_bytes()),
        control_envelope_id: approval.control_envelope_id,
        hold_binding_digest: approval.hold_binding_digest,
        action_id: request.action_id.clone(),
        correlation_id: request.correlation_id.clone(),
        grant_id: request.grant_id.clone(),
        grant_version: request.grant_version,
        scope_epoch: request.scope_epoch,
        lease_id: request.lease_id.clone(),
        intent_digest: request.intent_digest,
        effect_digest: approval.effect_digest,
        compiled_request_digest: approval.compiled_request_digest,
    };
    ActiveFixture {
        lease,
        reconciler: ReconciliationAuthority::new(
            "reconciliation-key:test".to_owned(),
            RECONCILIATION_KEY,
        )
        .expect("reconciliation authority"),
        spec,
        request,
        approval,
        snapshot: JournalSnapshot {
            lease_checkpoint_id: checkpoint.checkpoint_id(),
            lease_checkpoint: checkpoint.as_bytes().to_vec(),
            prepared_dispatches: vec![prepared],
            pending_responses: Vec::new(),
            acknowledged_responses: Vec::new(),
        },
    }
}

pub(super) fn control_reconciliation(
    fixture: &ActiveFixture,
    nonce: [u8; 16],
) -> SupervisorReconciliation {
    let reconciliation = fixture
        .reconciler
        .issue_control_plane_hold(
            ControlPlaneReconciliationHold {
                grant_id: fixture.spec.grant_id.clone(),
                grant_version: fixture.spec.grant_version,
                intent_digest: fixture.spec.intent_digest,
                effect_digest: fixture.spec.effect_digest,
                hold_binding_digest: fixture.approval.hold_binding_digest,
            },
            ReconciliationTerminal {
                outcome: DispatchOutcome::Failed,
                evidence_digest: Digest::of(b"terminal cancelled control evidence"),
                nonce,
                resolved_at_millis: NOW + 2,
            },
        )
        .expect("issue exact control reconciliation");
    SupervisorReconciliation::ControlPlane { reconciliation }
}

pub(super) fn finalize_unknown_receipt(fixture: &ActiveFixture) -> DispatchReceipt {
    fixture
        .lease
        .finalize(
            &fixture.approval,
            LeaseCompletion {
                outcome: DispatchOutcome::UnknownOutcome,
                bytes_sent: 4,
                bytes_received: 0,
                elapsed_millis: 50,
            },
        )
        .expect("finalize unknown lease");
    authenticated_unknown_receipt(fixture)
}

pub(super) fn authenticated_unknown_receipt(fixture: &ActiveFixture) -> DispatchReceipt {
    let mut receipt = DispatchReceipt {
        receipt_id: Digest::ZERO,
        receipt_authentication_tag: Digest::ZERO,
        action_id: fixture.request.action_id.clone(),
        correlation_id: fixture.request.correlation_id.clone(),
        lease_id: fixture.request.lease_id.clone(),
        grant_id: fixture.request.grant_id.clone(),
        grant_version: fixture.request.grant_version,
        authority_key_id: fixture.spec.authority_key_id.clone(),
        scope_epoch_binding_digest: fixture.spec.scope_epoch_binding_digest,
        lease_key_id: fixture.approval.lease_key_id.clone(),
        gateway_boot_id: fixture.approval.gateway_boot_id.clone(),
        boot_challenge_digest: fixture.approval.boot_challenge_digest,
        intent_digest: fixture.request.intent_digest,
        decision_digest: fixture.request.decision_digest,
        scope_epoch: fixture.request.scope_epoch,
        semantic_action_digest: fixture.request.semantic_action_digest,
        request_binding_digest: fixture.request.lease_binding_digest(),
        request_frame_digest: fixture.snapshot.prepared_dispatches[0].request_frame_digest,
        control_envelope_id: fixture.approval.control_envelope_id,
        hold_binding_digest: fixture.approval.hold_binding_digest,
        resolution_digest: fixture.request.resolution_digest,
        action_kind: fixture.request.action_kind,
        egress_plane: fixture.request.egress_plane,
        effect_digest: fixture.approval.effect_digest,
        dispatch_nonce: fixture.request.dispatch_nonce,
        lease_issued_at_millis: fixture.approval.issued_at_millis,
        lease_expires_at_millis: fixture.approval.expires_at_millis,
        retry_of_intent_digest: fixture.request.retry_of_intent_digest,
        reserved_action_count: fixture.approval.reservation.action_count,
        reserved_request_bytes: fixture.approval.reservation.request_bytes,
        reserved_response_bytes: fixture.approval.reservation.response_bytes,
        reserved_duration_seconds: fixture.approval.reservation.duration_seconds,
        request_digest: fixture.approval.compiled_request_digest,
        response_digest: None,
        outcome: DispatchOutcome::UnknownOutcome,
        dispatched_at_millis: NOW,
        completed_at_millis: NOW + 1,
        bytes_sent: 4,
        bytes_received: 0,
        reconciliation_required: true,
    };
    receipt.receipt_id = receipt.canonical_id();
    receipt.receipt_authentication_tag = fixture
        .lease
        .authenticate_receipt(&fixture.approval, &receipt)
        .expect("authenticate receipt");
    receipt
}
