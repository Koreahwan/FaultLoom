use std::sync::Arc;

use crate::Digest;
use crate::ipc::{DenialCode, DispatchOutcome};
use crate::lease::{ControlPlaneReconciliationHold, ReconciliationTerminal};
use crate::supervisor_protocol::SupervisorReconciliation;

use super::super::ReconciliationAdmission;
use super::active_fixture::{NOW, active_fixture, control_reconciliation};
use super::journal_fixture::durable_state;
use super::lease_request::{lease_spec, seal_spec};

#[test]
fn near_match_control_hold_cannot_clear_or_enable_retry() {
    // Given
    let mut fixture = active_fixture("near-match");
    fixture.snapshot.prepared_dispatches[0].hold_binding_digest =
        Digest::of(b"near-match prepared hold");
    fixture
        .lease
        .interrupt_grant(&fixture.spec.grant_id, fixture.spec.grant_version)
        .expect("interrupt active lease");
    let proof = fixture
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
                evidence_digest: Digest::of(b"terminal control evidence"),
                nonce: *b"reconcileproof01",
                resolved_at_millis: NOW + 2,
            },
        )
        .expect("issue exact control reconciliation");
    let reconciliation = SupervisorReconciliation::ControlPlane {
        reconciliation: proof,
    };
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);

    // When
    let result = durable.admit_reconciliation(Digest::of(b"near-match request"), &reconciliation);

    // Then
    assert!(matches!(
        result,
        Ok(ReconciliationAdmission::Rejected {
            reason: DenialCode::LeaseBindingMismatch,
            ..
        })
    ));
    assert_eq!(
        fixture.lease.reconciliation_receipt(
            &fixture.spec.grant_id,
            fixture.spec.grant_version,
            fixture.spec.intent_digest,
        ),
        Ok(None)
    );
    let mut retry = lease_spec("lease:retry-near-match", b"intent:retry-near-match");
    retry.retry_of_intent_digest = Some(fixture.spec.intent_digest);
    seal_spec(&mut retry);
    assert!(matches!(
        fixture.lease.issue(retry),
        Err(DenialCode::RetryAliasInvalid)
    ));
    assert_eq!(journal.lock().expect("journal state").commits, 1);
}

#[test]
fn duplicate_control_prepared_bindings_remain_denied() {
    // Given
    let mut fixture = active_fixture("duplicate-control");
    let mut duplicate = fixture.snapshot.prepared_dispatches[0].clone();
    duplicate.request_frame_digest = Digest::of(b"duplicate control request frame");
    duplicate.control_envelope_id = Digest::of(b"duplicate control envelope");
    duplicate.action_id = "action:duplicate-control".to_owned();
    duplicate.lease_id = "lease:duplicate-control-shadow".to_owned();
    fixture.snapshot.prepared_dispatches.push(duplicate);
    fixture.snapshot.prepared_dispatches.sort_by(|left, right| {
        left.request_frame_digest
            .as_bytes()
            .cmp(right.request_frame_digest.as_bytes())
    });
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot.clone());
    fixture
        .lease
        .interrupt_grant(&fixture.spec.grant_id, fixture.spec.grant_version)
        .expect("interrupt active lease");
    let reconciliation = control_reconciliation(&fixture, *b"reconcileproof09");

    // When
    let admission = durable.admit_reconciliation(
        Digest::of(b"duplicate control reconciliation request"),
        &reconciliation,
    );

    // Then
    assert!(matches!(
        admission,
        Ok(ReconciliationAdmission::Rejected {
            reason: DenialCode::LeaseBindingMismatch,
            ..
        })
    ));
    assert_eq!(journal.lock().expect("journal state").commits, 1);
    assert_eq!(
        fixture.lease.reconciliation_receipt(
            &fixture.spec.grant_id,
            fixture.spec.grant_version,
            fixture.spec.intent_digest,
        ),
        Ok(None)
    );
}
