use std::io::ErrorKind;
use std::sync::Arc;

use crate::Digest;
use crate::ipc::{DenialCode, DispatchOutcome};
use crate::supervisor_protocol::{
    ControlEgressDisposition, SupervisorControlReceipt, SupervisorReconciliation,
    SupervisorResponse,
};

use super::super::{DurableReconciliationError, ReconciliationAdmission};
use super::active_fixture::{NOW, active_fixture, finalize_unknown_receipt};
use super::journal_fixture::durable_state;

#[test]
fn dispatch_reconciliation_without_exact_prepared_binding_remains_denied() {
    // Given
    let mut fixture = active_fixture("missing-dispatch-prepared");
    let receipt = finalize_unknown_receipt(&fixture);
    let proof = fixture
        .reconciler
        .issue(
            &receipt,
            DispatchOutcome::Failed,
            Digest::of(b"missing dispatch prepared evidence"),
            *b"reconcileproof10",
            NOW + 2,
        )
        .expect("issue exact dispatch reconciliation");
    let reconciliation = SupervisorReconciliation::DispatchReceipt {
        unknown_receipt: Box::new(receipt),
        reconciliation: proof,
    };
    fixture.snapshot.prepared_dispatches.clear();
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);

    // When
    let admission = durable.admit_reconciliation(
        Digest::of(b"missing dispatch prepared reconciliation request"),
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
}

#[test]
fn persistence_failure_after_lease_mutation_is_terminal() {
    // Given
    let fixture = active_fixture("terminal");
    let receipt = finalize_unknown_receipt(&fixture);
    let proof = fixture
        .reconciler
        .issue(
            &receipt,
            DispatchOutcome::Failed,
            Digest::of(b"terminal dispatch evidence"),
            *b"reconcileproof02",
            NOW + 2,
        )
        .expect("issue exact dispatch reconciliation");
    let reconciliation_id = proof.reconciliation_id;
    let reconciliation = SupervisorReconciliation::DispatchReceipt {
        unknown_receipt: Box::new(receipt),
        reconciliation: proof,
    };
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    journal.lock().expect("journal state").fail_next_commit = true;

    // When
    let response_slot = match durable
        .admit_reconciliation(Digest::of(b"terminal request"), &reconciliation)
        .expect("admit exact reconciliation")
    {
        ReconciliationAdmission::Ready(response_slot) => response_slot,
        other => panic!("expected ready reconciliation, got {other:?}"),
    };
    let error = match durable.reconcile_hold(response_slot, &reconciliation) {
        Err(DurableReconciliationError::Terminal(error)) => error,
        other => panic!("expected terminal durability error, got {other:?}"),
    };

    // Then
    assert_eq!(error.kind(), ErrorKind::PermissionDenied);
    assert_eq!(
        fixture.lease.reconciliation_receipt(
            &fixture.spec.grant_id,
            fixture.spec.grant_version,
            fixture.spec.intent_digest,
        ),
        Ok(Some(reconciliation_id))
    );
    let state = journal.lock().expect("journal state");
    assert_eq!(state.commits, 1);
    assert_eq!(
        state
            .snapshot
            .as_ref()
            .expect("seed snapshot")
            .prepared_dispatches
            .len(),
        1
    );
    assert!(
        state
            .snapshot
            .as_ref()
            .expect("seed snapshot")
            .pending_responses
            .is_empty()
    );
}

#[test]
fn exact_replay_cannot_clear_twice() {
    // Given
    let fixture = active_fixture("replay");
    let receipt = finalize_unknown_receipt(&fixture);
    let proof = fixture
        .reconciler
        .issue(
            &receipt,
            DispatchOutcome::Failed,
            Digest::of(b"replay terminal evidence"),
            *b"reconcileproof03",
            NOW + 2,
        )
        .expect("issue exact dispatch reconciliation");
    let reconciliation_id = proof.reconciliation_id;
    let reconciliation = SupervisorReconciliation::DispatchReceipt {
        unknown_receipt: Box::new(receipt),
        reconciliation: proof,
    };
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let original_request_id = Digest::of(b"first reconciliation request");
    let response_slot = match durable
        .admit_reconciliation(original_request_id, &reconciliation)
        .expect("admit exact reconciliation")
    {
        ReconciliationAdmission::Ready(response_slot) => response_slot,
        other => panic!("expected ready reconciliation, got {other:?}"),
    };
    let response = durable
        .reconcile_hold(response_slot, &reconciliation)
        .expect("persist exact reconciliation response");
    let response_digest = Digest::of(&response);
    durable
        .acknowledge_response(original_request_id, response_digest)
        .expect("acknowledge durable response");
    let commits_before_replay = journal.lock().expect("journal state").commits;

    // When
    let replay = durable.admit_reconciliation(Digest::of(b"replayed request"), &reconciliation);

    // Then
    assert!(matches!(
        replay,
        Ok(ReconciliationAdmission::Rejected {
            reason: DenialCode::LeaseReplay,
            ..
        })
    ));
    assert_eq!(
        journal.lock().expect("journal state").commits,
        commits_before_replay
    );
    assert_eq!(
        SupervisorResponse::from_bytes(&response),
        Ok(SupervisorResponse::Control(
            SupervisorControlReceipt::HoldReconciled {
                reconciliation_id,
                removed_prepared_dispatches: 1,
                egress_disposition: ControlEgressDisposition::NoActiveEgress,
            }
        ))
    );
    let snapshot = journal
        .lock()
        .expect("journal state")
        .snapshot
        .clone()
        .expect("snapshot");
    assert!(snapshot.prepared_dispatches.is_empty());
    assert!(snapshot.pending_responses.is_empty());
}
