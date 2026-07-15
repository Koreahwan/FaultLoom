use std::sync::{Arc, Mutex};

use crate::Digest;
use crate::ipc::{DenialCode, GatewayResponse};
use crate::supervisor_protocol::{
    ControlEgressDisposition, SupervisorControlReceipt, SupervisorReconciliation,
    SupervisorResponse,
};

use super::super::{
    DurableReconciliationError, DurableSupervisorState, ReconciliationAdmission,
    ReservedResponseSlot,
};
use super::active_fixture::{
    ActiveFixture, active_fixture, authenticated_unknown_receipt, control_reconciliation,
};
use super::journal_fixture::{TestJournalState, durable_state};

#[test]
fn acknowledged_cancelled_unknown_without_prepared_dispatch_reconciles_control_hold() {
    // Given
    let (fixture, durable, journal) = acknowledged_cancelled_unknown("cancelled-control");
    let reconciliation = control_reconciliation(&fixture, *b"reconcileproof07");
    let reconciliation_id = match &reconciliation {
        SupervisorReconciliation::ControlPlane { reconciliation } => {
            reconciliation.reconciliation_id
        }
        SupervisorReconciliation::DispatchReceipt { .. } => {
            panic!("expected control-plane reconciliation")
        }
    };
    {
        let observed = journal.lock().expect("journal state");
        let snapshot = observed.snapshot.as_ref().expect("cancelled snapshot");
        assert!(snapshot.prepared_dispatches.is_empty());
        assert!(snapshot.pending_responses.is_empty());
        assert_eq!(snapshot.acknowledged_responses.len(), 1);
    }

    // When
    let request_id = Digest::of(b"cancelled control reconciliation request");
    let response_slot = match durable
        .admit_reconciliation(request_id, &reconciliation)
        .expect("admit cancelled control reconciliation")
    {
        ReconciliationAdmission::Ready(response_slot) => response_slot,
        other => panic!("expected ready control reconciliation, got {other:?}"),
    };
    let response = durable
        .reconcile_hold(response_slot, &reconciliation)
        .expect("persist terminal control reconciliation response");

    // Then
    assert_eq!(
        SupervisorResponse::from_bytes(&response),
        Ok(SupervisorResponse::Control(
            SupervisorControlReceipt::HoldReconciled {
                reconciliation_id,
                removed_prepared_dispatches: 0,
                egress_disposition: ControlEgressDisposition::NoActiveEgress,
            }
        ))
    );
    assert_eq!(
        fixture.lease.reconciliation_receipt(
            &fixture.spec.grant_id,
            fixture.spec.grant_version,
            fixture.spec.intent_digest,
        ),
        Ok(Some(reconciliation_id))
    );
    let observed = journal.lock().expect("journal state");
    let snapshot = observed.snapshot.as_ref().expect("reconciled snapshot");
    assert!(snapshot.prepared_dispatches.is_empty());
    assert_eq!(snapshot.pending_responses.len(), 1);
}

#[test]
fn tampered_control_proof_without_prepared_dispatch_cannot_clear_hold() {
    // Given
    let (fixture, durable, journal) = acknowledged_cancelled_unknown("tampered-control");
    let mut reconciliation = control_reconciliation(&fixture, *b"reconcileproof08");
    match &mut reconciliation {
        SupervisorReconciliation::ControlPlane { reconciliation } => {
            reconciliation.authentication_tag = Digest::of(b"tampered reconciliation tag");
        }
        SupervisorReconciliation::DispatchReceipt { .. } => {
            panic!("expected control-plane reconciliation")
        }
    }
    let commits_before = journal.lock().expect("journal state").commits;

    // When
    let response_slot = match durable
        .admit_reconciliation(Digest::of(b"tampered control request"), &reconciliation)
        .expect("reserve terminal denial response")
    {
        ReconciliationAdmission::Ready(response_slot) => response_slot,
        other => panic!("expected validation-ready reconciliation, got {other:?}"),
    };
    let error = durable.reconcile_hold(response_slot, &reconciliation);

    // Then
    match error {
        Err(DurableReconciliationError::Rejected {
            response_slot,
            reason: DenialCode::LeaseReconciliationRequired,
        }) => drop(response_slot),
        other => panic!("expected tampered reconciliation rejection, got {other:?}"),
    }
    assert_eq!(
        fixture.lease.reconciliation_receipt(
            &fixture.spec.grant_id,
            fixture.spec.grant_version,
            fixture.spec.intent_digest,
        ),
        Ok(None)
    );
    assert_eq!(
        journal.lock().expect("journal state").commits,
        commits_before
    );
}

fn acknowledged_cancelled_unknown(
    label: &str,
) -> (
    ActiveFixture,
    DurableSupervisorState,
    Arc<Mutex<TestJournalState>>,
) {
    let fixture = active_fixture(label);
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot.clone());
    fixture
        .lease
        .interrupt_grant(&fixture.spec.grant_id, fixture.spec.grant_version)
        .expect("interrupt active lease");
    let receipt = authenticated_unknown_receipt(&fixture);
    let response = SupervisorResponse::Gateway(Box::new(GatewayResponse::Receipt {
        action_id: receipt.action_id.clone(),
        receipt: receipt.clone(),
        semantic_http: None,
    }))
    .to_bytes()
    .expect("encode cancelled unknown response");
    let response_slot = ReservedResponseSlot {
        state: Arc::clone(&durable.state),
        request_envelope_id: fixture.approval.control_envelope_id,
    };
    let response_digest = durable
        .persist_response(response_slot, Some(&receipt), response)
        .expect("persist cancelled unknown response");
    durable
        .acknowledge_response(fixture.approval.control_envelope_id, response_digest)
        .expect("acknowledge cancelled unknown response");
    (fixture, durable, journal)
}
