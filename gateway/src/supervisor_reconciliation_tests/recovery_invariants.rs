use std::io::ErrorKind;
use std::sync::Arc;

use crate::Digest;
use crate::ipc::{DispatchOutcome, GatewayResponse};
use crate::lease::LeaseRecoveryCheckpoint;
use crate::supervisor_journal::AcknowledgedResponseTombstone;
use crate::supervisor_protocol::{
    ControlEgressDisposition, SupervisorControlReceipt, SupervisorReconciliation,
    SupervisorResponse,
};

use super::super::{ReconciliationAdmission, ReservedResponseSlot};
use super::active_fixture::{NOW, active_fixture, finalize_unknown_receipt};
use super::journal_fixture::{durable_state, restart_durable};
use super::recovery_fixture::{assert_same_restored_state, checkpoint_sequence, restored_lease};

#[test]
fn acknowledged_signed_unknown_response_tombstone_allows_zero_prepared_reconciliation() {
    // Given
    let fixture = active_fixture("acknowledged-dispatch-reconciliation");
    let receipt = finalize_unknown_receipt(&fixture);
    let proof = fixture
        .reconciler
        .issue(
            &receipt,
            DispatchOutcome::Failed,
            Digest::of(b"acknowledged dispatch terminal evidence"),
            *b"reconcileproof11",
            NOW + 2,
        )
        .expect("issue exact acknowledged dispatch reconciliation");
    let reconciliation_id = proof.reconciliation_id;
    let reconciliation = SupervisorReconciliation::DispatchReceipt {
        unknown_receipt: Box::new(receipt.clone()),
        reconciliation: proof,
    };
    let encoded_unknown_response =
        SupervisorResponse::Gateway(Box::new(GatewayResponse::Receipt {
            action_id: receipt.action_id.clone(),
            receipt: receipt.clone(),
            semantic_http: None,
        }))
        .to_bytes()
        .expect("encode signed unknown response");
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let response_slot = ReservedResponseSlot {
        state: Arc::clone(&durable.state),
        request_envelope_id: receipt.control_envelope_id,
    };
    let response_digest = durable
        .persist_response(response_slot, Some(&receipt), encoded_unknown_response)
        .expect("persist signed unknown response");
    durable
        .acknowledge_response(receipt.control_envelope_id, response_digest)
        .expect("acknowledge signed unknown response");
    {
        let observed = journal.lock().expect("journal state");
        let snapshot = observed.snapshot.as_ref().expect("acknowledged snapshot");
        assert!(snapshot.prepared_dispatches.is_empty());
        assert_eq!(
            snapshot.acknowledged_responses,
            vec![AcknowledgedResponseTombstone {
                original_request_envelope_id: receipt.control_envelope_id,
                inner_response_digest: response_digest,
            }]
        );
    }

    // When
    let response_slot = match durable
        .admit_reconciliation(
            Digest::of(b"acknowledged dispatch reconciliation request"),
            &reconciliation,
        )
        .expect("admit acknowledged dispatch reconciliation")
    {
        ReconciliationAdmission::Ready(response_slot) => response_slot,
        other => panic!("expected ready acknowledged reconciliation, got {other:?}"),
    };
    let response = durable
        .reconcile_hold(response_slot, &reconciliation)
        .expect("reconcile acknowledged dispatch hold");

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
}

#[test]
fn wrong_ack_rejection_preserves_checkpoint_and_journal_across_retry_restart() {
    // Given
    let fixture = active_fixture("wrong-ack-invariant");
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let baseline = journal
        .lock()
        .expect("journal state")
        .snapshot
        .clone()
        .expect("seed snapshot");
    let baseline_checkpoint =
        LeaseRecoveryCheckpoint::from_bytes(baseline.lease_checkpoint.clone())
            .expect("baseline checkpoint");

    // When
    let first = durable.acknowledge_response(Digest::of(b"wrong request"), Digest::of(b"wrong"));

    // Then
    assert_eq!(
        first.expect_err("wrong ACK must fail").kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        journal.lock().expect("journal state").snapshot,
        Some(baseline.clone())
    );
    assert_eq!(journal.lock().expect("journal state").commits, 1);
    let observed = fixture.lease.checkpoint().expect("observed checkpoint");
    assert_eq!(
        checkpoint_sequence(&observed),
        checkpoint_sequence(&baseline_checkpoint) + 1
    );
    assert_ne!(
        observed.checkpoint_id(),
        baseline_checkpoint.checkpoint_id()
    );
    assert_same_restored_state(
        &baseline_checkpoint,
        &observed,
        &fixture.spec,
        "wrong-ack-observed",
    );

    let restarted_lease = restored_lease(&baseline, "gateway:boot:restart-wrong-ack");
    let restarted = restart_durable(Arc::clone(&restarted_lease), Arc::clone(&journal));
    let retried = restarted.acknowledge_response(
        Digest::of(b"wrong request after restart"),
        Digest::of(b"wrong after restart"),
    );
    assert_eq!(
        retried.expect_err("retried wrong ACK must fail").kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        journal.lock().expect("journal state").snapshot,
        Some(baseline.clone())
    );
    assert_eq!(journal.lock().expect("journal state").commits, 1);
    let restart_observed = restarted_lease
        .checkpoint()
        .expect("restarted observed checkpoint");
    assert_eq!(
        checkpoint_sequence(&restart_observed),
        checkpoint_sequence(&baseline_checkpoint) + 1
    );
    assert_same_restored_state(
        &baseline_checkpoint,
        &restart_observed,
        &fixture.spec,
        "wrong-ack-restart-observed",
    );
}
