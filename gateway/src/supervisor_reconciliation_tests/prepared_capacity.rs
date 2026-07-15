use std::io::ErrorKind;
use std::sync::{Arc, Barrier};

use crate::Digest;
use crate::ipc::DispatchOutcome;
use crate::lease::{ControlPlaneReconciliationHold, ReconciliationTerminal};
use crate::supervisor_journal::MAX_DURABLE_RESPONSE_SLOTS;
use crate::supervisor_protocol::SupervisorReconciliation;

use super::super::ReconciliationAdmission;
use super::active_fixture::{NOW, active_fixture, finalize_unknown_receipt};
use super::journal_fixture::{durable_state, fill_acknowledged};

#[test]
fn prepared_reconciliation_transfers_the_final_response_slot() {
    // Given
    let mut fixture = active_fixture("prepared-transfer-at-capacity");
    fill_acknowledged(&mut fixture.snapshot, MAX_DURABLE_RESPONSE_SLOTS - 1);
    let receipt = finalize_unknown_receipt(&fixture);
    let proof = fixture
        .reconciler
        .issue(
            &receipt,
            DispatchOutcome::Failed,
            Digest::of(b"prepared transfer terminal evidence"),
            *b"reconcileproof04",
            NOW + 2,
        )
        .expect("issue exact prepared reconciliation");
    let reconciliation = SupervisorReconciliation::DispatchReceipt {
        unknown_receipt: Box::new(receipt),
        reconciliation: proof,
    };
    let request_id = Digest::of(b"prepared transfer request");
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);

    // When
    let response_slot = match durable
        .admit_reconciliation(request_id, &reconciliation)
        .expect("the prepared slot must transfer at full capacity")
    {
        ReconciliationAdmission::Ready(response_slot) => response_slot,
        other => panic!("expected prepared transfer admission, got {other:?}"),
    };
    let response = durable
        .reconcile_hold(response_slot, &reconciliation)
        .expect("persist transferred reconciliation response");

    // Then
    {
        let observed = journal.lock().expect("journal state");
        let snapshot = observed.snapshot.as_ref().expect("transferred snapshot");
        assert!(snapshot.prepared_dispatches.is_empty());
        assert_eq!(snapshot.pending_responses.len(), 1);
        assert_eq!(
            snapshot.acknowledged_responses.len(),
            MAX_DURABLE_RESPONSE_SLOTS - 1
        );
    }
    durable
        .acknowledge_response(request_id, Digest::of(&response))
        .expect("acknowledge transferred response");
    let observed = journal.lock().expect("journal state");
    let snapshot = observed.snapshot.as_ref().expect("acknowledged snapshot");
    assert!(snapshot.prepared_dispatches.is_empty());
    assert!(snapshot.pending_responses.is_empty());
    assert_eq!(
        snapshot.acknowledged_responses.len(),
        MAX_DURABLE_RESPONSE_SLOTS
    );
}

#[test]
fn invalid_reconciliation_at_full_capacity_is_terminal_without_mutation() {
    // Given
    let mut fixture = active_fixture("invalid-at-capacity");
    fixture.snapshot.prepared_dispatches[0].hold_binding_digest =
        Digest::of(b"invalid prepared hold at capacity");
    fill_acknowledged(&mut fixture.snapshot, MAX_DURABLE_RESPONSE_SLOTS - 1);
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
                evidence_digest: Digest::of(b"invalid terminal evidence at capacity"),
                nonce: *b"reconcileproof05",
                resolved_at_millis: NOW + 2,
            },
        )
        .expect("issue mismatched control reconciliation");
    let reconciliation = SupervisorReconciliation::ControlPlane {
        reconciliation: proof,
    };
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let baseline = journal.lock().expect("journal state").snapshot.clone();
    let commits = journal.lock().expect("journal state").commits;

    // When
    let result = durable.admit_reconciliation(
        Digest::of(b"invalid reconciliation at capacity request"),
        &reconciliation,
    );

    // Then
    assert_eq!(
        result
            .expect_err("invalid reconciliation cannot allocate a denial slot")
            .kind(),
        ErrorKind::Other
    );
    assert_eq!(
        fixture.lease.reconciliation_receipt(
            &fixture.spec.grant_id,
            fixture.spec.grant_version,
            fixture.spec.intent_digest,
        ),
        Ok(None)
    );
    let observed = journal.lock().expect("journal state");
    assert_eq!(observed.snapshot, baseline);
    assert_eq!(observed.commits, commits);
}

#[test]
fn concurrent_prepared_admission_mints_one_capability_and_drop_releases_it() {
    // Given
    let fixture = active_fixture("concurrent-prepared-claim");
    let receipt = finalize_unknown_receipt(&fixture);
    let proof = fixture
        .reconciler
        .issue(
            &receipt,
            DispatchOutcome::Failed,
            Digest::of(b"concurrent prepared claim evidence"),
            *b"reconcileproof06",
            NOW + 2,
        )
        .expect("issue exact prepared reconciliation");
    let reconciliation = Arc::new(SupervisorReconciliation::DispatchReceipt {
        unknown_receipt: Box::new(receipt),
        reconciliation: proof,
    });
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let baseline = journal.lock().expect("journal state").snapshot.clone();
    let durable = Arc::new(durable);
    let barrier = Arc::new(Barrier::new(3));
    let workers = (0_u8..2)
        .map(|index| {
            let durable = Arc::clone(&durable);
            let reconciliation = Arc::clone(&reconciliation);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let admission = durable.admit_reconciliation(
                    Digest::of(format!("concurrent reconciliation request {index}").as_bytes()),
                    reconciliation.as_ref(),
                );
                barrier.wait();
                match admission {
                    Ok(ReconciliationAdmission::Ready(_response_slot)) => Ok(()),
                    Err(error) => Err(error.kind()),
                    Ok(other) => panic!("unexpected reconciliation admission: {other:?}"),
                }
            })
        })
        .collect::<Vec<_>>();

    // When
    barrier.wait();
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("prepared claim worker"))
        .collect::<Vec<_>>();

    // Then
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Err(ErrorKind::WouldBlock))
            .count(),
        1
    );
    assert_eq!(journal.lock().expect("journal state").snapshot, baseline);
    assert_eq!(journal.lock().expect("journal state").commits, 1);
    let retry = durable
        .admit_reconciliation(
            Digest::of(b"prepared claim after drop"),
            reconciliation.as_ref(),
        )
        .expect("dropped prepared claim must be reusable");
    assert!(matches!(retry, ReconciliationAdmission::Ready(_)));
}
