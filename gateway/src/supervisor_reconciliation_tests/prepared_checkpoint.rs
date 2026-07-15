use std::io::ErrorKind;
use std::sync::Arc;

use crate::Digest;
use crate::lease::LeaseRecoveryCheckpoint;

use super::active_fixture::{active_fixture, finalize_unknown_receipt};
use super::journal_fixture::durable_state;
use super::recovery_fixture::{assert_same_restored_state, checkpoint_sequence};

#[test]
fn prepared_mismatch_rejection_preserves_checkpoint_and_journal() {
    // Given
    let mut fixture = active_fixture("prepared-mismatch-invariant");
    let control = active_fixture("prepared-mismatch-invariant");
    let receipt = finalize_unknown_receipt(&fixture);
    let _ = finalize_unknown_receipt(&control);
    fixture.snapshot.prepared_dispatches[0].hold_binding_digest =
        Digest::of(b"mismatched prepared binding");
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
    let result = durable.persist_response(
        durable
            .reserve_fresh_response(Digest::of(b"prepared mismatch response request"))
            .expect("reserve mismatch response slot"),
        Some(&receipt),
        b"encoded response".to_vec(),
    );

    // Then
    assert_eq!(
        result.expect_err("prepared mismatch must fail").kind(),
        ErrorKind::InvalidData
    );
    assert_eq!(
        journal.lock().expect("journal state").snapshot,
        Some(baseline)
    );
    assert_eq!(journal.lock().expect("journal state").commits, 1);
    let observed = fixture.lease.checkpoint().expect("observed checkpoint");
    let control = control.lease.checkpoint().expect("control checkpoint");
    assert_eq!(
        checkpoint_sequence(&observed),
        checkpoint_sequence(&baseline_checkpoint) + 1
    );
    assert_eq!(
        checkpoint_sequence(&control),
        checkpoint_sequence(&baseline_checkpoint) + 1
    );
    assert_ne!(
        observed.checkpoint_id(),
        baseline_checkpoint.checkpoint_id()
    );
    assert_same_restored_state(
        &control,
        &observed,
        &fixture.spec,
        "prepared-mismatch-observed",
    );
}
