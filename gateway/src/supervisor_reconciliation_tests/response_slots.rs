use std::io::ErrorKind;
use std::sync::{Arc, Barrier};

use crate::Digest;
use crate::policy::CompiledAction;
use crate::supervisor_journal::{
    AcknowledgedResponseTombstone, MAX_DURABLE_RESPONSE_SLOTS, PendingInnerResponse,
};

use super::active_fixture::active_fixture;
use super::journal_fixture::{durable_state, fill_acknowledged};

#[test]
fn pending_ack_reaches_64_tombstones_and_exact_replay_is_commit_free() {
    // Given
    let mut fixture = active_fixture("ack-capacity-invariant");
    let original_request_envelope_id = Digest::of(b"pending capacity request");
    let inner_response = b"pending capacity response".to_vec();
    let inner_response_digest = Digest::of(&inner_response);
    fixture.snapshot.pending_responses = vec![PendingInnerResponse {
        original_request_envelope_id,
        inner_response_digest,
        inner_response,
    }];
    fixture.snapshot.prepared_dispatches.clear();
    fixture.snapshot.acknowledged_responses = (0..MAX_DURABLE_RESPONSE_SLOTS - 1)
        .map(|index| AcknowledgedResponseTombstone {
            original_request_envelope_id: Digest::of(
                format!("acknowledged request {index}").as_bytes(),
            ),
            inner_response_digest: Digest::of(format!("acknowledged response {index}").as_bytes()),
        })
        .collect();
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    // When
    durable
        .acknowledge_response(original_request_envelope_id, inner_response_digest)
        .expect("acknowledge final durable response slot");
    let commits_after_first = journal.lock().expect("journal state").commits;
    durable
        .acknowledge_response(original_request_envelope_id, inner_response_digest)
        .expect("replay exact acknowledgement");

    // Then
    let observed = journal.lock().expect("journal state");
    let snapshot = observed.snapshot.as_ref().expect("acknowledged snapshot");
    assert!(snapshot.pending_responses.is_empty());
    assert_eq!(
        snapshot.acknowledged_responses.len(),
        MAX_DURABLE_RESPONSE_SLOTS
    );
    assert_eq!(observed.commits, commits_after_first);
}

#[test]
fn fresh_reservation_at_full_capacity_fails_without_journal_mutation() {
    // Given
    let mut fixture = active_fixture("full-reservation");
    fixture.snapshot.prepared_dispatches.clear();
    fill_acknowledged(&mut fixture.snapshot, MAX_DURABLE_RESPONSE_SLOTS);
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let baseline = journal.lock().expect("journal state").snapshot.clone();
    let commits = journal.lock().expect("journal state").commits;

    // When
    let result = durable.reserve_fresh_response(Digest::of(b"over-capacity request"));

    // Then
    assert_eq!(
        result.expect_err("full response quota must reject").kind(),
        ErrorKind::Other
    );
    let observed = journal.lock().expect("journal state");
    assert_eq!(observed.snapshot, baseline);
    assert_eq!(observed.commits, commits);
}

#[test]
fn dropping_transient_reservation_releases_its_slot() {
    // Given
    let mut fixture = active_fixture("drop-reservation");
    fixture.snapshot.prepared_dispatches.clear();
    fill_acknowledged(&mut fixture.snapshot, MAX_DURABLE_RESPONSE_SLOTS - 1);
    let (durable, _) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let first_id = Digest::of(b"first transient response");
    let second_id = Digest::of(b"second transient response");
    let first = durable
        .reserve_fresh_response(first_id)
        .expect("reserve last response slot");
    assert!(durable.reserve_fresh_response(second_id).is_err());

    // When
    drop(first);

    // Then
    drop(
        durable
            .reserve_fresh_response(second_id)
            .expect("released transient slot must be reusable"),
    );
}

#[test]
fn concurrent_transient_reservations_never_exceed_remaining_capacity() {
    // Given
    let mut fixture = active_fixture("concurrent-reservations");
    fixture.snapshot.prepared_dispatches.clear();
    fill_acknowledged(&mut fixture.snapshot, MAX_DURABLE_RESPONSE_SLOTS - 4);
    let (durable, _) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let durable = Arc::new(durable);
    let barrier = Arc::new(Barrier::new(9));
    let workers = (0_u8..8)
        .map(|index| {
            let durable = Arc::clone(&durable);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let slot = durable.reserve_fresh_response(Digest::from_bytes([index + 1; 32]));
                barrier.wait();
                slot.is_ok()
            })
        })
        .collect::<Vec<_>>();

    // When
    barrier.wait();
    let admitted = workers
        .into_iter()
        .map(|worker| worker.join().expect("reservation worker"))
        .filter(|admitted| *admitted)
        .count();

    // Then
    assert_eq!(admitted, 4);
}

#[test]
fn transient_dispatch_reservation_converts_to_prepared_at_barrier() {
    // Given
    let mut fixture = active_fixture("transient-to-prepared");
    fixture.snapshot.prepared_dispatches.clear();
    let request_frame_digest = Digest::of(b"transient prepared request frame");
    let response_id = fixture.approval.control_envelope_id;
    let compiled = CompiledAction::fixture(&fixture.request);
    let (durable, journal) = durable_state(Arc::clone(&fixture.lease), fixture.snapshot);
    let slot = durable
        .reserve_fresh_response(response_id)
        .expect("reserve dispatch response slot");

    // When
    let result = durable.persist_pre_egress(
        &fixture.request,
        request_frame_digest,
        &fixture.approval,
        &compiled,
    );
    drop(slot);

    // Then
    assert!(matches!(result, Ok(())));
    let snapshot = journal
        .lock()
        .expect("journal state")
        .snapshot
        .clone()
        .expect("prepared snapshot");
    assert_eq!(snapshot.prepared_dispatches.len(), 1);
    assert_eq!(
        snapshot.prepared_dispatches[0].control_envelope_id,
        response_id
    );
    assert!(durable.reserve_fresh_response(response_id).is_err());
}
