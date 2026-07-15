use crate::common::*;
use crate::network::*;

#[test]
fn full_tombstone_restart_keeps_exact_ack_replay_live_and_commit_free() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let (initial, journal, original_request_id, original_response_digest) = tombstone_fixture(
        listener.local_addr().expect("listener address"),
        MAX_DURABLE_RESPONSE_SLOTS,
    );
    let baseline = journal.snapshot().expect("full tombstone snapshot");
    let baseline_sequence = journal.durable_sequence();
    assert_eq!(
        baseline.acknowledged_responses.len(),
        MAX_DURABLE_RESPONSE_SLOTS
    );

    // When
    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    gateway.acknowledge_response(original_request_id, original_response_digest);
    gateway.finish();

    // Then
    assert_eq!(journal.durable_sequence(), baseline_sequence + 1);
    let observed = journal.snapshot().expect("post-replay snapshot");
    assert_eq!(
        observed.acknowledged_responses,
        baseline.acknowledged_responses
    );
    assert!(observed.prepared_dispatches.is_empty());
    assert!(observed.pending_responses.is_empty());
    assert_no_connection(&listener);
}

#[test]
fn full_capacity_fails_before_fresh_command_effects_or_responses() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let target = listener.local_addr().expect("listener address");
    let (initial, journal, _, _) = tombstone_fixture(target, MAX_DURABLE_RESPONSE_SLOTS);
    let baseline_anchor = journal.current_anchor().expect("full snapshot anchor");
    let baseline = journal.snapshot().expect("full snapshot");
    let baseline_sequence = journal.durable_sequence();
    // When
    let restarted = restart_bootstrap(&initial, &journal);
    let now = now_millis();
    let (canonical_envelope, verifier_receipt) =
        issuer(&restarted).issue(2, false, now, now + 60_000, 0x94);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    gateway.send(
        SupervisorCommand::AdmitEpoch {
            canonical_envelope,
            verifier_receipt,
        },
        0x70,
    );
    gateway.finish_expecting_failure();
    assert_eq!(journal.current_anchor(), Some(baseline_anchor));
    assert_eq!(journal.snapshot(), Some(baseline.clone()));
    assert_eq!(journal.durable_sequence(), baseline_sequence);

    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    gateway.send(SupervisorCommand::ReconcileExpiry, 0x71);
    gateway.finish_expecting_failure();
    assert_eq!(journal.current_anchor(), Some(baseline_anchor));
    assert_eq!(journal.snapshot(), Some(baseline.clone()));
    assert_eq!(journal.durable_sequence(), baseline_sequence);

    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    let client = restarted
        .channel_client()
        .expect("malformed-command channel client");
    let request_now = now_millis();
    let malformed = client
        .seal_request(
            b"authenticated but malformed supervisor command".to_vec(),
            nonce(0x7f),
            request_now,
            request_now + 20_000,
        )
        .expect("seal malformed supervisor command");
    gateway.write_raw_request(&malformed);
    gateway.finish_expecting_failure();

    // Then
    assert_eq!(journal.current_anchor(), Some(baseline_anchor));
    assert_eq!(journal.snapshot(), Some(baseline));
    assert_eq!(journal.durable_sequence(), baseline_sequence);

    let (dispatch_initial, dispatch_journal, _, _) =
        tombstone_fixture(target, MAX_DURABLE_RESPONSE_SLOTS - 1);
    let dispatch_restart = restart_bootstrap(&dispatch_initial, &dispatch_journal);
    let mut gateway =
        ProcessHarness::spawn_with_journal(&dispatch_restart, Arc::clone(&dispatch_journal));
    admit_epoch(&mut gateway, &dispatch_restart, 2);
    let dispatch_anchor = dispatch_journal
        .current_anchor()
        .expect("active full snapshot anchor");
    let dispatch_baseline = dispatch_journal.snapshot().expect("active full snapshot");
    let dispatch_sequence = dispatch_journal.durable_sequence();
    assert_eq!(
        dispatch_baseline.acknowledged_responses.len(),
        MAX_DURABLE_RESPONSE_SLOTS
    );
    gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "full-capacity-dispatch",
            2,
            &dispatch_restart.target.target_id,
            0x61,
        ))),
        0x76,
    );
    gateway.finish_expecting_failure();
    assert_eq!(dispatch_journal.current_anchor(), Some(dispatch_anchor));
    assert_eq!(dispatch_journal.snapshot(), Some(dispatch_baseline));
    assert_eq!(dispatch_journal.durable_sequence(), dispatch_sequence);
    assert_no_connection(&listener);
}
