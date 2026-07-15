use crate::common::*;
use crate::network::*;

#[test]
fn corrupt_pre_egress_ack_fails_closed_without_loopback_connection() {
    // Given: a healthy installed process whose next external-journal commit
    // ACK will be bound to the wrong request.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let initial = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let journal = gateway.journal();
    journal.corrupt_next_ack();
    let pre_egress_pause = journal.pause_next_ack_after_commit();

    // When: the dispatch's own prepared-record commit becomes durable while its
    // corrupt ACK is held behind a deterministic gate.
    let _request = gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "corrupt-pre-egress-ack",
            1,
            &initial.target.target_id,
            0x45,
        ))),
        0x25,
    );
    pre_egress_pause.wait_until_commit_visible();
    let terminal_anchor = journal.current_anchor().expect("prepared-record anchor");
    let terminal_snapshot = journal.snapshot().expect("prepared-record snapshot");
    let terminal_sequence = journal.durable_sequence();
    assert_eq!(terminal_snapshot.prepared_dispatches.len(), 1);
    assert!(terminal_snapshot.pending_responses.is_empty());
    assert_no_connection(&listener);
    pre_egress_pause.release();
    gateway.finish_expecting_failure();

    // Then: the journal contains only the prepared record committed before its
    // corrupt ACK, the child exits nonzero, and the target sees zero connects.
    assert_eq!(journal.current_anchor(), Some(terminal_anchor));
    assert_eq!(journal.snapshot(), Some(terminal_snapshot.clone()));
    assert_eq!(journal.durable_sequence(), terminal_sequence);
    assert_eq!(
        terminal_snapshot.prepared_dispatches[0].action_id,
        "action:corrupt-pre-egress-ack"
    );
    assert_no_connection(&listener);
}

#[test]
fn main_thread_persist_failure_with_active_worker_fail_stops_without_worker_progress() {
    // Given: one active target dispatch and a single-worker process whose next
    // main-thread response commit will receive a corrupt journal ACK.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let mut initial = bootstrap(listener.local_addr().expect("listener address"), now);
    initial.budget.max_concurrency = 1;
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let (observed_rx, target) = observe_until_peer_close(&listener);
    let _active_request = gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "active-before-main-persist-failure",
            1,
            &initial.target.target_id,
            0x46,
        ))),
        0x26,
    );
    let observed = observed_rx
        .recv_timeout(OBSERVATION_TIMEOUT)
        .expect("target observed active request");
    let journal = gateway.journal();
    journal.corrupt_next_ack();
    let commit_pause = journal.pause_next_ack_after_commit();

    // When: worker saturation makes a second dispatch denial run on the main
    // thread and its durable response ACK becomes terminal.
    let _denied_request = gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "main-thread-persist-failure",
            1,
            &initial.target.target_id,
            0x56,
        ))),
        0x36,
    );
    commit_pause.wait_until_commit_visible();
    let terminal_anchor = journal.current_anchor().expect("terminal commit anchor");
    let terminal_snapshot = journal.snapshot().expect("terminal commit snapshot");
    let terminal_sequence = journal.durable_sequence();
    assert_eq!(terminal_snapshot.prepared_dispatches.len(), 1);
    assert_eq!(terminal_snapshot.pending_responses.len(), 1);
    let released_at = Instant::now();
    commit_pause.release();
    gateway.finish_expecting_failure();

    // Then: fail-stop beats the active worker's I/O timeout, closes its socket,
    // and leaves the terminal commit as the final durable mutation.
    assert!(released_at.elapsed() < Duration::from_secs(1));
    target.join().expect("active target observed process close");
    assert!(observed.ends_with(b"probe-active-before-main-persist-failure"));
    assert_eq!(journal.current_anchor(), Some(terminal_anchor));
    assert_eq!(journal.snapshot(), Some(terminal_snapshot));
    assert_eq!(journal.durable_sequence(), terminal_sequence);
    assert_no_connection(&listener);
}

#[test]
fn ack_commit_crash_restart_exact_replay_is_idempotent_and_wrong_digest_fails_closed() {
    // Given: a response ACK committed to the external journal immediately
    // before the installed process is killed.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let initial = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&initial);
    let (canonical_envelope, verifier_receipt) =
        issuer(&initial).issue(1, false, now, now + 60_000, 0x92);
    let original_request = gateway.send(
        SupervisorCommand::AdmitEpoch {
            canonical_envelope,
            verifier_receipt,
        },
        0x12,
    );
    let original_outer = gateway.read_outer();
    let (_original_response, original_digest) =
        gateway.decode_for_without_ack(&original_request, original_outer);
    let journal = gateway.journal();
    let ack_pause = journal.pause_next_ack_after_commit();
    gateway.acknowledge_response(original_request.envelope_id(), original_digest);
    ack_pause.wait_until_commit_visible();
    assert!(
        journal
            .snapshot()
            .expect("ACK tombstone snapshot")
            .acknowledged_responses
            .iter()
            .any(|tombstone| {
                tombstone.original_request_envelope_id == original_request.envelope_id()
                    && tombstone.inner_response_digest == original_digest
            })
    );
    gateway.terminate_during_paused_journal_ack(ack_pause);

    // When: a restarted process receives the exact ACK replay, proves liveness
    // with a normal response cycle, and then receives a wrong digest replay.
    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    let sequence_before_exact_replay = journal.durable_sequence();
    gateway.acknowledge_response(original_request.envelope_id(), original_digest);
    admit_epoch(&mut gateway, &restarted, 1);
    assert_eq!(journal.durable_sequence(), sequence_before_exact_replay + 2);
    let stable_anchor = journal.current_anchor().expect("post-replay anchor");
    let stable_snapshot = journal.snapshot().expect("post-replay snapshot");
    let stable_sequence = journal.durable_sequence();
    gateway.acknowledge_response(
        original_request.envelope_id(),
        Digest::of(b"wrong acknowledged response digest"),
    );
    gateway.finish_expecting_failure();

    // Then: exact replay causes no journal mutation and keeps the process live;
    // mismatch terminates it without an ACK response or another journal commit.
    assert_eq!(journal.current_anchor(), Some(stable_anchor));
    assert_eq!(journal.snapshot(), Some(stable_snapshot));
    assert_eq!(journal.durable_sequence(), stable_sequence);
    assert_no_connection(&listener);
}
