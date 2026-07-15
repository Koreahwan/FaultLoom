use crate::common::*;
use crate::network::*;

#[test]
fn restart_preserves_replay_denial_and_consumed_budget() {
    // Given: one completed action under a one-action grant, durably ACKed before
    // the real supervisor process exits.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let mut initial = bootstrap(listener.local_addr().expect("listener address"), now);
    initial.budget.total_actions = 1;
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let first_dispatch = dispatch("restart-budget", 1, &initial.target.target_id, 0x41);
    let target = respond_once(&listener, b"OK");
    let first_response = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(first_dispatch.clone())),
        0x21,
    );
    assert_eq!(receipt(&first_response).outcome, DispatchOutcome::Completed);
    let observed = target.join().expect("completed target worker");
    assert!(observed.ends_with(b"probe-restart-budget"));
    let journal = gateway.journal();
    let committed = wait_for_snapshot(&journal, |snapshot| {
        snapshot.pending_responses.is_empty() && snapshot.prepared_dispatches.is_empty()
    });
    assert_ne!(committed.lease_checkpoint_id, Digest::ZERO);
    gateway.finish();

    // When: a fresh installed process restores the exact journal and receives
    // both the original lease identity and a genuinely fresh action.
    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    admit_epoch(&mut gateway, &restarted, 1);
    let replay = gateway.round_trip(SupervisorCommand::Dispatch(Box::new(first_dispatch)), 0x31);
    let fresh = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "budget-exhausted",
            1,
            &restarted.target.target_id,
            0x51,
        ))),
        0x41,
    );

    // Then: replay and consumed-budget state survive the boot boundary, and
    // the target observed exactly the original action.
    assert_denied(replay, DenialCode::LeaseReplay);
    assert_denied(fresh, DenialCode::GrantBudgetExhausted);
    wait_for_no_pending(&journal);
    assert_no_connection(&listener);
    gateway.finish();
}

#[test]
fn unacknowledged_exact_response_recovers_twice_without_reegress_and_ack_unblocks_work() {
    // Given: a completed real target action whose exact authenticated inner
    // response is durable but deliberately not ACKed before a hard kill.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let initial = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let target = respond_once(&listener, b"FIRST");
    let original_request = gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "unacked",
            1,
            &initial.target.target_id,
            0x42,
        ))),
        0x22,
    );
    let original_outer = gateway.read_outer();
    let (original_response, original_digest) =
        gateway.decode_for_without_ack(&original_request, original_outer);
    assert_eq!(
        receipt(&original_response).outcome,
        DispatchOutcome::Completed
    );
    let first_observed = target.join().expect("first target worker");
    assert!(first_observed.ends_with(b"probe-unacked"));
    let journal = gateway.journal();
    let pending = wait_for_snapshot(&journal, |snapshot| {
        snapshot.pending_responses.iter().any(|response| {
            response.original_request_envelope_id == original_request.envelope_id()
                && response.inner_response_digest == original_digest
        })
    });
    assert_eq!(pending.pending_responses.len(), 1);
    gateway.terminate_without_shutdown();

    // When: the restarted process recovers the same outbox entry twice, then
    // receives the exact ACK and a later valid action.
    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    let first_recovery_request = gateway.send(
        SupervisorCommand::RecoverPendingResponse {
            original_request_id: original_request.envelope_id(),
        },
        0x32,
    );
    let first_recovery_outer = gateway.read_outer();
    let (first_recovery, first_digest) =
        gateway.decode_for_without_ack(&first_recovery_request, first_recovery_outer);
    let second_recovery_request = gateway.send(
        SupervisorCommand::RecoverPendingResponse {
            original_request_id: original_request.envelope_id(),
        },
        0x33,
    );
    let second_recovery_outer = gateway.read_outer();
    let (second_recovery, second_digest) =
        gateway.decode_for_without_ack(&second_recovery_request, second_recovery_outer);
    assert_no_connection(&listener);
    gateway.acknowledge_response(original_request.envelope_id(), original_digest);
    let after_ack = wait_for_snapshot(&journal, |snapshot| snapshot.pending_responses.is_empty());
    assert!(after_ack.pending_responses.is_empty());
    admit_epoch(&mut gateway, &restarted, 1);
    let target = respond_once(&listener, b"SECOND");
    let later = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "after-ack",
            1,
            &restarted.target.target_id,
            0x52,
        ))),
        0x42,
    );
    let second_observed = target.join().expect("second target worker");

    // Then: recovery is byte-exact, causes zero target re-egress, ACK removes
    // the outbox item, and normal work resumes with one new connection.
    assert_eq!(first_recovery, original_response);
    assert_eq!(second_recovery, original_response);
    assert_eq!(first_digest, original_digest);
    assert_eq!(second_digest, original_digest);
    assert_eq!(receipt(&later).outcome, DispatchOutcome::Completed);
    assert!(second_observed.ends_with(b"probe-after-ack"));
    wait_for_no_pending(&journal);
    assert_no_connection(&listener);
    gateway.finish();
}
