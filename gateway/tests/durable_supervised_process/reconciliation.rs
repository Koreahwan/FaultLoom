use crate::common::*;
use crate::network::*;

#[test]
fn signed_unknown_outcome_reconciles_durably_and_completed_never_enables_retry() {
    // Given: the real transport times out after the owned target observes the
    // complete action, yielding a signed UnknownOutcome dispatch receipt.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let initial = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let (observed_rx, target) = observe_until_peer_close(&listener);
    let mut unknown_dispatch = dispatch("signed-unknown", 1, &initial.target.target_id, 0x44);
    let issued_at = now_millis();
    unknown_dispatch.issued_at_millis = issued_at;
    unknown_dispatch.expires_at_millis = issued_at + 2_000;
    let unknown_response = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(unknown_dispatch)),
        0x24,
    );
    let observed = observed_rx
        .recv_timeout(OBSERVATION_TIMEOUT)
        .expect("target observed unknown action");
    target.join().expect("unknown target worker");
    assert!(observed.ends_with(b"probe-signed-unknown"));
    let unknown = receipt(&unknown_response).clone();
    assert_eq!(unknown.outcome, DispatchOutcome::UnknownOutcome);
    assert!(unknown.reconciliation_required);
    assert_ne!(unknown.receipt_id, Digest::ZERO);
    assert_ne!(unknown.receipt_authentication_tag, Digest::ZERO);
    let journal = gateway.journal();
    wait_for_no_pending(&journal);
    assert!(
        journal
            .snapshot()
            .expect("unknown snapshot")
            .prepared_dispatches
            .is_empty()
    );

    // When: the control plane signs Completed terminal evidence, the process
    // accepts it, exits cleanly, and a restarted process sees both proof replay
    // and an explicit retry child.
    let reconciler = ReconciliationAuthority::new(
        initial.secrets.reconciliation_key_id.clone(),
        initial.secrets.reconciliation_verification_key,
    )
    .expect("reconciliation authority");
    let completed = reconciler
        .issue(
            &unknown,
            DispatchOutcome::Completed,
            Digest::of(b"completed terminal evidence"),
            nonce(0xc1),
            now_millis().max(unknown.completed_at_millis + 1),
        )
        .expect("completed reconciliation proof");
    let reconciled = gateway.round_trip(
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::DispatchReceipt {
            unknown_receipt: Box::new(unknown.clone()),
            reconciliation: completed.clone(),
        })),
        0x34,
    );
    assert_eq!(
        reconciled,
        SupervisorResponse::Control(SupervisorControlReceipt::HoldReconciled {
            reconciliation_id: completed.reconciliation_id,
            removed_prepared_dispatches: 0,
            egress_disposition: ControlEgressDisposition::NoActiveEgress,
        })
    );
    wait_for_no_pending(&journal);
    gateway.finish();
    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    let replay = gateway.round_trip(
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::DispatchReceipt {
            unknown_receipt: Box::new(unknown.clone()),
            reconciliation: completed,
        })),
        0x35,
    );
    assert_denied(replay, DenialCode::LeaseReplay);
    admit_epoch(&mut gateway, &restarted, 1);
    let mut retry = dispatch(
        "retry-after-completed",
        1,
        &restarted.target.target_id,
        0x54,
    );
    retry.retry_of_intent_digest = Some(unknown.intent_digest);
    let retry_response = gateway.round_trip(SupervisorCommand::Dispatch(Box::new(retry)), 0x45);

    // Then: the reconciliation is durable, single-use, and a Completed result
    // cannot mint retry authority or cause another target action.
    assert_denied(retry_response, DenialCode::RetryAliasInvalid);
    wait_for_no_pending(&journal);
    assert_no_connection(&listener);
    gateway.finish();
}
