use crate::common::*;
use crate::network::*;

#[test]
fn crashed_prepared_slot_transfers_at_capacity_and_ack_replays_after_restart() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let initial = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let (observed_rx, target) = observe_until_peer_close(&listener);
    gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "prepared-capacity-transfer",
            1,
            &initial.target.target_id,
            0x63,
        ))),
        0x43,
    );
    let observed = observed_rx
        .recv_timeout(OBSERVATION_TIMEOUT)
        .expect("target observed prepared dispatch");
    let journal = gateway.journal();
    let crashed = wait_for_snapshot(&journal, |snapshot| {
        snapshot.prepared_dispatches.len() == 1 && snapshot.pending_responses.is_empty()
    });
    let prepared = crashed.prepared_dispatches[0].clone();
    gateway.terminate_without_shutdown();
    target.join().expect("crashed target worker");
    assert!(observed.ends_with(b"probe-prepared-capacity-transfer"));
    fill_acknowledged_slots(&journal, MAX_DURABLE_RESPONSE_SLOTS - 1);
    let full_prepared = journal.snapshot().expect("full prepared snapshot");
    assert_eq!(
        full_prepared.acknowledged_responses.len(),
        MAX_DURABLE_RESPONSE_SLOTS - 1
    );
    assert_eq!(full_prepared.prepared_dispatches, vec![prepared.clone()]);

    // When
    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    let reconciler = ReconciliationAuthority::new(
        restarted.secrets.reconciliation_key_id.clone(),
        restarted.secrets.reconciliation_verification_key,
    )
    .expect("reconciliation authority");
    let exact = reconciler
        .issue_control_plane_hold(
            ControlPlaneReconciliationHold {
                grant_id: prepared.grant_id.clone(),
                grant_version: prepared.grant_version,
                intent_digest: prepared.intent_digest,
                effect_digest: prepared.effect_digest,
                hold_binding_digest: prepared.hold_binding_digest,
            },
            ReconciliationTerminal {
                outcome: DispatchOutcome::Failed,
                evidence_digest: Digest::of(b"capacity transfer evidence"),
                nonce: nonce(0xb4),
                resolved_at_millis: now_millis(),
            },
        )
        .expect("exact prepared proof");
    let reconciliation_request = gateway.send(
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::ControlPlane {
            reconciliation: exact.clone(),
        })),
        0x44,
    );
    let reconciliation_outer = gateway.read_outer();
    let (response, response_digest) =
        gateway.decode_for_without_ack(&reconciliation_request, reconciliation_outer);

    // Then
    assert_eq!(
        response,
        SupervisorResponse::Control(SupervisorControlReceipt::HoldReconciled {
            reconciliation_id: exact.reconciliation_id,
            removed_prepared_dispatches: 1,
            egress_disposition: ControlEgressDisposition::NoActiveEgress,
        })
    );
    let pending = wait_for_snapshot(&journal, |snapshot| {
        snapshot.prepared_dispatches.is_empty()
            && snapshot.pending_responses.len() == 1
            && snapshot.acknowledged_responses.len() == MAX_DURABLE_RESPONSE_SLOTS - 1
    });
    assert_eq!(
        pending.pending_responses[0].original_request_envelope_id,
        reconciliation_request.envelope_id()
    );
    assert_eq!(
        pending.pending_responses[0].inner_response_digest,
        response_digest
    );
    gateway.acknowledge_response(reconciliation_request.envelope_id(), response_digest);
    wait_for_snapshot(&journal, |snapshot| {
        snapshot.prepared_dispatches.is_empty()
            && snapshot.pending_responses.is_empty()
            && snapshot.acknowledged_responses.len() == MAX_DURABLE_RESPONSE_SLOTS
    });
    gateway.terminate_without_shutdown();

    let restarted_again = restart_bootstrap(&restarted, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted_again, Arc::clone(&journal));
    let before_replay = journal.snapshot().expect("full tombstone snapshot");
    let sequence_before_replay = journal.durable_sequence();
    gateway.acknowledge_response(reconciliation_request.envelope_id(), response_digest);
    gateway.finish();
    assert_eq!(journal.durable_sequence(), sequence_before_replay + 1);
    let after_replay = journal.snapshot().expect("post-replay snapshot");
    assert_eq!(
        after_replay.acknowledged_responses,
        before_replay.acknowledged_responses
    );
    assert!(after_replay.prepared_dispatches.is_empty());
    assert!(after_replay.pending_responses.is_empty());
    assert_no_connection(&listener);
}
