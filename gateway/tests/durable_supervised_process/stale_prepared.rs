use crate::common::*;
use crate::network::*;

#[test]
fn stale_anchor_fails_closed_without_egress_or_journal_mutation() {
    // Given: an older valid anchor followed by a clean shutdown checkpoint at
    // a newer anchor in the same external journal.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let initial = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let journal = gateway.journal();
    wait_for_no_pending(&journal);
    let stale_anchor = journal.current_anchor().expect("admission anchor");
    gateway.finish();
    let current_anchor = journal.current_anchor().expect("shutdown anchor");
    assert_ne!(stale_anchor, current_anchor);
    let snapshot_before = journal.snapshot().expect("current snapshot");

    // When: a real replacement process is bootstrapped with the stale anchor.
    let stale = rotate_bootstrap_for_restart(&initial, stale_anchor);
    let stale_gateway = ProcessHarness::spawn_with_journal(&stale, Arc::clone(&journal));
    stale_gateway.finish_expecting_failure();

    // Then: startup fails, no target connection occurs, and the journal has
    // neither advanced nor changed its snapshot.
    assert_eq!(journal.current_anchor(), Some(current_anchor));
    assert_eq!(journal.snapshot(), Some(snapshot_before));
    assert_no_connection(&listener);
}

#[test]
fn prepared_record_crash_requires_exact_proof_and_denies_proof_replay() {
    // Given: a real dispatch that reached the owned target after its prepared
    // record was durably committed, followed by SIGKILL before a response.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let initial = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let (observed_rx, target) = observe_until_peer_close(&listener);
    let _request = gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "prepared-crash",
            1,
            &initial.target.target_id,
            0x43,
        ))),
        0x23,
    );
    let observed = observed_rx
        .recv_timeout(OBSERVATION_TIMEOUT)
        .expect("target observed prepared dispatch");
    let journal = gateway.journal();
    let before_crash = wait_for_snapshot(&journal, |snapshot| {
        snapshot.prepared_dispatches.len() == 1 && snapshot.pending_responses.is_empty()
    });
    let prepared = before_crash.prepared_dispatches[0].clone();
    gateway.terminate_without_shutdown();
    target.join().expect("crashed target worker");
    assert!(observed.ends_with(b"probe-prepared-crash"));

    // When: the restored process receives an authenticated but incorrectly
    // bound proof, the exact proof, and then the exact proof a second time.
    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    let reconciler = ReconciliationAuthority::new(
        restarted.secrets.reconciliation_key_id.clone(),
        restarted.secrets.reconciliation_verification_key,
    )
    .expect("reconciliation authority");
    let wrong = reconciler
        .issue_control_plane_hold(
            ControlPlaneReconciliationHold {
                grant_id: prepared.grant_id.clone(),
                grant_version: prepared.grant_version,
                intent_digest: prepared.intent_digest,
                effect_digest: Digest::of(b"wrong prepared effect"),
                hold_binding_digest: prepared.hold_binding_digest,
            },
            ReconciliationTerminal {
                outcome: DispatchOutcome::Failed,
                evidence_digest: Digest::of(b"wrong prepared terminal evidence"),
                nonce: nonce(0xb1),
                resolved_at_millis: now_millis(),
            },
        )
        .expect("authenticated wrong proof");
    let wrong_response = gateway.round_trip(
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::ControlPlane {
            reconciliation: wrong,
        })),
        0x33,
    );
    assert_denied(wrong_response, DenialCode::LeaseBindingMismatch);
    wait_for_no_pending(&journal);
    assert_eq!(
        journal
            .snapshot()
            .expect("snapshot after wrong proof")
            .prepared_dispatches,
        vec![prepared.clone()]
    );
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
                evidence_digest: Digest::of(b"exact prepared terminal evidence"),
                nonce: nonce(0xb2),
                resolved_at_millis: now_millis(),
            },
        )
        .expect("exact prepared proof");
    let exact_response = gateway.round_trip(
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::ControlPlane {
            reconciliation: exact.clone(),
        })),
        0x34,
    );
    assert_eq!(
        exact_response,
        SupervisorResponse::Control(SupervisorControlReceipt::HoldReconciled {
            reconciliation_id: exact.reconciliation_id,
            removed_prepared_dispatches: 1,
            egress_disposition: ControlEgressDisposition::NoActiveEgress,
        })
    );
    wait_for_no_pending(&journal);
    assert!(
        journal
            .snapshot()
            .expect("snapshot after exact proof")
            .prepared_dispatches
            .is_empty()
    );
    let replay = gateway.round_trip(
        SupervisorCommand::ReconcileHold(Box::new(SupervisorReconciliation::ControlPlane {
            reconciliation: exact,
        })),
        0x35,
    );

    // Then: only the exact proof clears the prepared record, replay is denied,
    // and reconciliation never opens another target connection.
    assert!(matches!(
        denial(replay),
        DenialCode::LeaseBindingMismatch | DenialCode::LeaseReplay
    ));
    wait_for_no_pending(&journal);
    assert_no_connection(&listener);
    gateway.finish();
}
