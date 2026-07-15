use crate::common::*;
use crate::network::*;

#[test]
fn delayed_workers_reserve_every_remaining_slot_before_overflow_fail_stop() {
    // Given
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let mut initial = bootstrap(listener.local_addr().expect("listener address"), now);
    initial.budget.total_actions =
        u64::try_from(MAX_DURABLE_RESPONSE_SLOTS).expect("response capacity fits action budget");
    initial.budget.rate_per_minute =
        u64::try_from(MAX_DURABLE_RESPONSE_SLOTS).expect("response capacity fits rate budget");
    initial.budget.max_concurrency = 8;
    let mut gateway = ProcessHarness::spawn(&initial);
    admit_epoch(&mut gateway, &initial, 1);
    let journal = gateway.journal();
    gateway.finish();
    fill_acknowledged_slots(&journal, MAX_DURABLE_RESPONSE_SLOTS - 5);

    let restarted = restart_bootstrap(&initial, &journal);
    let mut gateway = ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal));
    admit_epoch(&mut gateway, &restarted, 2);
    let active_snapshot = journal.snapshot().expect("active response quota snapshot");
    assert_eq!(
        active_snapshot.acknowledged_responses.len(),
        MAX_DURABLE_RESPONSE_SLOTS - 4
    );
    let mut observed_requests = Vec::new();
    let mut target_workers = Vec::new();
    for index in 0_u8..4 {
        let (observed_rx, target_worker) = observe_until_peer_close(&listener);
        let label = format!("delayed-capacity-{index}");
        gateway.send(
            SupervisorCommand::Dispatch(Box::new(dispatch(
                &label,
                2,
                &restarted.target.target_id,
                0x70 + index,
            ))),
            0x50 + index,
        );
        observed_requests.push(
            observed_rx
                .recv_timeout(OBSERVATION_TIMEOUT)
                .expect("target observed delayed dispatch"),
        );
        target_workers.push(target_worker);
    }
    let prepared = wait_for_snapshot(&journal, |snapshot| {
        snapshot.prepared_dispatches.len() == 4
            && snapshot.pending_responses.is_empty()
            && snapshot.acknowledged_responses.len() == MAX_DURABLE_RESPONSE_SLOTS - 4
    });
    let prepared_anchor = journal.current_anchor().expect("prepared capacity anchor");
    let prepared_sequence = journal.durable_sequence();

    // When
    gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "delayed-capacity-overflow",
            2,
            &restarted.target.target_id,
            0x7f,
        ))),
        0x5f,
    );
    gateway.finish_expecting_failure();

    // Then
    for target_worker in target_workers {
        target_worker.join().expect("delayed target worker");
    }
    for index in 0_u8..4 {
        let expected = format!("probe-delayed-capacity-{index}");
        assert!(
            observed_requests
                .iter()
                .any(|request| request.ends_with(expected.as_bytes()))
        );
    }
    assert_eq!(journal.current_anchor(), Some(prepared_anchor));
    assert_eq!(journal.snapshot(), Some(prepared));
    assert_eq!(journal.durable_sequence(), prepared_sequence);
    assert_no_connection(&listener);
}
