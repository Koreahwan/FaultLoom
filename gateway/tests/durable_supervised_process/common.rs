pub(crate) use std::net::TcpListener;
pub(crate) use std::sync::Arc;
pub(crate) use std::thread;
pub(crate) use std::time::{Duration, Instant};

pub(crate) use faultloom_gateway::Digest;
pub(crate) use faultloom_gateway::ipc::{
    DenialCode, DeniedResponse, DispatchOutcome, DispatchReceipt, GatewayResponse,
};
pub(crate) use faultloom_gateway::lease::{
    ControlPlaneReconciliationHold, ReconciliationAuthority, ReconciliationTerminal,
};
pub(crate) use faultloom_gateway::supervisor_journal::{
    AcknowledgedResponseTombstone, JournalSnapshot, MAX_DURABLE_RESPONSE_SLOTS,
};
pub(crate) use faultloom_gateway::supervisor_protocol::{
    ControlEgressDisposition, SupervisorCommand, SupervisorControlReceipt,
    SupervisorReconciliation, SupervisorResponse,
};

pub(crate) use crate::bootstrap_fixture::TestBootstrap;
pub(crate) use crate::durable_process::rotate_bootstrap_for_restart;
pub(crate) use crate::fixtures::{dispatch, issuer};
pub(crate) use crate::journal::FakeJournal;
use crate::network::OBSERVATION_TIMEOUT;
pub(crate) use crate::process::{ProcessHarness, bootstrap, nonce, now_millis};

pub(crate) fn admit_epoch(gateway: &mut ProcessHarness, bootstrap: &TestBootstrap, epoch: u64) {
    let now = now_millis();
    let (envelope, verifier_receipt) =
        issuer(bootstrap).issue(epoch, false, now, now + 60_000, 0x91);
    let response = gateway.round_trip(
        SupervisorCommand::AdmitEpoch {
            canonical_envelope: envelope,
            verifier_receipt,
        },
        0x11,
    );
    assert!(matches!(
        response,
        SupervisorResponse::Control(SupervisorControlReceipt::EpochAdmitted {
            current_epoch,
            revoked: false,
            ..
        }) if current_epoch == epoch
    ));
    wait_for_no_pending(&gateway.journal());
}

pub(crate) fn tombstone_fixture(
    target: std::net::SocketAddr,
    acknowledged_count: usize,
) -> (TestBootstrap, Arc<FakeJournal>, Digest, Digest) {
    let now = now_millis();
    let initial = bootstrap(target, now);
    let mut gateway = ProcessHarness::spawn(&initial);
    let (canonical_envelope, verifier_receipt) =
        issuer(&initial).issue(1, false, now, now + 60_000, 0x93);
    let original_request = gateway.send(
        SupervisorCommand::AdmitEpoch {
            canonical_envelope,
            verifier_receipt,
        },
        0x13,
    );
    let original_outer = gateway.read_outer();
    let (_, original_response_digest) =
        gateway.decode_for_without_ack(&original_request, original_outer);
    gateway.acknowledge_response(original_request.envelope_id(), original_response_digest);
    let journal = gateway.journal();
    wait_for_snapshot(&journal, |snapshot| {
        snapshot.acknowledged_responses.iter().any(|tombstone| {
            tombstone.original_request_envelope_id == original_request.envelope_id()
                && tombstone.inner_response_digest == original_response_digest
        })
    });
    gateway.finish();
    fill_acknowledged_slots(&journal, acknowledged_count);
    (
        initial,
        journal,
        original_request.envelope_id(),
        original_response_digest,
    )
}

pub(crate) fn fill_acknowledged_slots(journal: &FakeJournal, target_count: usize) {
    let mut snapshot = journal.snapshot().expect("seedable journal snapshot");
    assert!(snapshot.acknowledged_responses.len() <= target_count);
    for index in snapshot.acknowledged_responses.len()..target_count {
        let original_request_envelope_id =
            Digest::of(format!("fixture acknowledged request {index}").as_bytes());
        assert!(
            snapshot
                .prepared_dispatches
                .iter()
                .all(|prepared| prepared.control_envelope_id != original_request_envelope_id)
        );
        assert!(
            snapshot
                .pending_responses
                .iter()
                .all(|pending| pending.original_request_envelope_id != original_request_envelope_id)
        );
        assert!(snapshot.acknowledged_responses.iter().all(|acknowledged| {
            acknowledged.original_request_envelope_id != original_request_envelope_id
        }));
        snapshot
            .acknowledged_responses
            .push(AcknowledgedResponseTombstone {
                original_request_envelope_id,
                inner_response_digest: Digest::of(
                    format!("fixture acknowledged response {index}").as_bytes(),
                ),
            });
    }
    journal
        .commit_snapshot(snapshot)
        .expect("commit seeded response slots");
}

pub(crate) fn restart_bootstrap(previous: &TestBootstrap, journal: &FakeJournal) -> TestBootstrap {
    rotate_bootstrap_for_restart(
        previous,
        journal.current_anchor().expect("durable restart anchor"),
    )
}

pub(crate) fn receipt(response: &SupervisorResponse) -> &DispatchReceipt {
    let SupervisorResponse::Gateway(response) = response else {
        panic!("expected gateway response, got {response:?}")
    };
    let GatewayResponse::Receipt { receipt, .. } = response.as_ref() else {
        panic!("expected dispatch receipt, got {response:?}")
    };
    receipt
}

pub(crate) fn assert_denied(response: SupervisorResponse, expected: DenialCode) {
    assert_eq!(denial(response), expected);
}

pub(crate) fn denial(response: SupervisorResponse) -> DenialCode {
    let SupervisorResponse::Gateway(response) = response else {
        panic!("expected gateway denial, got {response:?}")
    };
    let GatewayResponse::Denied(DeniedResponse { reason, .. }) = response.as_ref() else {
        panic!("expected denial, got {response:?}")
    };
    *reason
}

pub(crate) fn wait_for_no_pending(journal: &FakeJournal) {
    let snapshot = wait_for_snapshot(journal, |snapshot| snapshot.pending_responses.is_empty());
    assert!(snapshot.pending_responses.is_empty());
}

pub(crate) fn wait_for_snapshot(
    journal: &FakeJournal,
    predicate: impl Fn(&JournalSnapshot) -> bool,
) -> JournalSnapshot {
    let deadline = Instant::now() + OBSERVATION_TIMEOUT;
    let mut last = None;
    loop {
        if let Some(snapshot) = journal.snapshot() {
            if predicate(&snapshot) {
                return snapshot;
            }
            last = Some(snapshot);
        }
        assert!(
            Instant::now() < deadline,
            "journal observation timed out; last snapshot: {last:?}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}
