#[path = "support/bootstrap.rs"]
mod bootstrap_fixture;
#[path = "support/epoch.rs"]
mod epoch;
#[path = "support/fixtures.rs"]
mod fixtures;
#[allow(dead_code)]
#[path = "support/journal.rs"]
mod journal;
#[path = "support/journal_observation.rs"]
mod journal_observation;
#[allow(dead_code)]
#[path = "support/process.rs"]
mod process;
#[allow(dead_code)]
#[path = "support/process_convenience.rs"]
mod process_convenience;

use std::io::Write;
use std::net::TcpListener;
use std::thread;
use std::time::{Duration, Instant};

use faultloom_gateway::ipc::{DenialCode, DeniedResponse, DispatchOutcome, GatewayResponse};
use faultloom_gateway::supervisor_protocol::{
    SupervisorCommand, SupervisorControlReceipt, SupervisorResponse,
};
use faultloom_gateway::Digest;

use crate::fixtures::{dispatch, issuer, read_http_request};
use crate::journal::FakeJournal;
use crate::journal_observation::JournalObservation;
use crate::process::{bootstrap, now_millis, ProcessHarness};

#[test]
fn controller_owned_handoff_runs_one_signed_loopback_dispatch_and_denies_retargeting() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned loopback listener");
    let target_probe = listener.try_clone().expect("owned loopback probe");
    let now = now_millis();
    let bootstrap = bootstrap(listener.local_addr().expect("owned loopback address"), now);
    let authority = issuer(&bootstrap);
    let mut gateway = ProcessHarness::spawn(&bootstrap);
    let journal = gateway.journal();

    let epoch_now = now_millis();
    let (envelope, verifier_receipt) =
        authority.issue(1, false, epoch_now, epoch_now + 60_000, 0x50);
    let admission = gateway.round_trip(
        SupervisorCommand::AdmitEpoch {
            canonical_envelope: envelope,
            verifier_receipt,
        },
        0x30,
    );
    assert!(matches!(
        admission,
        SupervisorResponse::Control(SupervisorControlReceipt::EpochAdmitted {
            current_epoch: 1,
            revoked: false,
            ..
        })
    ));
    let admitted_journal = wait_for_durable_ack_after(&journal, 0);

    let target = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("signed loopback dispatch");
        let request = read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .expect("owned loopback response");
        request
    });
    let successful = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "provisioned-handoff",
            1,
            "target:owned-loopback",
            0x70,
        ))),
        0x40,
    );
    let observed_request = target.join().expect("owned target server");
    let admitted_acks = admitted_journal
        .snapshot
        .as_ref()
        .expect("admission journal snapshot")
        .acknowledged_responses
        .len();
    let dispatched_journal = wait_for_durable_ack_after(&journal, admitted_acks);

    let SupervisorResponse::Gateway(successful) = successful else {
        panic!("provisioned handoff did not return a Gateway response")
    };
    let GatewayResponse::Receipt {
        receipt,
        semantic_http: Some(semantic_http),
        ..
    } = *successful
    else {
        panic!("provisioned handoff did not return an HTTP receipt")
    };
    assert_eq!(receipt.outcome, DispatchOutcome::Completed);
    assert!(!receipt.reconciliation_required);
    assert_eq!(semantic_http.status_code, 200);
    assert_eq!(semantic_http.body, b"OK");
    assert_eq!(semantic_http.body_digest, Digest::of(b"OK"));
    assert!(observed_request.starts_with(b"POST /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n"));
    assert!(observed_request.ends_with(b"probe-provisioned-handoff"));

    let denied = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "provisioned-retarget",
            1,
            "target:not-authorized",
            0x90,
        ))),
        0x60,
    );
    assert!(matches!(
        denied,
        SupervisorResponse::Gateway(response)
            if matches!(
                response.as_ref(),
                GatewayResponse::Denied(DeniedResponse {
                    reason: DenialCode::ScopeTargetDenied,
                    ..
                })
            )
    ));
    let dispatched_acks = dispatched_journal
        .snapshot
        .as_ref()
        .expect("dispatch journal snapshot")
        .acknowledged_responses
        .len();
    let durable = wait_for_durable_ack_after(&journal, dispatched_acks);
    target_probe
        .set_nonblocking(true)
        .expect("nonblocking target probe");
    assert_eq!(
        target_probe
            .accept()
            .expect_err("wrong target must not create a second connection")
            .kind(),
        std::io::ErrorKind::WouldBlock,
    );

    let snapshot = durable.snapshot.as_ref().expect("durable journal snapshot");
    assert!(durable.frames > 0);
    assert!(durable.opens > 0);
    assert!(durable.commits > 0);
    assert!(durable.durable_sequence > 0);
    assert!(durable.current_anchor.is_some());
    assert!(snapshot.prepared_dispatches.is_empty());
    assert!(snapshot.pending_responses.is_empty());
    assert!(!snapshot.acknowledged_responses.is_empty());
    println!(
        "PROVISIONED_LOOPBACK_OK status=200 receipt={} journal_commits={} wrong_target=ScopeTargetDenied",
        receipt.receipt_id.to_hex(),
        durable.commits,
    );
    gateway.finish();
}

fn wait_for_durable_ack_after(journal: &FakeJournal, previous: usize) -> JournalObservation {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let observed = journal.observation();
        let acknowledged = observed.snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.pending_responses.is_empty()
                && snapshot.acknowledged_responses.len() > previous
        });
        if acknowledged {
            return observed;
        }
        assert!(
            Instant::now() < deadline,
            "authenticated journal did not durably commit the handoff response"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
