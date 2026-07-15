use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use faultloom_gateway::ipc::{DispatchOutcome, GatewayResponse};
use faultloom_gateway::supervisor_protocol::{
    SupervisorCommand, SupervisorControlReceipt, SupervisorResponse,
};

use crate::bootstrap_fixture::TestBootstrap;
use crate::fixtures::{dispatch, issuer, read_http_request};
use crate::process::{ProcessHarness, bootstrap, now_millis};
use crate::startup_support::{assert_no_connection, journal_for, rotated_bootstrap};

#[test]
fn signed_v4_startup_opens_once_and_dispatches_once_to_owned_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned loopback listener");
    let probe = listener.try_clone().expect("owned listener probe");
    let now = now_millis();
    let fixture = bootstrap(listener.local_addr().expect("listener address"), now);
    let journal = journal_for(&fixture);
    let before = journal.observation();
    let startup_commit = journal.pause_next_ack_after_commit();
    let mut gateway = ProcessHarness::spawn_with_journal(&fixture, Arc::clone(&journal));
    startup_commit.wait_until_commit_visible();
    startup_commit.release();
    admit_epoch(&mut gateway, &fixture, now);
    let target = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("authenticated dispatch connection");
        let request = read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .expect("owned target response");
        request
    });

    let response = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "installed-v4",
            1,
            &fixture.target.target_id,
            0x41,
        ))),
        0x31,
    );
    let request = target.join().expect("owned target worker");
    gateway.finish();

    let SupervisorResponse::Gateway(response) = response else {
        panic!("dispatch did not return gateway response")
    };
    let GatewayResponse::Receipt { receipt, .. } = *response else {
        panic!("dispatch did not return receipt")
    };
    assert_eq!(receipt.outcome, DispatchOutcome::Completed);
    assert!(request.starts_with(b"POST /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n"));
    assert!(request.ends_with(b"probe-installed-v4"));
    let after = journal.observation();
    assert_eq!(after.opens, before.opens + 1, "startup must issue one Open");
    assert!(
        after.commits > before.commits,
        "authenticated work was not durable"
    );
    assert!(
        journal.snapshot().is_some(),
        "startup did not persist a snapshot"
    );
    assert_no_connection(&probe);
}

#[test]
fn restart_reuses_stable_binding_only_with_rotated_boot_authorization() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned loopback listener");
    let initial = bootstrap(
        listener.local_addr().expect("listener address"),
        now_millis(),
    );
    let journal = journal_for(&initial);
    ProcessHarness::spawn_with_journal(&initial, Arc::clone(&journal)).finish();
    let anchor = journal
        .observation()
        .current_anchor
        .expect("clean startup anchor");
    let restarted = rotated_bootstrap(&initial, anchor);
    assert_eq!(
        initial
            .durability_binding()
            .expect("initial stable binding"),
        restarted
            .durability_binding()
            .expect("restart stable binding"),
    );
    assert_ne!(initial.boot.nonce, restarted.boot.nonce);
    assert!(restarted.boot.sequence > initial.boot.sequence);
    assert_ne!(initial.secrets.channel_key, restarted.secrets.channel_key);
    let before = journal.observation();

    ProcessHarness::spawn_with_journal(&restarted, Arc::clone(&journal)).finish();

    let after = journal.observation();
    assert_eq!(after.opens, before.opens + 1);
    assert!(after.commits > before.commits);
    assert_no_connection(&listener);
}

fn admit_epoch(gateway: &mut ProcessHarness, fixture: &TestBootstrap, now: u64) {
    let authority = issuer(fixture);
    let (canonical_envelope, verifier_receipt) = authority.issue(1, false, now, now + 60_000, 0x51);
    assert!(matches!(
        gateway.round_trip(
            SupervisorCommand::AdmitEpoch {
                canonical_envelope,
                verifier_receipt
            },
            0x21,
        ),
        SupervisorResponse::Control(SupervisorControlReceipt::EpochAdmitted {
            current_epoch: 1,
            revoked: false,
            ..
        })
    ));
}
