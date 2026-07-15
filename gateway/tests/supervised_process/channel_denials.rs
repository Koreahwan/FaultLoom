use std::io::Write;
use std::net::TcpListener;
use std::thread;

use faultloom_gateway::Digest;
use faultloom_gateway::channel::ChannelClient;
use faultloom_gateway::ipc::{DispatchOutcome, GatewayResponse};
use faultloom_gateway::supervisor_journal::JournalSnapshot;
use faultloom_gateway::supervisor_protocol::{
    SupervisorCommand, SupervisorControlReceipt, SupervisorResponse,
};

use crate::bootstrap_fixture::TestBootstrap;
use crate::fixtures::{dispatch, issuer, read_http_request};
use crate::process::{ProcessHarness, bootstrap, nonce, now_millis};

#[test]
fn installed_supervisor_rejects_wrong_session_before_trusted_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let now = now_millis();
    let bootstrap = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&bootstrap);
    let baseline = admit_epoch_and_snapshot(&mut gateway, &bootstrap);
    assert!(baseline.prepared_dispatches.is_empty());
    assert!(baseline.pending_responses.is_empty());
    let wrong_session = ChannelClient::new(
        bootstrap.secrets.channel_key,
        bootstrap.channel_challenge().expect("channel challenge"),
        "session:wrong-supervisor".to_owned(),
    )
    .expect("wrong-session client");
    let request = wrong_session
        .seal_request(
            SupervisorCommand::Dispatch(Box::new(dispatch(
                "wrong-session",
                1,
                &bootstrap.target.target_id,
                0xa0,
            )))
            .to_bytes()
            .expect("encode adversarial dispatch"),
            nonce(0xb0),
            now_millis(),
            now_millis() + 20_000,
        )
        .expect("seal wrong-session request");
    let journal = gateway.journal();

    gateway.write_raw_request(&request);
    gateway.finish_expecting_failure();

    let after = journal.snapshot().expect("channel failure snapshot");
    assert_eq!(&after.prepared_dispatches, &baseline.prepared_dispatches);
    assert_eq!(&after.pending_responses, &baseline.pending_responses);
    assert_no_connection(&listener);
}

#[test]
fn installed_supervisor_rejects_replay_resealed_in_new_session_before_worker_launch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let probe = listener.try_clone().expect("listener probe");
    let now = now_millis();
    let bootstrap = bootstrap(listener.local_addr().expect("listener address"), now);
    let mut gateway = ProcessHarness::spawn(&bootstrap);
    let _admission = admit_epoch_and_snapshot(&mut gateway, &bootstrap);
    let command = SupervisorCommand::Dispatch(Box::new(dispatch(
        "session-replay",
        1,
        &bootstrap.target.target_id,
        0xc0,
    )));
    let inner_command = command.to_bytes().expect("encode original dispatch");
    let target = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("supervised connection");
        let request = read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .expect("owned response");
        request
    });
    let original_request = gateway.send(command, 0xd0);
    let original_outer = gateway.read_outer();
    let (original_response, response_digest) =
        gateway.decode_for_without_ack(&original_request, original_outer);
    assert!(matches!(
        original_response,
        SupervisorResponse::Gateway(response)
            if matches!(
                response.as_ref(),
                GatewayResponse::Receipt { receipt, .. }
                    if receipt.outcome == DispatchOutcome::Completed
            )
    ));
    let observed = target.join().expect("owned target");
    assert!(observed.ends_with(b"probe-session-replay"));
    let baseline = acknowledge_and_snapshot(
        &mut gateway,
        original_request.envelope_id(),
        response_digest,
    );
    assert!(baseline.prepared_dispatches.is_empty());
    assert!(baseline.pending_responses.is_empty());
    let wrong_session = ChannelClient::new(
        bootstrap.secrets.channel_key,
        bootstrap.channel_challenge().expect("channel challenge"),
        "session:replay-alias".to_owned(),
    )
    .expect("replay-session client");
    let replay = wrong_session
        .seal_request(
            inner_command,
            nonce(0xe0),
            now_millis(),
            now_millis() + 20_000,
        )
        .expect("reseal replay request");
    let journal = gateway.journal();

    gateway.write_raw_request(&replay);
    gateway.finish_expecting_failure();

    let after = journal.snapshot().expect("replay failure snapshot");
    assert_eq!(&after.prepared_dispatches, &baseline.prepared_dispatches);
    assert_eq!(&after.pending_responses, &baseline.pending_responses);
    assert_no_connection(&probe);
}

fn admit_epoch_and_snapshot(
    gateway: &mut ProcessHarness,
    bootstrap: &TestBootstrap,
) -> JournalSnapshot {
    let now = now_millis();
    let (envelope, receipt) = issuer(bootstrap).issue(1, false, now, now + 60_000, 0x50);
    let request = gateway.send(
        SupervisorCommand::AdmitEpoch {
            canonical_envelope: envelope,
            verifier_receipt: receipt,
        },
        0x30,
    );
    let outer = gateway.read_outer();
    let (response, response_digest) = gateway.decode_for_without_ack(&request, outer);
    assert!(matches!(
        response,
        SupervisorResponse::Control(SupervisorControlReceipt::EpochAdmitted {
            current_epoch: 1,
            revoked: false,
            ..
        })
    ));
    acknowledge_and_snapshot(gateway, request.envelope_id(), response_digest)
}

fn acknowledge_and_snapshot(
    gateway: &mut ProcessHarness,
    original_request_id: Digest,
    response_digest: Digest,
) -> JournalSnapshot {
    let journal = gateway.journal();
    let acknowledgement = journal.pause_next_ack_after_commit();
    gateway.acknowledge_response(original_request_id, response_digest);
    acknowledgement.wait_until_commit_visible();
    let snapshot = journal.snapshot().expect("acknowledged response snapshot");
    acknowledgement.release();
    snapshot
}

fn assert_no_connection(listener: &TcpListener) {
    listener
        .set_nonblocking(true)
        .expect("nonblocking target probe");
    assert_eq!(
        listener
            .accept()
            .expect_err("rejected channel request cannot reach target")
            .kind(),
        std::io::ErrorKind::WouldBlock,
    );
}
