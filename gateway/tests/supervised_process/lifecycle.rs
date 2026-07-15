use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use faultloom_gateway::ipc::{DispatchOutcome, GatewayResponse};
use faultloom_gateway::supervisor_protocol::{SupervisorCommand, SupervisorResponse};

use crate::control::{ActiveControl, run_active_control};
use crate::fixtures::{dispatch, issuer, read_http_request};
use crate::process::{ProcessHarness, bootstrap, now_millis};

#[test]
fn installed_epoch_controls_interrupt_active_dispatches_without_automatic_retry() {
    for control in [
        ActiveControl::Advance,
        ActiveControl::Revoke,
        ActiveControl::Expire,
    ] {
        run_active_control(control);
    }
}

#[test]
fn supervisor_eof_cancels_and_joins_an_active_dispatch() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let probe = listener.try_clone().expect("listener probe");
    let now = now_millis();
    let bootstrap = bootstrap(listener.local_addr().expect("listener address"), now);
    let authority = issuer(&bootstrap);
    let mut gateway = ProcessHarness::spawn(&bootstrap);
    let (envelope, receipt) = authority.issue(1, false, now, now + 60_000, 0x50);
    assert!(matches!(
        gateway.round_trip(
            SupervisorCommand::AdmitEpoch {
                canonical_envelope: envelope,
                verifier_receipt: receipt,
            },
            0x30,
        ),
        SupervisorResponse::Control(_)
    ));
    let (request_seen_tx, request_seen_rx) = mpsc::sync_channel(0);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("active connection");
        let request = read_http_request(&mut stream);
        request_seen_tx.send(request.len()).expect("request signal");
        let mut byte = [0_u8; 1];
        match std::io::Read::read(&mut stream, &mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::UnexpectedEof
                ) => {}
            result => panic!("EOF shutdown did not cancel target transport: {result:?}"),
        }
    });
    let request = gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "eof-active",
            1,
            "target:owned-loopback",
            0xa0,
        ))),
        0xb0,
    );
    assert!(request_seen_rx.recv().expect("target request length") > 0);

    gateway.close_input();
    server.join().expect("canceled target");
    let response = gateway.read_outer();

    let response = gateway.decode_for(&request, response);
    assert!(matches!(
        response,
        SupervisorResponse::Gateway(response)
            if matches!(
                response.as_ref(),
                GatewayResponse::Receipt { receipt, .. }
                    if receipt.outcome == DispatchOutcome::UnknownOutcome
                        && receipt.reconciliation_required
            )
    ));
    probe.set_nonblocking(true).expect("nonblocking probe");
    assert_eq!(
        probe
            .accept()
            .expect_err("EOF shutdown cannot retry the dispatch")
            .kind(),
        std::io::ErrorKind::WouldBlock,
    );
    gateway.finish();
}
