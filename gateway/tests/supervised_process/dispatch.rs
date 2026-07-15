use std::io::Write;
use std::net::TcpListener;
use std::thread;

use faultloom_gateway::ipc::{DenialCode, DeniedResponse, DispatchOutcome, GatewayResponse};
use faultloom_gateway::supervisor_protocol::{
    ControlEgressDisposition, SupervisorCommand, SupervisorControlReceipt, SupervisorResponse,
};

use crate::fixtures::{dispatch, issuer, read_http_request};
use crate::process::{ProcessHarness, bootstrap, now_millis};

#[test]
fn installed_supervisor_dispatches_only_the_bootstrap_bound_loopback_target() {
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
        SupervisorResponse::Control(SupervisorControlReceipt::EpochAdmitted {
            current_epoch: 1,
            revoked: false,
            ..
        })
    ));
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("supervised connection");
        let request = read_http_request(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .expect("owned response");
        request
    });

    let successful = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "success",
            1,
            "target:owned-loopback",
            0x70,
        ))),
        0x40,
    );
    let request = server.join().expect("owned server");
    let denied = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(dispatch("wrong-target", 1, "target:other", 0x90))),
        0x60,
    );
    let expiry = gateway.round_trip(SupervisorCommand::ReconcileExpiry, 0x80);

    let SupervisorResponse::Gateway(successful) = successful else {
        panic!("installed supervised dispatch did not return a gateway response")
    };
    let GatewayResponse::Receipt { receipt, .. } = *successful else {
        panic!("installed supervised dispatch did not return a receipt")
    };
    assert_eq!(receipt.outcome, DispatchOutcome::Completed);
    assert!(!receipt.reconciliation_required);
    assert!(request.starts_with(b"POST /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n"));
    assert!(request.ends_with(b"probe-success"));
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
    probe.set_nonblocking(true).expect("nonblocking probe");
    assert_eq!(
        probe
            .accept()
            .expect_err("no unbound target connection")
            .kind(),
        std::io::ErrorKind::WouldBlock,
    );
    assert_eq!(
        expiry,
        SupervisorResponse::Control(SupervisorControlReceipt::ExpiryReconciled {
            interrupted_resources: 0,
            egress_disposition: ControlEgressDisposition::NoActiveEgress,
        })
    );
    gateway.finish();
}
