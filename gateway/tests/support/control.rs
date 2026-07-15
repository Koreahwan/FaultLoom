use std::io::Read;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use faultloom_gateway::ipc::{DenialCode, DeniedResponse, DispatchOutcome, GatewayResponse};
use faultloom_gateway::supervisor_protocol::{
    ControlEgressDisposition, SupervisorCommand, SupervisorControlReceipt, SupervisorResponse,
};

use crate::fixtures::{dispatch, issuer, read_http_request};
use crate::process::{ProcessHarness, bootstrap, now_millis};

const EXPIRY_DELAY_MILLIS: u64 = 5_000;

#[derive(Clone, Copy, Debug)]
pub enum ActiveControl {
    Advance,
    Revoke,
    Expire,
}

pub fn run_active_control(control: ActiveControl) {
    // Given: an authenticated dispatch whose owned target has received the
    // complete request and is blocking the response phase.
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let probe = listener.try_clone().expect("listener probe");
    let now = now_millis();
    let bootstrap = bootstrap(listener.local_addr().expect("listener address"), now);
    let issuer = issuer(&bootstrap);
    let mut gateway = ProcessHarness::spawn(&bootstrap);
    let epoch_now = now_millis();
    let first_expiry = match control {
        ActiveControl::Expire => epoch_now + EXPIRY_DELAY_MILLIS,
        ActiveControl::Advance | ActiveControl::Revoke => epoch_now + 60_000,
    };
    let (envelope, receipt) = issuer.issue(1, false, epoch_now, first_expiry, 0x50);
    let admitted = gateway.round_trip(
        SupervisorCommand::AdmitEpoch {
            canonical_envelope: envelope,
            verifier_receipt: receipt,
        },
        0x30,
    );
    assert!(matches!(admitted, SupervisorResponse::Control(_)));
    let (request_seen_tx, request_seen_rx) = mpsc::sync_channel(0);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("active connection");
        let request = read_http_request(&mut stream);
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .expect("cancellation read timeout");
        request_seen_tx.send(request.len()).expect("request signal");
        let mut byte = [0_u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::UnexpectedEof
                ) => {}
            result => panic!("active target did not observe cancellation: {result:?}"),
        }
    });
    let dispatch_request = gateway.send(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "active",
            1,
            "target:owned-loopback",
            0x70,
        ))),
        0x40,
    );
    assert!(request_seen_rx.recv().expect("target request length") > 0);

    // When: the installed control surface advances, revokes, or expires the
    // current scope while that transport is still active.
    if matches!(control, ActiveControl::Expire) {
        while now_millis() < first_expiry {
            thread::yield_now();
        }
    }
    let (dispatch_response, control_response) = match control {
        ActiveControl::Advance | ActiveControl::Revoke => {
            let current = now_millis();
            let (envelope, receipt) = issuer.issue(
                2,
                matches!(control, ActiveControl::Revoke),
                current,
                current + 60_000,
                0x90,
            );
            let control_request = gateway.send(
                SupervisorCommand::AdmitEpoch {
                    canonical_envelope: envelope,
                    verifier_receipt: receipt,
                },
                0x60,
            );
            let first = gateway.read_outer();
            let second = gateway.read_outer();
            if let Ok(dispatch_response) = gateway.try_decode_for(&dispatch_request, first.clone())
            {
                (
                    dispatch_response,
                    gateway.decode_for(&control_request, second),
                )
            } else {
                (
                    gateway.decode_for(&dispatch_request, second),
                    gateway.decode_for(&control_request, first),
                )
            }
        }
        ActiveControl::Expire => {
            let dispatch_outer = gateway.read_outer();
            let dispatch_response = gateway.decode_for(&dispatch_request, dispatch_outer);
            let control_response = gateway.round_trip(SupervisorCommand::ReconcileExpiry, 0x60);
            (dispatch_response, control_response)
        }
    };
    server.join().expect("canceled target");

    // Then: control acknowledgement names the canceled resource, the dispatch
    // is terminally unknown, and a same-intent automatic retry never connects.
    assert_control_receipt(control, control_response);
    let SupervisorResponse::Gateway(dispatch_response) = dispatch_response else {
        panic!("interrupted dispatch did not return a gateway response")
    };
    let GatewayResponse::Receipt { receipt, .. } = *dispatch_response else {
        panic!("interrupted dispatch did not return an unknown receipt")
    };
    assert_eq!(receipt.outcome, DispatchOutcome::UnknownOutcome);
    assert!(receipt.reconciliation_required);
    let next_epoch = if matches!(control, ActiveControl::Advance | ActiveControl::Revoke) {
        2
    } else {
        1
    };
    let retry = gateway.round_trip(
        SupervisorCommand::Dispatch(Box::new(dispatch(
            "automatic-retry",
            next_epoch,
            "target:owned-loopback",
            0xb0,
        ))),
        0x80,
    );
    let expected = DenialCode::LeaseReconciliationRequired;
    assert!(
        matches!(
            &retry,
            SupervisorResponse::Gateway(response)
                if matches!(
                    response.as_ref(),
                    GatewayResponse::Denied(DeniedResponse { reason, .. }) if *reason == expected
                )
        ),
        "unexpected {control:?} retry response: {retry:?}"
    );
    probe.set_nonblocking(true).expect("nonblocking probe");
    assert_eq!(
        probe
            .accept()
            .expect_err("no automatic retry connection")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    let journal = gateway.journal();
    gateway.finish();
    let snapshot = journal.snapshot().expect("shutdown journal snapshot");
    assert!(snapshot.prepared_dispatches.is_empty());
}

fn assert_control_receipt(control: ActiveControl, response: SupervisorResponse) {
    match (control, response) {
        (
            ActiveControl::Advance,
            SupervisorResponse::Control(SupervisorControlReceipt::EpochAdmitted {
                current_epoch: 2,
                revoked: false,
                interrupted_resources: 1,
                egress_disposition: ControlEgressDisposition::TargetOutcomeUnknown,
                ..
            }),
        )
        | (
            ActiveControl::Revoke,
            SupervisorResponse::Control(SupervisorControlReceipt::EpochAdmitted {
                current_epoch: 2,
                revoked: true,
                interrupted_resources: 1,
                egress_disposition: ControlEgressDisposition::TargetOutcomeUnknown,
                ..
            }),
        )
        | (
            ActiveControl::Expire,
            SupervisorResponse::Control(SupervisorControlReceipt::ExpiryReconciled {
                interrupted_resources: 0,
                egress_disposition: ControlEgressDisposition::NoActiveEgress,
            }),
        ) => {}
        (_, response) => panic!("unexpected control response: {response:?}"),
    }
}
