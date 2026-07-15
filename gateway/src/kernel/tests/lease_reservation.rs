use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::ipc::{DenialCode, DeniedResponse, DispatchOutcome, GatewayResponse};

use super::super::Gateway;
use super::fixture::{FixedClock, FixtureCompiler, FixtureScope, handle, request};
use super::lease_support::{issue_request, lease_authority};
use super::transport::RecordingTransport;

#[test]
fn authenticated_lease_replay_never_reaches_mock_transport() {
    let authority = lease_authority();
    let mut request = request("127.0.0.1:9".parse().expect("address"));
    issue_request(&authority, &mut request);
    let dispatches = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway::new(
        FixtureScope,
        authority,
        FixtureCompiler,
        RecordingTransport {
            dispatches: Arc::clone(&dispatches),
            outcome: DispatchOutcome::Completed,
            response: b"PONG".to_vec(),
        },
        FixedClock::new(),
    );

    let first = handle(&gateway, request.clone());
    let GatewayResponse::Receipt { receipt, .. } = &first else {
        panic!("first dispatch must produce a receipt");
    };
    assert_eq!(receipt.receipt_id, receipt.canonical_id());
    let encoded = crate::ipc::encode_response(&first).expect("canonical receipt frame");
    assert_eq!(crate::ipc::decode_response(&encoded), Ok(first));
    assert!(matches!(
        handle(&gateway, request),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::LeaseReplay,
            ..
        })
    ));
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
}

#[test]
fn compiler_failure_consumes_lease_without_target_dispatch() {
    let authority = lease_authority();
    let mut request = request("127.0.0.1:9".parse().expect("address"));
    issue_request(&authority, &mut request);
    request.compiler_proof = b"forged".to_vec();
    let dispatches = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway::new(
        FixtureScope,
        authority,
        FixtureCompiler,
        RecordingTransport {
            dispatches: Arc::clone(&dispatches),
            outcome: DispatchOutcome::Completed,
            response: b"PONG".to_vec(),
        },
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, request.clone()),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::CompilerDenied,
            ..
        })
    ));
    request.compiler_proof = b"fixture-compiler-proof".to_vec();
    assert!(matches!(
        handle(&gateway, request),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::LeaseReplay,
            ..
        })
    ));
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
}
