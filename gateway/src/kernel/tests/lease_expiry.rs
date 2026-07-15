use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::Digest;
use crate::ipc::{DenialCode, DeniedResponse, DispatchOutcome, DispatchReceipt, GatewayResponse};

use super::super::Gateway;
use super::fixture::{FixedClock, FixtureCompiler, FixtureScope, handle, request};
use super::lease_support::{issue_request, lease_authority, lease_spec};
use super::transport::RecordingTransport;

#[test]
fn expired_lease_is_denied_before_mock_transport() {
    let authority = lease_authority();
    let mut request = request("127.0.0.1:9".parse().expect("address"));
    request.request_expires_at_millis = 1_000;
    let issued = authority
        .issue(lease_spec(&request))
        .expect("issue expiring lease");
    request.lease_proof = issued.proof;
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
        handle(&gateway, request),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::LeaseExpired,
            ..
        })
    ));
    assert_eq!(dispatches.load(Ordering::SeqCst), 0);
}

#[test]
fn unknown_outcome_blocks_a_fresh_lease_for_the_same_intent() {
    let authority = lease_authority();
    let mut first = request("127.0.0.1:9".parse().expect("address"));
    first.lease_id = "lease:unknown-first".to_owned();
    first.decision_digest = Digest::of(b"decision:unknown-first");
    first.bind_canonical_semantics();
    issue_request(&authority, &mut first);
    let mut retry = first.clone();
    retry.action_id = "action:unknown-retry".to_owned();
    retry.lease_id = "lease:unknown-retry".to_owned();
    retry.decision_digest = Digest::of(b"decision:unknown-retry");
    retry.dispatch_nonce = *b"fedcba9876543210";
    retry.bind_canonical_semantics();
    let dispatches = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway::new(
        FixtureScope,
        authority,
        FixtureCompiler,
        RecordingTransport {
            dispatches: Arc::clone(&dispatches),
            outcome: DispatchOutcome::UnknownOutcome,
            response: Vec::new(),
        },
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, first),
        GatewayResponse::Receipt {
            receipt: DispatchReceipt {
                outcome: DispatchOutcome::UnknownOutcome,
                reconciliation_required: true,
                ..
            },
            ..
        }
    ));
    assert_eq!(
        gateway.lease.issue(lease_spec(&retry)),
        Err(DenialCode::LeaseReconciliationRequired)
    );
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
}
