use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use crate::Digest;
use crate::ipc::{DenialCode, DeniedResponse, DispatchOutcome, GatewayResponse};
use crate::policy::{
    CompiledAction, UnavailableActionCompiler, UnavailableLeaseVerifier, UnavailableScopeVerifier,
};
use crate::transport::{
    DispatchCancellation, DispatchLimits, TargetTransport, TcpTargetTransport, TransportObservation,
};

use super::super::{Gateway, SystemClock};
use super::fixture::{FixedClock, FixtureCompiler, FixtureLease, FixtureScope, handle, request};

#[test]
fn production_kernel_denies_before_opening_target_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let gateway = Gateway::new(
        UnavailableScopeVerifier,
        UnavailableLeaseVerifier,
        UnavailableActionCompiler,
        TcpTargetTransport::new(),
        SystemClock,
    );
    let response = handle(
        &gateway,
        request(listener.local_addr().expect("listener address")),
    );
    assert!(matches!(
        response,
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::ScopeVerifierUnavailable,
            ..
        })
    ));
    assert_eq!(
        listener.accept().expect_err("no target connection").kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn fixture_only_loopback_dispatch_produces_deterministic_receipts() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("owned listener");
    let target = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().expect("Gateway connection");
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).expect("read request");
            assert_eq!(request, *b"PING");
            stream.write_all(b"PONG").expect("write response");
        }
    });
    let gateway = Gateway::new(
        FixtureScope,
        FixtureLease,
        FixtureCompiler,
        TcpTargetTransport::new(),
        FixedClock::new(),
    );
    let first = handle(&gateway, request(target));
    let second = handle(&gateway, request(target));
    server.join().expect("loopback server");
    assert_eq!(first, second);
    let GatewayResponse::Receipt { receipt, .. } = first else {
        panic!("expected a dispatch receipt");
    };
    assert_eq!(receipt.outcome, DispatchOutcome::Completed);
    assert_eq!(receipt.request_digest, Digest::of(b"PING"));
    assert_eq!(receipt.response_digest, Some(Digest::of(b"PONG")));
    assert_eq!((receipt.bytes_sent, receipt.bytes_received), (4, 4));
    assert!(!receipt.reconciliation_required);
}

struct UnknownTransport(Arc<AtomicUsize>);

impl TargetTransport for UnknownTransport {
    fn dispatch_cancellable(
        &self,
        _action: &CompiledAction,
        _cancellation: &DispatchCancellation,
        _limits: DispatchLimits,
    ) -> TransportObservation {
        self.0.fetch_add(1, Ordering::SeqCst);
        TransportObservation {
            outcome: DispatchOutcome::UnknownOutcome,
            bytes_sent: 4,
            response: Vec::new(),
        }
    }
}

#[test]
fn unknown_outcome_is_not_retried_and_requires_reconciliation() {
    let dispatches = Arc::new(AtomicUsize::new(0));
    let gateway = Gateway::new(
        FixtureScope,
        FixtureLease,
        FixtureCompiler,
        UnknownTransport(dispatches.clone()),
        FixedClock::new(),
    );
    let response = handle(&gateway, request("127.0.0.1:9".parse().expect("address")));
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);
    let GatewayResponse::Receipt { receipt, .. } = response else {
        panic!("expected a dispatch receipt");
    };
    assert_eq!(receipt.outcome, DispatchOutcome::UnknownOutcome);
    assert!(receipt.reconciliation_required);
    assert_eq!(receipt.response_digest, None);
}

#[derive(Clone)]
pub(super) struct RecordingTransport {
    pub(super) dispatches: Arc<AtomicUsize>,
    pub(super) outcome: DispatchOutcome,
    pub(super) response: Vec<u8>,
}

impl TargetTransport for RecordingTransport {
    fn dispatch_cancellable(
        &self,
        action: &CompiledAction,
        _cancellation: &DispatchCancellation,
        _limits: DispatchLimits,
    ) -> TransportObservation {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        TransportObservation {
            outcome: self.outcome,
            bytes_sent: action.bytes.len() as u64,
            response: self.response.clone(),
        }
    }
}
