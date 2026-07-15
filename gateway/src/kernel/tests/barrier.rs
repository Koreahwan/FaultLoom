use crate::Digest;
use crate::ipc::{
    DenialCode, DeniedResponse, DispatchReceipt, DispatchRequest, GatewayResponse, encode_request,
};
use crate::policy::{
    CompiledAction, LeaseApproval, LeaseCompletion, LeaseFinalization, LeaseVerifier,
    PreEgressBarrier, PreEgressBarrierError, ScopeApproval, ScopeVerifier,
};

use super::super::Gateway;
use super::binding::PanicTransport;
use super::fixture::{FixedClock, FixtureCompiler, FixtureLease, FixtureScope, request};

struct FailIfTerminalMutatesScope;

impl ScopeVerifier for FailIfTerminalMutatesScope {
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        Ok(ScopeApproval::fixture(request))
    }

    fn register_dispatch(
        &self,
        _request: &DispatchRequest,
        _approval: &LeaseApproval,
    ) -> Result<(), DenialCode> {
        Ok(())
    }

    fn finish_dispatch(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
        panic!("terminal barrier failure reached scope finalization")
    }
}

struct FailIfTerminalMutatesLease;

impl LeaseVerifier for FailIfTerminalMutatesLease {
    fn reserve(
        &self,
        request: &DispatchRequest,
        _now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode> {
        Ok(LeaseApproval::fixture(request))
    }

    fn abandon(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
        panic!("terminal barrier failure reached lease abandon")
    }

    fn finalize(
        &self,
        _approval: &LeaseApproval,
        _completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        panic!("terminal barrier failure reached lease finalization")
    }

    fn authenticate_receipt(
        &self,
        _approval: &LeaseApproval,
        _receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode> {
        panic!("terminal barrier failure reached receipt authentication")
    }
}

struct TerminalBarrier;

impl PreEgressBarrier for TerminalBarrier {
    fn persist(
        &self,
        _request: &DispatchRequest,
        _request_frame_digest: Digest,
        _approval: &LeaseApproval,
        _compiled: &CompiledAction,
    ) -> Result<(), PreEgressBarrierError> {
        Err(PreEgressBarrierError::Terminal(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "forced terminal barrier failure",
        )))
    }
}

struct RejectedBarrier;

impl PreEgressBarrier for RejectedBarrier {
    fn persist(
        &self,
        _request: &DispatchRequest,
        _request_frame_digest: Digest,
        _approval: &LeaseApproval,
        _compiled: &CompiledAction,
    ) -> Result<(), PreEgressBarrierError> {
        Err(PreEgressBarrierError::Rejected(
            DenialCode::PendingResponseUnacknowledged,
        ))
    }
}

#[test]
fn terminal_pre_egress_failure_never_finalizes_or_abandons_after_terminality() {
    // Given: scope and lease implementations that panic on every mutation
    // after registration, plus a terminal durability barrier.
    let request = request("127.0.0.1:9".parse().expect("address"));
    let frame = encode_request(&request).expect("canonical request frame");
    let gateway = Gateway::new_with_barrier(
        FailIfTerminalMutatesScope,
        FailIfTerminalMutatesLease,
        FixtureCompiler,
        PanicTransport,
        FixedClock::new(),
        TerminalBarrier,
    );

    // When: the terminal barrier fails before target egress.
    let error = gateway
        .handle_terminal(request, Digest::of(&frame))
        .expect_err("terminal durability failure");

    // Then: the typed terminal result reaches the caller without invoking
    // transport, scope finalization, lease finalization, or lease abandon.
    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
}

#[test]
fn stable_pre_egress_rejection_remains_a_gateway_denial() {
    // Given
    let request = request("127.0.0.1:9".parse().expect("address"));
    let frame = encode_request(&request).expect("canonical request frame");
    let gateway = Gateway::new_with_barrier(
        FixtureScope,
        FixtureLease,
        FixtureCompiler,
        PanicTransport,
        FixedClock::new(),
        RejectedBarrier,
    );

    // When
    let response = gateway
        .handle_terminal(request, Digest::of(&frame))
        .expect("stable barrier rejection");

    // Then
    assert!(matches!(
        response,
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::PendingResponseUnacknowledged,
            ..
        })
    ));
}
