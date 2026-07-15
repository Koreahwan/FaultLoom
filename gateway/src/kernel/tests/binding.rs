use crate::Digest;
use crate::ipc::{DenialCode, DeniedResponse, DispatchReceipt, DispatchRequest, GatewayResponse};
use crate::policy::{
    ActionCompiler, CompiledAction, LeaseApproval, LeaseCompletion, LeaseFinalization,
    LeaseVerifier, ScopeApproval, ScopeVerifier, UnavailableActionCompiler,
};
use crate::transport::{
    DispatchCancellation, DispatchLimits, TargetTransport, TransportObservation,
};

use super::super::Gateway;
use super::fixture::{FixedClock, FixtureCompiler, FixtureLease, FixtureScope, handle, request};

struct MismatchedScope;

impl ScopeVerifier for MismatchedScope {
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        let mut approval = ScopeApproval::fixture(request);
        approval.scope_epoch += 1;
        Ok(approval)
    }
}

struct UncoupledScope;

impl ScopeVerifier for UncoupledScope {
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        Ok(ScopeApproval::fixture(request))
    }
}

pub(super) struct PanicTransport;

impl TargetTransport for PanicTransport {
    fn dispatch_cancellable(
        &self,
        _action: &CompiledAction,
        _cancellation: &DispatchCancellation,
        _limits: DispatchLimits,
    ) -> TransportObservation {
        panic!("binding mismatch reached target transport");
    }
}

#[test]
fn verifier_output_must_remain_bound_to_the_request() {
    let gateway = Gateway::new(
        MismatchedScope,
        FixtureLease,
        FixtureCompiler,
        PanicTransport,
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, request("127.0.0.1:9".parse().expect("address")),),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::VerificationBindingMismatch,
            ..
        })
    ));
}

#[test]
fn verifier_without_cancellation_registration_cannot_dispatch() {
    let gateway = Gateway::new(
        UncoupledScope,
        FixtureLease,
        FixtureCompiler,
        PanicTransport,
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, request("127.0.0.1:9".parse().expect("address"))),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::ScopeDenied,
            ..
        })
    ));
}

struct MismatchedLease;

impl LeaseVerifier for MismatchedLease {
    fn reserve(
        &self,
        request: &DispatchRequest,
        _now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode> {
        let mut approval = LeaseApproval::fixture(request);
        approval.request_binding_digest = Digest::of(b"substituted request binding");
        Ok(approval)
    }

    fn abandon(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
        Ok(())
    }

    fn finalize(
        &self,
        _approval: &LeaseApproval,
        _completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        panic!("mismatched lease reached finalization")
    }

    fn authenticate_receipt(
        &self,
        _approval: &LeaseApproval,
        _receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode> {
        panic!("mismatched lease reached receipt authentication")
    }
}

struct MismatchedCompiler;

impl ActionCompiler for MismatchedCompiler {
    fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
        let mut compiled = CompiledAction::fixture(request);
        compiled.resolution_digest = Digest::of(b"mutable resolver substitution");
        Ok(compiled)
    }
}

struct ByteSubstitutingCompiler;

impl ActionCompiler for ByteSubstitutingCompiler {
    fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
        let mut compiled = CompiledAction::fixture(request);
        compiled.bytes.extend_from_slice(b"-substituted");
        Ok(compiled)
    }
}

#[test]
fn forged_frame_digest_lease_binding_and_resolver_output_never_dispatch() {
    let target = "127.0.0.1:9".parse().expect("address");
    let request = request(target);
    let gateway = Gateway::new(
        FixtureScope,
        FixtureLease,
        FixtureCompiler,
        PanicTransport,
        FixedClock::new(),
    );
    assert!(matches!(
        gateway.handle(request.clone(), Digest::of(b"substituted request frame")),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::VerificationBindingMismatch,
            ..
        })
    ));

    let gateway = Gateway::new(
        FixtureScope,
        MismatchedLease,
        FixtureCompiler,
        PanicTransport,
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, request.clone()),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::VerificationBindingMismatch,
            ..
        })
    ));

    let gateway = Gateway::new(
        FixtureScope,
        FixtureLease,
        MismatchedCompiler,
        PanicTransport,
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, request.clone()),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::VerificationBindingMismatch,
            ..
        })
    ));

    let gateway = Gateway::new(
        FixtureScope,
        FixtureLease,
        ByteSubstitutingCompiler,
        PanicTransport,
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, request),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::VerificationBindingMismatch,
            ..
        })
    ));
}

#[test]
fn invalid_scope_and_lease_proofs_never_reach_transport() {
    let target = "127.0.0.1:9".parse().expect("address");
    let mut invalid_scope = request(target);
    invalid_scope.scope_proof = b"forged".to_vec();
    let gateway = Gateway::new(
        FixtureScope,
        FixtureLease,
        FixtureCompiler,
        PanicTransport,
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, invalid_scope),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::ScopeDenied,
            ..
        })
    ));

    let mut invalid_lease = request(target);
    invalid_lease.lease_proof = b"forged".to_vec();
    assert!(matches!(
        handle(&gateway, invalid_lease),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::LeaseDenied,
            ..
        })
    ));
}

#[test]
fn absent_semantic_compiler_never_reaches_transport() {
    let gateway = Gateway::new(
        FixtureScope,
        FixtureLease,
        UnavailableActionCompiler,
        PanicTransport,
        FixedClock::new(),
    );
    assert!(matches!(
        handle(&gateway, request("127.0.0.1:9".parse().expect("address")),),
        GatewayResponse::Denied(DeniedResponse {
            reason: DenialCode::CompilerUnavailable,
            ..
        })
    ));
}
