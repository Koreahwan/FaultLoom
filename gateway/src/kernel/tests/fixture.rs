use crate::Digest;
use crate::ipc::{
    ActionClass, ActionKind, DenialCode, DispatchOutcome, DispatchReceipt, DispatchRequest,
    EgressPlane, FlowKind, GatewayResponse, RequiredFeature, encode_request,
};
use crate::policy::{
    ActionCompiler, CompiledAction, LeaseApproval, LeaseCompletion, LeaseFinalization,
    LeaseVerifier, PreEgressBarrier, ScopeApproval, ScopeVerifier,
};
use crate::transport::TargetTransport;

use super::super::{Clock, Gateway};

pub(super) struct FixtureScope;

impl ScopeVerifier for FixtureScope {
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        if request.scope_proof != b"fixture-scope-proof" {
            return Err(DenialCode::ScopeDenied);
        }
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
        Ok(())
    }
}

pub(super) struct FixtureLease;

impl LeaseVerifier for FixtureLease {
    fn reserve(
        &self,
        request: &DispatchRequest,
        _now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode> {
        if request.lease_proof != b"fixture-lease-proof" {
            return Err(DenialCode::LeaseDenied);
        }
        Ok(LeaseApproval::fixture(request))
    }

    fn abandon(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
        Ok(())
    }

    fn finalize(
        &self,
        _approval: &LeaseApproval,
        completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        Ok(LeaseFinalization {
            reconciliation_required: completion.outcome == DispatchOutcome::UnknownOutcome,
            reservation_overrun: false,
        })
    }

    fn authenticate_receipt(
        &self,
        _approval: &LeaseApproval,
        receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode> {
        if receipt.receipt_id != receipt.canonical_id() {
            return Err(DenialCode::LeaseBindingMismatch);
        }
        Ok(Digest::of(b"fixture receipt authentication"))
    }
}

pub(super) struct FixtureCompiler;

impl ActionCompiler for FixtureCompiler {
    fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
        if request.compiler_proof != b"fixture-compiler-proof" || request.payload != b"PING" {
            return Err(DenialCode::CompilerDenied);
        }
        Ok(CompiledAction::fixture(request))
    }
}

#[derive(Clone)]
pub(super) struct FixedClock;

impl FixedClock {
    pub(super) const fn new() -> Self {
        Self
    }
}

impl Clock for FixedClock {
    fn now_millis(&self) -> u64 {
        1_000
    }
}

pub(super) fn request(target: std::net::SocketAddr) -> DispatchRequest {
    let mut request = DispatchRequest {
        action_id: "action:loopback".to_owned(),
        correlation_id: "correlation:loopback".to_owned(),
        grant_id: "grant:fixture".to_owned(),
        grant_version: 1,
        target_id: "target:owned-loopback".to_owned(),
        pack_id: "web".to_owned(),
        action_family: "http.semantic".to_owned(),
        identity_id: "identity:operator".to_owned(),
        tenant_id: Some("tenant:owned".to_owned()),
        intent_digest: Digest::of(b"fixture-intent"),
        decision_digest: Digest::of(b"fixture-decision"),
        lease_id: "lease:fixture".to_owned(),
        scope_epoch: 7,
        action_kind: ActionKind::SemanticHttpV1,
        action_class: ActionClass::SafeProbe,
        egress_plane: EgressPlane::TargetGateway,
        flow_kind: FlowKind::TopLevel,
        parent_action_id: None,
        required_features: vec![RequiredFeature::GatewayDispatchV1],
        hostname: "localhost".to_owned(),
        protocol: "http".to_owned(),
        method: "GET".to_owned(),
        path: "/".to_owned(),
        target,
        resolution_digest: Digest::ZERO,
        semantic_action_digest: Digest::ZERO,
        dispatch_nonce: *b"0123456789abcdef",
        request_issued_at_millis: 999,
        request_expires_at_millis: 6_000,
        retry_of_intent_digest: None,
        payload: b"PING".to_vec(),
        scope_proof: b"fixture-scope-proof".to_vec(),
        lease_proof: b"fixture-lease-proof".to_vec(),
        compiler_proof: b"fixture-compiler-proof".to_vec(),
        canary_ref: None,
        checkpoint_ref: None,
        cleanup_plan_ref: None,
    };
    request.bind_canonical_semantics();
    request
}

pub(super) fn handle<S, L, C, T, K, B>(
    gateway: &Gateway<S, L, C, T, K, B>,
    request: DispatchRequest,
) -> GatewayResponse
where
    S: ScopeVerifier,
    L: LeaseVerifier,
    C: ActionCompiler,
    T: TargetTransport,
    K: Clock,
    B: PreEgressBarrier,
{
    let frame = encode_request(&request).expect("canonical request frame");
    gateway.handle(request, Digest::of(&frame))
}
