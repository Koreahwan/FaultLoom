use std::net::SocketAddr;
use std::sync::Arc;

use crate::Digest;
use crate::ipc::{
    ActionClass, ActionKind, DenialCode, DispatchReceipt, DispatchRequest, EgressPlane,
    RequiredFeature,
};
use crate::lease::LeaseBudgetReservation;
use crate::transport::DispatchCancellation;

#[derive(Clone, Debug)]
pub(crate) struct ScopeApproval {
    pub(crate) intent_digest: Digest,
    pub(crate) decision_digest: Digest,
    pub(crate) lease_id: String,
    pub(crate) grant_id: String,
    pub(crate) grant_version: u64,
    pub(crate) scope_epoch: u64,
    pub(crate) authority_key_id: String,
    pub(crate) scope_epoch_binding_digest: Digest,
    pub(crate) gateway_boot_id: String,
    pub(crate) scope_binding_digest: Digest,
    pub(crate) target: SocketAddr,
    pub(crate) action_kind: ActionKind,
    pub(crate) action_class: ActionClass,
    pub(crate) required_features: Vec<RequiredFeature>,
}

impl ScopeApproval {
    #[cfg(test)]
    pub(crate) fn fixture(request: &DispatchRequest) -> Self {
        Self {
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            lease_id: request.lease_id.clone(),
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            scope_epoch: request.scope_epoch,
            authority_key_id: format!("ed25519:sha256:{}", "11".repeat(32)),
            scope_epoch_binding_digest: Digest::of(b"fixture-scope-epoch-binding"),
            gateway_boot_id: "gateway:boot:fixture".to_owned(),
            scope_binding_digest: request.scope_binding_digest(),
            target: request.target,
            action_kind: request.action_kind,
            action_class: request.action_class,
            required_features: request.required_features.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LeaseApproval {
    pub(crate) intent_digest: Digest,
    pub(crate) decision_digest: Digest,
    pub(crate) grant_id: String,
    pub(crate) grant_version: u64,
    pub(crate) lease_id: String,
    pub(crate) scope_epoch: u64,
    pub(crate) authority_key_id: String,
    pub(crate) scope_epoch_binding_digest: Digest,
    pub(crate) lease_key_id: String,
    pub(crate) gateway_boot_id: String,
    pub(crate) boot_challenge_digest: Digest,
    pub(crate) request_binding_digest: Digest,
    pub(crate) semantic_action_digest: Digest,
    pub(crate) resolution_digest: Digest,
    pub(crate) correlation_id: String,
    pub(crate) egress_plane: EgressPlane,
    pub(crate) dispatch_nonce: [u8; 16],
    pub(crate) issued_at_millis: u64,
    pub(crate) expires_at_millis: u64,
    pub(crate) retry_of_intent_digest: Option<Digest>,
    pub(crate) maximum_dispatches: u8,
    pub(crate) reservation: LeaseBudgetReservation,
    pub(crate) reservation_token: Digest,
    pub(crate) cancellation: DispatchCancellation,
}

impl LeaseApproval {
    #[cfg(test)]
    pub(crate) fn fixture(request: &DispatchRequest) -> Self {
        Self {
            intent_digest: request.intent_digest,
            decision_digest: request.decision_digest,
            grant_id: request.grant_id.clone(),
            grant_version: request.grant_version,
            lease_id: request.lease_id.clone(),
            scope_epoch: request.scope_epoch,
            authority_key_id: format!("ed25519:sha256:{}", "11".repeat(32)),
            scope_epoch_binding_digest: Digest::of(b"fixture-scope-epoch-binding"),
            lease_key_id: "lease-key:fixture".to_owned(),
            gateway_boot_id: "gateway:boot:fixture".to_owned(),
            boot_challenge_digest: Digest::of(b"fixture-gateway-challenge"),
            request_binding_digest: request.lease_binding_digest(),
            semantic_action_digest: request.semantic_action_digest,
            resolution_digest: request.resolution_digest,
            correlation_id: request.correlation_id.clone(),
            egress_plane: request.egress_plane,
            dispatch_nonce: request.dispatch_nonce,
            issued_at_millis: request.request_issued_at_millis,
            expires_at_millis: request.request_expires_at_millis,
            retry_of_intent_digest: request.retry_of_intent_digest,
            maximum_dispatches: 1,
            reservation: LeaseBudgetReservation {
                action_count: 1,
                request_bytes: request.payload.len() as u64,
                response_bytes: u64::MAX,
                duration_seconds: u64::MAX / 1_000,
            },
            reservation_token: Digest::of(b"fixture-reservation"),
            cancellation: DispatchCancellation::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LeaseCompletion {
    pub(crate) outcome: crate::ipc::DispatchOutcome,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
    pub(crate) elapsed_millis: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LeaseFinalization {
    pub(crate) reconciliation_required: bool,
    pub(crate) reservation_overrun: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledAction {
    pub(crate) intent_digest: Digest,
    pub(crate) action_kind: ActionKind,
    pub(crate) target: SocketAddr,
    pub(crate) egress_plane: EgressPlane,
    pub(crate) semantic_action_digest: Digest,
    pub(crate) resolution_digest: Digest,
    pub(crate) request_binding_digest: Digest,
    pub(crate) bytes: Vec<u8>,
}

impl CompiledAction {
    #[cfg(test)]
    pub(crate) fn fixture(request: &DispatchRequest) -> Self {
        Self {
            intent_digest: request.intent_digest,
            action_kind: request.action_kind,
            target: request.target,
            egress_plane: request.egress_plane,
            semantic_action_digest: request.semantic_action_digest,
            resolution_digest: request.resolution_digest,
            request_binding_digest: request.lease_binding_digest(),
            bytes: request.payload.clone(),
        }
    }
}

pub(crate) trait ScopeVerifier {
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode>;

    fn register_dispatch(
        &self,
        _request: &DispatchRequest,
        _approval: &LeaseApproval,
    ) -> Result<(), DenialCode> {
        Err(DenialCode::ScopeDenied)
    }

    fn finish_dispatch(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
        Err(DenialCode::ScopeDenied)
    }
}

impl<T> ScopeVerifier for Arc<T>
where
    T: ScopeVerifier + ?Sized,
{
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        self.as_ref().verify(request)
    }

    fn register_dispatch(
        &self,
        request: &DispatchRequest,
        approval: &LeaseApproval,
    ) -> Result<(), DenialCode> {
        self.as_ref().register_dispatch(request, approval)
    }

    fn finish_dispatch(&self, approval: &LeaseApproval) -> Result<(), DenialCode> {
        self.as_ref().finish_dispatch(approval)
    }
}

pub(crate) trait LeaseVerifier {
    fn reserve(
        &self,
        request: &DispatchRequest,
        now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode>;

    fn abandon(&self, approval: &LeaseApproval) -> Result<(), DenialCode>;

    fn finalize(
        &self,
        approval: &LeaseApproval,
        completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode>;

    fn authenticate_receipt(
        &self,
        approval: &LeaseApproval,
        receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode>;
}

impl<T> LeaseVerifier for Arc<T>
where
    T: LeaseVerifier + ?Sized,
{
    fn reserve(
        &self,
        request: &DispatchRequest,
        now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode> {
        self.as_ref().reserve(request, now_millis)
    }

    fn abandon(&self, approval: &LeaseApproval) -> Result<(), DenialCode> {
        self.as_ref().abandon(approval)
    }

    fn finalize(
        &self,
        approval: &LeaseApproval,
        completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        self.as_ref().finalize(approval, completion)
    }

    fn authenticate_receipt(
        &self,
        approval: &LeaseApproval,
        receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode> {
        self.as_ref().authenticate_receipt(approval, receipt)
    }
}

pub(crate) trait ActionCompiler {
    fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode>;
}

pub(crate) struct UnavailableScopeVerifier;

impl ScopeVerifier for UnavailableScopeVerifier {
    fn verify(&self, _request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        Err(DenialCode::ScopeVerifierUnavailable)
    }
}

pub(crate) struct UnavailableLeaseVerifier;

impl LeaseVerifier for UnavailableLeaseVerifier {
    fn reserve(
        &self,
        _request: &DispatchRequest,
        _now_millis: u64,
    ) -> Result<LeaseApproval, DenialCode> {
        Err(DenialCode::LeaseVerifierUnavailable)
    }

    fn abandon(&self, _approval: &LeaseApproval) -> Result<(), DenialCode> {
        Err(DenialCode::LeaseVerifierUnavailable)
    }

    fn finalize(
        &self,
        _approval: &LeaseApproval,
        _completion: LeaseCompletion,
    ) -> Result<LeaseFinalization, DenialCode> {
        Err(DenialCode::LeaseVerifierUnavailable)
    }

    fn authenticate_receipt(
        &self,
        _approval: &LeaseApproval,
        _receipt: &DispatchReceipt,
    ) -> Result<Digest, DenialCode> {
        Err(DenialCode::LeaseVerifierUnavailable)
    }
}

pub(crate) struct UnavailableActionCompiler;

impl ActionCompiler for UnavailableActionCompiler {
    fn compile(&self, _request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
        Err(DenialCode::CompilerUnavailable)
    }
}
