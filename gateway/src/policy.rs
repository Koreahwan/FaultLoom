use std::io;
use std::net::SocketAddr;

use crate::Digest;
use crate::ipc::{
    ActionClass, ActionKind, DenialCode, DispatchReceipt, DispatchRequest, EgressPlane,
    RequiredFeature,
};
use crate::lease::LeaseBudgetReservation;
use crate::transport::DispatchCancellation;

#[path = "policy/arc.rs"]
mod arc;

#[cfg(test)]
#[path = "policy/fixtures.rs"]
mod fixtures;

#[path = "policy/unavailable.rs"]
mod unavailable;

pub(crate) fn target_effect_digest(
    action_kind: ActionKind,
    egress_plane: EgressPlane,
    resolution_digest: Digest,
    compiled_request_digest: Digest,
) -> Digest {
    let mut binding = Vec::with_capacity(2 + (2 * 32) + 27);
    binding.extend_from_slice(b"faultloom-target-effect-v1\0");
    binding.push(action_kind as u8);
    binding.push(egress_plane as u8);
    binding.extend_from_slice(resolution_digest.as_bytes());
    binding.extend_from_slice(compiled_request_digest.as_bytes());
    Digest::of(&binding)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompilerLeaseBinding {
    pub(crate) proof: Vec<u8>,
    pub(crate) compiled_length: u64,
    pub(crate) compiled_request_digest: Digest,
    pub(crate) effect_digest: Digest,
}

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
    pub(crate) valid_until_millis: u64,
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
    pub(crate) control_envelope_id: Digest,
    pub(crate) request_binding_digest: Digest,
    pub(crate) semantic_action_digest: Digest,
    pub(crate) resolution_digest: Digest,
    pub(crate) compiled_request_digest: Digest,
    pub(crate) effect_digest: Digest,
    pub(crate) hold_binding_digest: Digest,
    pub(crate) retry_invariant_digest: Digest,
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
    pub(crate) effect_digest: Digest,
    pub(crate) bytes: Vec<u8>,
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

pub(crate) trait ActionCompiler {
    fn compile(&self, request: &DispatchRequest) -> Result<CompiledAction, DenialCode>;
}

#[derive(Debug)]
pub(crate) enum PreEgressBarrierError {
    Rejected(DenialCode),
    Terminal(io::Error),
}

pub(crate) trait PreEgressBarrier {
    fn persist(
        &self,
        request: &DispatchRequest,
        request_frame_digest: Digest,
        approval: &LeaseApproval,
        compiled: &CompiledAction,
    ) -> Result<(), PreEgressBarrierError>;
}

pub(crate) struct UnavailablePreEgressBarrier;

#[cfg(test)]
pub(crate) struct TestPreEgressBarrier;

pub(crate) struct UnavailableScopeVerifier;

pub(crate) struct UnavailableLeaseVerifier;

pub(crate) struct UnavailableActionCompiler;
