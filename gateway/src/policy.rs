use std::net::SocketAddr;

use crate::Digest;
use crate::ipc::{ActionClass, ActionKind, DenialCode, DispatchRequest, RequiredFeature};

#[derive(Clone, Debug)]
pub(crate) struct ScopeApproval {
    pub(crate) intent_digest: Digest,
    pub(crate) decision_digest: Digest,
    pub(crate) lease_id: String,
    pub(crate) grant_id: String,
    pub(crate) grant_version: u64,
    pub(crate) scope_epoch: u64,
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
            scope_binding_digest: request.scope_binding_digest(),
            target: request.target,
            action_kind: request.action_kind,
            action_class: request.action_class,
            required_features: request.required_features.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LeaseApproval {
    pub(crate) intent_digest: Digest,
    pub(crate) lease_id: String,
    pub(crate) scope_epoch: u64,
    pub(crate) maximum_dispatches: u8,
}

impl LeaseApproval {
    #[cfg(test)]
    pub(crate) fn fixture(request: &DispatchRequest) -> Self {
        Self {
            intent_digest: request.intent_digest,
            lease_id: request.lease_id.clone(),
            scope_epoch: request.scope_epoch,
            maximum_dispatches: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CompiledAction {
    pub(crate) intent_digest: Digest,
    pub(crate) action_kind: ActionKind,
    pub(crate) target: SocketAddr,
    pub(crate) bytes: Vec<u8>,
}

impl CompiledAction {
    #[cfg(test)]
    pub(crate) fn fixture(request: &DispatchRequest) -> Self {
        Self {
            intent_digest: request.intent_digest,
            action_kind: request.action_kind,
            target: request.target,
            bytes: request.payload.clone(),
        }
    }
}

pub(crate) trait ScopeVerifier {
    fn verify(&self, request: &DispatchRequest) -> Result<ScopeApproval, DenialCode>;
}

pub(crate) trait LeaseVerifier {
    fn verify(&self, request: &DispatchRequest) -> Result<LeaseApproval, DenialCode>;
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
    fn verify(&self, _request: &DispatchRequest) -> Result<LeaseApproval, DenialCode> {
        Err(DenialCode::LeaseVerifierUnavailable)
    }
}

pub(crate) struct UnavailableActionCompiler;

impl ActionCompiler for UnavailableActionCompiler {
    fn compile(&self, _request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
        Err(DenialCode::CompilerUnavailable)
    }
}
