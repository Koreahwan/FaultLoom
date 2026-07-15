#[cfg(test)]
use super::TestPreEgressBarrier;
use super::{
    ActionCompiler, CompiledAction, LeaseApproval, LeaseCompletion, LeaseFinalization,
    LeaseVerifier, PreEgressBarrier, PreEgressBarrierError, ScopeApproval, ScopeVerifier,
    UnavailableActionCompiler, UnavailableLeaseVerifier, UnavailablePreEgressBarrier,
    UnavailableScopeVerifier,
};
use crate::Digest;
use crate::ipc::{DenialCode, DispatchReceipt, DispatchRequest};

impl PreEgressBarrier for UnavailablePreEgressBarrier {
    fn persist(
        &self,
        _request: &DispatchRequest,
        _request_frame_digest: Digest,
        _approval: &LeaseApproval,
        _compiled: &CompiledAction,
    ) -> Result<(), PreEgressBarrierError> {
        Err(PreEgressBarrierError::Rejected(
            DenialCode::DurabilityUnavailable,
        ))
    }
}

#[cfg(test)]
impl PreEgressBarrier for TestPreEgressBarrier {
    fn persist(
        &self,
        _request: &DispatchRequest,
        _request_frame_digest: Digest,
        _approval: &LeaseApproval,
        _compiled: &CompiledAction,
    ) -> Result<(), PreEgressBarrierError> {
        Ok(())
    }
}

impl ScopeVerifier for UnavailableScopeVerifier {
    fn verify(&self, _request: &DispatchRequest) -> Result<ScopeApproval, DenialCode> {
        Err(DenialCode::ScopeVerifierUnavailable)
    }
}

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

impl ActionCompiler for UnavailableActionCompiler {
    fn compile(&self, _request: &DispatchRequest) -> Result<CompiledAction, DenialCode> {
        Err(DenialCode::CompilerUnavailable)
    }
}
