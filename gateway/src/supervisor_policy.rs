use crate::Digest;
use crate::ipc::DenialCode;
use crate::ipc::DispatchRequest;
use crate::lease::{GrantBudget, IssuedLease, LeaseAuthority, LeaseBudgetReservation, LeaseSpec};
use crate::policy::CompilerLeaseBinding;
use crate::scope::{EpochAdmissionError, PreparedScopeDispatch};

pub(super) struct LeaseIssuanceBindings<'a> {
    pub(super) request: &'a DispatchRequest,
    pub(super) control_envelope_id: Digest,
    pub(super) scope: PreparedScopeDispatch,
    pub(super) compiler: &'a CompilerLeaseBinding,
}

pub(super) fn map_epoch_error(error: EpochAdmissionError) -> DenialCode {
    match error {
        EpochAdmissionError::VerifierUnavailable => DenialCode::ScopeVerifierUnavailable,
        EpochAdmissionError::NotYetValid => DenialCode::ScopeEpochUnavailable,
        EpochAdmissionError::Expired => DenialCode::ScopeEpochExpired,
        EpochAdmissionError::Rollback => DenialCode::ScopeEpochStale,
        EpochAdmissionError::TrustAnchorRevoked => DenialCode::ScopeEpochRevoked,
        EpochAdmissionError::StateUnavailable => DenialCode::ScopeDenied,
        EpochAdmissionError::Replay => DenialCode::IpcReplay,
        _ => DenialCode::ScopeProofInvalid,
    }
}

pub(super) fn issue_lease(
    authority: &LeaseAuthority,
    budget: &GrantBudget,
    bindings: LeaseIssuanceBindings<'_>,
) -> Result<IssuedLease, DenialCode> {
    let LeaseIssuanceBindings {
        request,
        control_envelope_id,
        scope,
        compiler,
    } = bindings;
    authority.issue(LeaseSpec {
        lease_id: request.lease_id.clone(),
        intent_digest: request.intent_digest,
        decision_digest: request.decision_digest,
        grant_id: request.grant_id.clone(),
        grant_version: request.grant_version,
        scope_epoch: request.scope_epoch,
        authority_key_id: scope.authority_key_id,
        scope_epoch_binding_digest: scope.scope_epoch_binding_digest,
        gateway_boot_id: scope.gateway_boot_id,
        control_envelope_id,
        request_binding_digest: request.lease_binding_digest(),
        semantic_action_digest: request.semantic_action_digest,
        resolution_digest: request.resolution_digest,
        effect_digest: compiler.effect_digest,
        compiled_request_digest: compiler.compiled_request_digest,
        correlation_id: request.correlation_id.clone(),
        egress_plane: request.egress_plane,
        dispatch_nonce: request.dispatch_nonce,
        retry_of_intent_digest: request.retry_of_intent_digest,
        issued_at_millis: request.request_issued_at_millis,
        expires_at_millis: request.request_expires_at_millis,
        reservation: LeaseBudgetReservation {
            action_count: 1,
            request_bytes: compiler.compiled_length,
            response_bytes: budget.max_response_bytes,
            duration_seconds: budget.max_duration_seconds,
        },
    })
}
