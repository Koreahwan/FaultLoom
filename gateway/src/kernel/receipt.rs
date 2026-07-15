use crate::Digest;
use crate::ipc::{
    DenialCode, DeniedResponse, DispatchOutcome, DispatchReceipt, DispatchRequest, GatewayResponse,
};
use crate::policy::{
    ActionCompiler, LeaseApproval, LeaseVerifier, PreEgressBarrier, ScopeVerifier,
};
use crate::semantic_http::{SemanticHttpResponseArtifact, parse_semantic_http_response};
use crate::transport::{TargetTransport, TransportObservation};

use super::{Clock, Gateway};

impl<S, L, C, T, K, B> Gateway<S, L, C, T, K, B>
where
    S: ScopeVerifier,
    L: LeaseVerifier,
    C: ActionCompiler,
    T: TargetTransport,
    K: Clock,
    B: PreEgressBarrier,
{
    pub(super) fn abandon_then_deny(
        &self,
        request: &DispatchRequest,
        request_frame_digest: Digest,
        approval: &LeaseApproval,
        reason: DenialCode,
    ) -> GatewayResponse {
        let final_reason = self.lease.abandon(approval).err().unwrap_or(reason);
        denied(request, request_frame_digest, final_reason)
    }
}

pub(super) fn denied(
    request: &DispatchRequest,
    request_frame_digest: Digest,
    reason: DenialCode,
) -> GatewayResponse {
    GatewayResponse::Denied(DeniedResponse::bound(
        request.action_id.clone(),
        request_frame_digest,
        reason,
    ))
}

pub(super) fn make_receipt(
    request: &DispatchRequest,
    request_frame_digest: Digest,
    scope: &crate::policy::ScopeApproval,
    lease: &LeaseApproval,
    compiled_bytes: &[u8],
    observation: TransportObservation,
    timing: (u64, u64),
) -> (DispatchReceipt, Option<SemanticHttpResponseArtifact>) {
    let (dispatched_at_millis, completed_at_millis) = timing;
    let request_digest = Digest::of(compiled_bytes);
    let response_digest = match observation.outcome {
        DispatchOutcome::Completed => Some(Digest::of(&observation.response)),
        DispatchOutcome::UnknownOutcome if !observation.response.is_empty() => {
            Some(Digest::of(&observation.response))
        }
        DispatchOutcome::Failed | DispatchOutcome::UnknownOutcome => None,
    };
    let bytes_received = u64::try_from(observation.response.len()).unwrap_or(u64::MAX);
    let reconciliation_required = observation.outcome == DispatchOutcome::UnknownOutcome;
    let semantic_http = (observation.outcome == DispatchOutcome::Completed)
        .then(|| parse_semantic_http_response(&observation.response))
        .flatten();
    let mut receipt = DispatchReceipt {
        receipt_id: Digest::ZERO,
        receipt_authentication_tag: Digest::ZERO,
        action_id: request.action_id.clone(),
        correlation_id: request.correlation_id.clone(),
        lease_id: request.lease_id.clone(),
        grant_id: request.grant_id.clone(),
        grant_version: request.grant_version,
        authority_key_id: scope.authority_key_id.clone(),
        scope_epoch_binding_digest: scope.scope_epoch_binding_digest,
        lease_key_id: lease.lease_key_id.clone(),
        gateway_boot_id: scope.gateway_boot_id.clone(),
        boot_challenge_digest: lease.boot_challenge_digest,
        intent_digest: request.intent_digest,
        decision_digest: request.decision_digest,
        scope_epoch: request.scope_epoch,
        semantic_action_digest: request.semantic_action_digest,
        request_binding_digest: request.lease_binding_digest(),
        request_frame_digest,
        control_envelope_id: lease.control_envelope_id,
        hold_binding_digest: lease.hold_binding_digest,
        resolution_digest: request.resolution_digest,
        action_kind: request.action_kind,
        egress_plane: request.egress_plane,
        effect_digest: lease.effect_digest,
        dispatch_nonce: request.dispatch_nonce,
        lease_issued_at_millis: lease.issued_at_millis,
        lease_expires_at_millis: lease.expires_at_millis,
        retry_of_intent_digest: lease.retry_of_intent_digest,
        reserved_action_count: lease.reservation.action_count,
        reserved_request_bytes: lease.reservation.request_bytes,
        reserved_response_bytes: lease.reservation.response_bytes,
        reserved_duration_seconds: lease.reservation.duration_seconds,
        request_digest,
        response_digest,
        outcome: observation.outcome,
        dispatched_at_millis,
        completed_at_millis,
        bytes_sent: observation.bytes_sent,
        bytes_received,
        reconciliation_required,
    };
    receipt.receipt_id = receipt.canonical_id();
    (receipt, semantic_http)
}
