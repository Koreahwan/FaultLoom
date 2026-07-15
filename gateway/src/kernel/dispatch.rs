use std::io;

use crate::Digest;
use crate::ipc::{
    DenialCode, DeniedResponse, DispatchOutcome, DispatchRequest, GatewayResponse, encode_request,
};
use crate::policy::{
    ActionCompiler, LeaseCompletion, LeaseVerifier, PreEgressBarrier, PreEgressBarrierError,
    ScopeVerifier,
};
use crate::semantic_http::MAX_SEMANTIC_HTTP_RESPONSE_BYTES;
use crate::transport::{DispatchLimits, TargetTransport};

use super::receipt::{denied, make_receipt};
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
    pub(crate) fn handle(
        &self,
        request: DispatchRequest,
        request_frame_digest: Digest,
    ) -> GatewayResponse {
        let action_id = request.action_id.clone();
        match self.handle_terminal(request, request_frame_digest) {
            Ok(response) => response,
            Err(_) => GatewayResponse::Denied(DeniedResponse::bound(
                action_id,
                request_frame_digest,
                DenialCode::DurabilityUnavailable,
            )),
        }
    }

    pub(crate) fn handle_terminal(
        &self,
        request: DispatchRequest,
        request_frame_digest: Digest,
    ) -> io::Result<GatewayResponse> {
        if let Err(reason) = request.validate() {
            return Ok(denied(&request, request_frame_digest, reason));
        }
        let canonical_frame_digest = match encode_request(&request) {
            Ok(frame) => Digest::of(&frame),
            Err(reason) => return Ok(denied(&request, request_frame_digest, reason)),
        };
        if canonical_frame_digest != request_frame_digest {
            return Ok(denied(
                &request,
                canonical_frame_digest,
                DenialCode::VerificationBindingMismatch,
            ));
        }
        let scope = match self.scope.verify(&request) {
            Ok(approval) => approval,
            Err(reason) => return Ok(denied(&request, request_frame_digest, reason)),
        };
        let reserved_at_millis = self.clock.now_millis();
        if scope.intent_digest != request.intent_digest
            || scope.decision_digest != request.decision_digest
            || scope.lease_id != request.lease_id
            || scope.grant_id != request.grant_id
            || scope.grant_version != request.grant_version
            || scope.scope_epoch != request.scope_epoch
            || scope.scope_binding_digest != request.scope_binding_digest()
            || scope.target != request.target
            || scope.action_kind != request.action_kind
            || scope.action_class != request.action_class
            || scope.required_features != request.required_features
            || scope.valid_until_millis <= reserved_at_millis
        {
            return Ok(denied(
                &request,
                request_frame_digest,
                DenialCode::VerificationBindingMismatch,
            ));
        }
        let lease = match self.lease.reserve(&request, reserved_at_millis) {
            Ok(approval) => approval,
            Err(reason) => return Ok(denied(&request, request_frame_digest, reason)),
        };
        if lease.intent_digest != request.intent_digest
            || lease.decision_digest != request.decision_digest
            || lease.grant_id != request.grant_id
            || lease.grant_version != request.grant_version
            || lease.lease_id != request.lease_id
            || lease.scope_epoch != request.scope_epoch
            || lease.authority_key_id != scope.authority_key_id
            || lease.scope_epoch_binding_digest != scope.scope_epoch_binding_digest
            || lease.gateway_boot_id != scope.gateway_boot_id
            || lease.boot_challenge_digest == Digest::ZERO
            || lease.request_binding_digest != request.lease_binding_digest()
            || lease.semantic_action_digest != request.semantic_action_digest
            || lease.resolution_digest != request.resolution_digest
            || lease.effect_digest == Digest::ZERO
            || lease.correlation_id != request.correlation_id
            || lease.egress_plane != request.egress_plane
            || lease.dispatch_nonce != request.dispatch_nonce
            || lease.issued_at_millis != request.request_issued_at_millis
            || lease.expires_at_millis != request.request_expires_at_millis
            || lease.retry_of_intent_digest != request.retry_of_intent_digest
            || lease.maximum_dispatches != 1
            || lease.reservation.action_count != 1
        {
            return Ok(self.abandon_then_deny(
                &request,
                request_frame_digest,
                &lease,
                DenialCode::VerificationBindingMismatch,
            ));
        }
        let compiled = match self.compiler.compile(&request) {
            Ok(compiled) => compiled,
            Err(reason) => {
                return Ok(self.abandon_then_deny(&request, request_frame_digest, &lease, reason));
            }
        };
        if compiled.intent_digest != request.intent_digest
            || compiled.action_kind != request.action_kind
            || compiled.target != scope.target
            || compiled.egress_plane != request.egress_plane
            || compiled.semantic_action_digest != request.semantic_action_digest
            || compiled.resolution_digest != request.resolution_digest
            || compiled.request_binding_digest != request.lease_binding_digest()
            || compiled.effect_digest != lease.effect_digest
            || crate::policy::target_effect_digest(
                compiled.action_kind,
                compiled.egress_plane,
                compiled.resolution_digest,
                Digest::of(&compiled.bytes),
            ) != compiled.effect_digest
            || compiled.bytes.is_empty()
        {
            return Ok(self.abandon_then_deny(
                &request,
                request_frame_digest,
                &lease,
                DenialCode::VerificationBindingMismatch,
            ));
        }
        if !u64::try_from(compiled.bytes.len())
            .is_ok_and(|length| length <= lease.reservation.request_bytes)
        {
            return Ok(self.abandon_then_deny(
                &request,
                request_frame_digest,
                &lease,
                DenialCode::LeaseReservationExceeded,
            ));
        }
        if let Err(reason) = self.scope.register_dispatch(&request, &lease) {
            return Ok(self.abandon_then_deny(&request, request_frame_digest, &lease, reason));
        }

        let dispatch_started = std::time::Instant::now();
        let dispatched_at_millis = self.clock.now_millis();
        let maximum_duration_millis = scope
            .valid_until_millis
            .saturating_sub(dispatched_at_millis)
            .min(lease.expires_at_millis.saturating_sub(dispatched_at_millis))
            .min(lease.reservation.duration_seconds.saturating_mul(1_000));
        if maximum_duration_millis == 0 {
            let _ = self.scope.finish_dispatch(&lease);
            return Ok(self.abandon_then_deny(
                &request,
                request_frame_digest,
                &lease,
                DenialCode::LeaseExpired,
            ));
        }
        let limits = DispatchLimits {
            deadline: dispatch_started
                .checked_add(std::time::Duration::from_millis(maximum_duration_millis))
                .unwrap_or(dispatch_started),
            maximum_response_bytes: usize::try_from(lease.reservation.response_bytes)
                .unwrap_or(usize::MAX)
                .min(MAX_SEMANTIC_HTTP_RESPONSE_BYTES),
        };
        match self
            .barrier
            .persist(&request, request_frame_digest, &lease, &compiled)
        {
            Ok(()) => {}
            Err(PreEgressBarrierError::Rejected(reason)) => {
                let _ = self.scope.finish_dispatch(&lease);
                return Ok(self.abandon_then_deny(&request, request_frame_digest, &lease, reason));
            }
            Err(PreEgressBarrierError::Terminal(error)) => return Err(error),
        }
        let mut observation =
            self.transport
                .dispatch_cancellable(&compiled, &lease.cancellation, limits);
        let completed_at_millis = self.clock.now_millis().max(dispatched_at_millis);
        if self.scope.finish_dispatch(&lease).is_err() {
            observation.outcome = DispatchOutcome::UnknownOutcome;
        }
        let bytes_received = u64::try_from(observation.response.len()).unwrap_or(u64::MAX);
        let finalization = self.lease.finalize(
            &lease,
            LeaseCompletion {
                outcome: observation.outcome,
                bytes_sent: observation.bytes_sent,
                bytes_received,
                elapsed_millis: completed_at_millis.saturating_sub(dispatched_at_millis),
            },
        );
        if finalization.as_ref().map_or(true, |result| {
            result.reconciliation_required || result.reservation_overrun
        }) {
            observation.outcome = DispatchOutcome::UnknownOutcome;
        }
        let (mut receipt, semantic_http) = make_receipt(
            &request,
            request_frame_digest,
            &scope,
            &lease,
            &compiled.bytes,
            observation,
            (dispatched_at_millis, completed_at_millis),
        );
        receipt.receipt_authentication_tag = match self.lease.authenticate_receipt(&lease, &receipt)
        {
            Ok(authentication_tag) => authentication_tag,
            Err(reason) => return Ok(denied(&request, request_frame_digest, reason)),
        };
        Ok(GatewayResponse::Receipt {
            action_id: request.action_id,
            receipt,
            semantic_http,
        })
    }
}
