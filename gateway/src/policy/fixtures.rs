use super::{CompiledAction, LeaseApproval, ScopeApproval, target_effect_digest};
use crate::Digest;
use crate::ipc::DispatchRequest;
use crate::lease::LeaseBudgetReservation;
use crate::transport::DispatchCancellation;

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
            valid_until_millis: u64::MAX,
        }
    }
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
            control_envelope_id: Digest::of(b"fixture-control-envelope"),
            request_binding_digest: request.lease_binding_digest(),
            semantic_action_digest: request.semantic_action_digest,
            resolution_digest: request.resolution_digest,
            compiled_request_digest: Digest::of(&request.payload),
            effect_digest: target_effect_digest(
                request.action_kind,
                request.egress_plane,
                request.resolution_digest,
                Digest::of(&request.payload),
            ),
            hold_binding_digest: Digest::of(b"fixture-exact-hold-binding"),
            retry_invariant_digest: Digest::of(b"fixture-retry-invariant"),
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
            effect_digest: target_effect_digest(
                request.action_kind,
                request.egress_plane,
                request.resolution_digest,
                Digest::of(&request.payload),
            ),
            bytes: request.payload.clone(),
        }
    }
}
