use crate::Digest;

use super::binding::{push_binding_optional_digest, push_binding_string};
use super::tags::{ActionKind, DispatchOutcome, EgressPlane};
use super::validation::{valid_identifier, valid_nonce};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchReceipt {
    pub receipt_id: Digest,
    pub receipt_authentication_tag: Digest,
    pub action_id: String,
    pub correlation_id: String,
    pub lease_id: String,
    pub grant_id: String,
    pub grant_version: u64,
    pub authority_key_id: String,
    pub scope_epoch_binding_digest: Digest,
    pub lease_key_id: String,
    pub gateway_boot_id: String,
    pub boot_challenge_digest: Digest,
    pub intent_digest: Digest,
    pub decision_digest: Digest,
    pub scope_epoch: u64,
    pub semantic_action_digest: Digest,
    pub request_binding_digest: Digest,
    pub request_frame_digest: Digest,
    pub control_envelope_id: Digest,
    pub hold_binding_digest: Digest,
    pub resolution_digest: Digest,
    pub action_kind: ActionKind,
    pub egress_plane: EgressPlane,
    pub effect_digest: Digest,
    pub dispatch_nonce: [u8; 16],
    pub lease_issued_at_millis: u64,
    pub lease_expires_at_millis: u64,
    pub retry_of_intent_digest: Option<Digest>,
    pub reserved_action_count: u64,
    pub reserved_request_bytes: u64,
    pub reserved_response_bytes: u64,
    pub reserved_duration_seconds: u64,
    pub request_digest: Digest,
    pub response_digest: Option<Digest>,
    pub outcome: DispatchOutcome,
    pub dispatched_at_millis: u64,
    pub completed_at_millis: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub reconciliation_required: bool,
}

impl DispatchReceipt {
    pub(crate) fn canonical_id(&self) -> Digest {
        let mut canonical = Vec::with_capacity(256);
        canonical.extend_from_slice(b"faultloom-gateway-receipt-v2\0");
        push_binding_string(&mut canonical, &self.action_id);
        push_binding_string(&mut canonical, &self.correlation_id);
        push_binding_string(&mut canonical, &self.lease_id);
        push_binding_string(&mut canonical, &self.grant_id);
        canonical.extend_from_slice(&self.grant_version.to_be_bytes());
        push_binding_string(&mut canonical, &self.authority_key_id);
        canonical.extend_from_slice(self.scope_epoch_binding_digest.as_bytes());
        push_binding_string(&mut canonical, &self.lease_key_id);
        push_binding_string(&mut canonical, &self.gateway_boot_id);
        canonical.extend_from_slice(self.boot_challenge_digest.as_bytes());
        canonical.extend_from_slice(self.intent_digest.as_bytes());
        canonical.extend_from_slice(self.decision_digest.as_bytes());
        canonical.extend_from_slice(&self.scope_epoch.to_be_bytes());
        canonical.extend_from_slice(self.semantic_action_digest.as_bytes());
        canonical.extend_from_slice(self.request_binding_digest.as_bytes());
        canonical.extend_from_slice(self.request_frame_digest.as_bytes());
        canonical.extend_from_slice(self.control_envelope_id.as_bytes());
        canonical.extend_from_slice(self.hold_binding_digest.as_bytes());
        canonical.extend_from_slice(self.resolution_digest.as_bytes());
        canonical.push(self.action_kind as u8);
        canonical.push(self.egress_plane as u8);
        canonical.extend_from_slice(self.effect_digest.as_bytes());
        canonical.extend_from_slice(&self.dispatch_nonce);
        canonical.extend_from_slice(&self.lease_issued_at_millis.to_be_bytes());
        canonical.extend_from_slice(&self.lease_expires_at_millis.to_be_bytes());
        push_binding_optional_digest(&mut canonical, self.retry_of_intent_digest);
        canonical.extend_from_slice(&self.reserved_action_count.to_be_bytes());
        canonical.extend_from_slice(&self.reserved_request_bytes.to_be_bytes());
        canonical.extend_from_slice(&self.reserved_response_bytes.to_be_bytes());
        canonical.extend_from_slice(&self.reserved_duration_seconds.to_be_bytes());
        canonical.extend_from_slice(self.request_digest.as_bytes());
        match self.response_digest {
            Some(digest) => {
                canonical.push(1);
                canonical.extend_from_slice(digest.as_bytes());
            }
            None => canonical.push(0),
        }
        canonical.push(self.outcome as u8);
        canonical.extend_from_slice(&self.dispatched_at_millis.to_be_bytes());
        canonical.extend_from_slice(&self.completed_at_millis.to_be_bytes());
        canonical.extend_from_slice(&self.bytes_sent.to_be_bytes());
        canonical.extend_from_slice(&self.bytes_received.to_be_bytes());
        canonical.push(u8::from(self.reconciliation_required));
        Digest::of(&canonical)
    }

    pub(crate) fn validate(&self) -> bool {
        if !valid_identifier(&self.action_id)
            || !valid_identifier(&self.correlation_id)
            || !valid_identifier(&self.lease_id)
            || !valid_identifier(&self.grant_id)
            || self.grant_version == 0
            || !valid_identifier(&self.authority_key_id)
            || self.scope_epoch_binding_digest == Digest::ZERO
            || !valid_identifier(&self.lease_key_id)
            || !valid_identifier(&self.gateway_boot_id)
            || self.boot_challenge_digest == Digest::ZERO
            || self.scope_epoch == 0
            || self.intent_digest == Digest::ZERO
            || self.decision_digest == Digest::ZERO
            || self.semantic_action_digest == Digest::ZERO
            || self.request_binding_digest == Digest::ZERO
            || self.request_frame_digest == Digest::ZERO
            || self.control_envelope_id == Digest::ZERO
            || self.hold_binding_digest == Digest::ZERO
            || self.resolution_digest == Digest::ZERO
            || self.effect_digest == Digest::ZERO
            || !valid_nonce(&self.dispatch_nonce)
            || self.lease_issued_at_millis >= self.lease_expires_at_millis
            || self.retry_of_intent_digest == Some(Digest::ZERO)
            || self.retry_of_intent_digest == Some(self.intent_digest)
            || self.reserved_action_count != 1
            || self.reserved_request_bytes == 0
            || self.reserved_duration_seconds == 0
            || self.request_digest == Digest::ZERO
            || crate::policy::target_effect_digest(
                self.action_kind,
                self.egress_plane,
                self.resolution_digest,
                self.request_digest,
            ) != self.effect_digest
            || self.completed_at_millis < self.dispatched_at_millis
            || self.receipt_id != self.canonical_id()
            || self.receipt_authentication_tag == Digest::ZERO
        {
            return false;
        }
        self.reconciliation_required == (self.outcome == DispatchOutcome::UnknownOutcome)
    }
}
