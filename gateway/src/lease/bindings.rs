use super::*;

impl LeaseSpec {
    pub(super) fn hold_binding_digest(
        &self,
        lease_key_id: &str,
        boot_challenge_digest: Digest,
    ) -> Digest {
        let mut binding = Vec::with_capacity(640);
        binding.extend_from_slice(b"faultloom-reconciliation-hold-binding-v1\0");
        push_string(&mut binding, &self.grant_id);
        binding.extend_from_slice(&self.grant_version.to_be_bytes());
        binding.extend_from_slice(self.intent_digest.as_bytes());
        binding.extend_from_slice(self.decision_digest.as_bytes());
        binding.extend_from_slice(self.effect_digest.as_bytes());
        push_string(&mut binding, &self.lease_id);
        binding.extend_from_slice(&self.scope_epoch.to_be_bytes());
        push_string(&mut binding, &self.authority_key_id);
        binding.extend_from_slice(self.scope_epoch_binding_digest.as_bytes());
        push_string(&mut binding, lease_key_id);
        push_string(&mut binding, &self.gateway_boot_id);
        binding.extend_from_slice(boot_challenge_digest.as_bytes());
        binding.extend_from_slice(self.request_binding_digest.as_bytes());
        binding.extend_from_slice(self.semantic_action_digest.as_bytes());
        binding.extend_from_slice(self.resolution_digest.as_bytes());
        binding.extend_from_slice(self.compiled_request_digest.as_bytes());
        push_string(&mut binding, &self.correlation_id);
        binding.push(self.egress_plane as u8);
        binding.extend_from_slice(&self.dispatch_nonce);
        push_optional_digest(&mut binding, self.retry_of_intent_digest);
        binding.extend_from_slice(&self.issued_at_millis.to_be_bytes());
        binding.extend_from_slice(&self.expires_at_millis.to_be_bytes());
        binding.extend_from_slice(&self.reservation.action_count.to_be_bytes());
        binding.extend_from_slice(&self.reservation.request_bytes.to_be_bytes());
        binding.extend_from_slice(&self.reservation.response_bytes.to_be_bytes());
        binding.extend_from_slice(&self.reservation.duration_seconds.to_be_bytes());
        binding.extend_from_slice(self.control_envelope_id.as_bytes());
        Digest::of(&binding)
    }
}

impl LeaseAuthority {
    pub(super) fn sign_spec(&self, spec: &LeaseSpec) -> Digest {
        let mut message = Vec::with_capacity(256);
        message.extend_from_slice(b"faultloom-action-lease-v3\0");
        push_string(&mut message, &self.lease_key_id);
        push_string(&mut message, &self.gateway_boot_id);
        message.extend_from_slice(self.boot_challenge_digest.as_bytes());
        push_string(&mut message, &spec.lease_id);
        message.extend_from_slice(spec.intent_digest.as_bytes());
        message.extend_from_slice(spec.decision_digest.as_bytes());
        push_string(&mut message, &spec.grant_id);
        message.extend_from_slice(&spec.grant_version.to_be_bytes());
        message.extend_from_slice(&spec.scope_epoch.to_be_bytes());
        push_string(&mut message, &spec.authority_key_id);
        message.extend_from_slice(spec.scope_epoch_binding_digest.as_bytes());
        push_string(&mut message, &spec.gateway_boot_id);
        message.extend_from_slice(spec.control_envelope_id.as_bytes());
        message.extend_from_slice(spec.request_binding_digest.as_bytes());
        message.extend_from_slice(spec.semantic_action_digest.as_bytes());
        message.extend_from_slice(spec.resolution_digest.as_bytes());
        message.extend_from_slice(spec.compiled_request_digest.as_bytes());
        message.extend_from_slice(spec.effect_digest.as_bytes());
        push_string(&mut message, &spec.correlation_id);
        message.push(spec.egress_plane as u8);
        message.extend_from_slice(&spec.dispatch_nonce);
        push_optional_digest(&mut message, spec.retry_of_intent_digest);
        message.extend_from_slice(&spec.issued_at_millis.to_be_bytes());
        message.extend_from_slice(&spec.expires_at_millis.to_be_bytes());
        message.extend_from_slice(&spec.reservation.action_count.to_be_bytes());
        message.extend_from_slice(&spec.reservation.request_bytes.to_be_bytes());
        message.extend_from_slice(&spec.reservation.response_bytes.to_be_bytes());
        message.extend_from_slice(&spec.reservation.duration_seconds.to_be_bytes());
        hmac_sha256(&self.signing_key, &message)
    }

    pub(super) fn dispatch_receipt_authentication_tag(&self, receipt: &DispatchReceipt) -> Digest {
        let mut message = Vec::with_capacity(128);
        message.extend_from_slice(b"faultloom-dispatch-receipt-authentication-v1\0");
        push_string(&mut message, &self.lease_key_id);
        message.extend_from_slice(receipt.receipt_id.as_bytes());
        hmac_sha256(&self.signing_key, &message)
    }

    pub(super) fn receipt_matches_approval(
        receipt: &DispatchReceipt,
        approval: &LeaseApproval,
    ) -> bool {
        receipt.intent_digest == approval.intent_digest
            && receipt.decision_digest == approval.decision_digest
            && receipt.grant_id == approval.grant_id
            && receipt.grant_version == approval.grant_version
            && receipt.lease_id == approval.lease_id
            && receipt.scope_epoch == approval.scope_epoch
            && receipt.authority_key_id == approval.authority_key_id
            && receipt.scope_epoch_binding_digest == approval.scope_epoch_binding_digest
            && receipt.lease_key_id == approval.lease_key_id
            && receipt.gateway_boot_id == approval.gateway_boot_id
            && receipt.boot_challenge_digest == approval.boot_challenge_digest
            && receipt.control_envelope_id == approval.control_envelope_id
            && receipt.request_binding_digest == approval.request_binding_digest
            && receipt.semantic_action_digest == approval.semantic_action_digest
            && receipt.resolution_digest == approval.resolution_digest
            && receipt.request_digest == approval.compiled_request_digest
            && receipt.effect_digest == approval.effect_digest
            && receipt.hold_binding_digest == approval.hold_binding_digest
            && crate::policy::target_effect_digest(
                receipt.action_kind,
                receipt.egress_plane,
                receipt.resolution_digest,
                receipt.request_digest,
            ) == approval.effect_digest
            && receipt.correlation_id == approval.correlation_id
            && receipt.egress_plane == approval.egress_plane
            && receipt.dispatch_nonce == approval.dispatch_nonce
            && receipt.lease_issued_at_millis == approval.issued_at_millis
            && receipt.lease_expires_at_millis == approval.expires_at_millis
            && receipt.retry_of_intent_digest == approval.retry_of_intent_digest
            && receipt.reserved_action_count == approval.reservation.action_count
            && receipt.reserved_request_bytes == approval.reservation.request_bytes
            && receipt.reserved_response_bytes == approval.reservation.response_bytes
            && receipt.reserved_duration_seconds == approval.reservation.duration_seconds
    }

    pub(super) fn reservation_token(&self, entry: &LeaseEntry, reserved_at_millis: u64) -> Digest {
        let mut message = Vec::with_capacity(128);
        message.extend_from_slice(b"faultloom-lease-reservation-v1\0");
        message.extend_from_slice(entry.proof.as_bytes());
        message.extend_from_slice(&reserved_at_millis.to_be_bytes());
        hmac_sha256(&self.signing_key, &message)
    }

    pub(super) fn retry_invariant_digest(
        &self,
        request: &DispatchRequest,
        spec: &LeaseSpec,
    ) -> Digest {
        let mut binding = Vec::with_capacity(1_024 + request.payload.len());
        binding.extend_from_slice(b"faultloom-retry-invariant-v1\0");
        push_string(&mut binding, &spec.grant_id);
        binding.extend_from_slice(&spec.grant_version.to_be_bytes());
        binding.extend_from_slice(&spec.scope_epoch.to_be_bytes());
        push_string(&mut binding, &spec.authority_key_id);
        binding.extend_from_slice(spec.scope_epoch_binding_digest.as_bytes());
        push_string(&mut binding, &self.lease_key_id);
        push_string(&mut binding, &spec.gateway_boot_id);
        binding.extend_from_slice(self.boot_challenge_digest.as_bytes());
        binding.extend_from_slice(spec.decision_digest.as_bytes());
        push_string(&mut binding, &request.target_id);
        push_string(&mut binding, &request.pack_id);
        push_string(&mut binding, &request.action_family);
        push_string(&mut binding, &request.identity_id);
        push_optional_string(&mut binding, request.tenant_id.as_deref());
        binding.push(request.action_kind as u8);
        binding.push(request.action_class as u8);
        binding.push(request.egress_plane as u8);
        binding.push(request.flow_kind as u8);
        push_optional_string(&mut binding, request.parent_action_id.as_deref());
        binding.extend_from_slice(&(request.required_features.len() as u32).to_be_bytes());
        for feature in &request.required_features {
            binding.push(*feature as u8);
        }
        push_string(&mut binding, &request.hostname);
        push_string(&mut binding, &request.protocol);
        push_string(&mut binding, &request.method);
        push_string(&mut binding, &request.path);
        match request.target.ip() {
            std::net::IpAddr::V4(address) => {
                binding.push(4);
                binding.extend_from_slice(&address.octets());
            }
            std::net::IpAddr::V6(address) => {
                binding.push(6);
                binding.extend_from_slice(&address.octets());
            }
        }
        binding.extend_from_slice(&request.target.port().to_be_bytes());
        binding.extend_from_slice(spec.resolution_digest.as_bytes());
        binding.extend_from_slice(Digest::of(&request.payload).as_bytes());
        binding.extend_from_slice(spec.compiled_request_digest.as_bytes());
        binding.extend_from_slice(spec.effect_digest.as_bytes());
        push_optional_string(&mut binding, request.canary_ref.as_deref());
        push_optional_string(&mut binding, request.checkpoint_ref.as_deref());
        push_optional_string(&mut binding, request.cleanup_plan_ref.as_deref());
        binding.extend_from_slice(&spec.reservation.action_count.to_be_bytes());
        binding.extend_from_slice(&spec.reservation.request_bytes.to_be_bytes());
        binding.extend_from_slice(&spec.reservation.response_bytes.to_be_bytes());
        binding.extend_from_slice(&spec.reservation.duration_seconds.to_be_bytes());
        Digest::of(&binding)
    }
}
