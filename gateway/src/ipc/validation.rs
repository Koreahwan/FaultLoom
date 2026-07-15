use std::net::IpAddr;

use crate::Digest;

use super::request::DispatchRequest;
use super::tags::{
    ActionClass, DenialCode, FlowKind, MAX_DISPATCH_TTL_MILLIS, MAX_ID_BYTES, MAX_PAYLOAD_BYTES,
    MAX_PROOF_BYTES, RequiredFeature,
};

impl DispatchRequest {
    pub(crate) fn validate(&self) -> Result<(), DenialCode> {
        if !valid_identifier(&self.action_id)
            || !valid_identifier(&self.correlation_id)
            || !valid_identifier(&self.grant_id)
            || self.grant_version == 0
            || !valid_identifier(&self.target_id)
            || !valid_identifier(&self.pack_id)
            || !valid_identifier(&self.action_family)
            || !valid_identifier(&self.identity_id)
            || self
                .tenant_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || !valid_identifier(&self.lease_id)
            || self.scope_epoch == 0
            || !valid_hostname(&self.hostname)
            || !valid_protocol(&self.protocol)
            || !valid_method(&self.method)
            || !valid_path(&self.path)
            || self.target.port() == 0
            || self.resolution_digest == Digest::ZERO
            || self.resolution_digest != self.canonical_resolution_digest()
            || self.semantic_action_digest == Digest::ZERO
            || self.semantic_action_digest != self.canonical_semantic_action_digest()
            || !valid_nonce(&self.dispatch_nonce)
            || self.request_issued_at_millis >= self.request_expires_at_millis
            || self
                .request_expires_at_millis
                .saturating_sub(self.request_issued_at_millis)
                > MAX_DISPATCH_TTL_MILLIS
            || self.retry_of_intent_digest == Some(Digest::ZERO)
            || self.retry_of_intent_digest == Some(self.intent_digest)
            || self.payload.len() > MAX_PAYLOAD_BYTES
            || self.scope_proof.is_empty()
            || self.scope_proof.len() > MAX_PROOF_BYTES
            || self.lease_proof.is_empty()
            || self.lease_proof.len() > MAX_PROOF_BYTES
            || self.compiler_proof.is_empty()
            || self.compiler_proof.len() > MAX_PROOF_BYTES
        {
            return Err(DenialCode::InvalidRequest);
        }
        if (self.flow_kind == FlowKind::TopLevel) != self.parent_action_id.is_none()
            || self
                .parent_action_id
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
        {
            return Err(DenialCode::InvalidChildFlow);
        }
        if self.required_features != [RequiredFeature::GatewayDispatchV1] {
            return Err(DenialCode::UnknownRequiredFeature);
        }
        if self.action_class == ActionClass::StateChange
            && (self
                .canary_ref
                .as_deref()
                .is_none_or(|value| !valid_identifier(value))
                || self
                    .checkpoint_ref
                    .as_deref()
                    .is_none_or(|value| !valid_identifier(value))
                || self
                    .cleanup_plan_ref
                    .as_deref()
                    .is_none_or(|value| !valid_identifier(value)))
        {
            return Err(DenialCode::StateChangeContractMissing);
        }
        if self
            .canary_ref
            .as_deref()
            .is_some_and(|value| !valid_identifier(value))
            || self
                .checkpoint_ref
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
            || self
                .cleanup_plan_ref
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
        {
            return Err(DenialCode::InvalidRequest);
        }
        Ok(())
    }
}

pub(super) fn valid_nonce(value: &[u8; 16]) -> bool {
    let mut seen = [false; 256];
    for byte in value {
        seen[usize::from(*byte)] = true;
    }
    seen.into_iter().filter(|present| *present).take(4).count() == 4
}

pub(crate) fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_ID_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_hostname(value: &str) -> bool {
    if let Ok(address) = value.parse::<IpAddr>() {
        return value == address.to_string().to_ascii_lowercase();
    }
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 253
        && value == value.to_ascii_lowercase()
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_protocol(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && value == value.to_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_method(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4_096
        && value.starts_with('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#' && byte != b'?')
}
