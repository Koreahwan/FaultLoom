use std::net::{IpAddr, SocketAddr};

use crate::Digest;

use super::request::DispatchRequest;

impl DispatchRequest {
    /// Recompute the two caller-visible semantic digests after constructing a
    /// typed request. Encoding still validates them, so later mutation fails
    /// closed instead of silently re-sealing changed fields.
    pub fn bind_canonical_semantics(&mut self) {
        self.resolution_digest = self.canonical_resolution_digest();
        self.semantic_action_digest = self.canonical_semantic_action_digest();
    }

    pub fn canonical_resolution_digest(&self) -> Digest {
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(b"faultloom-resolution-v1\0");
        push_binding_string(&mut bytes, &self.hostname);
        bytes.push(self.egress_plane as u8);
        push_socket(&mut bytes, self.target);
        Digest::of(&bytes)
    }

    pub fn canonical_semantic_action_digest(&self) -> Digest {
        let mut bytes = Vec::with_capacity(768 + self.payload.len());
        bytes.extend_from_slice(b"faultloom-semantic-action-v1\0");
        push_binding_string(&mut bytes, &self.action_id);
        push_binding_string(&mut bytes, &self.target_id);
        push_binding_string(&mut bytes, &self.pack_id);
        push_binding_string(&mut bytes, &self.action_family);
        push_binding_string(&mut bytes, &self.identity_id);
        push_binding_optional_string(&mut bytes, self.tenant_id.as_deref());
        bytes.push(self.action_kind as u8);
        bytes.push(self.action_class as u8);
        bytes.push(self.egress_plane as u8);
        bytes.push(self.flow_kind as u8);
        push_binding_optional_string(&mut bytes, self.parent_action_id.as_deref());
        push_binding_string(&mut bytes, &self.hostname);
        push_binding_string(&mut bytes, &self.protocol);
        push_binding_string(&mut bytes, &self.method);
        push_binding_string(&mut bytes, &self.path);
        push_socket(&mut bytes, self.target);
        bytes.extend_from_slice(self.resolution_digest.as_bytes());
        bytes.extend_from_slice(Digest::of(&self.payload).as_bytes());
        push_binding_optional_string(&mut bytes, self.canary_ref.as_deref());
        push_binding_optional_string(&mut bytes, self.checkpoint_ref.as_deref());
        push_binding_optional_string(&mut bytes, self.cleanup_plan_ref.as_deref());
        Digest::of(&bytes)
    }

    pub fn lease_binding_digest(&self) -> Digest {
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(b"faultloom-lease-request-binding-v1\0");
        push_binding_string(&mut bytes, &self.correlation_id);
        bytes.extend_from_slice(self.intent_digest.as_bytes());
        bytes.extend_from_slice(self.decision_digest.as_bytes());
        bytes.extend_from_slice(self.semantic_action_digest.as_bytes());
        bytes.extend_from_slice(self.resolution_digest.as_bytes());
        bytes.push(self.egress_plane as u8);
        bytes.extend_from_slice(&self.dispatch_nonce);
        bytes.extend_from_slice(&self.request_issued_at_millis.to_be_bytes());
        bytes.extend_from_slice(&self.request_expires_at_millis.to_be_bytes());
        push_binding_optional_digest(&mut bytes, self.retry_of_intent_digest);
        bytes.extend_from_slice(self.scope_binding_digest().as_bytes());
        Digest::of(&bytes)
    }

    pub fn scope_binding_digest(&self) -> Digest {
        fn push_string(bytes: &mut Vec<u8>, value: &str) {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }

        fn push_optional(bytes: &mut Vec<u8>, value: Option<&str>) {
            match value {
                Some(value) => {
                    bytes.push(1);
                    push_string(bytes, value);
                }
                None => bytes.push(0),
            }
        }

        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(b"faultloom-scope-binding-v1\0");
        push_string(&mut bytes, &self.action_id);
        push_string(&mut bytes, &self.grant_id);
        bytes.extend_from_slice(&self.grant_version.to_be_bytes());
        push_string(&mut bytes, &self.target_id);
        push_string(&mut bytes, &self.pack_id);
        push_string(&mut bytes, &self.action_family);
        push_string(&mut bytes, &self.identity_id);
        push_optional(&mut bytes, self.tenant_id.as_deref());
        bytes.extend_from_slice(&self.scope_epoch.to_be_bytes());
        bytes.push(self.action_kind as u8);
        bytes.push(self.action_class as u8);
        bytes.push(self.egress_plane as u8);
        bytes.push(self.flow_kind as u8);
        push_optional(&mut bytes, self.parent_action_id.as_deref());
        push_string(&mut bytes, &self.hostname);
        push_string(&mut bytes, &self.protocol);
        push_string(&mut bytes, &self.method);
        push_string(&mut bytes, &self.path);
        push_socket(&mut bytes, self.target);
        bytes.extend_from_slice(self.resolution_digest.as_bytes());
        push_optional(&mut bytes, self.canary_ref.as_deref());
        push_optional(&mut bytes, self.checkpoint_ref.as_deref());
        push_optional(&mut bytes, self.cleanup_plan_ref.as_deref());
        Digest::of(&bytes)
    }
}

pub(super) fn push_binding_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn push_binding_optional_string(bytes: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            bytes.push(1);
            push_binding_string(bytes, value);
        }
        None => bytes.push(0),
    }
}

pub(super) fn push_binding_optional_digest(bytes: &mut Vec<u8>, value: Option<Digest>) {
    match value {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(value.as_bytes());
        }
        None => bytes.push(0),
    }
}

fn push_socket(bytes: &mut Vec<u8>, target: SocketAddr) {
    match target.ip() {
        IpAddr::V4(address) => {
            bytes.push(4);
            bytes.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            bytes.push(6);
            bytes.extend_from_slice(&address.octets());
        }
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
}
