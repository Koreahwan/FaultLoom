use crate::Digest;

use super::binding::push_binding_string;
use super::receipt::DispatchReceipt;
use super::tags::DenialCode;
use super::validation::valid_identifier;
use crate::semantic_http::SemanticHttpResponseArtifact;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeniedResponse {
    pub denial_id: Digest,
    pub action_id: String,
    pub request_digest: Digest,
    pub reason: DenialCode,
}

impl DeniedResponse {
    pub fn bound(action_id: String, request_digest: Digest, reason: DenialCode) -> Self {
        let mut denied = Self {
            denial_id: Digest::ZERO,
            action_id,
            request_digest,
            reason,
        };
        denied.denial_id = denied.canonical_id();
        denied
    }

    pub fn canonical_id(&self) -> Digest {
        let mut canonical = Vec::with_capacity(128);
        canonical.extend_from_slice(b"faultloom-gateway-denial-v1\0");
        push_binding_string(&mut canonical, &self.action_id);
        canonical.extend_from_slice(self.request_digest.as_bytes());
        canonical.push(self.reason as u8);
        Digest::of(&canonical)
    }

    pub(super) fn validate(&self) -> bool {
        valid_identifier(&self.action_id)
            && self.request_digest != Digest::ZERO
            && self.denial_id == self.canonical_id()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)] // The public typed frame stays allocation-shape stable.
pub enum GatewayResponse {
    Denied(DeniedResponse),
    Receipt {
        action_id: String,
        receipt: DispatchReceipt,
        semantic_http: Option<SemanticHttpResponseArtifact>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodeError {
    pub action_id: Option<String>,
    pub reason: DenialCode,
}
