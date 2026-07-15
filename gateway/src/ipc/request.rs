use std::net::SocketAddr;

use crate::Digest;

use super::tags::{ActionClass, ActionKind, EgressPlane, FlowKind, RequiredFeature};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchRequest {
    pub action_id: String,
    pub correlation_id: String,
    pub grant_id: String,
    pub grant_version: u64,
    pub target_id: String,
    pub pack_id: String,
    pub action_family: String,
    pub identity_id: String,
    pub tenant_id: Option<String>,
    pub intent_digest: Digest,
    pub decision_digest: Digest,
    pub lease_id: String,
    pub scope_epoch: u64,
    pub action_kind: ActionKind,
    pub action_class: ActionClass,
    pub egress_plane: EgressPlane,
    pub flow_kind: FlowKind,
    pub parent_action_id: Option<String>,
    pub required_features: Vec<RequiredFeature>,
    pub hostname: String,
    pub protocol: String,
    pub method: String,
    pub path: String,
    pub target: SocketAddr,
    pub resolution_digest: Digest,
    pub semantic_action_digest: Digest,
    pub dispatch_nonce: [u8; 16],
    pub request_issued_at_millis: u64,
    pub request_expires_at_millis: u64,
    pub retry_of_intent_digest: Option<Digest>,
    pub payload: Vec<u8>,
    pub scope_proof: Vec<u8>,
    pub lease_proof: Vec<u8>,
    pub compiler_proof: Vec<u8>,
    pub canary_ref: Option<String>,
    pub checkpoint_ref: Option<String>,
    pub cleanup_plan_ref: Option<String>,
}
