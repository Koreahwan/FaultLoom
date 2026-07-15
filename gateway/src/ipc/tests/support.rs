use crate::Digest;

use super::super::tags::REQUEST_MESSAGE;
use super::super::wire::Decoder;
use super::super::{
    ActionClass, ActionKind, DispatchRequest, EgressPlane, FlowKind, RequiredFeature,
};

pub(super) fn request() -> DispatchRequest {
    let mut request = DispatchRequest {
        action_id: "action:1".to_owned(),
        correlation_id: "correlation:1".to_owned(),
        grant_id: "grant:1".to_owned(),
        grant_version: 1,
        target_id: "target:loopback".to_owned(),
        pack_id: "web".to_owned(),
        action_family: "http.semantic".to_owned(),
        identity_id: "identity:operator".to_owned(),
        tenant_id: Some("tenant:owned".to_owned()),
        intent_digest: Digest::of(b"intent"),
        decision_digest: Digest::of(b"decision"),
        lease_id: "lease:1".to_owned(),
        scope_epoch: 3,
        action_kind: ActionKind::SemanticHttpV1,
        action_class: ActionClass::SafeProbe,
        egress_plane: EgressPlane::TargetGateway,
        flow_kind: FlowKind::TopLevel,
        parent_action_id: None,
        required_features: vec![RequiredFeature::GatewayDispatchV1],
        hostname: "localhost".to_owned(),
        protocol: "http".to_owned(),
        method: "GET".to_owned(),
        path: "/".to_owned(),
        target: "127.0.0.1:8080".parse().expect("socket address"),
        resolution_digest: Digest::ZERO,
        semantic_action_digest: Digest::ZERO,
        dispatch_nonce: *b"0123456789abcdef",
        request_issued_at_millis: 1_000,
        request_expires_at_millis: 6_000,
        retry_of_intent_digest: None,
        payload: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        scope_proof: b"scope-proof".to_vec(),
        lease_proof: b"lease-proof".to_vec(),
        compiler_proof: b"compiler-proof".to_vec(),
        canary_ref: None,
        checkpoint_ref: None,
        cleanup_plan_ref: None,
    };
    request.bind_canonical_semantics();
    request
}

pub(super) fn tags_offset(frame: &[u8]) -> usize {
    let mut decoder = Decoder::new(frame, REQUEST_MESSAGE).expect("valid header");
    decoder.string().expect("action ID");
    decoder.string().expect("correlation ID");
    decoder.string().expect("grant ID");
    decoder.u64().expect("grant version");
    decoder.string().expect("target ID");
    decoder.string().expect("pack ID");
    decoder.string().expect("action family");
    decoder.string().expect("identity ID");
    decoder.optional_string().expect("tenant ID");
    decoder.digest().expect("intent digest");
    decoder.digest().expect("decision digest");
    decoder.string().expect("lease ID");
    decoder.u64().expect("scope epoch");
    decoder.offset
}
