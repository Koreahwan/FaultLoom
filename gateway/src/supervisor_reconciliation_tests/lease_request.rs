use crate::Digest;
use crate::ipc::{
    ActionClass, ActionKind, DispatchRequest, EgressPlane, FlowKind, RequiredFeature,
};
use crate::lease::{LeaseBudgetReservation, LeaseSpec};
use crate::policy::target_effect_digest;

use super::active_fixture::NOW;

pub(super) fn lease_spec(lease_id: &str, intent: &[u8]) -> LeaseSpec {
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&Digest::of(lease_id.as_bytes()).as_bytes()[..16]);
    let mut spec = LeaseSpec {
        lease_id: lease_id.to_owned(),
        intent_digest: Digest::of(intent),
        decision_digest: Digest::of(format!("decision:{lease_id}").as_bytes()),
        grant_id: "grant:1".to_owned(),
        grant_version: 3,
        scope_epoch: 7,
        authority_key_id: "authority-key:test".to_owned(),
        scope_epoch_binding_digest: Digest::of(b"scope epoch binding:test"),
        gateway_boot_id: "gateway:boot:test".to_owned(),
        control_envelope_id: Digest::of(format!("control-envelope:{lease_id}").as_bytes()),
        request_binding_digest: Digest::ZERO,
        semantic_action_digest: Digest::ZERO,
        resolution_digest: Digest::ZERO,
        compiled_request_digest: Digest::ZERO,
        effect_digest: Digest::ZERO,
        correlation_id: "correlation:1".to_owned(),
        egress_plane: EgressPlane::TargetGateway,
        dispatch_nonce: nonce,
        retry_of_intent_digest: None,
        issued_at_millis: NOW - 1,
        expires_at_millis: NOW + 5_000,
        reservation: LeaseBudgetReservation {
            action_count: 1,
            request_bytes: 4,
            response_bytes: 8,
            duration_seconds: 2,
        },
    };
    seal_spec(&mut spec);
    spec
}

pub(super) fn seal_spec(spec: &mut LeaseSpec) {
    let request = dispatch_request(spec, vec![1]);
    spec.request_binding_digest = request.lease_binding_digest();
    spec.semantic_action_digest = request.semantic_action_digest;
    spec.resolution_digest = request.resolution_digest;
    spec.compiled_request_digest = Digest::of(&request.payload);
    spec.effect_digest = target_effect_digest(
        request.action_kind,
        request.egress_plane,
        request.resolution_digest,
        spec.compiled_request_digest,
    );
}

pub(super) fn dispatch_request(spec: &LeaseSpec, lease_proof: Vec<u8>) -> DispatchRequest {
    let mut request = DispatchRequest {
        action_id: "action:1".to_owned(),
        correlation_id: spec.correlation_id.clone(),
        target_id: "target:loopback".to_owned(),
        grant_id: spec.grant_id.clone(),
        grant_version: spec.grant_version,
        pack_id: "web".to_owned(),
        action_family: "http.semantic".to_owned(),
        identity_id: "identity:operator".to_owned(),
        tenant_id: Some("tenant:owned".to_owned()),
        intent_digest: spec.intent_digest,
        decision_digest: spec.decision_digest,
        lease_id: spec.lease_id.clone(),
        scope_epoch: spec.scope_epoch,
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
        target: "127.0.0.1:8080".parse().expect("loopback address"),
        resolution_digest: Digest::ZERO,
        semantic_action_digest: Digest::ZERO,
        dispatch_nonce: spec.dispatch_nonce,
        request_issued_at_millis: spec.issued_at_millis,
        request_expires_at_millis: spec.expires_at_millis,
        retry_of_intent_digest: spec.retry_of_intent_digest,
        payload: b"PING".to_vec(),
        scope_proof: b"scope-proof".to_vec(),
        lease_proof,
        compiler_proof: b"compiler-proof".to_vec(),
        canary_ref: None,
        checkpoint_ref: None,
        cleanup_plan_ref: None,
    };
    request.bind_canonical_semantics();
    request
}
