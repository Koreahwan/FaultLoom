use crate::Digest;
use crate::ipc::DispatchRequest;
use crate::lease::{GrantBudget, LeaseAuthority, LeaseBudgetReservation, LeaseSpec};

pub(super) fn lease_authority() -> LeaseAuthority {
    let authority = LeaseAuthority::new(
        "lease-key:fixture".to_owned(),
        std::array::from_fn(|index| u8::try_from(index + 17).expect("small fixture key byte")),
        "gateway:boot:fixture".to_owned(),
        Digest::of(b"fixture-gateway-challenge"),
    )
    .expect("lease authority");
    authority
        .register_grant(
            "grant:fixture",
            1,
            GrantBudget {
                total_actions: 10,
                rate_per_minute: 10,
                max_concurrency: 2,
                max_request_bytes: 64,
                max_response_bytes: 64,
                max_duration_seconds: 5,
            },
        )
        .expect("register grant");
    authority
}

pub(super) fn issue_request(authority: &LeaseAuthority, request: &mut DispatchRequest) {
    let spec = lease_spec(request);
    let issued = authority.issue(spec).expect("issue request lease");
    request.lease_proof = issued.proof;
}

pub(super) fn lease_spec(request: &DispatchRequest) -> LeaseSpec {
    LeaseSpec {
        lease_id: request.lease_id.clone(),
        intent_digest: request.intent_digest,
        decision_digest: request.decision_digest,
        grant_id: request.grant_id.clone(),
        grant_version: request.grant_version,
        scope_epoch: request.scope_epoch,
        authority_key_id: format!("ed25519:sha256:{}", "11".repeat(32)),
        scope_epoch_binding_digest: Digest::of(b"fixture-scope-epoch-binding"),
        gateway_boot_id: "gateway:boot:fixture".to_owned(),
        control_envelope_id: Digest::of(b"fixture authenticated control envelope"),
        request_binding_digest: request.lease_binding_digest(),
        semantic_action_digest: request.semantic_action_digest,
        resolution_digest: request.resolution_digest,
        compiled_request_digest: Digest::of(&request.payload),
        effect_digest: crate::policy::target_effect_digest(
            request.action_kind,
            request.egress_plane,
            request.resolution_digest,
            Digest::of(&request.payload),
        ),
        correlation_id: request.correlation_id.clone(),
        egress_plane: request.egress_plane,
        dispatch_nonce: request.dispatch_nonce,
        retry_of_intent_digest: request.retry_of_intent_digest,
        issued_at_millis: request.request_issued_at_millis,
        expires_at_millis: request.request_expires_at_millis,
        reservation: LeaseBudgetReservation {
            action_count: 1,
            request_bytes: request.payload.len() as u64,
            response_bytes: 8,
            duration_seconds: 2,
        },
    }
}
