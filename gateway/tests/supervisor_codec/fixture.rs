use faultloom_gateway::ipc::{ActionKind, DispatchOutcome, DispatchReceipt, EgressPlane};
use faultloom_gateway::lease::ReconciliationAuthority;

use super::codec::{nonce, now_millis};

pub(super) fn reconciliation_authority() -> ReconciliationAuthority {
    ReconciliationAuthority::new(
        "reconciliation-key:codec".to_owned(),
        std::array::from_fn(|index| 0x90_u8.wrapping_add(index as u8)),
    )
    .expect("valid reconciliation authority")
}

pub(super) fn unknown_receipt(label: &str, nonce_seed: u8) -> DispatchReceipt {
    let request_digest = faultloom_gateway::Digest::of(format!("request:{label}").as_bytes());
    let resolution_digest = faultloom_gateway::Digest::of(format!("resolution:{label}").as_bytes());
    let effect_digest = target_effect_digest(resolution_digest, request_digest);
    let now = now_millis();
    let mut receipt = DispatchReceipt {
        receipt_id: faultloom_gateway::Digest::ZERO,
        receipt_authentication_tag: faultloom_gateway::Digest::of(b"receipt authentication"),
        action_id: format!("action:{label}"),
        correlation_id: format!("correlation:{label}"),
        lease_id: format!("lease:{label}"),
        grant_id: "grant:codec".to_owned(),
        grant_version: 1,
        authority_key_id: "authority-key:codec".to_owned(),
        scope_epoch_binding_digest: faultloom_gateway::Digest::of(b"scope epoch binding"),
        lease_key_id: "lease-key:codec".to_owned(),
        gateway_boot_id: "gateway-boot:codec".to_owned(),
        boot_challenge_digest: faultloom_gateway::Digest::of(b"gateway challenge"),
        intent_digest: faultloom_gateway::Digest::of(format!("intent:{label}").as_bytes()),
        decision_digest: faultloom_gateway::Digest::of(format!("decision:{label}").as_bytes()),
        scope_epoch: 1,
        semantic_action_digest: faultloom_gateway::Digest::of(
            format!("semantic action:{label}").as_bytes(),
        ),
        request_binding_digest: faultloom_gateway::Digest::of(
            format!("request binding:{label}").as_bytes(),
        ),
        request_frame_digest: faultloom_gateway::Digest::of(
            format!("request frame:{label}").as_bytes(),
        ),
        control_envelope_id: faultloom_gateway::Digest::of(
            format!("control envelope:{label}").as_bytes(),
        ),
        hold_binding_digest: faultloom_gateway::Digest::of(
            format!("hold binding:{label}").as_bytes(),
        ),
        resolution_digest,
        action_kind: ActionKind::SemanticHttpV1,
        egress_plane: EgressPlane::TargetGateway,
        effect_digest,
        dispatch_nonce: nonce(nonce_seed),
        lease_issued_at_millis: now.saturating_sub(1_000),
        lease_expires_at_millis: now + 10_000,
        retry_of_intent_digest: None,
        reserved_action_count: 1,
        reserved_request_bytes: 16,
        reserved_response_bytes: 32,
        reserved_duration_seconds: 2,
        request_digest,
        response_digest: None,
        outcome: DispatchOutcome::UnknownOutcome,
        dispatched_at_millis: now,
        completed_at_millis: now + 1,
        bytes_sent: 16,
        bytes_received: 0,
        reconciliation_required: true,
    };
    receipt.receipt_id = canonical_receipt_id(&receipt);
    receipt
}

fn target_effect_digest(
    resolution_digest: faultloom_gateway::Digest,
    request_digest: faultloom_gateway::Digest,
) -> faultloom_gateway::Digest {
    let mut binding = Vec::with_capacity(93);
    binding.extend_from_slice(b"faultloom-target-effect-v1\0");
    binding.push(ActionKind::SemanticHttpV1 as u8);
    binding.push(EgressPlane::TargetGateway as u8);
    binding.extend_from_slice(resolution_digest.as_bytes());
    binding.extend_from_slice(request_digest.as_bytes());
    faultloom_gateway::Digest::of(&binding)
}

fn canonical_receipt_id(receipt: &DispatchReceipt) -> faultloom_gateway::Digest {
    let mut canonical = Vec::with_capacity(512);
    canonical.extend_from_slice(b"faultloom-gateway-receipt-v2\0");
    push_string(&mut canonical, &receipt.action_id);
    push_string(&mut canonical, &receipt.correlation_id);
    push_string(&mut canonical, &receipt.lease_id);
    push_string(&mut canonical, &receipt.grant_id);
    canonical.extend_from_slice(&receipt.grant_version.to_be_bytes());
    push_string(&mut canonical, &receipt.authority_key_id);
    canonical.extend_from_slice(receipt.scope_epoch_binding_digest.as_bytes());
    push_string(&mut canonical, &receipt.lease_key_id);
    push_string(&mut canonical, &receipt.gateway_boot_id);
    canonical.extend_from_slice(receipt.boot_challenge_digest.as_bytes());
    canonical.extend_from_slice(receipt.intent_digest.as_bytes());
    canonical.extend_from_slice(receipt.decision_digest.as_bytes());
    canonical.extend_from_slice(&receipt.scope_epoch.to_be_bytes());
    canonical.extend_from_slice(receipt.semantic_action_digest.as_bytes());
    canonical.extend_from_slice(receipt.request_binding_digest.as_bytes());
    canonical.extend_from_slice(receipt.request_frame_digest.as_bytes());
    canonical.extend_from_slice(receipt.control_envelope_id.as_bytes());
    canonical.extend_from_slice(receipt.hold_binding_digest.as_bytes());
    canonical.extend_from_slice(receipt.resolution_digest.as_bytes());
    canonical.push(receipt.action_kind as u8);
    canonical.push(receipt.egress_plane as u8);
    canonical.extend_from_slice(receipt.effect_digest.as_bytes());
    canonical.extend_from_slice(&receipt.dispatch_nonce);
    canonical.extend_from_slice(&receipt.lease_issued_at_millis.to_be_bytes());
    canonical.extend_from_slice(&receipt.lease_expires_at_millis.to_be_bytes());
    push_optional_digest(&mut canonical, receipt.retry_of_intent_digest);
    canonical.extend_from_slice(&receipt.reserved_action_count.to_be_bytes());
    canonical.extend_from_slice(&receipt.reserved_request_bytes.to_be_bytes());
    canonical.extend_from_slice(&receipt.reserved_response_bytes.to_be_bytes());
    canonical.extend_from_slice(&receipt.reserved_duration_seconds.to_be_bytes());
    canonical.extend_from_slice(receipt.request_digest.as_bytes());
    push_optional_digest(&mut canonical, receipt.response_digest);
    canonical.push(receipt.outcome as u8);
    canonical.extend_from_slice(&receipt.dispatched_at_millis.to_be_bytes());
    canonical.extend_from_slice(&receipt.completed_at_millis.to_be_bytes());
    canonical.extend_from_slice(&receipt.bytes_sent.to_be_bytes());
    canonical.extend_from_slice(&receipt.bytes_received.to_be_bytes());
    canonical.push(u8::from(receipt.reconciliation_required));
    faultloom_gateway::Digest::of(&canonical)
}

fn push_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value.as_bytes());
}

fn push_optional_digest(output: &mut Vec<u8>, value: Option<faultloom_gateway::Digest>) {
    match value {
        Some(digest) => {
            output.push(1);
            output.extend_from_slice(digest.as_bytes());
        }
        None => output.push(0),
    }
}
