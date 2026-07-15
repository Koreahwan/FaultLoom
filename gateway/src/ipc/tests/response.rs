use crate::Digest;

use super::super::tags::RESPONSE_MESSAGE;
use super::super::wire::Decoder;
use super::super::{
    DenialCode, DeniedResponse, DispatchOutcome, DispatchReceipt, GatewayResponse, decode_response,
    encode_request, encode_response,
};
use super::support::request;

#[test]
fn dispatch_receipt_response_round_trip_is_canonical() {
    let request = request();
    let request_frame = encode_request(&request).expect("request frame");
    let mut receipt = DispatchReceipt {
        receipt_id: Digest::ZERO,
        receipt_authentication_tag: Digest::of(b"fixture receipt authentication tag"),
        action_id: request.action_id.clone(),
        correlation_id: request.correlation_id.clone(),
        lease_id: "lease:1".to_owned(),
        grant_id: request.grant_id.clone(),
        grant_version: request.grant_version,
        authority_key_id: format!("ed25519:sha256:{}", "11".repeat(32)),
        scope_epoch_binding_digest: Digest::of(b"scope epoch binding"),
        lease_key_id: "lease-key:1".to_owned(),
        gateway_boot_id: "gateway:boot:1".to_owned(),
        boot_challenge_digest: Digest::of(b"gateway challenge"),
        intent_digest: Digest::of(b"intent"),
        decision_digest: Digest::of(b"decision"),
        scope_epoch: 3,
        semantic_action_digest: request.semantic_action_digest,
        request_binding_digest: request.lease_binding_digest(),
        request_frame_digest: Digest::of(&request_frame),
        control_envelope_id: Digest::of(b"authenticated control envelope"),
        hold_binding_digest: Digest::of(b"exact reconciliation hold binding"),
        resolution_digest: request.resolution_digest,
        action_kind: request.action_kind,
        egress_plane: request.egress_plane,
        effect_digest: crate::policy::target_effect_digest(
            request.action_kind,
            request.egress_plane,
            request.resolution_digest,
            Digest::of(b"request"),
        ),
        dispatch_nonce: request.dispatch_nonce,
        lease_issued_at_millis: request.request_issued_at_millis,
        lease_expires_at_millis: request.request_expires_at_millis,
        retry_of_intent_digest: None,
        reserved_action_count: 1,
        reserved_request_bytes: 7,
        reserved_response_bytes: 8,
        reserved_duration_seconds: 1,
        request_digest: Digest::of(b"request"),
        response_digest: Some(Digest::of(b"response")),
        outcome: DispatchOutcome::Completed,
        dispatched_at_millis: 1_000,
        completed_at_millis: 1_001,
        bytes_sent: 7,
        bytes_received: 8,
        reconciliation_required: false,
    };
    receipt.receipt_id = receipt.canonical_id();
    let response = GatewayResponse::Receipt {
        action_id: "action:1".to_owned(),
        receipt,
        semantic_http: None,
    };
    let encoded = encode_response(&response).expect("encode response");
    assert_eq!(decode_response(&encoded), Ok(response.clone()));

    let mut tampered = encoded;
    let mut decoder = Decoder::new(&tampered, RESPONSE_MESSAGE).expect("response header");
    assert_eq!(decoder.byte().expect("response tag"), 2);
    decoder.string().expect("action ID");
    let receipt_id_offset = decoder.offset;
    tampered[receipt_id_offset] ^= 1;
    assert_eq!(
        decode_response(&tampered)
            .expect_err("tampered receipt ID")
            .reason,
        DenialCode::MalformedFrame
    );

    let GatewayResponse::Receipt {
        action_id,
        mut receipt,
        ..
    } = response
    else {
        unreachable!("fixture response is a receipt")
    };
    receipt.request_binding_digest = Digest::of(b"substituted request binding");
    assert_eq!(
        encode_response(&GatewayResponse::Receipt {
            action_id,
            receipt,
            semantic_http: None,
        }),
        Err(DenialCode::InvalidRequest)
    );
}

#[test]
fn lease_denial_codes_round_trip_without_aliasing() {
    let reasons = [
        DenialCode::LeaseBindingMismatch,
        DenialCode::LeaseNotYetValid,
        DenialCode::LeaseExpired,
        DenialCode::LeaseReplay,
        DenialCode::GrantBudgetExhausted,
        DenialCode::LeaseRateExceeded,
        DenialCode::LeaseConcurrencyExceeded,
        DenialCode::LeaseReservationExceeded,
        DenialCode::LeaseReconciliationRequired,
        DenialCode::LeaseAccountingUnavailable,
    ];
    for reason in reasons {
        let response = GatewayResponse::Denied(DeniedResponse::bound(
            "action:lease-denial".to_owned(),
            Digest::of(b"request"),
            reason,
        ));
        let encoded = encode_response(&response).expect("encode lease denial");
        assert_eq!(decode_response(&encoded), Ok(response));
    }

    let mut forged = DeniedResponse::bound(
        "action:forged-denial".to_owned(),
        Digest::of(b"request"),
        DenialCode::LeaseDenied,
    );
    forged.reason = DenialCode::ScopeDenied;
    assert_eq!(
        encode_response(&GatewayResponse::Denied(forged)),
        Err(DenialCode::InvalidRequest)
    );
}
