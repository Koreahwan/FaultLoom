use std::collections::HashSet;

use faultloom_gateway::Digest;
use faultloom_gateway::ipc::DenialCode;
use faultloom_gateway::supervisor_journal::{
    JournalDenial, JournalOperation, JournalReply, JournalRequest, JournalResult,
};

use super::support::{KEY, request};

const OTHER_KEY: [u8; 32] = *b"fedcba9876543210fedcba9876543210";

#[test]
fn request_authentication_rejects_tamper_wrong_key_and_weak_key() {
    // Given
    let request = request(JournalOperation::Open {
        expected_anchor: None,
    });
    let mut tampered = request.to_bytes(&KEY).expect("encode request");
    let last = tampered.len() - 1;
    tampered[last] ^= 1;

    // When / Then
    assert_authentication_failed(JournalRequest::from_bytes(&tampered, &KEY));
    let encoded = request.to_bytes(&KEY).expect("encode request again");
    assert_authentication_failed(JournalRequest::from_bytes(&encoded, &OTHER_KEY));
    assert_authentication_failed(request.to_bytes(&[7; 32]));
}

#[test]
fn reply_authentication_rejects_tamper_and_wrong_key() {
    // Given
    let request = request(JournalOperation::Open {
        expected_anchor: None,
    });
    let reply = JournalReply::for_request(
        &request,
        JournalResult::Denied(JournalDenial::AnchorMismatch),
    )
    .expect("bind reply");
    let mut tampered = reply.to_bytes(&KEY).expect("encode reply");
    tampered[0] ^= 1;

    // When / Then
    assert_authentication_failed(JournalReply::from_bytes(&tampered, &KEY));
    let encoded = reply.to_bytes(&KEY).expect("encode reply again");
    assert_authentication_failed(JournalReply::from_bytes(&encoded, &OTHER_KEY));
}

#[test]
fn authenticated_v2_journal_frame_is_rejected_as_stale() {
    // Given: an otherwise authentic request carrying the superseded v2 wire version.
    let request = request(JournalOperation::Open {
        expected_anchor: None,
    });
    let encoded = request.to_bytes(&KEY).expect("encode current request");
    let stale = resign_request_version(encoded, 2, &KEY);

    // When: the authenticated stale frame crosses the codec boundary.
    let decoded = JournalRequest::from_bytes(&stale, &KEY);

    // Then: version rejection is explicit rather than accepted as current state.
    assert_eq!(decoded, Err(DenialCode::MalformedFrame));
}

#[test]
fn request_id_binds_session_sequence_nonce_binding_and_operation() {
    // Given
    let original = request(JournalOperation::Open {
        expected_anchor: None,
    });
    let mut variants = Vec::new();
    for mutation in 0..5 {
        let mut variant = original.clone();
        match mutation {
            0 => variant.session_id = "journal-session:other".to_owned(),
            1 => variant.sequence += 1,
            2 => variant.nonce[0] ^= 1,
            3 => variant.stable_binding = Digest::of(b"other stable binding"),
            4 => {
                variant.operation = JournalOperation::Open {
                    expected_anchor: Some(Digest::of(b"other anchor")),
                }
            }
            _ => unreachable!("bounded mutation set"),
        }
        variants.push(variant);
    }

    // When
    let ids = std::iter::once(original)
        .chain(variants)
        .map(|value| value.request_id().expect("request id"))
        .collect::<HashSet<_>>();

    // Then
    assert_eq!(ids.len(), 6);
}

fn assert_authentication_failed<T>(result: Result<T, DenialCode>) {
    assert!(matches!(result, Err(DenialCode::IpcAuthenticationFailed)));
}

fn resign_request_version(mut encoded: Vec<u8>, version: u8, key: &[u8; 32]) -> Vec<u8> {
    let unsigned_length = encoded.len() - 32;
    encoded[4] = version;
    let tag = journal_hmac(
        key,
        b"faultloom-journal-request-mac-v1\0",
        &encoded[..unsigned_length],
    );
    encoded[unsigned_length..].copy_from_slice(tag.as_bytes());
    encoded
}

fn journal_hmac(key: &[u8; 32], domain: &[u8], message: &[u8]) -> Digest {
    let mut inner_pad = [0x36_u8; 64];
    let mut outer_pad = [0x5c_u8; 64];
    for index in 0..32 {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    let mut inner = Vec::with_capacity(64 + domain.len() + message.len());
    inner.extend_from_slice(&inner_pad);
    inner.extend_from_slice(domain);
    inner.extend_from_slice(message);
    let mut outer = Vec::with_capacity(96);
    outer.extend_from_slice(&outer_pad);
    outer.extend_from_slice(Digest::of(&inner).as_bytes());
    Digest::of(&outer)
}
