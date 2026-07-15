use std::net::{Ipv4Addr, SocketAddr};

use crate::Digest;
use crate::authority::{RequestedSelection, RequestedSelectionParts};
use crate::ipc::DenialCode;

use super::{
    BootAuthorization, MAX_SIGNED_AUTHORITY_GRANT_BYTES, SupervisorSecretsV4,
    UnverifiedSupervisorBootstrapV4,
};

fn secret(seed: u8) -> [u8; 32] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

fn nonce(seed: u8) -> [u8; 16] {
    std::array::from_fn(|index| seed.wrapping_add(u8::try_from(index).unwrap_or(0)))
}

fn bootstrap() -> UnverifiedSupervisorBootstrapV4 {
    let selection = RequestedSelection::from_untrusted_parts(RequestedSelectionParts {
        target_id: "loopback-lab".into(),
        hostname: "localhost".into(),
        socket: SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
        protocol: "http".into(),
        pack_id: "web".into(),
        action_family: "semantic-http".into(),
        identity_id: "operator-owned".into(),
        tenant_id: Some("tenant-a".into()),
    })
    .unwrap();
    UnverifiedSupervisorBootstrapV4 {
        signed_authority_grant: br#"{"purpose":"authority-grant"}"#.to_vec(),
        selection,
        secrets: SupervisorSecretsV4 {
            channel_key_id: "channel-key".into(),
            channel_key: secret(1),
            channel_boot_id: "channel-boot".into(),
            channel_nonce: nonce(0x21),
            channel_issued_at_millis: 1_000,
            channel_expires_at_millis: 31_000,
            epoch_channel_key_id: "epoch-key".into(),
            epoch_channel_key: secret(33),
            gateway_boot_id: "gateway-boot".into(),
            gateway_challenge: secret(65),
            lease_key_id: "lease-key".into(),
            lease_key: secret(97),
            compiler_key_id: "compiler-key".into(),
            compiler_key: secret(129),
            journal_key_id: "journal-key".into(),
            journal_key: secret(161),
            reconciliation_key_id: "reconciliation-key".into(),
            reconciliation_verification_key: secret(193),
        },
        expected_journal_anchor: Digest::of(b"journal-anchor"),
        boot_authorization: BootAuthorization {
            controller_key_id: format!("ed25519:sha256:{}", "11".repeat(32)),
            issued_at_millis: 2_000,
            expires_at_millis: 32_000,
            boot_sequence: 7,
            nonce: nonce(0x52),
            signature: [0x73; 64],
        },
    }
}

#[test]
fn v4_round_trip_preserves_only_selection_and_boot_authorization() {
    // Given: an FLBS v4 bootstrap with a bounded signed grant and selection.
    let expected = bootstrap();

    // When: it crosses the FD3 binary boundary.
    let encoded = expected.to_bytes().unwrap();
    let actual = UnverifiedSupervisorBootstrapV4::from_bytes(&encoded).unwrap();

    // Then: the typed, selection-only value round-trips canonically.
    assert!(actual == expected);
    assert_eq!(actual.to_bytes().unwrap(), encoded);
}

#[test]
fn v4_decoder_rejects_v3_and_trailing_authority_widening_fields() {
    // Given: canonical v4 bytes and names of every v3 authority-widening field.
    let encoded = bootstrap().to_bytes().unwrap();
    let former_fields = [
        "grant-id",
        "grant-version",
        "authority-key-id",
        "method",
        "path-pattern",
        "action-class",
        "budget",
        "execution-window",
    ];

    // When/Then: v3 is rejected, and no former field can be appended to v4.
    let mut v3 = encoded.clone();
    v3[4] = 3;
    assert_eq!(
        UnverifiedSupervisorBootstrapV4::from_bytes(&v3).err(),
        Some(DenialCode::MalformedFrame)
    );
    for former_field in former_fields {
        let mut widened = encoded.clone();
        widened.extend_from_slice(former_field.as_bytes());
        assert_eq!(
            UnverifiedSupervisorBootstrapV4::from_bytes(&widened).err(),
            Some(DenialCode::MalformedFrame),
            "accepted former authority field {former_field}"
        );
    }
}

#[test]
fn signed_grant_length_is_bounded_on_both_codec_directions() {
    // Given: a signed grant exactly at the v4 boundary.
    let mut boundary = bootstrap();
    boundary.signed_authority_grant = vec![b'x'; MAX_SIGNED_AUTHORITY_GRANT_BYTES];

    // When: the maximum admitted grant crosses the FD3 boundary.
    let boundary_encoded = boundary.to_bytes().unwrap();
    let boundary_decoded = UnverifiedSupervisorBootstrapV4::from_bytes(&boundary_encoded).unwrap();

    // Then: the exact boundary is preserved without widening it.
    assert_eq!(
        boundary_decoded.signed_authority_grant.len(),
        MAX_SIGNED_AUTHORITY_GRANT_BYTES
    );

    // Given: a bootstrap whose signed grant exceeds the v4 boundary.
    let mut oversized = bootstrap();
    oversized.signed_authority_grant = vec![b'x'; MAX_SIGNED_AUTHORITY_GRANT_BYTES + 1];

    // When/Then: encoding rejects it before FD3 can carry it.
    assert_eq!(oversized.to_bytes().err(), Some(DenialCode::InvalidRequest));

    // Given: a canonical frame whose grant length prefix claims the same size.
    let mut encoded = bootstrap().to_bytes().unwrap();
    encoded[6..10].copy_from_slice(
        &u32::try_from(MAX_SIGNED_AUTHORITY_GRANT_BYTES + 1)
            .unwrap()
            .to_be_bytes(),
    );

    // When/Then: decoding rejects before allocating the claimed grant.
    assert_eq!(
        UnverifiedSupervisorBootstrapV4::from_bytes(&encoded).err(),
        Some(DenialCode::MalformedFrame)
    );
}

#[test]
fn fresh_journal_zero_anchor_round_trips_without_becoming_an_override() {
    // Given: a first-start bootstrap with the canonical empty-journal sentinel.
    let mut expected = bootstrap();
    expected.expected_journal_anchor = Digest::ZERO;

    // When: it crosses the v4 FD3 boundary.
    let encoded = expected.to_bytes().unwrap();
    let actual = UnverifiedSupervisorBootstrapV4::from_bytes(&encoded).unwrap();

    // Then: ZERO remains explicit and unchanged for later signed binding.
    assert_eq!(actual.expected_journal_anchor, Digest::ZERO);
    assert!(actual == expected);
}

#[test]
fn decoder_rejects_signature_moved_before_controller_binding_fields() {
    // Given: canonical v4 bytes with the detached signature as the final field.
    let expected = bootstrap();
    let encoded = expected.to_bytes().unwrap();
    let controller = expected.boot_authorization.controller_key_id.as_bytes();
    let controller_offset = encoded
        .windows(controller.len())
        .position(|window| window == controller)
        .unwrap()
        - 4;
    let signature_offset = encoded.len() - 68;

    // When: the same field bytes are reordered to put signature before controller metadata.
    let mut reordered = Vec::with_capacity(encoded.len());
    reordered.extend_from_slice(&encoded[..controller_offset]);
    reordered.extend_from_slice(&encoded[signature_offset..]);
    reordered.extend_from_slice(&encoded[controller_offset..signature_offset]);

    // Then: the v4 decoder enforces the exact controller/time/nonce/signature wire order.
    assert_eq!(
        UnverifiedSupervisorBootstrapV4::from_bytes(&reordered).err(),
        Some(DenialCode::MalformedFrame)
    );
}
