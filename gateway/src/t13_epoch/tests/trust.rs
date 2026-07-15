use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::Digest;
use crate::installed_trust::installed_trust_store_from_canonical_bytes_for_test;
use crate::t13_epoch::{
    ExpectedScopeEpochGrant, GatewayBootBinding, ReceiptAuthenticationChannel,
    T13EpochVerifierConfig, T13ReceiptEpochVerifier,
};

pub(super) const NOW_MILLIS: u64 = 1_893_553_445_679;
pub(super) const CHANNEL_KEY_ID: &str = "gateway-channel:test";
pub(super) const GATEWAY_BOOT_ID: &str = "gateway-boot:test-1";
pub(super) const CHANNEL_KEY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
pub(super) const GATEWAY_CHALLENGE: [u8; 32] = [
    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146,
    147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
];

pub(super) enum TrustCase {
    Active,
    Revoked,
    ActiveUnpinned,
    AuthorityUnknown,
}

pub(super) struct ExpectedFixture {
    pub(super) grant_id: &'static str,
    pub(super) grant_version: u64,
}

impl ExpectedFixture {
    pub(super) const fn standard() -> Self {
        Self {
            grant_id: "grant.test",
            grant_version: 3,
        }
    }

    pub(super) const fn golden() -> Self {
        Self {
            grant_id: "grant.golden",
            grant_version: 1,
        }
    }
}

pub(super) fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&CHANNEL_KEY)
}

pub(super) fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}

pub(super) fn key_id(key: &SigningKey) -> String {
    format!(
        "ed25519:sha256:{}",
        Digest::of(key.verifying_key().as_bytes()).to_hex()
    )
}

pub(super) fn verifier(
    trust_case: TrustCase,
    expected: ExpectedFixture,
) -> T13ReceiptEpochVerifier {
    let authority = authority_key();
    let other = other_key();
    let (authority_keys, pinned) = match trust_case {
        TrustCase::Active => (vec![root(&authority, "active")], key_id(&authority)),
        TrustCase::Revoked => (vec![root(&authority, "revoked")], key_id(&authority)),
        TrustCase::ActiveUnpinned => (
            vec![root(&authority, "active"), root(&other, "active")],
            key_id(&other),
        ),
        TrustCase::AuthorityUnknown => (vec![root(&other, "active")], key_id(&other)),
    };
    let controller = SigningKey::from_bytes(&[0x75; 32]);
    let raw = serde_json::to_vec(&json!({
        "authority_keys": authority_keys,
        "controller_keys": [root(&controller, "active")],
        "generation": 1,
        "grant_pins": [{
            "authority_key_ids": [pinned],
            "controller_key_ids": [key_id(&controller)],
            "grant_id": expected.grant_id,
            "minimum_version": expected.grant_version
        }],
        "schema_version": 1
    }))
    .expect("canonical test trust store");
    let trust = installed_trust_store_from_canonical_bytes_for_test(&raw)
        .expect("installed test trust store");
    let boot = GatewayBootBinding::new(GATEWAY_BOOT_ID.to_owned(), GATEWAY_CHALLENGE)
        .expect("test boot binding");
    let channel = ReceiptAuthenticationChannel::new(CHANNEL_KEY_ID.to_owned(), CHANNEL_KEY, boot)
        .expect("test receipt channel");
    let expected_grant =
        ExpectedScopeEpochGrant::new(expected.grant_id.to_owned(), expected.grant_version)
            .expect("test expected grant");
    T13ReceiptEpochVerifier::new(T13EpochVerifierConfig::new(
        channel,
        Arc::new(trust),
        expected_grant,
    ))
}

fn root(key: &SigningKey, status: &str) -> Value {
    json!({
        "key_id": key_id(key),
        "public_key_base64url": public_key_base64url(key.verifying_key().as_bytes()),
        "status": status
    })
}

fn public_key_base64url(raw: &[u8; 32]) -> String {
    let mut encoded = [0_u8; 43];
    let length = URL_SAFE_NO_PAD
        .encode_slice(raw, &mut encoded)
        .expect("public key base64url");
    std::str::from_utf8(&encoded[..length])
        .expect("base64url UTF-8")
        .to_owned()
}
