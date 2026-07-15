use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use serde_json::json;

use crate::Digest;
use crate::installed_trust::{
    InstalledTrustStore, installed_trust_store_from_canonical_bytes_for_test,
};

use super::super::{boot_authorization_signing_bytes, verify_boot_authorization};
use super::support::{key_id, nonce, signature_accepts, signed_fixture};

fn encoded_public_key(key: &SigningKey) -> String {
    let mut encoded = [0_u8; 43];
    let encoded_length = URL_SAFE_NO_PAD
        .encode_slice(key.verifying_key().as_bytes(), &mut encoded)
        .unwrap();
    std::str::from_utf8(&encoded[..encoded_length])
        .unwrap()
        .to_owned()
}

fn trust_store(controller: &SigningKey, pinned_controller: &SigningKey) -> InstalledTrustStore {
    let authority = SigningKey::from_bytes(&[0x55; 32]);
    let mut controller_keys = vec![json!({
        "key_id": key_id(controller),
        "public_key_base64url": encoded_public_key(controller),
        "status": "active"
    })];
    if key_id(controller) != key_id(pinned_controller) {
        controller_keys.push(json!({
            "key_id": key_id(pinned_controller),
            "public_key_base64url": encoded_public_key(pinned_controller),
            "status": "active"
        }));
    }
    let raw = serde_json::to_vec(&json!({
        "authority_keys": [{
            "key_id": key_id(&authority),
            "public_key_base64url": encoded_public_key(&authority),
            "status": "active"
        }],
        "controller_keys": controller_keys,
        "generation": 4,
        "grant_pins": [{
            "authority_key_ids": [key_id(&authority)],
            "controller_key_ids": [key_id(pinned_controller)],
            "grant_id": "grant-a",
            "minimum_version": 9
        }],
        "schema_version": 1
    }))
    .unwrap();
    installed_trust_store_from_canonical_bytes_for_test(&raw).unwrap()
}

#[test]
fn deterministic_binding_accepts_only_the_exact_controller_authorization() {
    // Given: a deterministic binding signed by the pinned controller fixture.
    let (fixture, signing_key) = signed_fixture();

    // When: the same context is encoded repeatedly.
    let first =
        boot_authorization_signing_bytes(&fixture.context(), &fixture.authorization).unwrap();
    let second =
        boot_authorization_signing_bytes(&fixture.context(), &fixture.authorization).unwrap();

    // Then: the exact golden binding is stable and strict Ed25519 accepts its signature.
    assert_eq!(first, second);
    assert_eq!(first.len(), 588);
    assert_eq!(
        Digest::of(&first).to_hex(),
        "ecc765449a556dc2171e615f324fe8a6aa0b7f3f57dc483aabaf572e6489eff5"
    );
    assert!(signature_accepts(&fixture, &signing_key));
}

#[test]
fn installed_controller_pin_verifies_and_exposes_t19_replay_inputs() {
    // Given: a grant-pinned controller and its exact short-lived authorization.
    let (fixture, signing_key) = signed_fixture();
    let trust = trust_store(&signing_key, &signing_key);

    // When: the installed trust boundary verifies the binding at an in-window time.
    let verified =
        verify_boot_authorization(&trust, &fixture.context(), &fixture.authorization, 2_500)
            .unwrap();

    // Then: verified sequence and nonce are available for T19 durable replay controls.
    assert_eq!(verified.boot_sequence(), 7);
    assert_eq!(verified.nonce(), nonce(0x52));
}

#[test]
fn installed_controller_gate_rejects_wrong_pin_and_out_of_window_replay() {
    // Given: a valid signature, an unpinned controller store, and exact time boundaries.
    let (fixture, signing_key) = signed_fixture();
    let other = SigningKey::from_bytes(&[0x66; 32]);
    let wrong_pin = trust_store(&signing_key, &other);
    let valid_trust = trust_store(&signing_key, &signing_key);

    // When/Then: wrong pin, pre-issuance, and expiry are all fail-closed.
    assert!(
        verify_boot_authorization(
            &wrong_pin,
            &fixture.context(),
            &fixture.authorization,
            2_500,
        )
        .is_err()
    );
    assert!(
        verify_boot_authorization(
            &valid_trust,
            &fixture.context(),
            &fixture.authorization,
            1_999,
        )
        .is_err()
    );
    assert!(
        verify_boot_authorization(
            &valid_trust,
            &fixture.context(),
            &fixture.authorization,
            32_000,
        )
        .is_err()
    );
}

#[test]
fn binding_rejects_invalid_time_nonce_and_signature_contracts() {
    // Given: a valid fixture and security-boundary mutations.
    let (fixture, signing_key) = signed_fixture();
    let mut invalid = fixture.clone();
    invalid.authorization.issued_at_millis = 0;
    assert!(boot_authorization_signing_bytes(&invalid.context(), &invalid.authorization).is_err());
    let mut invalid = fixture.clone();
    invalid.authorization.expires_at_millis = invalid.authorization.issued_at_millis;
    assert!(boot_authorization_signing_bytes(&invalid.context(), &invalid.authorization).is_err());
    let mut invalid = fixture.clone();
    invalid.authorization.expires_at_millis = invalid.authorization.issued_at_millis + 30_001;
    assert!(boot_authorization_signing_bytes(&invalid.context(), &invalid.authorization).is_err());
    let mut invalid = fixture.clone();
    invalid.authorization.boot_sequence = 0;
    assert!(boot_authorization_signing_bytes(&invalid.context(), &invalid.authorization).is_err());
    let mut invalid = fixture.clone();
    invalid.authorization.nonce = [0; 16];
    assert!(boot_authorization_signing_bytes(&invalid.context(), &invalid.authorization).is_err());

    // When: only the detached signature is altered.
    let mut invalid = fixture.clone();
    invalid.authorization.signature[0] ^= 1;

    // Then: strict verification rejects it while the binding remains encodable.
    assert!(!signature_accepts(&invalid, &signing_key));
}
