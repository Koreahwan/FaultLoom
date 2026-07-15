use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

use crate::Digest;
use crate::installed_trust::{
    InstalledTrustStore, installed_trust_store_from_canonical_bytes_for_test,
};

pub(super) const NOT_BEFORE_MILLIS: u64 = 1_893_553_500_000;
pub(super) const EXPIRES_MILLIS: u64 = 1_893_560_645_000;

pub(super) fn authority_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(super) fn key_id(key: &SigningKey) -> String {
    format!(
        "ed25519:sha256:{}",
        Digest::of(key.verifying_key().as_bytes()).to_hex()
    )
}

fn base64url<const ENCODED: usize>(raw: &[u8]) -> String {
    let mut encoded = [0_u8; ENCODED];
    let length = URL_SAFE_NO_PAD
        .encode_slice(raw, &mut encoded)
        .expect("fixed base64url buffer");
    core::str::from_utf8(&encoded[..length])
        .expect("base64url is ASCII")
        .to_owned()
}

pub(super) fn grant_payload() -> Value {
    json!({
        "action_policy": {
            "allowed_classes": ["observe", "safe_probe", "state_change"],
            "allowed_families": ["semantic-http"],
            "allowed_methods": ["GET", "POST"],
            "allowed_path_patterns": ["/api/*"],
            "denied": [{
                "action_families": ["semantic-http"],
                "deny_id": "deny-admin",
                "host_pattern": "loopback.test",
                "methods": ["POST"],
                "path_pattern": "/api/admin/*",
                "reason": "admin mutation is outside approval",
                "schema_version": "0.1.0",
                "target_id": "target-alpha"
            }],
            "schema_version": "0.1.0"
        },
        "adapter_ids": [],
        "approved_by": "operator-alpha",
        "budget": {
            "max_concurrency": 2,
            "max_duration_seconds": 30,
            "max_request_bytes": 4096,
            "max_response_bytes": 8192,
            "rate_per_minute": 8,
            "schema_version": "0.1.0",
            "total_actions": 8
        },
        "callback_policy": {
            "maximum_ttl_seconds": 60,
            "owned_domains": [],
            "schema_version": "0.1.0"
        },
        "draft_digest": concat!(
            "sha256:",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        "emergency_contact_ref": "contact-alpha",
        "execution_windows": [{
            "ends_at": "2030-01-02T04:04:05.000000Z",
            "schema_version": "0.1.0",
            "starts_at": "2030-01-02T03:05:00.000000Z"
        }],
        "expires_at": "2030-01-02T05:04:05.000000Z",
        "grant_id": "grant-alpha",
        "grant_version": 3,
        "identities": ["identity-alpha"],
        "issued_at": "2030-01-02T03:04:05.000000Z",
        "issued_to": "researcher-alpha",
        "not_before": "2030-01-02T03:05:00.000000Z",
        "pack_ids": ["web"],
        "provider_policy": {
            "allowed_model_snapshots": ["model-snapshot-alpha"],
            "allowed_providers": ["provider-alpha"],
            "arbitrary_provider_web_tools": false,
            "data_policy_id": "data-policy-alpha",
            "schema_version": "0.1.0"
        },
        "retention_policy": {
            "delete_after_seconds": 0,
            "policy_id": "retention-alpha",
            "retain_until": "2030-01-02T05:04:05.000000Z",
            "schema_version": "0.1.0"
        },
        "roles": ["researcher"],
        "schema_version": "0.1.0",
        "state_change_policy": {
            "allowed_families": ["semantic-http"],
            "canary_required": true,
            "cleanup_plan_required": true,
            "external_messages_allowed": false,
            "payment_or_real_asset_change_allowed": false,
            "schema_version": "0.1.0"
        },
        "targets": [{
            "cidrs": ["127.0.0.0/8"],
            "hostnames": ["loopback.test"],
            "methods": ["GET", "POST"],
            "paths": ["/api/*"],
            "ports": [8080],
            "protocols": ["http"],
            "schema_version": "0.1.0",
            "supporting_read_only": false,
            "target_id": "target-alpha"
        }],
        "tenants": ["tenant-alpha"]
    })
}

pub(super) fn signed_grant(payload: &Value, signer: &SigningKey) -> Vec<u8> {
    let payload_bytes = serde_json::to_vec(payload).expect("canonical payload");
    let payload_digest = format!("sha256:{}", Digest::of(&payload_bytes).to_hex());
    let key_id = key_id(signer);
    let signing_document = json!({
        "algorithm": "Ed25519",
        "expires_at": payload["expires_at"].clone(),
        "key_id": key_id,
        "payload": payload,
        "payload_digest": payload_digest,
        "protocol_version": "0.1.0",
        "purpose": "authority_grant",
        "sequence": payload["grant_version"].clone(),
        "signed_at": "2030-01-02T03:05:00.000000Z"
    });
    let signing_bytes = serde_json::to_vec(&signing_document).expect("canonical signing bytes");
    let signature = base64url::<86>(&signer.sign(&signing_bytes).to_bytes());
    serde_json::to_vec(&json!({
        "payload": payload,
        "schema_version": "0.1.0",
        "signature": {
            "algorithm": "Ed25519",
            "expires_at": payload["expires_at"].clone(),
            "key_id": key_id,
            "payload_digest": payload_digest,
            "protocol_version": "0.1.0",
            "purpose": "authority_grant",
            "schema_version": "0.1.0",
            "sequence": payload["grant_version"].clone(),
            "signature": signature,
            "signed_at": "2030-01-02T03:05:00.000000Z"
        }
    }))
    .expect("canonical envelope")
}

pub(super) fn trust_store(
    roots: &[&SigningKey],
    pinned: &SigningKey,
    minimum_version: u64,
) -> InstalledTrustStore {
    let controller = authority_key(91);
    let authority_keys = roots
        .iter()
        .map(|key| {
            json!({
                "key_id": key_id(key),
                "public_key_base64url": base64url::<43>(key.verifying_key().as_bytes()),
                "status": "active"
            })
        })
        .collect::<Vec<_>>();
    let raw = serde_json::to_vec(&json!({
        "authority_keys": authority_keys,
        "controller_keys": [{
            "key_id": key_id(&controller),
            "public_key_base64url": base64url::<43>(controller.verifying_key().as_bytes()),
            "status": "active"
        }],
        "generation": 1,
        "grant_pins": [{
            "authority_key_ids": [key_id(pinned)],
            "controller_key_ids": [key_id(&controller)],
            "grant_id": "grant-alpha",
            "minimum_version": minimum_version
        }],
        "schema_version": 1
    }))
    .expect("canonical trust store");
    installed_trust_store_from_canonical_bytes_for_test(&raw).expect("test trust store")
}
